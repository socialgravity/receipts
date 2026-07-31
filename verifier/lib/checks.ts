// The checks themselves, separated from the CLI so they can be unit-tested against fixtures
// with no network.
//
// Three outcomes, and keeping them distinct is the point of this file:
//
//   pass          checked, and it held
//   fail          checked, and it did not hold
//   not_checkable we cannot check this from public data at all
//
// Collapsing the third into either of the others is how a verifier starts lying. "Consent is on
// record" is an assertion by the party under examination; reporting it as a cryptographic pass
// would put our word inside a result that is supposed to contain only arithmetic.

import { canonicalJson, sha256Hex } from "./canonical.ts";
import { verifyEd25519 } from "./ed25519.ts";
import { pinnedKey, PINNED_KEYS } from "./keys.ts";
import { bytesToHex, leafHash, rootFromPath } from "./merkle.ts";

export type Result = "pass" | "fail" | "not_checkable";

export interface Check {
  link: number; // 0 = document level, 1..5 = the five links
  name: string;
  result: Result;
  detail?: string;
}

// deno-lint-ignore no-explicit-any
type Json = any;

export class Checks {
  readonly list: Check[] = [];

  add(link: number, name: string, result: Result, detail?: string): void {
    this.list.push({ link, name, result, ...(detail ? { detail } : {}) });
  }

  get failed(): number {
    return this.list.filter((c) => c.result === "fail").length;
  }
  get unchecked(): number {
    return this.list.filter((c) => c.result === "not_checkable").length;
  }
  get verdict(): "pass" | "fail" | "incomplete" {
    if (this.failed > 0) return "fail";
    return this.unchecked > 0 ? "incomplete" : "pass";
  }
}

/** Envelope shape. A response that is not the envelope cannot be reasoned about further. */
export function checkEnvelope(c: Checks, body: Json): boolean {
  if (body?.ok !== true) {
    c.add(0, "response envelope", "fail", `ok was ${JSON.stringify(body?.ok)}`);
    return false;
  }
  if (body?.contract_version !== 1) {
    // Not a failure of the record: a newer contract version means this verifier is the stale
    // party, and saying so is more useful than reporting the licence as broken.
    c.add(
      0,
      "contract version",
      "not_checkable",
      `response is contract_version ${body?.contract_version}, this verifier implements 1`,
    );
    return false;
  }
  c.add(0, "response envelope", "pass", "ok=true, contract_version=1");
  return true;
}

/**
 * Verify a signature block against a PINNED key. The inline public key in the block is compared
 * to the pinned one and disagreement is a failure, because that is the shape a substituted-key
 * attack takes: a response signed with an attacker key that carries the attacker key alongside.
 */
export async function checkSignature(
  c: Checks,
  link: number,
  label: string,
  sig: Json,
): Promise<void> {
  if (!sig) {
    c.add(link, `${label} signature`, "fail", "no signature block on the record");
    return;
  }
  if (sig.algorithm !== "Ed25519") {
    c.add(link, `${label} signature`, "not_checkable", `unknown algorithm ${sig.algorithm}`);
    return;
  }

  const keyId = String(sig.company_key_id ?? "");
  const pinned = pinnedKey(keyId);
  if (!pinned) {
    // A refusal, not a failure. An unknown key id after a rotation means this verifier needs
    // updating; treating it as a bad signature would be a false accusation.
    c.add(
      link,
      `${label} key id`,
      "not_checkable",
      `record names key "${keyId}", which this verifier does not pin (known: ${
        Object.keys(PINNED_KEYS).join(", ")
      })`,
    );
    return;
  }
  if (sig.public_key_spki_b64 && sig.public_key_spki_b64 !== pinned) {
    c.add(
      link,
      `${label} key id`,
      "fail",
      `the key served inline for "${keyId}" is not the pinned key for that id`,
    );
    return;
  }
  c.add(link, `${label} key id`, "pass", `${keyId}, matches the pinned key`);

  // Canonicalize the payload ourselves. If the served canonical_json disagrees with our own
  // canonicalization, the signature might still verify against THEIR bytes while meaning
  // something else, so this is checked before the signature and not after.
  if (!sig.signed_payload || typeof sig.signed_payload !== "object") {
    c.add(link, `${label} payload`, "fail", "no signed_payload to canonicalize");
    return;
  }
  const ours = canonicalJson(sig.signed_payload);
  if (typeof sig.canonical_json === "string" && sig.canonical_json !== ours) {
    c.add(
      link,
      `${label} canonical bytes`,
      "fail",
      "our canonicalization of signed_payload differs from the canonical_json served",
    );
    return;
  }
  c.add(link, `${label} canonical bytes`, "pass", `${ours.length} bytes, reproduced locally`);

  const outcome = await verifyEd25519(ours, String(sig.sig_base64 ?? ""), pinned);
  if (outcome.ok === true) {
    c.add(link, `${label} signature`, "pass", "Ed25519 verified against the pinned key");
  } else if (outcome.ok === false) {
    c.add(link, `${label} signature`, "fail", outcome.reason);
  } else {
    c.add(link, `${label} signature`, "not_checkable", outcome.reason);
  }
}

/** Link 1. Nothing here is cryptographically checkable from public data, and it says so. */
export function checkPerson(c: Checks, license: Json): void {
  c.add(
    1,
    "consent on record",
    license?.consent_on_record === true ? "not_checkable" : "fail",
    license?.consent_on_record === true
      ? "asserted by the issuer: consent evidence exists and this is not a demo record. Consent here is a signed agreement plus a verified ID, never a recording; the agreement's hash is committed inside the signature and is checked separately below"
      : "the record does not assert a consent record",
  );

  const method = license?.identity_method;
  if (method === undefined) {
    c.add(
      1,
      "identity method",
      "not_checkable",
      "absent, so NO CLAIM is made either way; this licence predates the field. Do not read it as either method",
    );
  } else if (method === "document") {
    c.add(
      1,
      "identity method",
      "not_checkable",
      "'document': a government ID was verified. Signed, but the check itself is the issuer's. " +
        "NO LIVENESS: a document check establishes that a valid ID exists, never that the person " +
        "holding it was present. Do not read this as proof a human took part",
    );
  } else if (method === "video_attestation") {
    c.add(
      1,
      "identity method",
      "not_checkable",
      "'video_attestation': a named operator confirmed a spoken statement. NO government document " +
        "was checked, and a human watching a recording is not a vendor liveness check",
    );
  } else {
    c.add(1, "identity method", "fail", `unknown identity_method "${method}"`);
  }

  // What actually binds an authorisation to this licence. Since 2026-07-30 that can be either a
  // scripted recording or the signed platform agreement, and the payload names which. Neither
  // artifact is published; only its hash is signed, which is what stops it being swapped later.
  const payload = license?.signature?.signed_payload ?? {};
  const evidence = payload.consent_evidence;
  if (evidence && typeof evidence === "object") {
    const kind = String(evidence.kind ?? "");
    const sha = String(evidence.sha256 ?? "");
    if (!["consent_video", "platform_agreement"].includes(kind)) {
      c.add(1, "consent evidence", "fail", `unknown consent evidence kind "${kind}"`);
    } else if (!/^[0-9a-f]{64}$/.test(sha)) {
      c.add(1, "consent evidence", "fail", `consent evidence sha256 is not a sha256: "${sha.slice(0, 40)}"`);
    } else {
      c.add(
        1,
        "consent evidence",
        "pass",
        kind === "consent_video"
          ? "a consent recording is committed by hash inside the signature"
          : "a signed platform agreement is committed by hash inside the signature",
      );
    }
    // A licence carrying evidence needs nothing further from the legacy field; when it also has a
    // recording, the check below still runs and both must hold.
    if (payload.consent_video_sha256 === undefined) return;
  }

  const hash = payload.consent_video_sha256;
  if (typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash)) {
    c.add(1, "consent hash is signed", "pass", "consent_video_sha256 is inside the signed payload");
  } else if (hash === undefined) {
    c.add(
      1,
      "consent hash is signed",
      "fail",
      "the signed payload names no consent artifact at all, neither a recording hash nor consent_evidence",
    );
  } else if (hash === "") {
    c.add(
      1,
      "consent hash is signed",
      "fail",
      "consent_video_sha256 is the empty string in the signed payload, so the signature binds no recording",
    );
  } else {
    // A signature over a placeholder is a valid signature over nothing. The licence verifies
    // perfectly and still fails to bind a recording, which is exactly the case a verifier has
    // to shout about rather than smooth over.
    c.add(
      1,
      "consent hash is signed",
      "fail",
      `consent_video_sha256 is "${
        String(hash).slice(0, 40)
      }", which is not a sha256, so the signature binds no consent recording`,
    );
  }
}

/** Link 2. */
export function checkAssets(c: Checks, license: Json): void {
  const assets = license?.assets_licensed;
  if (!Array.isArray(assets) || assets.length === 0) {
    c.add(
      2,
      "asset versions",
      "not_checkable",
      "the licence names no asset fingerprints, so 'which exact voice or pack' is not answerable from it. Expected on licences issued before asset fingerprinting",
    );
    return;
  }
  const bad = assets.filter(
    (a: Json) =>
      !a || !["voice", "face"].includes(a.asset_type) ||
      !/^[0-9a-f]{64}$/.test(String(a.sha256 ?? "")) ||
      !Number.isInteger(a.version) || a.version < 1,
  );
  if (bad.length) {
    c.add(2, "asset versions", "fail", `${bad.length} of ${assets.length} fingerprints are malformed`);
    return;
  }
  const inPayload = license?.signature?.signed_payload?.assets_licensed;
  if (!inPayload) {
    c.add(
      2,
      "asset versions",
      "fail",
      "the response lists assets_licensed but the signed payload does not, so the list is not covered by the signature",
    );
    return;
  }
  if (canonicalJson(inPayload) !== canonicalJson(assets)) {
    c.add(2, "asset versions", "fail", "assets_licensed on the response differs from the signed copy");
    return;
  }
  c.add(
    2,
    "asset versions",
    "pass",
    `${assets.length} signed fingerprint(s): ${
      assets.map((a: Json) => `${a.asset_type} v${a.version}`).join(", ")
    }`,
  );
}

/**
 * What the platform took, if the record says. A rate, not an amount: deal pricing is never
 * published, so this reveals nothing about what the brand paid.
 *
 * The only interesting failure is a fee shown but not signed, or shown differently from the way
 * it was signed. Either means the number a talent reads is one the issuer can change at will,
 * which makes it a claim rather than a disclosure. Absent is not a failure: licences issued
 * before 2026-07-31 have no fee recorded, and "not recorded" is a different and honest answer.
 */
export function checkPlatformFee(c: Checks, license: Json): void {
  const shown = license?.platform_fee_bps;
  const signed = license?.signature?.signed_payload?.platform_fee_bps;
  if (shown === undefined && signed === undefined) {
    c.add(3, "platform fee", "not_checkable", "this licence records no platform fee");
    return;
  }
  if (signed === undefined) {
    c.add(
      3,
      "platform fee",
      "fail",
      `the response shows ${shown} bps but the signed payload does not carry it, so the issuer could change it at will`,
    );
    return;
  }
  if (shown !== undefined && shown !== signed) {
    c.add(
      3,
      "platform fee",
      "fail",
      `response says ${shown} bps, signature covers ${signed} bps`,
    );
    return;
  }
  const bps = signed as number;
  c.add(
    3,
    "platform fee",
    "pass",
    `${bps} bps (${(bps / 100).toFixed(2)} percent) taken by the platform, inside the signature`,
  );
}

/** Link 3, the non-signature half: does the record say what it appears to say. */
export function checkLicenseFacts(c: Checks, license: Json): void {
  const payload = license?.signature?.signed_payload ?? {};

  // A public field that is NOT inside the signed payload is a field we could change at will.
  // Worth stating per field rather than in prose, since a reader assumes the whole page is signed.
  const signedFields = ["license_id", "contract_sha256", "effective_at", "expires_at"];
  const unsigned = signedFields.filter((f) => payload[f] === undefined);
  if (unsigned.length) {
    c.add(3, "core fields are signed", "fail", `not in the signed payload: ${unsigned.join(", ")}`);
  } else {
    c.add(3, "core fields are signed", "pass", signedFields.join(", "));
  }

  for (const f of ["license_id", "contract_sha256"]) {
    if (payload[f] !== undefined && license[f] !== undefined && payload[f] !== license[f]) {
      c.add(3, `${f} agreement`, "fail", `response says ${license[f]}, signature covers ${payload[f]}`);
    }
  }
  // Timestamps are compared as instants, since the signed copy is normalized to
  // Date.toISOString() and the response may render the same instant differently.
  for (const f of ["effective_at", "expires_at"]) {
    if (payload[f] && license[f] && Date.parse(payload[f]) !== Date.parse(license[f])) {
      c.add(3, `${f} agreement`, "fail", `response says ${license[f]}, signature covers ${payload[f]}`);
    }
  }

  // Scope is the substance of what was permitted; it is signed, so confirm the published copy
  // is the signed one rather than a friendlier summary.
  const scopeFields: Array<[string, string]> = [
    ["assets", "assets"],
    ["use_case", "use_case"],
    ["media_channels", "media_channels"],
    ["territories", "territories"],
  ];
  const scope = payload.scope;
  if (!scope) {
    c.add(3, "scope is signed", "fail", "no scope inside the signed payload");
  } else {
    const drift = scopeFields.filter(([resp, sc]) =>
      license[resp] !== undefined && canonicalJson(license[resp]) !== canonicalJson(scope[sc])
    );
    if (drift.length) {
      c.add(3, "scope is signed", "fail", `published scope differs from signed scope: ${drift.map((d) => d[0]).join(", ")}`);
    } else {
      c.add(3, "scope is signed", "pass", "assets, use case, channels and territories match the signed scope");
    }
  }

  const status = license?.status;
  const now = Date.now();
  const from = Date.parse(license?.effective_at ?? "");
  const to = Date.parse(license?.expires_at ?? "");
  if (Number.isNaN(from) || Number.isNaN(to)) {
    c.add(3, "term", "fail", "effective_at or expires_at is not a parseable timestamp");
  } else if (to <= from) {
    c.add(3, "term", "fail", "expires_at is not after effective_at");
  } else {
    const inTerm = now >= from && now < to;
    // Status is a mutable platform fact and the term is signed, so they can legitimately
    // disagree (revoked inside the term, for instance). Only report the combination.
    c.add(
      3,
      "term",
      "pass",
      `${new Date(from).toISOString()} to ${new Date(to).toISOString()}; ${
        inTerm ? "in term now" : "outside its term now"
      }, status "${status}"`,
    );
    if (status === "active" && !inTerm) {
      c.add(
        3,
        "status against term",
        "fail",
        'status is "active" but now is outside the signed term',
      );
    }
  }
}

/** Link 4 and 5, for a receipt fetched by output id. */
export async function checkCredential(
  c: Checks,
  out: Json,
  license: Json,
  fileBytes: Uint8Array | null,
): Promise<void> {
  const cred = out?.credential;
  if (!cred) {
    c.add(5, "credential", "fail", "no credential on the response");
    return;
  }

  await checkSignature(c, 5, "credential", cred.signature);

  const payload = cred?.signature?.signed_payload ?? {};
  if (payload.output_sha256 !== cred.output_sha256) {
    c.add(5, "output hash is signed", "fail", "output_sha256 on the credential is not the signed one");
  } else if (!/^[0-9a-f]{64}$/.test(String(cred.output_sha256 ?? ""))) {
    c.add(5, "output hash is signed", "fail", "output_sha256 is not a sha256");
  } else {
    c.add(5, "output hash is signed", "pass", cred.output_sha256);
  }

  if (payload.captured !== "registered" && payload.captured !== "metered") {
    c.add(4, "capture basis", "fail", `captured is "${payload.captured}" in the signed payload`);
  } else {
    c.add(
      4,
      "capture basis",
      "pass",
      payload.captured === "metered"
        ? "metered: generated by the platform, so the event was observed"
        : "registered: brand-reported filing, not observed by the platform",
    );
  }

  // The actual file, if one was handed to us. This is the check a legal reviewer cares about.
  if (fileBytes) {
    const localHash = await sha256Hex(fileBytes);
    if (localHash === cred.output_sha256) {
      c.add(5, "file matches the credential", "pass", `sha256 ${localHash}`);
    } else {
      c.add(
        5,
        "file matches the credential",
        "fail",
        `the file hashes to ${localHash}, the credential covers ${cred.output_sha256}. This is not the registered original: possibly an edit, possibly something else`,
      );
    }
  } else {
    c.add(
      5,
      "file matches the credential",
      "not_checkable",
      "no local file supplied; pass --file to compare bytes",
    );
  }

  // Recompute in-term-at-publication rather than trusting the served boolean.
  const basis = cred.license_term_basis;
  const moment = basis === "published_at" ? Date.parse(cred.published_at ?? "") : Date.parse(cred.registered_at ?? "");
  const from = Date.parse(license?.effective_at ?? "");
  const to = Date.parse(license?.expires_at ?? "");
  if ([moment, from, to].some(Number.isNaN)) {
    c.add(5, "in term at publication", "not_checkable", "a timestamp needed for the arithmetic is missing");
  } else {
    const ours = moment >= from && moment < to;
    if (typeof cred.license_active_at_publication === "boolean" && cred.license_active_at_publication !== ours) {
      c.add(
        5,
        "in term at publication",
        "fail",
        `served ${cred.license_active_at_publication}, our arithmetic over the signed term says ${ours}`,
      );
    } else {
      c.add(
        5,
        "in term at publication",
        "pass",
        `${ours ? "in term" : "OUTSIDE the term"} at ${new Date(moment).toISOString()} (basis: ${basis})${
          basis === "registered_at" ? ", which is a fallback because no publication date was stated" : ""
        }`,
      );
    }
  }

  if (cred.license_id !== license?.license_id) {
    c.add(5, "credential points at this licence", "fail", `credential names ${cred.license_id}`);
  } else {
    c.add(5, "credential points at this licence", "pass", cred.license_id);
  }

  // The per-licence register chain: publicly this is continuity, not recomputation.
  if (typeof out.register_record_hash === "string" && /^[0-9a-f]{64}$/.test(out.register_record_hash)) {
    c.add(
      4,
      "register chain link",
      "not_checkable",
      "a chain hash is published, but its preimage includes unpublished fields and Postgres timestamp text, so it cannot be recomputed from public data (receipt-spec-v1 section 3.1)",
    );
  } else {
    c.add(4, "register chain link", "not_checkable", "no register_record_hash published for this output");
  }
}

/** The private block, when the caller holds their own copy. */
export async function checkPrivateBlock(c: Checks, cred: Json, blockJson: string): Promise<void> {
  let block: unknown;
  try {
    block = JSON.parse(blockJson);
  } catch (e) {
    c.add(5, "private block", "fail", `not JSON: ${e instanceof Error ? e.message : String(e)}`);
    return;
  }
  const expected = cred?.signature?.signed_payload?.private_sha256 ?? cred?.private_sha256;
  if (!expected) {
    c.add(5, "private block", "not_checkable", "the credential publishes no private_sha256 to compare against");
    return;
  }
  const got = await sha256Hex(canonicalJson(block));
  if (got === expected) {
    c.add(5, "private block", "pass", `rehashes to the committed ${expected}`);
  } else {
    c.add(
      5,
      "private block",
      "fail",
      `block hashes to ${got}, the credential commits to ${expected}. Either this is not the block that was committed, or it was altered`,
    );
  }
}

/** Transparency-log inclusion, when the log is reachable. */
export async function checkLogInclusion(c: Checks, sth: Json, proof: Json): Promise<void> {
  await checkSignature(c, 0, "tree head", sth?.signature);

  const size = Number(sth?.tree_size);
  const index = Number(proof?.leaf_index);
  if (!Number.isInteger(size) || !Number.isInteger(index)) {
    c.add(0, "log inclusion", "fail", "tree_size or leaf_index is not an integer");
    return;
  }
  if (typeof proof?.preimage === "string" && proof.preimage.length) {
    const recomputed = await sha256Hex(proof.preimage);
    if (recomputed !== proof.entry_hash) {
      c.add(
        0,
        "ledger entry hash",
        "fail",
        `sha256 of the published preimage is ${recomputed}, the entry claims ${proof.entry_hash}`,
      );
      return;
    }
    c.add(0, "ledger entry hash", "pass", "sha256 of the published preimage matches the entry hash");
  } else {
    c.add(0, "ledger entry hash", "not_checkable", "the log published no preimage for this entry");
  }

  try {
    const path = (proof.audit_path ?? []).map((h: string) => hexBytes(h));
    const root = await rootFromPath(await leafHash(proof.entry_hash), index, size, path);
    const rootHex = bytesToHex(root);
    if (rootHex === sth.root_hash) {
      c.add(0, "log inclusion", "pass", `leaf ${index} of ${size} is under root ${rootHex.slice(0, 16)}...`);
    } else {
      c.add(0, "log inclusion", "fail", `recomputed root ${rootHex} does not match the signed root ${sth.root_hash}`);
    }
  } catch (e) {
    c.add(0, "log inclusion", "fail", `proof is malformed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // An anchor earns a PASS only if it is an EXTERNAL timestamp AND it actually covers this
  // entry. Two ways the presence of an anchor field means nothing for the record in hand, both
  // of which the log itself reports and this check used to throw away:
  //   - method "signed" is our own key over our own head. That proves origin, not date, so it
  //     rules out exactly nothing about back-dating.
  //   - an anchor taken at ledger seq N says nothing about an entry at seq N+1, which is the
  //     normal state for a freshly issued licence: the anchor lags the entry it would cover.
  // Passing on presence alone told a reader "back-dating is ruled out" when neither held.
  // The log now reports every anchor of the newest head under `anchors`, with `anchor` kept as
  // the strongest for older readers. Prefer finding rfc3161 ourselves rather than trusting the
  // server's idea of strongest: this verifier's job includes the case where the server is wrong.
  const reported = Array.isArray(sth?.anchors) ? sth.anchors : [];
  const anchor = reported.find((a: { method?: string }) => a?.method === "rfc3161") ?? sth?.anchor;
  if (!anchor?.method) {
    c.add(
      0,
      "external anchor",
      "not_checkable",
      "this head carries no external timestamp, so its signature proves origin but not that it existed on the date it carries",
    );
    return;
  }

  const anchoredSeq = Number(anchor.head_seq);
  const entrySeq = Number(proof?.seq);
  if (anchor.method !== "rfc3161") {
    c.add(
      0,
      "external anchor",
      "not_checkable",
      `the newest anchor is method "${anchor.method}", our own signature over our own head rather than an ` +
        "external timestamp, so it proves origin and not that the tree had this shape on the stated date",
    );
  } else if (Number.isInteger(anchoredSeq) && Number.isInteger(entrySeq) && anchoredSeq < entrySeq) {
    c.add(
      0,
      "external anchor",
      "not_checkable",
      `the newest external timestamp covers ledger seq ${anchoredSeq} and this entry is seq ${entrySeq}, ` +
        "so no anchor covers it yet; back-dating is ruled out only up to the anchored point",
    );
  } else {
    c.add(
      0,
      "external anchor",
      "pass",
      `head timestamped by ${anchor.method} at ${anchor.anchored_at}, covering ledger seq ${anchor.head_seq} ` +
        `and so this entry at seq ${proof?.seq}, which is what rules out back-dating`,
    );
  }
}

/**
 * The per-licence chain, recomputed rather than believed.
 *
 * Until chain versions 5 and 3 this check could not exist: the preimages held the brand's key
 * and the volume, so the only public statement available was "trust us, the hashes link". Now
 * every recomputable row publishes the exact string its hash was taken over, and this walks them
 * hashing each one and following prev_hash. A row that fails is a row whose published preimage
 * does not produce its published hash, which is the accusation this surface exists to answer.
 *
 * What a pass does NOT mean: that the chain is complete. A log that never wrote a row cannot be
 * caught by a check on the rows it did write, which is what the transparency log's inclusion
 * proofs and the anchors are for. Stated here because "the chain verified" is easy to over-read.
 */
export async function checkLicenseChain(c: Checks, chain: Json): Promise<void> {
  const rows = (chain?.rows ?? []) as Json[];
  if (!rows.length) {
    c.add(4, "licence chain", "not_checkable", "this licence has no metered or registered rows yet");
    return;
  }

  const byKind = new Map<string, Json[]>();
  for (const r of rows) {
    const k = String(r.kind ?? "unknown");
    if (!byKind.has(k)) byKind.set(k, []);
    byKind.get(k)!.push(r);
  }

  let recomputed = 0;
  let skipped = 0;
  for (const [kind, kindRows] of byKind) {
    let expectedPrev = "genesis";
    for (const r of kindRows) {
      if (!r.recomputable || typeof r.preimage !== "string") {
        skipped++;
        // The link still has to hold across a row we cannot recompute, so carry its hash
        // forward: an unpublishable preimage is not permission to lose the thread.
        expectedPrev = typeof r.record_hash === "string" ? r.record_hash : expectedPrev;
        continue;
      }
      const got = await sha256Hex(r.preimage);
      if (got !== r.record_hash) {
        c.add(
          4,
          "licence chain",
          "fail",
          `${kind} row ${r.seq}: sha256 of the published preimage is ${got}, the row claims ${r.record_hash}`,
        );
        return;
      }
      if (r.prev_hash !== expectedPrev) {
        c.add(
          4,
          "licence chain",
          "fail",
          `${kind} row ${r.seq}: prev_hash is ${r.prev_hash}, but the row before it hashes to ${expectedPrev}`,
        );
        return;
      }
      expectedPrev = String(r.record_hash);
      recomputed++;
    }
  }

  if (!recomputed) {
    c.add(
      4,
      "licence chain",
      "not_checkable",
      `${skipped} row(s) predate the recomputable formulas, so none of this chain can be rehashed`,
    );
    return;
  }
  c.add(
    4,
    "licence chain",
    "pass",
    `${recomputed} row(s) rehashed from their published preimages and linked` +
      (skipped ? `; ${skipped} older row(s) not recomputable and skipped` : ""),
  );
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
