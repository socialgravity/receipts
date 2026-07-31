// Verifier tests against a fixture captured from production (licence LGVGMQAWVE2, a real signed
// record with a real consent hash and a signed asset fingerprint).
//
// The clean case is one test. The rest are tampering: every one of them is a way a receipt could
// be forged or quietly weakened, and each must produce a FAIL rather than a pass or a crash. A
// verifier that only proves valid things valid has not been tested.

import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  Checks,
  checkAssets,
  checkEnvelope,
  checkLicenseChain,
  checkLicenseFacts,
  checkPlatformFee,
  checkLogInclusion,
  checkPerson,
  checkPrivateBlock,
  checkSignature,
} from "./checks.ts";
import { canonicalJson, sha256Hex } from "./canonical.ts";
import { bytesToHex, leafHash } from "./merkle.ts";

const FIXTURE = JSON.parse(
  await Deno.readTextFile(new URL("../fixtures/license-LGVGMQAWVE2.json", import.meta.url)),
);

// deno-lint-ignore no-explicit-any
function fresh(): any {
  return JSON.parse(JSON.stringify(FIXTURE));
}

function named(c: Checks, name: string) {
  const found = c.list.find((x) => x.name === name);
  assert(found, `no check named "${name}" was recorded (have: ${c.list.map((x) => x.name).join(", ")})`);
  return found;
}

// ---------------------------------------------------------------------------
// The clean record
// ---------------------------------------------------------------------------

Deno.test("a real production licence verifies", async () => {
  const body = fresh();
  const c = new Checks();
  assert(checkEnvelope(c, body));
  await checkSignature(c, 3, "licence", body.data.signature);
  checkPerson(c, body.data);
  checkAssets(c, body.data);
  checkLicenseFacts(c, body.data);

  assertEquals(c.failed, 0, `unexpected failures: ${JSON.stringify(c.list.filter((x) => x.result === "fail"))}`);
  assertEquals(named(c, "licence signature").result, "pass");
  assertEquals(named(c, "licence canonical bytes").result, "pass");
  assertEquals(named(c, "consent hash is signed").result, "pass");
  assertEquals(named(c, "asset versions").result, "pass");
  assertEquals(named(c, "scope is signed").result, "pass");
});

Deno.test("consent-on-record is never reported as a cryptographic pass", () => {
  const c = new Checks();
  checkPerson(c, fresh().data);
  // The single most important honesty property in the tool: it is an assertion by the party
  // under examination, so it can only ever be not_checkable.
  assertEquals(named(c, "consent on record").result, "not_checkable");
  assertEquals(c.verdict, "incomplete");
});

// ---------------------------------------------------------------------------
// Signature tampering
// ---------------------------------------------------------------------------

Deno.test("a flipped signature byte fails", async () => {
  const body = fresh();
  const sig = body.data.signature;
  const bytes = atob(sig.sig_base64).split("").map((ch) => ch.charCodeAt(0));
  bytes[0] ^= 0xff;
  sig.sig_base64 = btoa(String.fromCharCode(...bytes));
  const c = new Checks();
  await checkSignature(c, 3, "licence", sig);
  assertEquals(named(c, "licence signature").result, "fail");
});

Deno.test("an altered signed payload fails, even with canonical_json rewritten to match", async () => {
  // The realistic forgery: change the term, then rebuild the canonical string so the record
  // looks internally consistent. Only the signature catches it.
  const body = fresh();
  const sig = body.data.signature;
  sig.signed_payload.expires_at = "2099-01-01T00:00:00.000Z";
  sig.canonical_json = canonicalJson(sig.signed_payload);
  const c = new Checks();
  await checkSignature(c, 3, "licence", sig);
  assertEquals(named(c, "licence canonical bytes").result, "pass");
  assertEquals(named(c, "licence signature").result, "fail");
});

Deno.test("canonical_json that disagrees with the payload fails before the signature", async () => {
  // Someone serving friendly-looking bytes next to a payload that says something else.
  const body = fresh();
  body.data.signature.canonical_json = '{"license_id":"SOMETHING ELSE"}';
  const c = new Checks();
  await checkSignature(c, 3, "licence", body.data.signature);
  assertEquals(named(c, "licence canonical bytes").result, "fail");
  assert(!c.list.some((x) => x.name === "licence signature"), "must not proceed to the signature");
});

Deno.test("a substituted inline public key fails rather than verifying", async () => {
  // The attack the pinned key exists to stop: a record signed with an attacker key, served
  // alongside that key. Without pinning this would verify perfectly.
  const body = fresh();
  body.data.signature.public_key_spki_b64 = "MCowBQYDK2VwAyEA" + "A".repeat(28) + "=";
  const c = new Checks();
  await checkSignature(c, 3, "licence", body.data.signature);
  assertEquals(named(c, "licence key id").result, "fail");
});

Deno.test("an unknown key id refuses rather than accuses", async () => {
  const body = fresh();
  body.data.signature.company_key_id = "idl-signing-v9";
  const c = new Checks();
  await checkSignature(c, 3, "licence", body.data.signature);
  // not_checkable, not fail: after a real rotation this verifier is the stale party, and
  // reporting a valid licence as forged would be worse than saying "I cannot tell".
  assertEquals(named(c, "licence key id").result, "not_checkable");
  assertEquals(c.verdict, "incomplete");
});

Deno.test("a missing signature block fails", async () => {
  const c = new Checks();
  await checkSignature(c, 3, "licence", undefined);
  assertEquals(named(c, "licence signature").result, "fail");
});

// ---------------------------------------------------------------------------
// Published-versus-signed drift
// ---------------------------------------------------------------------------

Deno.test("a scope published wider than the scope signed fails", async () => {
  const body = fresh();
  body.data.media_channels = [...body.data.media_channels, "tv_ctv"];
  const c = new Checks();
  checkLicenseFacts(c, body.data);
  assertEquals(named(c, "scope is signed").result, "fail");
  // And the signature still verifies, which is exactly why this check exists separately.
  const c2 = new Checks();
  await checkSignature(c2, 3, "licence", body.data.signature);
  assertEquals(named(c2, "licence signature").result, "pass");
});

Deno.test("a licence id on the page that differs from the signed one fails", () => {
  const body = fresh();
  body.data.license_id = "LNOTTHEONE1";
  const c = new Checks();
  checkLicenseFacts(c, body.data);
  assertEquals(named(c, "license_id agreement").result, "fail");
});

Deno.test("timestamps are compared as instants, not strings", () => {
  const body = fresh();
  const signed = body.data.signature.signed_payload.effective_at;
  // Same instant, different rendering. A string comparison would report a false failure.
  body.data.effective_at = new Date(Date.parse(signed)).toISOString().replace(".000Z", ".000+00:00");
  const c = new Checks();
  checkLicenseFacts(c, body.data);
  assert(!c.list.some((x) => x.name === "effective_at agreement" && x.result === "fail"));
});

Deno.test("active status outside the signed term fails", () => {
  // A term wholly in the past, with the status left at active. This is the state a broken
  // expiry sweep leaves behind, and a licence page still saying "active" is the visible harm.
  const body = fresh();
  for (const target of [body.data, body.data.signature.signed_payload]) {
    target.effective_at = "2019-01-01T00:00:00.000Z";
    target.expires_at = "2020-01-01T00:00:00.000Z";
  }
  assertEquals(body.data.status, "active");
  const c = new Checks();
  checkLicenseFacts(c, body.data);
  assertEquals(named(c, "term").result, "pass"); // the term itself is well formed
  assertEquals(named(c, "status against term").result, "fail");
});

Deno.test("an inverted term fails on its own", () => {
  const body = fresh();
  body.data.expires_at = body.data.effective_at;
  body.data.signature.signed_payload.expires_at = body.data.effective_at;
  const c = new Checks();
  checkLicenseFacts(c, body.data);
  assertEquals(named(c, "term").result, "fail");
});

Deno.test("core fields missing from the signed payload fail", () => {
  const body = fresh();
  delete body.data.signature.signed_payload.contract_sha256;
  const c = new Checks();
  checkLicenseFacts(c, body.data);
  assertEquals(named(c, "core fields are signed").result, "fail");
});

// ---------------------------------------------------------------------------
// Link 1 and 2 edge cases
// ---------------------------------------------------------------------------

Deno.test("a placeholder consent hash fails even though the signature is valid", async () => {
  // This is the live state of the public demo licence LYL7ZYRM2Q2: perfectly signed, and the
  // thing it commits to is the string "smoke-test-placeholder".
  const body = fresh();
  body.data.signature.signed_payload.consent_video_sha256 = "smoke-test-placeholder";
  const c = new Checks();
  checkPerson(c, body.data);
  const check = named(c, "consent hash is signed");
  assertEquals(check.result, "fail");
  assert(check.detail?.includes("not a sha256"));
});

Deno.test("an absent identity method makes no claim in either direction", () => {
  const body = fresh();
  delete body.data.identity_method;
  const c = new Checks();
  checkPerson(c, body.data);
  const check = named(c, "identity method");
  assertEquals(check.result, "not_checkable");
  assert(check.detail?.includes("NO CLAIM"));
});

Deno.test("video attestation is reported as weaker than a document, not as equivalent", () => {
  const body = fresh();
  body.data.identity_method = "video_attestation";
  const c = new Checks();
  checkPerson(c, body.data);
  assert(named(c, "identity method").detail?.includes("NO government document"));
});

Deno.test("an unknown identity method fails", () => {
  const body = fresh();
  body.data.identity_method = "vibes";
  const c = new Checks();
  checkPerson(c, body.data);
  assertEquals(named(c, "identity method").result, "fail");
});

Deno.test("asset fingerprints on the page but not in the signature fail", () => {
  const body = fresh();
  delete body.data.signature.signed_payload.assets_licensed;
  const c = new Checks();
  checkAssets(c, body.data);
  assertEquals(named(c, "asset versions").result, "fail");
});

Deno.test("an asset version bumped only on the page fails", () => {
  const body = fresh();
  body.data.assets_licensed[0].version = 99;
  const c = new Checks();
  checkAssets(c, body.data);
  assertEquals(named(c, "asset versions").result, "fail");
});

Deno.test("no asset fingerprints is not checkable rather than a failure", () => {
  const body = fresh();
  delete body.data.assets_licensed;
  delete body.data.signature.signed_payload.assets_licensed;
  const c = new Checks();
  checkAssets(c, body.data);
  // Legitimate for licences issued before fingerprinting, so it must not read as forgery.
  assertEquals(named(c, "asset versions").result, "not_checkable");
});

// ---------------------------------------------------------------------------
// Envelope and private block
// ---------------------------------------------------------------------------

Deno.test("an error envelope stops verification", () => {
  const c = new Checks();
  assertEquals(checkEnvelope(c, { ok: false, contract_version: 1, error: { code: "not_found", message: "x" } }), false);
  assertEquals(named(c, "response envelope").result, "fail");
});

Deno.test("a future contract version makes the verifier the stale party", () => {
  const c = new Checks();
  assertEquals(checkEnvelope(c, { ok: true, contract_version: 2, data: {} }), false);
  assertEquals(named(c, "contract version").result, "not_checkable");
});

Deno.test("a private block that rehashes to its commitment passes", async () => {
  const block = { media_channel: "paid_social", territory: "US", flags: [] };
  const cred = { private_sha256: await sha256Hex(canonicalJson(block)) };
  const c = new Checks();
  await checkPrivateBlock(c, cred, JSON.stringify(block));
  assertEquals(named(c, "private block").result, "pass");
});

Deno.test("a private block with a flag removed fails its commitment", async () => {
  // The tamper this defends: quietly dropping a flag from the copy handed to a third party.
  const committed = { media_channel: "paid_social", territory: "US", flags: ["late"] };
  const cred = { private_sha256: await sha256Hex(canonicalJson(committed)) };
  const softened = { media_channel: "paid_social", territory: "US", flags: [] };
  const c = new Checks();
  await checkPrivateBlock(c, cred, JSON.stringify(softened));
  assertEquals(named(c, "private block").result, "fail");
});

Deno.test("private block key order does not matter but content does", async () => {
  const block = { territory: "US", flags: ["late"], media_channel: "web" };
  const cred = { private_sha256: await sha256Hex(canonicalJson(block)) };
  const c = new Checks();
  await checkPrivateBlock(c, cred, JSON.stringify({ flags: ["late"], media_channel: "web", territory: "US" }));
  assertEquals(named(c, "private block").result, "pass");
});

// ---------------------------------------------------------------------------
// Transparency-log anchoring
//
// The anchor line is the only thing on a receipt that speaks to WHEN, so an over-claim here is
// the most expensive kind. These pin the three cases apart. Found live on 2026-07-30: the demo
// licence sat at ledger seq 4 under an anchor of method "signed" covering seq 3, and the
// verifier printed "which is what rules out back-dating" over both facts.
// ---------------------------------------------------------------------------

/** A one-leaf tree whose inclusion proof is genuinely valid, so only the anchor is under test. */
async function oneLeafLog(anchor: unknown) {
  const entryHash = "a".repeat(64);
  const root = bytesToHex(await leafHash(entryHash));
  return {
    sth: { tree_size: "1", root_hash: root, anchor },
    proof: { leaf_index: "0", seq: "1", entry_hash: entryHash, audit_path: [] },
  };
}

Deno.test("an anchor signed by our own key is never reported as ruling out back-dating", async () => {
  const { sth, proof } = await oneLeafLog({
    method: "signed",
    anchored_at: "2026-07-30T16:21:24.329+00:00",
    head_seq: "1",
  });
  const c = new Checks();
  await checkLogInclusion(c, sth, proof);
  assertEquals(named(c, "log inclusion").result, "pass");
  assertEquals(named(c, "external anchor").result, "not_checkable");
  assert(!(named(c, "external anchor").detail ?? "").includes("rules out back-dating"));
});

Deno.test("an external timestamp taken before this entry existed does not cover it", async () => {
  const { sth, proof } = await oneLeafLog({
    method: "rfc3161",
    anchored_at: "2026-07-30T16:21:24.329+00:00",
    head_seq: "0",
  });
  const c = new Checks();
  await checkLogInclusion(c, sth, proof);
  const line = named(c, "external anchor");
  assertEquals(line.result, "not_checkable");
  const detail = line.detail ?? "";
  assert(detail.includes("seq 0"), detail);
  assert(detail.includes("seq 1"), detail);
});

Deno.test("an external timestamp covering this entry passes", async () => {
  const { sth, proof } = await oneLeafLog({
    method: "rfc3161",
    anchored_at: "2026-07-30T16:21:24.329+00:00",
    head_seq: "1",
  });
  const c = new Checks();
  await checkLogInclusion(c, sth, proof);
  const line = named(c, "external anchor");
  assertEquals(line.result, "pass");
  assert((line.detail ?? "").includes("rules out back-dating"));
});

Deno.test("no anchor at all is not_checkable, not a silent pass", async () => {
  const { sth, proof } = await oneLeafLog(null);
  const c = new Checks();
  await checkLogInclusion(c, sth, proof);
  assertEquals(named(c, "external anchor").result, "not_checkable");
});

// ---------------------------------------------------------------------------
// Per-licence chain recomputation (chain versions 5 and 3)
// ---------------------------------------------------------------------------
// The property under test is the one the receipt spec had to disclaim until now: a stranger can
// rehash these rows. So every test here builds the preimages, hashes them the way the database
// does, and then breaks something.

async function chainOf(
  preimages: string[],
  opts: { recomputable?: boolean[]; kind?: string } = {},
): Promise<{ rows: Record<string, unknown>[] }> {
  const rows: Record<string, unknown>[] = [];
  let prev = "genesis";
  for (let i = 0; i < preimages.length; i++) {
    // The preimage always opens with prev_hash, exactly as the SQL builder does.
    const preimage = `${prev}|${preimages[i]}`;
    const hash = await sha256Hex(preimage);
    rows.push({
      kind: opts.kind ?? "generation",
      seq: String(i + 1),
      chain_version: "5",
      prev_hash: prev,
      record_hash: hash,
      preimage,
      recomputable: opts.recomputable?.[i] ?? true,
      private_commitment: "ab".repeat(32),
    });
    prev = hash;
  }
  return { rows };
}

Deno.test("a published chain that rehashes and links passes", async () => {
  const chain = await chainOf(["LTEST|one", "LTEST|two", "LTEST|three"]);
  const c = new Checks();
  await checkLicenseChain(c, chain);
  const line = named(c, "licence chain");
  assertEquals(line.result, "pass");
  assert((line.detail ?? "").includes("3 row(s) rehashed"));
});

Deno.test("a preimage edited after the fact fails, because it no longer hashes to the row", async () => {
  const chain = await chainOf(["LTEST|one", "LTEST|two"]);
  // The exact forgery this endpoint has to catch: the story is changed, the hash is left alone.
  (chain.rows[1] as Record<string, unknown>).preimage =
    String(chain.rows[1].preimage).replace("two", "twz");
  const c = new Checks();
  await checkLicenseChain(c, chain);
  assertEquals(named(c, "licence chain").result, "fail");
});

Deno.test("a row spliced out of the middle breaks the link and fails", async () => {
  const chain = await chainOf(["LTEST|one", "LTEST|two", "LTEST|three"]);
  chain.rows.splice(1, 1);
  const c = new Checks();
  await checkLicenseChain(c, chain);
  const line = named(c, "licence chain");
  assertEquals(line.result, "fail");
  assert((line.detail ?? "").includes("prev_hash"));
});

Deno.test("rows too old to recompute are skipped, not silently counted as verified", async () => {
  const chain = await chainOf(["LTEST|one", "LTEST|two"], { recomputable: [false, true] });
  delete (chain.rows[0] as Record<string, unknown>).preimage;
  // Row 2 still links to row 1's hash, which the check must carry across the gap.
  const c = new Checks();
  await checkLicenseChain(c, chain);
  const line = named(c, "licence chain");
  assertEquals(line.result, "pass");
  assert((line.detail ?? "").includes("1 older row(s) not recomputable"));
});

Deno.test("a chain with nothing recomputable is not_checkable rather than a pass", async () => {
  const chain = await chainOf(["LTEST|one"], { recomputable: [false] });
  delete (chain.rows[0] as Record<string, unknown>).preimage;
  const c = new Checks();
  await checkLicenseChain(c, chain);
  assertEquals(named(c, "licence chain").result, "not_checkable");
});

Deno.test("an empty chain is not_checkable, never a pass", async () => {
  const c = new Checks();
  await checkLicenseChain(c, { rows: [] });
  assertEquals(named(c, "licence chain").result, "not_checkable");
});

// ---------------------------------------------------------------------------
// Platform fee. A rate the issuer could revise afterwards is a claim, not a
// disclosure, so the only interesting cases are the dishonest ones.
// ---------------------------------------------------------------------------

Deno.test("a platform fee inside the signature passes and states the rate", () => {
  const body = fresh();
  body.data.platform_fee_bps = 1500;
  body.data.signature.signed_payload.platform_fee_bps = 1500;
  const c = new Checks();
  checkPlatformFee(c, body.data);
  assertEquals(named(c, "platform fee").result, "pass");
  assert(named(c, "platform fee").detail?.includes("15.00 percent"));
});

Deno.test("a fee shown but not signed FAILS, because the issuer could revise it", () => {
  const body = fresh();
  body.data.platform_fee_bps = 1500;
  delete body.data.signature.signed_payload.platform_fee_bps;
  const c = new Checks();
  checkPlatformFee(c, body.data);
  assertEquals(named(c, "platform fee").result, "fail");
});

Deno.test("a fee displayed differently from the signed one FAILS", () => {
  const body = fresh();
  body.data.platform_fee_bps = 500;
  body.data.signature.signed_payload.platform_fee_bps = 1500;
  const c = new Checks();
  checkPlatformFee(c, body.data);
  assertEquals(named(c, "platform fee").result, "fail");
});

Deno.test("no fee recorded is not_checkable, and a signed zero is a real answer", () => {
  const absent = fresh();
  const c1 = new Checks();
  checkPlatformFee(c1, absent.data);
  assertEquals(named(c1, "platform fee").result, "not_checkable");

  // "we took nothing" and "we did not record it" must not collapse into one answer.
  const zero = fresh();
  zero.data.platform_fee_bps = 0;
  zero.data.signature.signed_payload.platform_fee_bps = 0;
  const c2 = new Checks();
  checkPlatformFee(c2, zero.data);
  assertEquals(named(c2, "platform fee").result, "pass");
});
