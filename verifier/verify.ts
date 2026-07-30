#!/usr/bin/env -S deno run --allow-net
// SocialGravity receipt verifier. Fetches public data, verifies LOCALLY.
//
//   deno run --allow-net verifier/verify.ts --license L24SQXLKQFC
//   deno run --allow-net verifier/verify.ts --output  OUT4K2Q9Z
//   deno run --allow-net --allow-read verifier/verify.ts --output OUT4K2Q9Z --file ./spot.wav
//   deno run --allow-net verifier/verify.ts --license L24SQXLKQFC --json > receipt.json
//
// The only thing this takes from the network is data. Every signature check, every hash and
// every piece of arithmetic happens here, against a public key pinned in verifier/lib/keys.ts
// rather than the one served alongside the record. That is the whole design: if verifying
// required trusting the issuer, there would be no point verifying.
//
// Exit codes, so this is usable in a pipeline:
//   0  every check passed
//   1  at least one check FAILED
//   2  no failures, but something could not be checked (see NOT CHECKABLE lines)
//   3  the verifier could not run at all (bad arguments, network, unparseable response)

import {
  Check,
  Checks,
  checkAssets,
  checkCredential,
  checkEnvelope,
  checkLicenseFacts,
  checkLogInclusion,
  checkPerson,
  checkPrivateBlock,
  checkSignature,
} from "./lib/checks.ts";

const DEFAULT_BASE = "https://id.socialgravity.ai/functions/v1";

interface Args {
  license?: string;
  output?: string;
  file?: string;
  privateBlock?: string;
  base: string;
  json: boolean;
  quiet: boolean;
  noLog: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { base: DEFAULT_BASE, json: false, quiet: false, noLog: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) die(3, `${k} needs a value`);
      return v;
    };
    switch (k) {
      case "--license": case "-l": a.license = next().toUpperCase(); break;
      case "--output": case "-o": a.output = next().toUpperCase(); break;
      case "--file": case "-f": a.file = next(); break;
      case "--private-block": a.privateBlock = next(); break;
      case "--base": a.base = next().replace(/\/+$/, ""); break;
      case "--json": a.json = true; break;
      case "--quiet": case "-q": a.quiet = true; break;
      case "--no-log": a.noLog = true; break;
      case "--help": case "-h": usage(); Deno.exit(0); break;
      default: die(3, `unknown argument ${k}`);
    }
  }
  if (!a.license && !a.output) die(3, "one of --license or --output is required");
  return a;
}

function usage(): void {
  console.log(`
Verify a SocialGravity identity licensing receipt locally.

  --license, -l <id>     verify a licence by id
  --output,  -o <id>     verify a per-output receipt (fetches its licence too)
  --file,    -f <path>   hash a local file and compare it to the credential
  --private-block <path> a private block JSON you hold, rehashed against its commitment
  --base <url>           API base (default ${DEFAULT_BASE})
  --no-log               skip the transparency-log lookup
  --json                 print the receipt document (docs/schemas/receipt-v1.schema.json)
  --quiet, -q            print only the verdict line

Exit: 0 pass, 1 fail, 2 incomplete, 3 could not run.
`.trim());
}

function die(code: number, message: string): never {
  console.error(`verify: ${message}`);
  Deno.exit(code);
}

// deno-lint-ignore no-explicit-any
async function getJson(url: string): Promise<any> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: "application/json" } });
  } catch (e) {
    die(3, `could not reach ${url}: ${e instanceof Error ? e.message : String(e)}`);
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    die(3, `${url} did not return JSON (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }
}

const args = parseArgs(Deno.args);
const checks = new Checks();

// deno-lint-ignore no-explicit-any
let licenseData: any = null;
// deno-lint-ignore no-explicit-any
let outputData: any = null;

// ---------------------------------------------------------------------------
// Fetch. An output receipt names its licence, so verifying one always verifies both: a
// credential whose licence does not check out is not a valid receipt however well it is signed.
// ---------------------------------------------------------------------------

if (args.output) {
  const body = await getJson(`${args.base}/idl-verify?output=${encodeURIComponent(args.output)}`);
  if (!checkEnvelope(checks, body)) {
    report();
    Deno.exit(finalCode());
  }
  outputData = body.data;
  const licenseId = outputData?.credential?.license_id;
  if (!licenseId) {
    checks.add(5, "credential names a licence", "fail", "no license_id on the credential");
  } else {
    const lic = await getJson(`${args.base}/idl-verify?id=${encodeURIComponent(licenseId)}`);
    if (checkEnvelope(checks, lic)) licenseData = lic.data;
  }
} else {
  const body = await getJson(`${args.base}/idl-verify?id=${encodeURIComponent(args.license!)}`);
  if (!checkEnvelope(checks, body)) {
    report();
    Deno.exit(finalCode());
  }
  licenseData = body.data;
}

// ---------------------------------------------------------------------------
// Check, link by link
// ---------------------------------------------------------------------------

if (licenseData) {
  await checkSignature(checks, 3, "licence", licenseData.signature);
  checkPerson(checks, licenseData);
  checkAssets(checks, licenseData);
  checkLicenseFacts(checks, licenseData);
} else {
  checks.add(3, "licence", "fail", "the licence behind this receipt could not be read");
}

if (outputData) {
  let fileBytes: Uint8Array | null = null;
  if (args.file) {
    try {
      fileBytes = await Deno.readFile(args.file);
    } catch (e) {
      die(3, `could not read ${args.file}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  await checkCredential(checks, outputData, licenseData ?? {}, fileBytes);

  if (args.privateBlock) {
    let raw: string;
    try {
      raw = await Deno.readTextFile(args.privateBlock);
    } catch (e) {
      die(3, `could not read ${args.privateBlock}: ${e instanceof Error ? e.message : String(e)}`);
    }
    await checkPrivateBlock(checks, outputData.credential, raw);
  }
} else if (args.file) {
  // Hashing a file against a licence rather than an output is meaningless, and silently
  // ignoring --file would look like a pass.
  checks.add(
    5,
    "file matches the credential",
    "not_checkable",
    "--file needs --output: a licence does not commit to any particular file",
  );
}

// ---------------------------------------------------------------------------
// Transparency log. Optional on purpose: the log is a separate deployment, and a receipt is
// still a receipt without it. Absence is reported as not-checkable, never as a pass.
// ---------------------------------------------------------------------------

if (!args.noLog) {
  const subjectId = args.output ?? args.license;
  const sthUrl = `${args.base}/idl-log-sth`;
  // deno-lint-ignore no-explicit-any
  let logData: any = null;
  try {
    const res = await fetch(`${sthUrl}?include=${encodeURIComponent(subjectId!)}`, {
      headers: { accept: "application/json" },
    });
    if (res.ok) {
      const body = await res.json();
      if (body?.ok === true) logData = body.data;
    } else if (res.status === 404) {
      checks.add(
        0,
        "transparency log",
        "not_checkable",
        "no log endpoint is deployed at this base, so nothing pins this record into a public log",
      );
    } else {
      checks.add(0, "transparency log", "not_checkable", `log endpoint answered HTTP ${res.status}`);
    }
  } catch {
    checks.add(0, "transparency log", "not_checkable", "log endpoint unreachable");
  }

  if (logData) {
    // The head is checked whether or not this record is in the tree. A log that answers with a
    // head it cannot sign is broken regardless of whose entry is being looked up, and finding
    // that out should not depend on asking about the right record.
    const head = logData.sth ?? logData;
    if (logData.inclusion) {
      await checkLogInclusion(checks, head, logData.inclusion);
    } else {
      await checkSignature(checks, 0, "tree head", head?.signature);
      checks.add(
        0,
        "tree size",
        Number(head?.tree_size) >= 0 ? "pass" : "fail",
        `the log signs a tree of ${head?.tree_size} entries`,
      );
      // An absent entry is not evidence against the record: everything issued before the log
      // began is legitimately missing from it. Saying "not in the log" as though it were a
      // finding would turn our own deployment date into an accusation.
      checks.add(
        0,
        "transparency log",
        "not_checkable",
        `the log holds no entry for this record (tree size ${
          logData.sth?.tree_size ?? "?"
        }); expected for records created before the log began, and not evidence against them`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

if (args.json) {
  console.log(JSON.stringify(buildReceipt(), null, 2));
} else {
  report();
}
Deno.exit(finalCode());

function finalCode(): number {
  const v = checks.verdict;
  return v === "fail" ? 1 : v === "incomplete" ? 2 : 0;
}

function report(): void {
  const LINKS: Record<number, string> = {
    0: "document and log",
    1: "link 1: person",
    2: "link 2: asset version",
    3: "link 3: licence",
    4: "link 4: generation event",
    5: "link 5: content credential",
  };
  const mark = (r: Check["result"]) =>
    r === "pass" ? "PASS         " : r === "fail" ? "FAIL         " : "NOT CHECKABLE";

  if (!args.quiet) {
    const subject = args.output ? `output ${args.output}` : `licence ${args.license}`;
    console.log(`\nSocialGravity receipt verification: ${subject}`);
    console.log(`base: ${args.base}\n`);

    for (const link of [0, 1, 2, 3, 4, 5]) {
      const group = checks.list.filter((c) => c.link === link);
      if (!group.length) continue;
      console.log(LINKS[link]);
      for (const c of group) {
        console.log(`  ${mark(c.result)}  ${c.name}`);
        if (c.detail) console.log(`                 ${c.detail}`);
      }
      console.log("");
    }
  }

  const v = checks.verdict;
  const counts = `${checks.list.length - checks.failed - checks.unchecked} passed, ${checks.failed} failed, ${checks.unchecked} not checkable`;
  if (v === "pass") console.log(`VERDICT: PASS. ${counts}.`);
  else if (v === "fail") console.log(`VERDICT: FAIL. ${counts}.`);
  else {
    console.log(
      `VERDICT: INCOMPLETE. ${counts}. Nothing contradicted the receipt, but the lines above ` +
        `marked NOT CHECKABLE are assertions or unavailable data, not proofs.`,
    );
  }
}

/** The archivable receipt document, per docs/schemas/receipt-v1.schema.json. */
// deno-lint-ignore no-explicit-any
function buildReceipt(): any {
  const l = licenseData;
  const cred = outputData?.credential;
  const payload = l?.signature?.signed_payload ?? {};
  // deno-lint-ignore no-explicit-any
  const doc: any = {
    receipt_version: "1",
    assembled_at: new Date().toISOString(),
    person: {
      display_name: l?.talent_display_name ?? "",
      consent_on_record: true,
      ...(l?.identity_method ? { identity_method: l.identity_method } : {}),
      ...(payload.consent_video_sha256 ? { consent_video_sha256: payload.consent_video_sha256 } : {}),
    },
    ...(Array.isArray(l?.assets_licensed) && l.assets_licensed.length
      ? { assets: l.assets_licensed }
      : {}),
    license: {
      license_id: l?.license_id,
      status: l?.status,
      brand_name: l?.brand_name ?? "",
      ...(l?.agency_name ? { agency_name: l.agency_name } : {}),
      scope: {
        assets: l?.assets,
        use_case: l?.use_case,
        media_channels: l?.media_channels,
        territories: l?.territories,
      },
      effective_at: l?.effective_at,
      expires_at: l?.expires_at,
      contract_sha256: l?.contract_sha256,
      ...(l?.asset_pack_sha256 ? { asset_pack_sha256: l.asset_pack_sha256 } : {}),
      ...(l?.post_expiry ? { post_expiry: l.post_expiry } : {}),
      signature: l?.signature,
    },
    verification: {
      verdict: checks.verdict,
      verified_at: new Date().toISOString(),
      checks: checks.list,
    },
  };

  if (cred) {
    doc.generation = {
      captured: cred.captured,
      ...(cred.model ? { model: cred.model } : {}),
      output_sha256: cred.output_sha256,
      ...(cred.registered_at ? { registered_at: cred.registered_at } : {}),
    };
    doc.credential = {
      output_id: cred.output_id,
      license_id: cred.license_id,
      ...(cred.talent_display_name ? { talent_display_name: cred.talent_display_name } : {}),
      ...(cred.brand_name ? { brand_name: cred.brand_name } : {}),
      output_sha256: cred.output_sha256,
      ...(cred.media_kind ? { media_kind: cred.media_kind } : {}),
      ...(cred.model ? { model: cred.model } : {}),
      captured: cred.captured,
      ...(cred.published_at ? { published_at: cred.published_at } : {}),
      registered_at: cred.registered_at,
      ...(cred.assets_licensed ? { assets_licensed: cred.assets_licensed } : {}),
      ...(typeof cred.license_active_at_publication === "boolean"
        ? { license_active_at_publication: cred.license_active_at_publication }
        : {}),
      ...(cred.license_term_basis ? { license_term_basis: cred.license_term_basis } : {}),
      ...(cred.signature?.signed_payload?.private_sha256
        ? { private_sha256: cred.signature.signed_payload.private_sha256 }
        : {}),
      ...(outputData?.register_record_hash
        ? { register_record_hash: outputData.register_record_hash }
        : {}),
      signature: cred.signature,
      verify_url: cred.verify_url,
    };
  }
  return doc;
}
