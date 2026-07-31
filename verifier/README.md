# Receipt verifier

Checks a SocialGravity identity licensing receipt **locally**. It fetches public data from the
API and then does every signature check, hash and date comparison on your machine, against a
public key pinned in [`lib/keys.ts`](lib/keys.ts) rather than the key served alongside the
record.

That last part is the whole design. If verifying a receipt required trusting the party who
issued it, there would be no point verifying it.

Zero dependencies (WebCrypto and the Deno standard library only), no services, no keys, no
config. It reads public endpoints and, optionally, files you point it at.

## Use

```
deno run --allow-net verifier/verify.ts --license LDNAEEDY5UB
deno run --allow-net verifier/verify.ts --output  OUT4K2Q9Z
deno run --allow-net --allow-read verifier/verify.ts --output OUT4K2Q9Z --file ./spot.wav
deno run --allow-net verifier/verify.ts --license LDNAEEDY5UB --json > receipt.json
```

| Flag | What it does |
|---|---|
| `--license, -l <id>` | Verify a licence by id |
| `--output, -o <id>` | Verify a per-output receipt. Its licence is fetched and verified too |
| `--file, -f <path>` | Hash a local file and compare it to the credential. Needs `--output` |
| `--private-block <path>` | A private block JSON you hold, rehashed against its commitment |
| `--base <url>` | API base. Defaults to `https://id.socialgravity.ai/functions/v1` |
| `--no-log` | Skip the transparency-log lookup |
| `--json` | Print the receipt document instead of the report |
| `--quiet, -q` | Verdict line only |

Exit codes: `0` all checks passed, `1` at least one FAILED, `2` no failures but something could
not be checked, `3` the verifier could not run.

## Three outcomes, not two

```
PASS           checked, and it held
FAIL           checked, and it did not hold
NOT CHECKABLE  cannot be checked from public data at all
```

The third one is the reason to trust the other two. "Consent is on record" is an assertion by the
party under examination; the recording is not published, so no amount of arithmetic here can
confirm it. Reporting that as a green tick would put our word inside a result that is meant to
contain only mathematics. So it is reported as NOT CHECKABLE, and a run with no failures and any
unchecked line comes back INCOMPLETE, not PASS.

The same goes for the per-licence hash chains: a chain hash is published, but its preimage
includes fields we do not publish, so a public verifier gets continuity rather than
recomputation. It says so instead of implying more.

## What it checks

| Link | Checks |
|---|---|
| 0, document | Envelope shape, contract version, transparency-log inclusion when the log is reachable |
| 1, person | Consent asserted, consent hash actually inside the signed payload, identity method reported at its true strength |
| 2, asset version | Fingerprints well formed AND covered by the signature, not just printed on the page |
| 3, licence | Ed25519 against the pinned key, our own canonicalization of the payload, core fields and scope genuinely signed, term arithmetic, status against term |
| 4, generation | Capture basis (metered versus brand-reported), register chain link |
| 5, credential | Ed25519, output hash signed, local file bytes against the credential, in-term-at-publication recomputed rather than trusted, private block rehashed |

## Design notes worth knowing before you extend it

**Canonicalization is deliberately a second implementation.** [`lib/canonical.ts`](lib/canonical.ts)
does not import the server's `_shared/signing.ts`, and it must not. Sharing that function would
make the verifier agree with the server by construction, including when both are wrong, which is
the one outcome a verifier exists to rule out. The rules are written out in
[`../docs/receipt-spec-v1.md`](../docs/receipt-spec-v1.md) section 4 precisely so a third party
can write a third implementation.

**An unknown key id refuses; a substituted key fails.** They are different situations. After a
key rotation, a verifier that has not been updated is the stale party, and reporting a valid
licence as forged would be worse than saying "I cannot tell": that is NOT CHECKABLE. But a
record whose inline key contradicts the pinned key for the same key id is the shape of a
substituted-key forgery, and that is a FAIL.

**Signed-versus-published drift is checked separately from the signature.** A page can serve a
wider scope than the one that was signed while the signature still verifies perfectly, because
the signature only covers the payload. Those are two different checks and the tests hold both.

## Tests

```
deno test --allow-read verifier/
```

37 tests. One covers the clean production fixture; the rest are tampering, because a verifier
that only proves valid things valid has not been tested. Covered: flipped signature bytes, an
altered payload with `canonical_json` rebuilt to match, served bytes that contradict the
payload, a substituted inline key, an unknown key id, scope published wider than signed, a
licence id swapped on the page, a term wholly in the past still marked active, a placeholder
consent hash, asset versions bumped on the page only, a private block with a flag quietly
removed, and, for the Merkle code, tampered siblings, truncated and padded paths, a proof reused
for a different leaf, and every leaf of every tree size from 1 to 17.

To check that `--json` output still conforms to the published schema, validate it with any JSON
Schema 2020-12 validator against
[`../docs/schemas/receipt-v1.schema.json`](../docs/schemas/receipt-v1.schema.json). No validator
is vendored here, deliberately: the verifier's own dependency count is a feature.

## Publishing

This tool is published in two places: as readable source and a single-file bundle at
[socialgravity.ai/docs](https://socialgravity.ai/docs), and as the public repository
[socialgravity/receipts](https://github.com/socialgravity/receipts). The bundle and this source
are built from the same files; if they ever disagree, this repository plus the platform's
private repo history is the record of what changed and when.
