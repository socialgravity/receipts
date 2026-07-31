<div align="center">

# SocialGravity receipts

**The receipt format for licensed human identity, and the tool that checks it.**

Every authorised AI use of a human identity on SocialGravity carries a cryptographic receipt
linking the person, their permission, the licence, the generation and the output. This
repository is the public half of that promise, so that you can check any receipt yourself, on
your machine, without trusting us.

[![Verifier CI](https://github.com/socialgravity/receipts/actions/workflows/verifier.yml/badge.svg)](https://github.com/socialgravity/receipts/actions/workflows/verifier.yml)
[![Spec](https://img.shields.io/badge/receipt%20spec-v1-20231C?style=flat-square)](docs/receipt-spec-v1.md)
[![Code](https://img.shields.io/badge/code-Apache--2.0-6B705C?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-CC%20BY%204.0-6B705C?style=flat-square)](LICENSE-DOCS)
[![Deps](https://img.shields.io/badge/dependencies-zero-6B705C?style=flat-square)](verifier/)

[Spec](docs/receipt-spec-v1.md) · [Log audit guide](docs/transparency-log-audit.md) ·
[API](openapi.yaml) · [Verifier](verifier/) · [Live docs](https://socialgravity.ai/docs)

</div>

---

## Verify a real licence, in thirty seconds

```sh
git clone https://github.com/socialgravity/receipts && cd receipts
deno run --allow-net verifier/verify.ts --license LDNAEEDY5UB
```

Or without cloning anything:

```sh
deno run --allow-net https://socialgravity.ai/docs/verify.js --license LDNAEEDY5UB
```

Real output, trimmed to four of the nineteen checks:

```text
SocialGravity receipt verification: licence LDNAEEDY5UB
base: https://id.socialgravity.ai/functions/v1

document and log
  PASS           external anchor
                 head timestamped by rfc3161 at 2026-07-31T07:07:01+00:00, covering
                 ledger seq 51 and so this entry at seq 45, which is what rules out
                 back-dating
  PASS           witnessed head
                 today's tree of 56 is a pure append of the publicly witnessed head of
                 30: nothing witnessed has been altered or removed

link 1: person
  NOT CHECKABLE  identity method
                 'document': a government ID was verified. Signed, but the check itself
                 is the issuer's

link 3: licence
  PASS           licence signature
                 Ed25519 verified against the pinned key

VERDICT: INCOMPLETE. 16 passed, 0 failed, 3 not checkable. Nothing contradicted the
receipt, but the lines above marked NOT CHECKABLE are assertions or unavailable data,
not proofs.
```

`LDNAEEDY5UB` is a real licence: a document-verified person, a voice asset fingerprint, a signed
platform agreement, Ed25519-signed and logged. The verifier fetches only public endpoints and
does every check locally against a key pinned in [`verifier/lib/keys.ts`](verifier/lib/keys.ts).

Three outcomes per check: **PASS**, **FAIL**, or **NOT CHECKABLE**. Anything that would require
taking our word for it is reported as NOT CHECKABLE rather than dressed up as proof, which is
why our own showcase licence returns INCOMPLETE rather than a green tick. See
[verifier/README.md](verifier/README.md) for the full design and the tampering test suite.

## What is in here

| Path | What it is |
|---|---|
| [`docs/receipt-spec-v1.md`](docs/receipt-spec-v1.md) | The receipt format, normative. Section 4 has the canonicalization rules a third party needs to write an independent verifier. Section 8 is the honest status of the live register |
| [`docs/schemas/receipt-v1.schema.json`](docs/schemas/receipt-v1.schema.json) | JSON Schema 2020-12 for the receipt document |
| [`docs/transparency-log-audit.md`](docs/transparency-log-audit.md) | How to audit the RFC 6962 transparency log, including what is deliberately outside it |
| [`openapi.yaml`](openapi.yaml) | The API surface, including the public verification endpoints |
| [`verifier/`](verifier/) | The zero-dependency Deno verifier CLI, with its tampering test suite |

Related public repository:
[**socialgravity/ledger-anchors**](https://github.com/socialgravity/ledger-anchors), the head
hashes of our ledger mirrored where we cannot quietly rewrite them. The verifier's
`witnessed head` check reads it.

## Write your own verifier

That is the point of publishing this, and it is the most useful thing you can do with it.

1. Read [section 4](docs/receipt-spec-v1.md) for the canonical byte rules. If your bytes match
   ours, your signature check will agree with ours.
2. Fetch a receipt: `GET https://id.socialgravity.ai/functions/v1/idl-license-receipt?license_id=LDNAEEDY5UB`
3. Fetch the signed tree head and an inclusion proof: `GET .../idl-log-sth?include=LDNAEEDY5UB`
4. Pin the key from [`verifier/lib/keys.ts`](verifier/lib/keys.ts). Do not trust a key the
   server hands you at check time.

If your implementation disagrees with ours anywhere, one of us has a bug and we want to know
which. Open an issue.

## What is open and what is not

The proof layer is open: the format, the schema, the log construction and the tool that checks
them. Anyone can verify what we claim, and anyone can implement this format independently.

The custody and enforcement layer is closed and stays closed: biometric template extraction and
matching, matching thresholds, watermarking, and the gating logic that enforces deals. Opening
those would help exactly one audience, the people trying to defeat them.

## Honesty notes

- The register is young. [Section 8 of the spec](docs/receipt-spec-v1.md) says which records are
  real and which are synthetic test data, and every synthetic one reports `demo: true` when you
  fetch it. Never read a `demo: true` record as a deal.
- External anchoring of the ledger began 2026-07-30, and the public mirror was seeded at head
  30. Nothing before that has third-party proof of time.
- Per-licence hash chains are publicly recomputable from chain version 5 (generation) and 3
  (registration) on: those rows publish their whole preimage, with a small number of commercial
  fields replaced by a salted commitment. Rows written under earlier versions carry no preimage,
  because the old formula held private fields in the clear and no honest public preimage exists
  for them. The verifier and the API say which case a row is in rather than implying more.
- Some internal documents referenced by the spec are not published. Those references resolve
  inside our platform repository, not here.

## Relationship to the platform

This repository mirrors the public artifacts of SocialGravity's platform repository, which is
private. Issues and pull requests are welcome here; accepted changes land upstream first and
flow back in the next sync. See
[CONTRIBUTING](https://github.com/socialgravity/.github/blob/main/CONTRIBUTING.md) and
[SECURITY](https://github.com/socialgravity/.github/blob/main/SECURITY.md).

## Licences

- Code (`verifier/`): [Apache License 2.0](LICENSE)
- Documentation and specifications (`docs/`, `openapi.yaml`): [CC BY 4.0](LICENSE-DOCS)
</content>
