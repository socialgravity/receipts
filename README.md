# SocialGravity receipts

Every authorised AI use of a human identity on SocialGravity carries a cryptographic receipt
linking the person, their permission, the licence, the generation and the output. This
repository is the public half of that promise: the receipt format, its JSON Schema, the API
surface it is served over, and a zero-dependency verifier so you can check any receipt
yourself, on your machine, without trusting us.

Live documentation and a browser-readable copy of all of this:
[socialgravity.ai/docs](https://socialgravity.ai/docs)

## Verify a real licence right now

```
deno run --allow-net verifier/verify.ts --license L24SQXLKQFC
```

That licence is real: a document-verified person, a voice asset fingerprint, a signed platform
agreement, Ed25519-signed and logged. The verifier fetches only public endpoints and does every
check locally against a pinned key. Three outcomes per check: PASS, FAIL, or NOT CHECKABLE,
and anything that would require taking our word for it is reported as NOT CHECKABLE rather
than dressed up as proof. See [verifier/README.md](verifier/README.md) for the full design.

## What is in this repository

| Path | What it is |
|---|---|
| [`docs/receipt-spec-v1.md`](docs/receipt-spec-v1.md) | The receipt format, normative. Section 4 has the canonicalization rules a third party needs to write an independent verifier |
| [`docs/schemas/receipt-v1.schema.json`](docs/schemas/receipt-v1.schema.json) | JSON Schema 2020-12 for the receipt document |
| [`docs/transparency-log-audit.md`](docs/transparency-log-audit.md) | How to audit the RFC 6962 transparency log, including what is deliberately outside it |
| [`openapi.yaml`](openapi.yaml) | The API surface, including the public verification endpoints |
| [`verifier/`](verifier/) | The zero-dependency Deno verifier CLI, with its tampering test suite |

The hourly ledger head hashes are mirrored to
[socialgravity/ledger-anchors](https://github.com/socialgravity/ledger-anchors), a public
append-only witness we cannot rewrite quietly.

## What is open and what is not

The proof layer is open: the format, the schema, the log construction and the tool that checks
them. Anyone can verify what we claim, and anyone can implement this format independently.

The custody and enforcement layer is closed and stays closed: biometric template extraction and
matching, matching thresholds, watermarking, and the gating logic that enforces deals. Opening
those would help exactly one audience, the people trying to defeat them.

## Honesty notes

- The register is young. Read the spec's section 8 for what is and is not yet provable,
  including which records are synthetic test data.
- External anchoring of the ledger began 2026-07-30. Nothing before that date has third-party
  proof of time.
- The per-licence hash chains publish continuity, not recomputability: their preimages include
  fields we do not publish. The verifier says so instead of implying more.
- Some internal documents referenced by the spec (for example the provenance design note) are
  not published. Those references resolve inside our platform repository, not here.

## Relationship to the platform

This repository mirrors the public artifacts of SocialGravity's platform repository, which is
private. Issues and pull requests are welcome here; accepted changes land upstream first and
flow back in the next sync. If you implement this format independently, open an issue and tell
us, we want to know.

## Licences

- Code (`verifier/`): [Apache License 2.0](LICENSE)
- Documentation and specifications (`docs/`, `openapi.yaml`): [CC BY 4.0](LICENSE-DOCS)
