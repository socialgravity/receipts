# Transparency log: audit procedure

**Status: live in production 2026-07-30, and no longer empty. Inclusion proofs verified end to end
against the live tree.**

The log publishes a signed Merkle tree head over the unified provenance ledger, inclusion proofs
for a record you hold the id of, and the ordered entry hashes so you can recompute the root
yourself. That last part is what makes the other two worth anything.

Endpoint: `https://id.socialgravity.ai/functions/v1/idl-log-sth`. No auth. No blockchain, by
design ([`provenance-spec.md`](provenance-spec.md) section 2): the only property a public chain
would add is proof that history was not rewritten after the fact, and an external RFC 3161
timestamp on a signed head buys exactly that without a token.

## What the log is for

A hash chain already makes the ledger tamper-evident: change an old entry and every hash after it
breaks. But proving one entry's position that way means walking every link between it and a signed
head, which costs O(n) and gets worse forever.

A Merkle tree proves the same thing with log(n) hashes against one signed root, and the proof
stays valid as the log grows. Construction is RFC 6962, the Certificate Transparency one, and
deliberately not something invented here:

```
leaf(entry)       = SHA256(0x00 || entry_hash_bytes)
node(left, right) = SHA256(0x01 || left || right)
empty tree root   = SHA256(<no bytes>)
                  = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Subtrees split at the largest power of two strictly below their size. The `0x00`/`0x01` prefixes
are domain separation: without them an interior node could be presented as a leaf.

## Procedure A: check a signed tree head

```
curl -s "https://id.socialgravity.ai/functions/v1/idl-log-sth" | jq .data.sth
```

1. Read `signature.company_key_id` and resolve the public key **from a source other than this
   response**. The key is in [`receipt-spec-v1.md`](receipt-spec-v1.md) section 5 and in the
   repository. The inline `public_key_spki_b64` is a convenience; trusting it makes the check
   circular.
2. Canonicalize `signature.signed_payload` yourself (rules: `receipt-spec-v1.md` section 4) and
   confirm it equals `signature.canonical_json`. Do not sign what you were handed.
3. Verify `signature.sig_base64` with Ed25519 over those bytes.
4. Confirm the payload's `statement` is `transparency_log_tree_head`. That constant is what stops
   a head being read as a licence, a credential or a chain anchor, all of which are signed with
   the same key.
5. Note `tree_size` is a decimal **string**. JSON numbers are where a canonical encoding stops
   being canonical across languages.

Ignore `self_check_passed`. It is our own re-verification and we are the party being checked.

## Procedure B: recompute the root

This is the audit that does not depend on us being honest about anything except the hashes.

```
curl -s "https://id.socialgravity.ai/functions/v1/idl-log-sth?leaves=1" | jq .data.leaves
```

Returns every entry hash in ledger sequence order, and nothing else: no bodies, no ids, no
timestamps. Hash each with the leaf rule, combine with the node rule and the power-of-two split,
and compare your root to the signed one. A mismatch means the head does not describe the ledger
we are serving, which is the only interesting failure this log can have.

`verifier/lib/merkle.ts` is a working implementation in about a hundred lines if you want one to
read.

## Procedure C: check that a record is in the log

```
curl -s "https://id.socialgravity.ai/functions/v1/idl-log-sth?include=LDNAEEDY5UB" | jq .data
```

You get the head, the record's ledger entries with the exact **preimage** each hash was taken
over, and an audit path.

1. For each entry: `sha256(preimage)` must equal `entry_hash`. Because the preimage is published,
   checking an entry needs no reimplementation of the ledger's hashing rules at all.
2. Confirm the preimage's contents are what you expect: it contains the entry's sequence,
   timestamp, event type, subject and canonical body, joined by `|`.
3. Compute the leaf hash, then fold the `audit_path` (ordered leaf-first) up to a root using the
   index and `tree_size`, and compare to the signed `root_hash`.

Or run the verifier, which does all of it:

```
deno run --allow-net verifier/verify.ts --license LDNAEEDY5UB
```

## What the log does NOT prove

Stated plainly, because a log is exactly the kind of artifact people over-read.

- **A signature on a head does not date it.** It proves the head came from SocialGravity. We could
  sign a head today carrying any date. Only an external timestamp on a head rules out
  back-dating, which is why the response carries an `anchor` block and an `anchor_note` saying
  which case you are in. Since 2026-07-30 heads ARE externally anchored: `idl-ledger-anchor` runs
  hourly (`idl-ledger-anchor-hourly`) and takes both a signed anchor and an RFC 3161 timestamp
  from an independent authority. **This still does not date anything before the first anchor.**
  The bound an anchor gives you is backwards-looking only as far as the previous anchor, so heads
  that existed before 2026-07-30 16:21 UTC carry tamper-evidence and inclusion, not proof of when.
- **An absent entry is not evidence against a record.** Everything created before the writers were
  deployed is legitimately missing, and the ledger held zero rows at that moment. A verifier that
  reported "not in the log" as a finding would be turning our own deployment date into an
  accusation. The tool reports it as NOT CHECKABLE.
- **Inclusion is not validity.** A licence can be in the log and revoked. The log says a record
  existed in this position in the chain, nothing more.
- **The log does not prove the ledger is complete.** It proves that what is in it has not been
  altered or reordered. An event that was never written cannot be detected by a Merkle tree, which
  is exactly why the writers are database triggers rather than service calls: an event a service
  has to remember to emit is one that goes missing on the path nobody tested.

### Records that are legitimately outside the chain

Named here rather than back-filled. Writing today's entry carrying yesterday's date is the exact
back-dating that anchoring exists to rule out, so importing history would weaken every future
anchor while looking like progress.

| What | How many | Why it is outside |
|---|---|---|
| Generations before 2026-07-30 | 7 | `generation_recorded` did not exist; the meter's own per-licence chain still covers them |
| Voice enrolments before 2026-07-30 | 10 | the voice ledger writers did not exist; face had them since 2026-07-29 |
| Licences, consents and outputs before 2026-07-30 | see ID-PROOF | those writers did not exist either |

One record is worse than absent and is called out separately. Generation `idl_usage_events` id 1,
on licence `L7Q4RXK2ZP`, has **no `record_hash` at all**: it was written before the meter chain
existed, so nothing hashed it. The consequence is not one unhashed row. The next generation on
that licence starts its chain at `genesis`, so that chain asserts it begins where it does not, and
a real generation sits above the chain that is supposed to account for it. From 2026-07-30 the
constraint `idl_usage_record_hash_present` makes this impossible to repeat; it is `NOT VALID` so
that the one historical row is grandfathered rather than given an invented hash.

## What the log discloses

Publishing every entry hash discloses the **size** of the ledger and the timing of activity. Any
transparency log discloses that by construction and it is worth saying rather than discovering.

What it does not disclose: entry bodies, except for a record whose id the caller already holds.
That restraint is inherited from the ledger's own design, and the reason is specific. The
existence of a biometric template is itself a disclosure about a person, so a ledger you can page
through is a list of who we hold biometrics for. The `?leaves=1` list is hash-only, and there is
no endpoint that enumerates bodies.

Entry bodies themselves carry hashes, ids, enums and timestamps only. Never biometrics, never KYC
documents, never money terms, never a media placement. The SQL assertions in
`scripts/verify-transparency-log.sql` check that per event type, including a test that fails if
pricing ever reaches the ledger.

## What is in the log

| Event | Written when | Body carries |
|---|---|---|
| `consent_recorded` | A consent recording is stored | Recording hash, script version. Not the path |
| `license_issued` | A licence is issued | Licence id, contract hash, asset fingerprints, identity method, key id, the signature itself, term |
| `license_status_changed` | Status moves | Both statuses, so a revocation is dated |
| `output_registered` | A brand registers a published file | Output id and hash, private commitment, register chain hash, flags. Not the placement |
| `biometric_template_*`, `face_pack_*` | Face template and pack lifecycle | Template hashes, model, protection, key epoch (lane ID-BIO-B-crypto) |
| `biometric_template_*` (voice) | Voice template creation and destruction | Template hash, model version, protection version and key id, consent id (lane ID-CHAIN) |
| `voice_asset_confirmed`, `voice_asset_withdrawn` | A rights holder clears a voice for licensing, or withdraws that | Sample recording hash, enrolment version, capture method, confirmation hash. Not the path |
| `license_marked_demo` | We annotate a licence as test data | Licence id, the reason, when. Append only, so the annotation cannot be quietly removed |
| `generation_recorded` | A licensed voice is actually spoken | Licence id, output hash, watermark index and version, declared channel and territory, meter chain hash. Not the brand's API key, not the volume |

The licence entry includes `signature_b64` on purpose: the ledger then commits to the exact
signature, so re-signing an existing licence with different bytes stops being silent.

## Operating notes

- The tree is rebuilt per request. At ledger volumes that is cheaper than maintaining an
  incremental tree, and a recomputed root cannot drift away from the rows. The endpoint refuses
  above 100,000 entries rather than degrading quietly; past that this needs a cached tree.
- Heads are signed on demand by this endpoint and **not persisted**. Persisted chain anchors are
  written by `idl-ledger-anchor` (lane ID-BIO-B-crypto) and this endpoint only reports the newest
  one. Two writers to one chain is how a chain forks.
- Anchoring runs hourly at :07 via `idl_ledger_anchor_tick()` (lane ID-CHAIN, 2026-07-30), which
  reads `idl_edge_base_url` and `idl_admin_secret` out of Vault and calls the endpoint with method
  `both`. The two secrets are created by hand per environment and never live in a migration or in
  `cron.job.command`, because that column is readable by anyone who can read the catalog. If they
  are missing the job raises a WARNING and returns `{"anchored": false}` rather than doing nothing
  quietly.
- The timestamp authority is `IDL_TSA_URL`, currently `https://freetsa.org/tsr`. It is deliberately
  configuration and not a hard-coded vendor, so swapping it is an env change. It receives one
  sha256 head hash per anchor and nothing else.
- Consistency proofs between two heads (RFC 6962 section 2.1.2) are **live** as of 2026-07-30
  (lane ID-CHAIN): `GET /idl-log-sth?consistency=<m>[&to=<n>]`. They were impossible until that
  afternoon for a concrete reason rather than a scheduling one, and it is worth keeping: no head
  had ever been persisted, so there was no second head to be consistent with.
- **Why this matters more than it sounds.** An anchor says a head existed at a time. Two anchors
  say that twice, and say nothing about whether the second tree still contains the first. Without
  a consistency proof a log can anchor a head, quietly rewrite its history, and anchor a second
  head that is perfectly well formed, externally timestamped, and shares nothing with the first.
  Consistency is what makes that detectable.
- The endpoint publishes `anchor_points`, which maps each anchored `head_seq` to the tree size to
  ask about. The two are not the same number: the ledger's identity column has gaps because it
  does not roll back with a transaction, and a tree size is a count of leaves. Guessing that
  translation and getting it off by one produces a failed proof that looks like evidence of
  tampering, which is why it is published rather than left to be derived.
- The roots the endpoint returns are recomputed from the ledger on that request. To make a
  consistency check a constraint on us rather than a restatement of our own claims, take the two
  roots from tree heads we signed on different days and pass those.

## Verification status, 2026-07-30

What has actually been checked, and how:

| Property | Where proven |
|---|---|
| Triggers write licence, consent and output events; chain holds; preimages hash to their entries; money and placements stay out; append-only covers the new entries | `scripts/verify-transparency-log.sql`, 12 assertion groups, on a from-scratch Postgres with every migration applied (`LOG=1 bash scripts/verify-db-local.sh`) |
| Log-generated proofs verify in the independent verifier, for every leaf of every tree size 1 to 17 | `supabase/functions/_tests/transparency_log.test.ts`, 9 tests |
| Tampered siblings, truncated and padded paths, and proofs reused for another leaf are all rejected | `verifier/lib/merkle_test.ts` |
| The live endpoint serves a correctly signed head, and the signature verifies against the pinned key in the verifier rather than by self-check | Production, `?leaves=1`, `?seq=`, and POST paths exercised |
| **Inclusion end to end against the live tree**: a licence id resolved to its ledger entries, every published preimage rehashed to its entry hash, and every audit path folded to the signed root by the independent verifier implementation | Production, tree size 3, licence `LRHOVSEEEF7`, both its entries (issue and revocation) proven |

### A note on what those first three entries are

The log filled up within the hour, from another lane's live verification harness: a synthetic
consent recording, a licence issued, and that licence revoked. The writers worked exactly as
intended on real production events, which is how inclusion came to be provable end to end today
rather than after the first customer.

It is also a permanent illustration of the rule in this document. Those three entries **cannot be
removed**, and real receipts are now proven against a tree whose first leaves are test data. That
is not a defect in the log, and cleaning it would be far worse than living with it, but it is the
reason nothing in this lane wrote a synthetic row deliberately, and the reason nobody else should
either. If a harness needs to exercise a path that reaches the ledger, run it against a throwaway
database (`LOG=1 bash scripts/verify-db-local.sh`), not production.
