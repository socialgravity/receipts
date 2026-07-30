# Receipt spec v1

**Status: v1, stable field names. 2026-07-29.**

This is the document a platform, agency or legal team integrates against. It defines what a
SocialGravity receipt contains, which parts are independently checkable without trusting us,
and, just as importantly, which parts are not.

Machine-readable form: [`schemas/receipt-v1.schema.json`](schemas/receipt-v1.schema.json)
(JSON Schema 2020-12). Wire-level API shapes: [`../openapi.yaml`](../openapi.yaml). The
five-link model this implements: [`provenance-spec.md`](provenance-spec.md).

## 0. What a receipt is for

One question, asked by someone who does not trust either party:

> This file shows a real person. Was that person's identity licensed for this use, by whom,
> under what terms, and is this file the thing that was actually produced?

A receipt answers it with hashes and signatures rather than with our word. The design rule
throughout: **verification must not require trusting SocialGravity.** Every signed record
publishes the public key, the exact payload, the canonical bytes and the recipe, so a third
party can check it offline. Where that property does not hold, this spec says so out loud
rather than implying it.

### Compatibility promise

Field names in this document are stable for v1. Additive fields may appear; existing names
will not change meaning. **Optional fields are omitted, never sent as `null`**, and that is
load-bearing rather than stylistic: a record signed before a field existed must keep verifying
against the exact bytes it was signed with, so a verifier must treat "absent" as "this record
makes no claim" and never as a default value.

Breaking changes get `receipt_version: "2"` and a new schema file. The version lives in the
document, not in a URL.

## 1. The five links

A receipt is a chain of five records. Each is separately signed or hashed; together they answer
the question above.

| # | Link | The record | What it establishes |
|---|---|---|---|
| 1 | Person | Consent evidence, hashed | A real, identified person authorised licensing, by signature or on camera |
| 2 | Asset version | `AssetFingerprint` | Exactly which voice model or face pack, at which version |
| 3 | Licence | Signed registry row | Who licensed what, for how long, in what territory and channel |
| 4 | Generation event | Metered event or registration | A specific use happened, of that asset, under that licence |
| 5 | Content credential | Signed output receipt | This exact file, tied to that use |

Link 1 to 3 answer "was this allowed". Link 4 and 5 answer "is this the thing that was made".
A checker holding only a file can start at link 5 by hashing it; a checker holding only a
licence id can start at link 3.

### 1.1 Link 1: person

Not published: the consent artifact itself, the government document, the biometric templates. What
is published is that consent evidence exists, WHICH artifact it is, its hash, and how identity was
established.

**Two artifacts are acceptable, and the receipt names which one backs it** (`consent_evidence`):

- `platform_agreement`: the agreement the person, or their authorised rights holder, signed. A
  countersigned instrument with an audit trail is what a dispute actually turns on, and it is what
  our biometric notice calls for: "a distinct written disclosure and a written release".
- `consent_video`: a recording in which the person states their legal name, the date, and what they
  authorise. It adds one thing a signature cannot: a live human at a stated moment. That matters
  most for someone with no document check behind them.

Either way the artifact's `sha256` is inside the signed payload, so it cannot be swapped after
issue even though it is never published.

Until 2026-07-30 only a recording counted, and the licence table required one. That requirement was
a day-one modelling choice rather than a legal one, and it had a cost worth recording here: a
required field pointing at an artifact nobody had produced does not stay empty. Four licences on
this register are signed over a `consent_video_sha256` of the literal string
`smoke-test-placeholder`. A verifier fails their first link, correctly. Issuing now refuses any
value that is not a real hash rather than signing over it.

`identity_method` is a separate question from consent, and takes exactly one of two values:

- `document`: a government ID was verified by a KYC provider.
- `video_attestation`: the person stated their legal name and the date on camera and a named
  operator confirmed it. **No government document was checked.**

**When the field is absent, no claim is made either way.** It is omitted rather than defaulted
because the licence predates the field. Do not render an absent value as either method, and do not
render `video_attestation` as equivalent to `document`. A receipt that hid the difference would be
worth less than no receipt, which is why the field is signed: we cannot quietly revise the strength
of a check behind an already-issued licence.

### 1.2 Link 2: asset version

An `AssetFingerprint` is `{asset_type, sha256, version, created_at}`. Re-enrollment mints a new
version and never mutates an old one, which is what makes "which exact voice said this"
answerable years later.

A licence carries `assets_licensed`: the full set of asset versions it covers, in the order
stored on the record. It is **omitted entirely when empty**, on the compatibility rule above.

A licence covering both voice and face cannot be narrowed to a single asset from an output hash
alone, so a credential carries the full set rather than us guessing which one produced a file.

### 1.3 Link 3: licence

The signed registry row, the root of everything downstream. Public at
`GET /idl-verify?id=<licenseId>`.

**Signed payload** (canonical JSON, Ed25519, key `idl-signing-v1`):

```
{license_id, listing_id, brand_org_id, scope, contract_sha256, asset_pack_sha256?,
 assets_licensed?, identity_method?, effective_at, expires_at,
 consent_video_sha256?, consent_evidence?}
```

Exactly one of `consent_video_sha256` and `consent_evidence` is always present, and a licence
backed by a recording carries both. Licences issued before 2026-07-30 carry only the first; the
field is omitted, never nulled, so those signatures keep verifying against identical bytes.

**Never in the payload and never public: money.** Pricing sits outside the signature on
purpose, so public verification never requires disclosing commercial terms. This is the same
reasoning that keeps the per-output private block out of the clear (2.2).

Also public, and deliberately: `post_expiry`. "The term ended" and "the content must come
down" are different facts, and a reviewer looking at an expired licence needs to know which one
applies. Expiry only ever stops future generation.

### 1.4 Link 4: generation event

Two ways a use gets recorded, and the difference is not cosmetic:

- **Metered** (`captured: "metered"`): we ran the generation, so capture is total. Every
  `/idl-tts` call writes the asset version, the model, the declared channel and territory, and
  the sha256 of the exact bytes returned. There is no unmetered path: if metering fails, the
  audio is not delivered. The event id comes back as `x-idl-request-ref`.
- **Registered** (`captured: "registered"`): the brand generated on their own tools and filed
  the result. Brand-reported, and the constant `captured` value says so, so a filing can never
  be mistaken for something we observed.

Why both exist: the meter records what WE generated, not what the brand PUBLISHED. A published
cut is routinely trimmed, mixed and re-encoded, so it has different bytes and a different hash.
Registration is what distinguishes a legitimate edited cut (on the register, with
`derived_from` pointing at the metered events it came from) from a re-clone (not on it), which
neither a watermark nor a speaker embedding can tell apart.

### 1.5 Link 5: content credential

The signed receipt for one file. Public at `GET /idl-verify?output=<outputId>`.

**Signed payload** (canonical JSON, Ed25519, same key):

```
{output_id, license_id, output_sha256, media_kind, model, captured, published_at?,
 assets_licensed?, private_sha256, registered_at}
```

`output_sha256` is the whole point: hash the file you are holding and compare.

## 2. What is published and what is withheld

### 2.1 The public surface

Public, no auth: the parties' display names, the licensed assets and versions, the scope
(assets, use case, channels, territories), the term, the status now, the contract hash, the
consent-on-record fact, the identity method, post-expiry terms, and the full signature block.

### 2.2 The private block, committed by hash

Per-output channel, territory, placement, `derived_from` and our flags are **not** published.
They are canonicalized, hashed, and the hash (`private_sha256`) goes inside the signed
credential.

Two reasons, both deliberate:

- Publishing which channel one specific ad ran in hands competitors a media plan.
- Publishing a flag would be a public accusation. A flag is our reading of a filing, not the
  filing itself, and marking is not a determination of breach.

The registering party gets the block itself in the registration response, which is the only
copy we hand out. They check it by rehashing. So the parties can prove nothing was softened
afterwards, and the public still gets a receipt.

### 2.3 Flags never gate

Late, out-of-scope, post-expiry and inactive-licence filings are all **recorded**, and flagged.
Registration never refuses. A register that rejected inconvenient filings would destroy the
evidence the obligation depends on, and would teach brands not to file.

Registration is not approval and does not extend scope or term. The response says so in `note`.

## 3. What a third party can actually check

This is the section to read before building on any of it. Not everything in a receipt is
equally verifiable, and the difference is not marketing.

| Check | Independently verifiable? | How |
|---|---|---|
| Licence signature | **Yes, fully offline** | Ed25519 over `canonical_json` against the published SPKI key |
| Credential signature | **Yes, fully offline** | Same, with the output payload |
| Is this file the original | **Yes, fully offline** | sha256 the file, compare to `output_sha256` |
| Was the licence in force at publication | **Yes** | Compare `published_at` against the signed term |
| Private block matches its commitment | **Yes, for a party holding it** | Recanonicalize and rehash to `private_sha256` |
| Consent exists | No, trusted assertion | `consent_on_record`. The recording is not published; its hash is signed |
| Per-licence chain continuity | Partly | See 3.1 |
| Ledger entry integrity | Yes by design, **not yet reachable** | See 3.2 |

### 3.1 The per-licence chains are tamper-evident, not publicly recomputable

Both `idl_usage_events` and `idl_output_registrations` are hash-chained per licence by database
trigger: each row's `record_hash` covers the previous row's hash, so editing or deleting an old
row breaks every hash after it. Rows are append-only, enforced in the database rather than in a
service.

But a **public** verifier cannot recompute those leaf hashes, for two concrete reasons:

1. The preimage includes fields we do not publish (`api_key_id` on a metered event,
   `registered_by` on a registration).
2. The preimage renders timestamps with Postgres text formatting rather than ISO 8601, which is
   session-dependent and not part of any published recipe.

So what a public checker gets from these chains is **continuity of the hashes we publish**
(`register_record_hash` links a credential into its licence's register), not an independent
recomputation of the leaves. A party who receives the raw rows can do the full check. This is
stated because "hash-chained" is easy to read as "publicly verifiable", and here it is not.

Each chained table carries a `chain_version` column. A verifier must select the formula by that
column; historical rows will fail against a newer formula once one gains a field.

### 3.2 The unified ledger: designed to be recomputable, not yet reachable

The unified append-only ledger (`idl_ledger`) is the one designed for public recomputation:
every entry publishes **its own preimage** alongside its hash, so checking an entry is
`sha256(published_preimage)` and needs no reimplementation of anything. Chain heads are signed,
and can carry an RFC 3161 timestamp, which is the only thing that rules out back-dating.

**As of 2026-07-29 this is schema-only in production.** The tables exist and the code is on
`main`, but the public read endpoints are not deployed and the ledger holds zero rows. Do not
build against it yet, and do not cite it as live. The chain with real data today is the
per-licence one behind `idl-verify`.

### 3.3 `self_check_passed` proves nothing

Signature blocks include `self_check_passed`, our own re-verification. It is a convenience for
spotting an obviously broken record, and it is worthless as evidence: we are the party you are
checking. Verify the signature yourself. `verifier/verify.ts` in this repo does it locally, and
so should any integration that cares.

## 4. Canonical bytes

Every signature is taken over **canonical JSON**, defined exactly:

- Object keys sorted bytewise (JavaScript `Array.prototype.sort` on strings) at every level.
- Array order preserved.
- No whitespace.
- Keys whose value is `undefined` are dropped. Absent is not `null`; a `null` in a payload is a
  literal null and changes the bytes.
- UTF-8 encoding.
- Timestamps normalized to JavaScript `Date.toISOString()`: millisecond precision, `Z` suffix.
  A timestamp that arrives in another form is normalized before signing, so reproduce that
  exactly.

Integers that could be large are rendered as decimal **strings** in payloads (the transparency
log's `head_seq` is the current case). JSON numbers are where a canonical encoding quietly
stops being canonical, since a verifier in another language has to agree on integer rendering,
and there is no reason to make them.

Reference implementation: `canonicalJson` in `supabase/functions/_shared/signing.ts`. It is
about ten lines; reimplementing it is expected and is why the rules are written out here.

## 5. Keys

| Key id | Algorithm | Public key (SPKI, base64) |
|---|---|---|
| `idl-signing-v1` | Ed25519 | `MCowBQYDK2VwAyEAXzTD6OwOCWzDk9K4zLoOeHSpGTO+b25SNUvkmqmqRE4=` |

One keypair signs licences, credentials and log heads. The payload builder distinguishes the
record types, so one published key means one thing for a verifier to trust.

Rotation **appends** a key id; ids are never reused and old records keep verifying against the
key they were signed with. A signed record always names its `company_key_id`; resolve the key
by that field, never by "the current key". A verifier that hardcodes one key will silently fail
after a rotation, so read the key id.

Signature blocks carry `public_key_spki_b64` inline as a convenience. For anything that
matters, pin the key out of band from this document rather than trusting the copy inside the
response you are checking.

## 6. Verifying a receipt, end to end

Given a file and either id:

1. `sha256` the file. If you have an `output_id`, fetch `GET /idl-verify?output=<id>` and
   compare to `credential.output_sha256`. A mismatch means this is not the registered original:
   possibly an edit, possibly something else.
2. Check the credential signature: canonicalize `signature.signed_payload`, verify
   `signature.sig_base64` with Ed25519 against the key for `signature.company_key_id`.
   Independently confirm `canonical_json` matches your own canonicalization.
3. Fetch the licence: `GET /idl-verify?id=<credential.license_id>`. Check its signature the
   same way.
4. Check the licence covers the use: assets, use case, channels, territories, and that
   `license_active_at_publication` agrees with your own arithmetic over the signed term. Note
   `license_term_basis`: when the brand stated no publication date this falls back to
   registration time, which changes what the answer means.
5. Read `identity_method` and treat an absent value as "no claim", not as a pass.
6. If you hold the private block, recanonicalize and rehash it to `private_sha256`.

`verifier/verify.ts` performs 1 to 6 and prints PASS or FAIL per link, with
`NOT CHECKABLE` as a distinct outcome so a trusted assertion is never reported as a
cryptographic pass.

## 7. Not in v1

Named so nobody integrates against a plan:

- **C2PA embedding.** Credentials exist and are signed, but they are not yet embedded as C2PA
  manifests in delivered files. Signed metadata also dies on screenshot and re-encode, which is
  why the hash and the register matter more than the embedding.
- **Public ledger endpoints and external anchoring** (see 3.2).
- **Payment and payout state.** Verifiable by the parties against the same ledger the meter
  writes; never on a public page.
- **Watermark detection as proof.** Watermarks and perceptual fingerprints route a checker back
  to a credential. They are detection aids, not enforcement, and not part of a receipt.

## 8. Honest status, 2026-07-30

There are **zero listed talent** on the platform. One licence on the register covers a real person
and a real voice sample; the rest are internal test records.

The one to check against is `L24SQXLKQFC`, which verifies at
`https://id.socialgravity.ai/functions/v1/idl-verify?id=L24SQXLKQFC`. What is real about it: the
person is document-verified through Stripe Identity, link 1 is a platform agreement he actually
signed, and its asset fingerprint is the sha256 of a real confirmed voice sample (enrollment v2),
not a placeholder. What is not arm's length about it: the brand is SocialGravity, so it is a
first-party deal, and it was issued through the direct operator path rather than negotiated, which
the record itself states as `issue_path: direct_operator`. Read it as a working example of the
mechanism, not as evidence of a market.

Its predecessor `LGVGMQAWVE2` remains on the register and still verifies, but its parties are
placeholder organisations and its asset fingerprint is a placeholder hash rather than the digest
of a real voice sample. It is retained as the verifier's regression fixture.

Two records also carry fake cryptographic material written directly into the table by test
harnesses rather than signed: `LSYNTHREG01`, whose signature is the literal string `SYNTHETIC`,
and `L7Q4RXK2ZP`, which names a `smoke-test` key we publish no public key for. A verifier fails
the first and refuses to judge the second, both correctly. New rows can no longer look like this:
the database now requires a real key id and a 64-byte signature.

Do not use `LYL7ZYRM2Q2` as a reference. It is signed correctly over a `consent_video_sha256` of
the literal string `smoke-test-placeholder`, so it commits to no consent recording at all, and a
verifier will correctly fail its first link. Four records share that placeholder. Three of them
named a real person, so on 2026-07-30 they were **revoked** rather than left active: `LYL7ZYRM2Q2`,
`LJKDLJVVFRH` and `LLQQJQNQS2U`. The rows stay, the failure stays reproducible, and the ledger
carries the status change. This is named rather than quietly fixed because a spec that pointed at
a broken example would be worse than one that admits which examples are broken.

Of 12 licence records, 4 are active. 7 carry `assets_licensed` and 4 carry `identity_method`, the
rest predating those fields, which is exactly the omit-rather-than-default case in 0. Registered
outputs: zero. This spec describes a working mechanism on a nearly empty register, and says so
rather than implying volume.
