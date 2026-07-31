# We mark our own test data, and the mark cannot be removed

2026-07-31

A register is easy to fake while it is small. Seed it with impressive-looking rows, sign them
properly, and every cryptographic check passes, because the checks were never about whether the
deal happened. The signature is real. The deal is not.

We are small, and our register contains test data. So the interesting question is not whether we
have test rows. It is whether you can tell.

Any test licence carries a demo mark, and the public verify response leads with it, above
everything else:

```
curl -s "https://id.socialgravity.ai/functions/v1/idl-verify?id=L24SQXLKQFC"
```

```json
"demo": true,
"demo_reason": "TEST DATA: this licence has no consent record at all, so it commits to no recording",
"demo_note": "THIS IS TEST DATA. It is not a real deal, no real person's likeness is licensed by it, and it must never be quoted as evidence of anything. The signature below is genuine, which is the point: a valid signature over a record proves the record has not been altered, never that its contents describe something real."
```

Every other field on that licence is well formed and the signature verifies cleanly. That is
deliberate. A demo licence that failed its signature check would teach you nothing, because real
fraud does not fail signature checks either.

## The part that makes it worth anything

A label you can remove is not a safeguard, it is a courtesy. So the marks are append-only,
enforced in the database rather than in a policy document. Attempting to edit one, which we did
on 2026-07-30 while writing this, gets refused:

```
ERROR: a demo mark is never removed or edited
HINT:  Marking real data as demo is a harmless mistake. Unmarking demo data as real is the
       direction that makes a fake deal look genuine.
```

The asymmetry in that hint is the whole design. Wrongly marking a real deal as test data costs us
a licence we have to reissue. Being able to unmark test data as real would let us launder a fake
deal into a genuine-looking one, and it would let us do it silently, after the fact, with every
signature still verifying.

So we gave that ability up permanently. It has already cost us: the mark quoted above says the
licence "has no consent record at all", which was true when it was written and is not true now,
because that licence carries a signed platform agreement committed by hash. We cannot correct the
sentence. It stays wrong, publicly, forever, and the only route to a clean record is to issue a
new licence. That is the trade, and we would make it again.

## What this means when you read our register

Check the `demo` field before you believe anything else on a licence. If it is present, the
licence is not evidence of a deal, whatever else passes.

We would suggest asking the same of anyone else in this category, and noticing what happens when
the answer is that their register has no such field.

```
deno run --allow-net verifier/verify.ts --license L24SQXLKQFC
```
