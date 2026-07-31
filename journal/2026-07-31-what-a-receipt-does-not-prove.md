# What a receipt does not prove

2026-07-31

The verifier in this repository reports three outcomes per check, not two: PASS, FAIL, and NOT
CHECKABLE. The third one is the one worth writing about, because getting rid of it would have
been easy and would have made everything look better.

A cryptographic signature proves one thing precisely: the bytes have not been altered since they
were signed. It proves nothing whatsoever about whether those bytes describe something true. A
signed record saying a person consented is a signed record saying we say a person consented.

Most of the value of a receipt is destroyed by quietly blurring that line. So the verifier
refuses to. Anything that would require taking our word for it is reported as NOT CHECKABLE and
never dressed up as proof.

Run it and read the `link 1: person` block:

```
deno run --allow-net verifier/verify.ts --license L24SQXLKQFC
```

```
link 1: person
  FAIL           consent on record
                 the record does not assert a consent record
  NOT CHECKABLE  identity method
                 'document': a government ID was verified. Signed, but the check itself is
                 the issuer's
  PASS           consent evidence
                 a signed platform agreement is committed by hash inside the signature
```

Three different epistemic states in three lines.

**PASS on consent evidence** is a real check. The signed platform agreement is committed by
sha256 inside the signature, so the document behind this licence cannot be swapped for a
different one after the fact. You are not trusting us about which document it is; you are
checking that the hash inside a signature you verified matches the document you were handed.

**NOT CHECKABLE on identity method** is honest reporting of a limit. `document` means a
government ID was verified through an identity provider. We signed that this happened. We cannot
hand you proof it happened, because the check was performed by somebody else and we only hold
their answer. Rendering that as a green tick would be the single cheapest lie available to us and
it is exactly the lie this field exists to refuse.

**FAIL on consent on record** is a live failing check on our own headline example. It is
explained in the next post. It stays failing rather than being hidden, because a verifier that
only ever prints PASS is decoration.

The API says the same thing in its own words. Ask it directly:

```
curl -s "https://id.socialgravity.ai/functions/v1/idl-verify?id=L24SQXLKQFC"
```

> a valid signature over a record proves the record has not been altered, never that its contents
> describe something real

If you are evaluating anyone in this category, including us, that sentence is the question to
ask them. Not "is it signed". Signed is easy. Ask which of their green ticks are checks and which
are assertions, and whether their tooling can tell you the difference without being asked nicely.
