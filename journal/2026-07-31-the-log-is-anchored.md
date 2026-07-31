# The log is anchored, and the anchor is the part that matters

2026-07-31

Every licence and every registered output on SocialGravity goes into an append-only transparency
log, RFC 6962 style. The log publishes a signed tree head: a size, a Merkle root, a timestamp, an
Ed25519 signature.

A signed tree head on its own proves less than it looks like it proves. We hold the signing key.
Nothing in a document we signed ourselves stops us signing a different history tomorrow and
claiming it was always that way. Self-signed timestamps are not evidence against the party doing
the signing, which is the exact party a receipt exists to constrain.

So the head is also timestamped by an external RFC 3161 authority. That is the piece that rules
out back-dating. We can still be wrong about what a record means, but we can no longer quietly
move when it existed, because somebody outside this company stamped the head at a moment we do
not control.

Fetch the current head:

```
curl -s https://id.socialgravity.ai/functions/v1/idl-log-sth
```

At the time of writing that returns tree size 44, root
`3a87a86f2c9a1d6a78f900d2539c81aea8f69fe28c6eec379792f464b4c829eb`, signed under key
`idl-signing-v1`. Your numbers will be larger; the log only grows.

To see the anchor doing its job, run the verifier against a licence and read the `document and
log` block:

```
deno run --allow-net verifier/verify.ts --license L24SQXLKQFC
```

```
  PASS           log inclusion
                 leaf 3 of 44 is under root 3a87a86f2c9a1d6a...
  PASS           external anchor
                 head timestamped by rfc3161 at 2026-07-31T04:07:02+00:00, covering ledger
                 seq 44 and so this entry at seq 4, which is what rules out back-dating
```

Two notes on that output, because both are the point rather than footnotes.

The inclusion check recomputes the Merkle path locally against the pinned key. It does not ask us
whether the entry is in the log; it proves the entry is under the root we published.

The anchor covers seq 44, and the entry is seq 4. An anchor over a later head covers everything
before it, which is why one anchor per tick is enough and why the useful question about any
transparency log is not "is it signed" but "who else saw the head, and when".

One thing this does not give you: it says nothing about whether the contents of an entry describe
something real. That is a different problem and it has its own post.

Hourly head hashes are mirrored to a separate repository with force-pushes blocked:
[socialgravity/ledger-anchors](https://github.com/socialgravity/ledger-anchors). Rewriting that
history requires visibly turning off the protection first.
