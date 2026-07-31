# Security policy

The full policy for every SocialGravity repository is
[here](https://github.com/socialgravity/.github/blob/main/SECURITY.md).

**Report to alvaro@socialgravity.ai** with `SECURITY` in the subject, or open a private security
advisory on this repository. Please do not open a public issue for anything exploitable. We
answer within 72 hours.

For this repository specifically, the highest-severity finding is anything that makes the
verifier accept a receipt it should reject: signature bypass, canonical byte ambiguity that lets
two different documents share one signature, an inclusion proof that validates against the wrong
tree, or a log rewrite that the consistency check does not catch.

Report privately, give us a window to fix, then publish whatever you like. We will not ask you
to stay quiet. If a finding means something we published was overclaimed, the correction gets
published too.
