// Pinned trust roots.
//
// This is the out-of-band copy of the company public key. It matters that it lives HERE, in the
// verifier, and not in whatever response is being checked: a signature block carries
// public_key_spki_b64 inline as a convenience, and trusting that copy would make the whole
// check circular. An attacker who can alter the response can alter the key alongside it and
// sign with their own.
//
// So: resolve the key by company_key_id from this table. If a record names a key id we do not
// pin, that is a REFUSAL to verify, not a failure to verify, and the two are reported
// differently. Rotations append here; ids are never reused, and old records keep verifying
// against the key they were signed with.
//
// Source of truth for this value: supabase/functions/_shared/signing.ts (PUBLIC_KEYS_SPKI_B64),
// and it is also printed on the public verify surface, so a third party can obtain it from a
// channel other than the response under examination.

export const PINNED_KEYS: Readonly<Record<string, string>> = {
  "idl-signing-v1": "MCowBQYDK2VwAyEAXzTD6OwOCWzDk9K4zLoOeHSpGTO+b25SNUvkmqmqRE4=",
};

export function pinnedKey(keyId: string): string | null {
  return PINNED_KEYS[keyId] ?? null;
}
