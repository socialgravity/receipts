// Ed25519 verification over canonical bytes, using WebCrypto only. No dependencies, because a
// verifier that needs a supply chain is a verifier with a new trust assumption.

import { b64ToBytes } from "./canonical.ts";

export type VerifyOutcome =
  | { ok: true }
  | { ok: false; reason: string }
  /** Distinct from a failure: we could not even attempt the check. */
  | { ok: null; reason: string };

export async function verifyEd25519(
  canonicalBytes: string,
  sigBase64: string,
  publicKeySpkiB64: string,
): Promise<VerifyOutcome> {
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "spki",
      b64ToBytes(publicKeySpkiB64) as unknown as ArrayBuffer,
      "Ed25519",
      false,
      ["verify"],
    );
  } catch (e) {
    // Almost always a malformed pinned key or a runtime without Ed25519. Either way it is our
    // problem, not evidence about the record, so it is not reported as a failed signature.
    return { ok: null, reason: `could not import the public key: ${msg(e)}` };
  }

  let sig: Uint8Array;
  try {
    sig = b64ToBytes(sigBase64);
  } catch (e) {
    return { ok: false, reason: `signature is not valid base64: ${msg(e)}` };
  }
  if (sig.length !== 64) {
    return { ok: false, reason: `signature is ${sig.length} bytes, Ed25519 signatures are 64` };
  }

  try {
    const good = await crypto.subtle.verify(
      "Ed25519",
      key,
      sig as unknown as ArrayBuffer,
      new TextEncoder().encode(canonicalBytes) as unknown as ArrayBuffer,
    );
    return good ? { ok: true } : { ok: false, reason: "signature does not match these bytes" };
  } catch (e) {
    return { ok: null, reason: `verification threw: ${msg(e)}` };
  }
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
