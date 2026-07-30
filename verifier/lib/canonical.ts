// Canonical JSON, per docs/receipt-spec-v1.md section 4.
//
// DELIBERATELY A SECOND IMPLEMENTATION. This does not import _shared/signing.ts, and it must
// not: the whole claim being tested is that a third party can reproduce our canonical bytes
// from the written rules. Sharing the function would make the verifier agree with the server
// by construction, including when both are wrong, which is the one outcome a verifier exists
// to rule out.
//
// The rules, restated so this file is checkable against the spec without reading either:
//   - object keys sorted bytewise at every level (JS string sort; identical for ASCII keys)
//   - array order preserved
//   - no whitespace
//   - keys whose value is undefined are dropped; a literal null is kept and changes the bytes
//   - UTF-8 output
//   - timestamps already normalized to Date.toISOString() by the producer

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === "number" || typeof v === "boolean" || typeof v === "string") {
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(o[k])).join(",") + "}";
  }
  throw new Error(`canonicalJson: unsupported type ${typeof v}`);
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
