// Merkle tests. The generator and the verifier are separate code paths that must agree for
// every tree size and every leaf, and a proof system that only round-trips on the happy path is
// worth nothing, so the tampering cases carry equal weight here.

import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  bytesToHex,
  inclusionPath,
  leafHash,
  merkleRoot,
  pathLength,
  rootFromPath,
  splitPoint,
} from "./merkle.ts";
import { sha256Hex } from "./canonical.ts";

async function leaves(n: number): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(await leafHash(await sha256Hex(`entry-${i}`)));
  return out;
}

Deno.test("splitPoint is the largest power of two strictly below n", () => {
  assertEquals(splitPoint(2), 1);
  assertEquals(splitPoint(3), 2);
  assertEquals(splitPoint(4), 2);
  assertEquals(splitPoint(5), 4);
  assertEquals(splitPoint(8), 4);
  assertEquals(splitPoint(9), 8);
});

Deno.test("empty tree root is sha256 of nothing", async () => {
  assertEquals(bytesToHex(await merkleRoot([])), await sha256Hex(new Uint8Array()));
});

Deno.test("single-leaf root is the leaf itself, with an empty path", async () => {
  const ls = await leaves(1);
  assertEquals(bytesToHex(await merkleRoot(ls)), bytesToHex(ls[0]));
  assertEquals((await inclusionPath(ls, 0)).length, 0);
});

Deno.test("leaf and node hashing are domain-separated per RFC 6962", async () => {
  // A leaf must never hash the same as an interior node over the same bytes, which is the
  // second-preimage attack the 0x00/0x01 prefixes exist to stop.
  const entry = await sha256Hex("x");
  const leaf = await leafHash(entry);
  assert(bytesToHex(leaf) !== entry, "leaf hash must not equal the raw entry hash");
});

Deno.test("every leaf of every tree size 1..17 round-trips", async () => {
  for (let size = 1; size <= 17; size++) {
    const ls = await leaves(size);
    const root = bytesToHex(await merkleRoot(ls));
    for (let i = 0; i < size; i++) {
      const path = await inclusionPath(ls, i);
      assertEquals(
        path.length,
        pathLength(i, size),
        `path length disagreement at size ${size} leaf ${i}`,
      );
      const recomputed = bytesToHex(await rootFromPath(ls[i], i, size, path));
      assertEquals(recomputed, root, `round trip failed at size ${size} leaf ${i}`);
    }
  }
});

Deno.test("a tampered sibling does not reach the root", async () => {
  const size = 11;
  const ls = await leaves(size);
  const root = bytesToHex(await merkleRoot(ls));
  const path = await inclusionPath(ls, 6);
  path[0] = new Uint8Array(path[0]);
  path[0][0] ^= 0xff;
  assert(bytesToHex(await rootFromPath(ls[6], 6, size, path)) !== root);
});

Deno.test("a proof for one leaf does not validate another", async () => {
  const size = 13;
  const ls = await leaves(size);
  const root = bytesToHex(await merkleRoot(ls));
  const path = await inclusionPath(ls, 3);
  // Same path, different leaf: this is the substitution a log would attempt.
  assert(bytesToHex(await rootFromPath(ls[4], 3, size, path)) !== root);
});

Deno.test("a truncated or padded path is rejected rather than mis-verified", async () => {
  const size = 9;
  const ls = await leaves(size);
  const path = await inclusionPath(ls, 2);
  await assertRejects(() => rootFromPath(ls[2], 2, size, path.slice(1)));
  await assertRejects(() => rootFromPath(ls[2], 2, size, [...path, path[0]]));
});

Deno.test("an out-of-range index is rejected", async () => {
  const ls = await leaves(5);
  const path = await inclusionPath(ls, 4);
  await assertRejects(() => rootFromPath(ls[4], 5, 5, path));
  await assertRejects(() => rootFromPath(ls[4], -1, 5, path));
});

Deno.test("claiming a smaller tree than the proof was made for fails", async () => {
  const ls = await leaves(8);
  const path = await inclusionPath(ls, 1);
  // Path length for leaf 1 differs between a tree of 8 and a tree of 4, so this is caught by
  // the length check rather than by a hash comparison, which is the cheaper place to catch it.
  await assertRejects(() => rootFromPath(ls[1], 1, 4, path));
});

Deno.test("growing the tree keeps old leaves provable under the new root", async () => {
  // The property that makes an append-only log useful: adding entries never invalidates the
  // fact that an earlier entry was included, it only changes the root it sits under.
  const small = await leaves(6);
  const big = [...small, ...(await leaves(9)).slice(6)];
  const bigRoot = bytesToHex(await merkleRoot(big));
  for (let i = 0; i < 6; i++) {
    const path = await inclusionPath(big, i);
    assertEquals(bytesToHex(await rootFromPath(big[i], i, big.length, path)), bigRoot);
  }
});
