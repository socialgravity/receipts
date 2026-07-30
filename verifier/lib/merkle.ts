// RFC 6962 Merkle tree hashing, the Certificate Transparency construction.
//
// Why this construction rather than a hand-rolled one: the domain separation prefixes (0x00 for
// leaves, 0x01 for interior nodes) are what stop a second-preimage attack where an interior
// node is presented as a leaf, and the "everything to the left of the largest power of two"
// split is what makes proofs stable as the tree grows. Both are easy to get subtly wrong and
// already specified, so this follows the spec rather than inventing.
//
// Hash function is SHA-256 throughout, matching the ledger's entry hashes.
//
//   leaf(entry)        = SHA256(0x00 || entry_hash_bytes)
//   node(left, right)  = SHA256(0x01 || left || right)
//   empty tree root    = SHA256(<empty>)

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`not lower-case hex of even length: ${hex.slice(0, 16)}...`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  const d = await crypto.subtle.digest("SHA-256", buf as unknown as ArrayBuffer);
  return new Uint8Array(d);
}

const PREFIX_LEAF = new Uint8Array([0x00]);
const PREFIX_NODE = new Uint8Array([0x01]);

/** Leaf hash of one ledger entry, given its entry_hash as lower-case hex. */
export async function leafHash(entryHashHex: string): Promise<Uint8Array> {
  return await sha256(PREFIX_LEAF, hexToBytes(entryHashHex));
}

export async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return await sha256(PREFIX_NODE, left, right);
}

/** The largest power of two strictly less than n. RFC 6962's split point. */
export function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle root over leaf hashes. Empty tree is SHA256 of the empty string. */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return await sha256();
  if (leaves.length === 1) return leaves[0];
  const k = splitPoint(leaves.length);
  const [l, r] = await Promise.all([
    merkleRoot(leaves.slice(0, k)),
    merkleRoot(leaves.slice(k)),
  ]);
  return await nodeHash(l, r);
}

/** Audit path for leaf `index` in a tree of these leaves: siblings from the bottom up. */
export async function inclusionPath(leaves: Uint8Array[], index: number): Promise<Uint8Array[]> {
  if (index < 0 || index >= leaves.length) {
    throw new Error(`leaf index ${index} out of range for a tree of ${leaves.length}`);
  }
  if (leaves.length === 1) return [];
  const k = splitPoint(leaves.length);
  if (index < k) {
    return [...await inclusionPath(leaves.slice(0, k), index), await merkleRoot(leaves.slice(k))];
  }
  return [...await inclusionPath(leaves.slice(k), index - k), await merkleRoot(leaves.slice(0, k))];
}

/**
 * Recompute a root from a leaf and its audit path. This is the verifier's half: it never sees
 * the whole tree, only its own leaf plus log(n) sibling hashes and the tree size from the STH.
 *
 * Deliberately the mirror image of inclusionPath above, same recursion and same split, so the
 * two can be read side by side. The audit path is ordered leaf-first (as RFC 6962 specifies),
 * which means descending the tree consumes it from the END: the last element is the sibling of
 * the whole opposite subtree at the top split.
 *
 * Whether a sibling goes on the left or the right is derived from the leaf index rather than
 * supplied by the log, on purpose. A log that could choose the direction could produce a path
 * that validates a leaf it never committed to.
 */
export async function rootFromPath(
  leaf: Uint8Array,
  leafIndex: number,
  treeSize: number,
  path: Uint8Array[],
): Promise<Uint8Array> {
  if (treeSize < 1) throw new Error("tree size must be at least 1");
  if (leafIndex < 0 || leafIndex >= treeSize) {
    throw new Error(`leaf index ${leafIndex} out of range for a tree of ${treeSize}`);
  }
  const expected = pathLength(leafIndex, treeSize);
  if (path.length !== expected) {
    throw new Error(
      `audit path has ${path.length} hashes, a tree of ${treeSize} needs ${expected} for leaf ${leafIndex}`,
    );
  }
  return await walk(leaf, leafIndex, treeSize, path);
}

async function walk(
  leaf: Uint8Array,
  index: number,
  size: number,
  path: Uint8Array[],
): Promise<Uint8Array> {
  if (size === 1) return leaf;
  const k = splitPoint(size);
  const sibling = path[path.length - 1];
  const rest = path.slice(0, -1);
  if (index < k) {
    return await nodeHash(await walk(leaf, index, k, rest), sibling);
  }
  return await nodeHash(sibling, await walk(leaf, index - k, size - k, rest));
}

/** How many hashes a valid audit path holds. Checked so a truncated path cannot pass. */
export function pathLength(index: number, size: number): number {
  if (size <= 1) return 0;
  const k = splitPoint(size);
  return 1 + (index < k ? pathLength(index, k) : pathLength(index - k, size - k));
}

/**
 * RFC 9162 section 2.1.4.2: check that the tree of size `first` is a prefix of the tree of size
 * `second`. Returns true only if the proof reconstructs BOTH published roots and consumes exactly
 * the hashes it was given.
 *
 * The deliberate constraint here is that this function never sees the log's leaves. It is handed
 * two roots the log signed on two different days and a handful of sibling hashes, and it either
 * rebuilds both roots from them or it does not. That is what makes it a check on the log rather
 * than a restatement of what the log said. The algorithm is also structurally different from the
 * recursive SUBPROOF that generates these proofs on the server, so the two agreeing is evidence
 * rather than tautology.
 *
 * What a pass means: every entry that existed at the first size still exists, in the same position,
 * with the same hash. What it does not mean: that either head is honest on its own. A log that
 * signed one head is still just a log; the heads need their own signatures and external timestamps,
 * and this function deliberately checks neither.
 */
export async function verifyConsistency(
  first: number,
  second: number,
  proof: Uint8Array[],
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
): Promise<boolean> {
  if (!Number.isInteger(first) || !Number.isInteger(second)) return false;
  if (first < 0 || second < 0 || first > second) return false;

  // The two degenerate cases carry no hashes, and a proof supplied for them is a red flag rather
  // than something to ignore: it means the prover and the verifier disagree about what is being
  // claimed, and silently accepting extra hashes is how a verifier stops being one.
  if (first === 0) return proof.length === 0;
  if (first === second) return proof.length === 0 && sameBytes(firstRoot, secondRoot);
  if (proof.length === 0) return false;

  // Walk up from the last leaf of the first tree, discarding the run of right-hand edges: those
  // nodes are interior to both trees and need no sibling from the proof.
  let node = first - 1;
  let lastNode = second - 1;
  while (node & 1) {
    node >>= 1;
    lastNode >>= 1;
  }

  let p = 0;
  // When `node` reached zero the first tree is a whole power of two, so its root IS the first
  // subtree and the proof does not restate it. Otherwise the proof opens with that subtree's hash.
  let newHash = node !== 0 ? proof[p++] : firstRoot;
  let oldHash = newHash;

  while (node !== 0) {
    if (node & 1) {
      if (p >= proof.length) return false;
      const sibling = proof[p++];
      // The same sibling folds into both accumulators, which is the crux: one set of hashes has to
      // rebuild the old root and the new one at once, and only a genuine prefix relationship lets
      // it.
      oldHash = await nodeHash(sibling, oldHash);
      newHash = await nodeHash(sibling, newHash);
    } else if (node < lastNode) {
      if (p >= proof.length) return false;
      newHash = await nodeHash(newHash, proof[p++]);
    }
    node >>= 1;
    lastNode >>= 1;
  }

  // Everything the larger tree grew on its right-hand side.
  while (lastNode !== 0) {
    if (p >= proof.length) return false;
    newHash = await nodeHash(newHash, proof[p++]);
    lastNode >>= 1;
  }

  // Exact consumption, not "at least". A proof carrying spare hashes is a proof whose shape was
  // not the one this size pair implies, and accepting it would let a caller pad past a check.
  return p === proof.length &&
    sameBytes(oldHash, firstRoot) &&
    sameBytes(newHash, secondRoot);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
