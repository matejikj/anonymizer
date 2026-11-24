/** Fenwick (binary indexed) tree helpers for Int32 length deltas. */

export function fenwickBuild(deltas: Int32Array): Int32Array {
  const n = deltas.length
  const tree = new Int32Array(n + 1)
  for (let i = 0; i < n; i++) {
    let idx = i + 1
    while (idx <= n) {
      tree[idx]! += deltas[i]!
      idx += idx & -idx
    }
  }
  return tree
}

export function fenwickPrefix(tree: Int32Array, count: number): number {
  let sum = 0
  let idx = count
  while (idx > 0) {
    sum += tree[idx]!
    idx -= idx & -idx
  }
  return sum
}

export function fenwickUpdate(tree: Int32Array, index: number, delta: number): void {
  const n = tree.length - 1
  let idx = index + 1
  while (idx <= n) {
    tree[idx]! += delta
    idx += idx & -idx
  }
}
