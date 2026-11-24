/**
 * T65 — compact Aho-Corasick multi-pattern matcher over Uint8Array haystacks.
 * Patterns are raw needles; outputs start offsets only (never captured values).
 */

export interface AhoPattern {
  readonly id: number
  readonly bytes: Uint8Array
}

interface AcNode {
  next: Map<number, AcNode>
  fail: AcNode | null
  /** Pattern ids that end at this node. */
  out: number[]
}

function createNode(): AcNode {
  return { next: new Map(), fail: null, out: [] }
}

export interface AhoCorasickAutomaton {
  readonly maxNeedle: number
  /**
   * Find all matches in `haystack`.
   * Callback receives (patternId, startOffset). Return false to stop early.
   */
  readonly findAll: (
    haystack: Uint8Array,
    onMatch: (patternId: number, start: number) => boolean | void,
  ) => void
}

/** Build an automaton for the given patterns (empty patterns skipped). */
export function buildAhoCorasick(patterns: readonly AhoPattern[]): AhoCorasickAutomaton {
  const root = createNode()
  let maxNeedle = 0
  const byId = new Map<number, Uint8Array>()

  for (const p of patterns) {
    if (p.bytes.length === 0) continue
    maxNeedle = Math.max(maxNeedle, p.bytes.length)
    byId.set(p.id, p.bytes)
    let node = root
    for (let i = 0; i < p.bytes.length; i++) {
      const b = p.bytes[i]!
      let child = node.next.get(b)
      if (!child) {
        child = createNode()
        node.next.set(b, child)
      }
      node = child
    }
    node.out.push(p.id)
  }

  const queue: AcNode[] = []
  for (const child of root.next.values()) {
    child.fail = root
    queue.push(child)
  }
  while (queue.length > 0) {
    const node = queue.shift()!
    for (const [b, child] of node.next) {
      queue.push(child)
      let f = node.fail
      while (f && !f.next.has(b)) f = f.fail
      child.fail = f?.next.get(b) ?? root
      if (child.fail.out.length > 0) {
        child.out = child.out.concat(child.fail.out)
      }
    }
  }

  return {
    maxNeedle,
    findAll(haystack, onMatch) {
      let node: AcNode = root
      for (let i = 0; i < haystack.length; i++) {
        const b = haystack[i]!
        while (node !== root && !node.next.has(b)) {
          node = node.fail ?? root
        }
        node = node.next.get(b) ?? root
        for (const id of node.out) {
          const needle = byId.get(id)
          if (!needle) continue
          const start = i - needle.length + 1
          if (start < 0) continue
          if (onMatch(id, start) === false) return
        }
      }
    },
  }
}
