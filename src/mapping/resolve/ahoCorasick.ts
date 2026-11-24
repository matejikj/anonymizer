/**
 * Aho-Corasick multi-pattern matcher for pseudonym scan (Stage 22).
 * Linear in text length + number of matches — not O(text × patterns).
 */

export interface AcMatch {
  readonly patternIndex: number
  readonly start: number
  readonly end: number
}

interface Node {
  next: Map<string, number>
  fail: number
  out: number[]
}

export class AhoCorasick {
  private readonly patterns: readonly string[]
  private readonly nodes: Node[] = [{ next: new Map(), fail: 0, out: [] }]

  constructor(patterns: readonly string[]) {
    this.patterns = patterns
    for (let i = 0; i < patterns.length; i++) {
      this.insert(patterns[i]!, i)
    }
    this.buildFailures()
  }

  private insert(pattern: string, index: number): void {
    let state = 0
    for (const ch of pattern) {
      let next = this.nodes[state]!.next.get(ch)
      if (next === undefined) {
        next = this.nodes.length
        this.nodes.push({ next: new Map(), fail: 0, out: [] })
        this.nodes[state]!.next.set(ch, next)
      }
      state = next
    }
    this.nodes[state]!.out.push(index)
  }

  private buildFailures(): void {
    const queue: number[] = []
    for (const [, next] of this.nodes[0]!.next) {
      this.nodes[next]!.fail = 0
      queue.push(next)
    }
    while (queue.length > 0) {
      const state = queue.shift()!
      for (const [ch, next] of this.nodes[state]!.next) {
        queue.push(next)
        let fail = this.nodes[state]!.fail
        while (fail !== 0 && !this.nodes[fail]!.next.has(ch)) {
          fail = this.nodes[fail]!.fail
        }
        const f = this.nodes[fail]!.next.get(ch)
        this.nodes[next]!.fail = f ?? 0
        this.nodes[next]!.out.push(...this.nodes[this.nodes[next]!.fail]!.out)
      }
    }
  }

  search(text: string): AcMatch[] {
    const matches: AcMatch[] = []
    let state = 0
    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!
      while (state !== 0 && !this.nodes[state]!.next.has(ch)) {
        state = this.nodes[state]!.fail
      }
      state = this.nodes[state]!.next.get(ch) ?? 0
      const outs = this.nodes[state]!.out
      if (outs.length > 0) {
        for (const patternIndex of outs) {
          const pattern = this.patterns[patternIndex]!
          matches.push({
            patternIndex,
            start: i - pattern.length + 1,
            end: i + 1,
          })
        }
      }
    }
    return matches
  }
}
