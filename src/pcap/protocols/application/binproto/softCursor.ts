/**
 * T16 — result-based binary cursor that never throws (walkers return ParseIssue).
 * Views a window `bytes[windowStart, windowEnd)` with relative reads.
 */

export interface BinParseIssue {
  readonly code: string
  readonly offset: number
}

export class SoftCursor {
  private _rel = 0
  private _issue: BinParseIssue | null = null
  private readonly bytes: Uint8Array
  private readonly windowStart: number
  private readonly windowEnd: number

  constructor(
    bytes: Uint8Array,
    windowStart = 0,
    windowEnd?: number,
  ) {
    this.bytes = bytes
    this.windowStart = windowStart
    this.windowEnd = windowEnd ?? bytes.length
  }

  get offset(): number {
    return this._rel
  }

  get absoluteOffset(): number {
    return this.windowStart + this._rel
  }

  get remaining(): number {
    return Math.max(0, this.windowEnd - this.windowStart - this._rel)
  }

  get issue(): BinParseIssue | null {
    return this._issue
  }

  clearIssue(): void {
    this._issue = null
  }

  seek(rel: number): boolean {
    const span = this.windowEnd - this.windowStart
    if (rel < 0 || rel > span) {
      this._issue = { code: 'seek-oob', offset: this.absoluteOffset }
      return false
    }
    this._rel = rel
    return true
  }

  skip(n: number): boolean {
    if (n < 0 || this._rel + n > this.windowEnd - this.windowStart) {
      this._issue = { code: 'skip-oob', offset: this.absoluteOffset }
      return false
    }
    this._rel += n
    return true
  }

  private absIndex(): number {
    return this.windowStart + this._rel
  }

  u8(): number | null {
    if (this.remaining < 1) {
      this._issue = { code: 'u8-oob', offset: this.absoluteOffset }
      return null
    }
    const v = this.bytes[this.absIndex()]!
    this._rel++
    return v
  }

  u16(le: boolean): number | null {
    if (this.remaining < 2) {
      this._issue = { code: 'u16-oob', offset: this.absoluteOffset }
      return null
    }
    const i = this.absIndex()
    const b0 = this.bytes[i]!
    const b1 = this.bytes[i + 1]!
    this._rel += 2
    return le ? b0 | (b1 << 8) : (b0 << 8) | b1
  }

  u32(le: boolean): number | null {
    if (this.remaining < 4) {
      this._issue = { code: 'u32-oob', offset: this.absoluteOffset }
      return null
    }
    const i = this.absIndex()
    const b0 = this.bytes[i]!
    const b1 = this.bytes[i + 1]!
    const b2 = this.bytes[i + 2]!
    const b3 = this.bytes[i + 3]!
    this._rel += 4
    return le
      ? (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0
      : ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0
  }

  slice(n: number): Uint8Array | null {
    if (n < 0 || this.remaining < n) {
      this._issue = { code: 'slice-oob', offset: this.absoluteOffset }
      return null
    }
    const i = this.absIndex()
    const out = this.bytes.subarray(i, i + n)
    this._rel += n
    return out
  }
}
