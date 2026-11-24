/**
 * T56 — APER BitCursor: checked bit arithmetic over a BufferLease window.
 * Never throws past lease; issues instead (same contract class as SoftCursor).
 */

export interface AperParseIssue {
  readonly code: string
  readonly bitOffset: number
}

export interface BitSpan {
  readonly bitOffset: number
  readonly bitLength: number
}

export class BitCursor {
  private _bit = 0
  private _issue: AperParseIssue | null = null
  private readonly bytes: Uint8Array
  private readonly byteStart: number
  private readonly byteEnd: number

  constructor(bytes: Uint8Array, byteStart = 0, byteEnd?: number) {
    this.bytes = bytes
    this.byteStart = byteStart
    this.byteEnd = byteEnd ?? bytes.length
  }

  get bitOffset(): number {
    return this._bit
  }

  get absoluteBitOffset(): number {
    return this.byteStart * 8 + this._bit
  }

  get remainingBits(): number {
    return Math.max(0, (this.byteEnd - this.byteStart) * 8 - this._bit)
  }

  get issue(): AperParseIssue | null {
    return this._issue
  }

  clearIssue(): void {
    this._issue = null
  }

  /** Align to next octet boundary (APER). */
  align(): boolean {
    const rem = this._bit & 7
    if (rem === 0) return true
    return this.skipBits(8 - rem)
  }

  seekBit(bit: number): boolean {
    const max = (this.byteEnd - this.byteStart) * 8
    if (bit < 0 || bit > max) {
      this._issue = { code: 'seek-oob', bitOffset: this.absoluteBitOffset }
      return false
    }
    this._bit = bit
    return true
  }

  skipBits(n: number): boolean {
    if (n < 0 || n > this.remainingBits) {
      this._issue = { code: 'skip-oob', bitOffset: this.absoluteBitOffset }
      return false
    }
    this._bit += n
    return true
  }

  /** Read `n` bits MSB-first within each octet (X.691). */
  readBits(n: number): number | null {
    if (n < 0 || n > 32) {
      this._issue = { code: 'bits-range', bitOffset: this.absoluteBitOffset }
      return null
    }
    if (n > this.remainingBits) {
      this._issue = { code: 'bits-oob', bitOffset: this.absoluteBitOffset }
      return null
    }
    let value = 0
    for (let i = 0; i < n; i++) {
      const absBit = this.byteStart * 8 + this._bit
      const byteIndex = absBit >> 3
      const bitInByte = 7 - (absBit & 7)
      const bit = (this.bytes[byteIndex]! >> bitInByte) & 1
      value = (value << 1) | bit
      this._bit++
    }
    return value >>> 0
  }

  /** Peek without advancing. */
  peekBits(n: number): number | null {
    const saved = this._bit
    const v = this.readBits(n)
    this._bit = saved
    return v
  }

  /** Write `n` bits MSB-first into a mutable buffer (same window). */
  writeBits(n: number, value: number): boolean {
    if (n < 0 || n > 32 || n > this.remainingBits) {
      this._issue = { code: 'write-oob', bitOffset: this.absoluteBitOffset }
      return false
    }
    for (let i = n - 1; i >= 0; i--) {
      const bit = (value >>> i) & 1
      const absBit = this.byteStart * 8 + this._bit
      const byteIndex = absBit >> 3
      const bitInByte = 7 - (absBit & 7)
      const mask = 1 << bitInByte
      if (bit) this.bytes[byteIndex] = this.bytes[byteIndex]! | mask
      else this.bytes[byteIndex] = this.bytes[byteIndex]! & ~mask
      this._bit++
    }
    return true
  }

  /** Absolute bit span for the last `bitLength` bits ending at current offset. */
  spanEnding(bitLength: number): BitSpan {
    return {
      bitOffset: this.absoluteBitOffset - bitLength,
      bitLength,
    }
  }
}

/** Allocate zeroed scratch with `byteLength` octets. */
export function createBitScratch(byteLength: number): Uint8Array {
  return new Uint8Array(Math.max(0, byteLength))
}
