/**
 * Bounded little-endian IO for recovery codecs.
 * Length fields are rejected before any allocation of the claimed size.
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'

export class RecoveryReader {
  private readonly bytes: Uint8Array
  private offset: number
  private readonly end: number

  constructor(bytes: Uint8Array, offset = 0, end = bytes.byteLength) {
    this.bytes = bytes
    this.offset = offset
    this.end = end
  }

  remaining(): number {
    return this.end - this.offset
  }

  position(): number {
    return this.offset
  }

  readU8(): PcapRecoveryResult<number> {
    if (this.offset + 1 > this.end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated')
    }
    const v = this.bytes[this.offset]!
    this.offset += 1
    return recoveryOk(v)
  }

  readU16(): PcapRecoveryResult<number> {
    if (this.offset + 2 > this.end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated')
    }
    const v = this.bytes[this.offset]! | (this.bytes[this.offset + 1]! << 8)
    this.offset += 2
    return recoveryOk(v)
  }

  readU32(): PcapRecoveryResult<number> {
    if (this.offset + 4 > this.end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated')
    }
    const view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength)
    const v = view.getUint32(this.offset, true)
    this.offset += 4
    return recoveryOk(v)
  }

  readU64(): PcapRecoveryResult<bigint> {
    if (this.offset + 8 > this.end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated')
    }
    const view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength)
    const lo = view.getUint32(this.offset, true)
    const hi = view.getUint32(this.offset + 4, true)
    this.offset += 8
    const value = BigInt(lo) + (BigInt(hi) << 32n)
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'length exceeds safe integer')
    }
    return recoveryOk(value)
  }

  /**
   * Slice existing bytes; never allocates `len` unless the length already passed
   * a caller-supplied max and fits in the remaining window.
   */
  readBytes(len: number, maxLen: number): PcapRecoveryResult<Uint8Array> {
    if (!Number.isInteger(len) || len < 0) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid length')
    }
    if (len > maxLen) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'field exceeds limit')
    }
    if (this.offset + len > this.end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated')
    }
    const slice = this.bytes.subarray(this.offset, this.offset + len)
    this.offset += len
    return recoveryOk(slice.slice())
  }

  readUtf8(len: number, maxBytes: number): PcapRecoveryResult<string> {
    const raw = this.readBytes(len, maxBytes)
    if (!raw.ok) return raw
    try {
      return recoveryOk(new TextDecoder('utf-8', { fatal: true }).decode(raw.value))
    } catch {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid utf-8')
    }
  }

  expectConsumed(): PcapRecoveryResult<void> {
    if (this.offset !== this.end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'trailing bytes')
    }
    return recoveryOk(undefined)
  }
}

export class RecoveryWriter {
  private readonly chunks: Uint8Array[] = []
  private size = 0

  get byteLength(): number {
    return this.size
  }

  writeU8(v: number): void {
    const b = new Uint8Array(1)
    b[0] = v & 0xff
    this.chunks.push(b)
    this.size += 1
  }

  writeU16(v: number): void {
    const b = new Uint8Array(2)
    b[0] = v & 0xff
    b[1] = (v >>> 8) & 0xff
    this.chunks.push(b)
    this.size += 2
  }

  writeU32(v: number): void {
    const b = new Uint8Array(4)
    const view = new DataView(b.buffer)
    view.setUint32(0, v >>> 0, true)
    this.chunks.push(b)
    this.size += 4
  }

  writeU64(v: bigint | number): void {
    const n = typeof v === 'bigint' ? v : BigInt(v)
    if (n < 0n || n > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new RangeError('u64 out of safe range')
    }
    const b = new Uint8Array(8)
    const view = new DataView(b.buffer)
    view.setUint32(0, Number(n & 0xffffffffn), true)
    view.setUint32(4, Number(n >> 32n), true)
    this.chunks.push(b)
    this.size += 8
  }

  writeBytes(bytes: Uint8Array): void {
    this.chunks.push(bytes.slice())
    this.size += bytes.byteLength
  }

  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this.size)
    let off = 0
    for (const chunk of this.chunks) {
      out.set(chunk, off)
      off += chunk.byteLength
    }
    return out
  }
}

export function writeU32LeTo(target: Uint8Array, offset: number, value: number): void {
  const view = new DataView(target.buffer, target.byteOffset, target.byteLength)
  view.setUint32(offset, value >>> 0, true)
}

export function readU32Le(bytes: Uint8Array, offset: number): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  return view.getUint32(offset, true)
}
