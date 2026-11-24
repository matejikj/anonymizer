/**
 * Async capture cursor — bounded Blob.slice reads (never whole-file materialization).
 */

import { MAX_RECORD_SIZE } from '../domain/types'
import { BoundsError } from './BoundedCursor'

export interface IAsyncCaptureCursor {
  readonly offset: number
  readonly size: number
  remaining(): number
  u8(): Promise<number>
  u16le(): Promise<number>
  u16be(): Promise<number>
  u32le(): Promise<number>
  u32be(): Promise<number>
  u64le(): Promise<bigint>
  u64be(): Promise<bigint>
  i32le(): Promise<number>
  i32be(): Promise<number>
  skip(n: number): Promise<void>
  slice(n: number): Promise<Uint8Array>
  seek(offset: number): Promise<void>
}

/** In-memory cursor for sync reference adapter. */
export class MemoryAsyncCursor implements IAsyncCaptureCursor {
  private view: DataView
  private bytes: Uint8Array
  private _offset = 0

  constructor(buffer: ArrayBuffer, start = 0, length?: number) {
    const end = length !== undefined ? start + length : buffer.byteLength
    this.bytes = new Uint8Array(buffer, start, end - start)
    this.view = new DataView(buffer, start, end - start)
  }

  get offset(): number {
    return this._offset
  }

  get size(): number {
    return this.bytes.byteLength
  }

  remaining(): number {
    return this.bytes.byteLength - this._offset
  }

  async seek(offset: number): Promise<void> {
    if (offset < 0 || offset > this.bytes.byteLength) {
      throw new BoundsError('Seek out of bounds', offset, 0, this.bytes.byteLength)
    }
    this._offset = offset
  }

  async skip(n: number): Promise<void> {
    await this.seek(this._offset + n)
  }

  private check(n: number): void {
    if (this._offset + n > this.bytes.byteLength) {
      throw new BoundsError('Read out of bounds', this._offset, n, this.remaining())
    }
  }

  async u8(): Promise<number> {
    this.check(1)
    return this.bytes[this._offset++]!
  }

  async u16le(): Promise<number> {
    this.check(2)
    const v = this.view.getUint16(this._offset, true)
    this._offset += 2
    return v
  }

  async u16be(): Promise<number> {
    this.check(2)
    const v = this.view.getUint16(this._offset, false)
    this._offset += 2
    return v
  }

  async u32le(): Promise<number> {
    this.check(4)
    const v = this.view.getUint32(this._offset, true)
    this._offset += 4
    return v
  }

  async u32be(): Promise<number> {
    this.check(4)
    const v = this.view.getUint32(this._offset, false)
    this._offset += 4
    return v
  }

  async u64le(): Promise<bigint> {
    this.check(8)
    const lo = this.view.getUint32(this._offset, true)
    const hi = this.view.getUint32(this._offset + 4, true)
    this._offset += 8
    return (BigInt(hi) << 32n) | BigInt(lo)
  }

  async u64be(): Promise<bigint> {
    this.check(8)
    const hi = this.view.getUint32(this._offset, false)
    const lo = this.view.getUint32(this._offset + 4, false)
    this._offset += 8
    return (BigInt(hi) << 32n) | BigInt(lo)
  }

  async i32le(): Promise<number> {
    this.check(4)
    const v = this.view.getInt32(this._offset, true)
    this._offset += 4
    return v
  }

  async i32be(): Promise<number> {
    this.check(4)
    const v = this.view.getInt32(this._offset, false)
    this._offset += 4
    return v
  }

  async slice(n: number): Promise<Uint8Array> {
    assertSliceSize(n)
    this.check(n)
    const s = this.bytes.slice(this._offset, this._offset + n)
    this._offset += n
    return s
  }
}

/**
 * Chunk window size for BlobSliceCursor's read-ahead buffer. Each Blob.slice().arrayBuffer()
 * call is a real async I/O round-trip in the browser (unlike an in-memory buffer read), so
 * batching many small header-field reads (u8/u16/u32/u64 are 1-8 bytes each) into one chunked
 * fetch avoids thousands of separate round-trips per capture. Bounded, so the cursor still
 * never materializes the whole file.
 */
const BLOB_READ_CHUNK_SIZE = 64 * 1024

/** Production cursor — bounded Blob.slice reads, batched via a read-ahead window. */
export class BlobSliceCursor implements IAsyncCaptureCursor {
  private _offset = 0
  private readonly blob: Blob
  private _buf: Uint8Array | null = null
  private _bufOffset = 0

  constructor(blob: Blob) {
    this.blob = blob
  }

  get offset(): number {
    return this._offset
  }

  get size(): number {
    return this.blob.size
  }

  remaining(): number {
    return this.blob.size - this._offset
  }

  async seek(offset: number): Promise<void> {
    if (offset < 0 || offset > this.blob.size) {
      throw new BoundsError('Seek out of bounds', offset, 0, this.blob.size)
    }
    this._offset = offset
  }

  async skip(n: number): Promise<void> {
    if (n < 0 || this._offset + n > this.blob.size) {
      throw new BoundsError('Skip out of bounds', this._offset, n, this.remaining())
    }
    this._offset += n
  }

  private async read(n: number): Promise<Uint8Array> {
    if (n <= 0) return new Uint8Array(0)
    if (this._offset + n > this.blob.size) {
      throw new BoundsError('Read out of bounds', this._offset, n, this.remaining())
    }
    if (!this.bufferCovers(this._offset, n)) {
      await this.fillBuffer(this._offset, n)
    }
    const start = this._offset - this._bufOffset
    const out = this._buf!.slice(start, start + n)
    this._offset += n
    return out
  }

  private bufferCovers(offset: number, n: number): boolean {
    return (
      this._buf !== null &&
      offset >= this._bufOffset &&
      offset + n <= this._bufOffset + this._buf.byteLength
    )
  }

  private async fillBuffer(offset: number, n: number): Promise<void> {
    const size = Math.max(n, BLOB_READ_CHUNK_SIZE)
    const end = Math.min(offset + size, this.blob.size)
    const ab = await this.blob.slice(offset, end).arrayBuffer()
    this._buf = new Uint8Array(ab)
    this._bufOffset = offset
  }

  async u8(): Promise<number> {
    const b = await this.read(1)
    return b[0]!
  }

  async u16le(): Promise<number> {
    const b = await this.read(2)
    return b[0]! | (b[1]! << 8)
  }

  async u16be(): Promise<number> {
    const b = await this.read(2)
    return (b[0]! << 8) | b[1]!
  }

  async u32le(): Promise<number> {
    const b = await this.read(4)
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0
  }

  async u32be(): Promise<number> {
    const b = await this.read(4)
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0
  }

  async u64le(): Promise<bigint> {
    const lo = await this.u32le()
    const hi = await this.u32le()
    return (BigInt(hi) << 32n) | BigInt(lo)
  }

  async u64be(): Promise<bigint> {
    const hi = await this.u32be()
    const lo = await this.u32be()
    return (BigInt(hi) << 32n) | BigInt(lo)
  }

  async i32le(): Promise<number> {
    const b = await this.read(4)
    return new DataView(b.buffer, b.byteOffset, 4).getInt32(0, true)
  }

  async i32be(): Promise<number> {
    const b = await this.read(4)
    return new DataView(b.buffer, b.byteOffset, 4).getInt32(0, false)
  }

  async slice(n: number): Promise<Uint8Array> {
    assertSliceSize(n)
    return this.read(n)
  }
}

function assertSliceSize(n: number): void {
  if (n > MAX_RECORD_SIZE) {
    throw new BoundsError(`Slice ${n} exceeds MAX_RECORD_SIZE`, 0, n, MAX_RECORD_SIZE)
  }
}
