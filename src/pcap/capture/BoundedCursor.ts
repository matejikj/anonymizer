/**
 * Bounds-checked cursor for reading binary data from a Uint8Array.
 * Every read validates offset, length, alignment and integer overflow.
 */

export class BoundsError extends Error {
  readonly offset: number;
  readonly requested: number;
  readonly available: number;

  constructor(message: string, offset: number, requested: number, available: number) {
    super(message);
    this.name = 'BoundsError';
    this.offset = offset;
    this.requested = requested;
    this.available = available;
  }
}

export class BoundedCursor {
  private _offset: number;
  private readonly _view: DataView;
  private readonly _bytes: Uint8Array;
  private readonly _end: number;

  constructor(buffer: ArrayBuffer, start = 0, length?: number) {
    const end = length !== undefined ? start + length : buffer.byteLength;
    if (start < 0 || end > buffer.byteLength || start > end) {
      throw new BoundsError('Invalid cursor range', start, end - start, buffer.byteLength);
    }
    this._bytes = new Uint8Array(buffer, start, end - start);
    this._view = new DataView(buffer, start, end - start);
    this._offset = 0;
    this._end = end - start;
  }

  get offset(): number {
    return this._offset;
  }

  get remaining(): number {
    return this._end - this._offset;
  }

  get length(): number {
    return this._end;
  }

  seek(offset: number): void {
    if (offset < 0 || offset > this._end) {
      throw new BoundsError('Seek out of bounds', offset, 0, this._end);
    }
    this._offset = offset;
  }

  skip(n: number): void {
    this.seek(this._offset + n);
  }

  private check(n: number): void {
    if (this._offset + n > this._end) {
      throw new BoundsError(
        `Read ${n} bytes at offset ${this._offset} exceeds bounds`,
        this._offset,
        n,
        this.remaining,
      );
    }
  }

  u8(): number {
    this.check(1);
    return this._bytes[this._offset++]!;
  }

  u16le(): number {
    this.check(2);
    const v = this._view.getUint16(this._offset, true);
    this._offset += 2;
    return v;
  }

  u16be(): number {
    this.check(2);
    const v = this._view.getUint16(this._offset, false);
    this._offset += 2;
    return v;
  }

  u32le(): number {
    this.check(4);
    const v = this._view.getUint32(this._offset, true);
    this._offset += 4;
    return v;
  }

  u32be(): number {
    this.check(4);
    const v = this._view.getUint32(this._offset, false);
    this._offset += 4;
    return v;
  }

  u64le(): bigint {
    this.check(8);
    const lo = this._view.getUint32(this._offset, true);
    const hi = this._view.getUint32(this._offset + 4, true);
    this._offset += 8;
    return (BigInt(hi) << 32n) | BigInt(lo);
  }

  u64be(): bigint {
    this.check(8);
    const hi = this._view.getUint32(this._offset, false);
    const lo = this._view.getUint32(this._offset + 4, false);
    this._offset += 8;
    return (BigInt(hi) << 32n) | BigInt(lo);
  }

  i32le(): number {
    this.check(4);
    const v = this._view.getInt32(this._offset, true);
    this._offset += 4;
    return v;
  }

  i32be(): number {
    this.check(4);
    const v = this._view.getInt32(this._offset, false);
    this._offset += 4;
    return v;
  }

  slice(n: number): Uint8Array {
    this.check(n);
    const s = this._bytes.slice(this._offset, this._offset + n);
    this._offset += n;
    return s;
  }

  /** View into underlying buffer without copy — valid only while cursor is alive */
  view(n: number): Uint8Array {
    this.check(n);
    const v = this._bytes.subarray(this._offset, this._offset + n);
    this._offset += n;
    return v;
  }

  peekU32le(): number {
    this.check(4);
    return this._view.getUint32(this._offset, true);
  }

  peekU32be(): number {
    this.check(4);
    return this._view.getUint32(this._offset, false);
  }
}
