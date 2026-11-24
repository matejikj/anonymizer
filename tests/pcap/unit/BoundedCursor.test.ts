import { describe, it, expect } from 'vitest';
import { BoundedCursor, BoundsError } from '../../../src/pcap/capture/BoundedCursor';

describe('BoundedCursor', () => {
  it('reads u8', () => {
    const buf = new Uint8Array([0x42, 0xff]).buffer;
    const c = new BoundedCursor(buf);
    expect(c.u8()).toBe(0x42);
    expect(c.u8()).toBe(0xff);
    expect(c.remaining).toBe(0);
  });

  it('reads u16le and u16be', () => {
    const buf = new Uint8Array([0x01, 0x02, 0x03, 0x04]).buffer;
    const c = new BoundedCursor(buf);
    expect(c.u16le()).toBe(0x0201);
    expect(c.u16be()).toBe(0x0304);
  });

  it('reads u32le and u32be', () => {
    const buf = new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 0xa1, 0xb2, 0xc3, 0xd4]).buffer;
    const c = new BoundedCursor(buf);
    expect(c.u32le()).toBe(0xa1b2c3d4);
    expect(c.u32be()).toBe(0xa1b2c3d4);
  });

  it('reads u64le', () => {
    const buf = new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]).buffer;
    const c = new BoundedCursor(buf);
    expect(c.u64le()).toBe((2n << 32n) | 1n);
  });

  it('throws BoundsError on overflow', () => {
    const buf = new Uint8Array([0x01, 0x02]).buffer;
    const c = new BoundedCursor(buf);
    c.u16le();
    expect(() => c.u8()).toThrow(BoundsError);
  });

  it('seek and skip', () => {
    const buf = new Uint8Array([10, 20, 30, 40]).buffer;
    const c = new BoundedCursor(buf);
    c.seek(2);
    expect(c.u8()).toBe(30);
    c.seek(0);
    c.skip(3);
    expect(c.u8()).toBe(40);
  });

  it('slice copies data', () => {
    const arr = new Uint8Array([1, 2, 3, 4, 5]);
    const c = new BoundedCursor(arr.buffer);
    c.skip(1);
    const s = c.slice(3);
    expect(Array.from(s)).toEqual([2, 3, 4]);
    expect(c.remaining).toBe(1);
  });

  it('rejects invalid range', () => {
    const buf = new ArrayBuffer(10);
    expect(() => new BoundedCursor(buf, -1)).toThrow(BoundsError);
    expect(() => new BoundedCursor(buf, 5, 20)).toThrow(BoundsError);
  });

  it('supports subrange', () => {
    const buf = new Uint8Array([0, 0, 0x42, 0x43, 0, 0]).buffer;
    const c = new BoundedCursor(buf, 2, 2);
    expect(c.length).toBe(2);
    expect(c.u8()).toBe(0x42);
    expect(c.u8()).toBe(0x43);
    expect(c.remaining).toBe(0);
  });
});
