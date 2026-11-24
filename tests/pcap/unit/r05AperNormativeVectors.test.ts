/**
 * R05 — normative APER integer wire vectors (ITU-T X.691 §11.5.7 / §13.2.6, ALIGNED).
 * Expected bytes are fixed independently of encode().
 */
import { describe, expect, it } from 'vitest'
import {
  BitCursor,
  encodeAper,
  decodeAper,
  readBoolean,
  readConstrainedInteger,
  writeConstrainedInteger,
  type AperTypeDesc,
} from '../../../src/pcap/protocols/asn1/aper'

const FLAG_THEN_ID_0_65535: AperTypeDesc = {
  kind: 'sequence',
  fields: [
    { name: 'flag', type: { kind: 'boolean' } },
    { name: 'id', type: { kind: 'integer', lower: 0, upper: 65535 } },
  ],
}

describe('R05 APER normative vectors (X.691 ALIGNED)', () => {
  it('decodes SEQUENCE { BOOLEAN, INTEGER(0..65535) } from 00 00 01 as false / 1', () => {
    const wire = Uint8Array.from([0x00, 0x00, 0x01])
    const dec = decodeAper(wire, 0, wire.length, FLAG_THEN_ID_0_65535)
    expect(dec.ok).toBe(true)
    expect(dec.leaves.find((l) => l.path === 'flag')?.value).toBe(false)
    expect(dec.leaves.find((l) => l.path === 'id')?.value).toBe(1)
  })

  it('encodes SEQUENCE { flag=false, id=1 } via schema to exactly 00 00 01', () => {
    const enc = encodeAper(FLAG_THEN_ID_0_65535, { flag: false, id: 1 })
    expect(enc).not.toBeNull()
    expect(Array.from(enc!)).toEqual([0x00, 0x00, 0x01])
  })

  it('rejects legacy misaligned wire 00 00 80 as id=1', () => {
    const wire = Uint8Array.from([0x00, 0x00, 0x80])
    const dec = decodeAper(wire, 0, wire.length, FLAG_THEN_ID_0_65535)
    const id = dec.leaves.find((l) => l.path === 'id')?.value
    expect(id).not.toBe(1)
  })

  it('INTEGER(0..255) offset 1 uses one aligned octet (range 256)', () => {
    const wire = Uint8Array.from([0x01])
    const cur = new BitCursor(wire)
    expect(cur.align()).toBe(true)
    const got = readConstrainedInteger(cur, 0, 255)
    expect(got?.value).toBe(1)
    const buf = new Uint8Array(2)
    const w = new BitCursor(buf)
    expect(w.align()).toBe(true)
    expect(writeConstrainedInteger(w, 0, 255, 1)).toBe(true)
    expect(Array.from(buf.subarray(0, 1))).toEqual([0x01])
  })

  it('decodes INTEGER(0..2^40-1) value 1 from wire 00 01', () => {
    const upper = 1_099_511_627_775
    const wire = Uint8Array.from([0x00, 0x01])
    const cur = new BitCursor(wire)
    const got = readConstrainedInteger(cur, 0, upper)
    expect(got?.value).toBe(1)
  })

  it('encodes INTEGER(0..2^40-1) value 1 to exactly 00 01', () => {
    const upper = 1_099_511_627_775
    const buf = new Uint8Array(8)
    const cur = new BitCursor(buf)
    expect(writeConstrainedInteger(cur, 0, upper, 1)).toBe(true)
    const used = (cur.bitOffset + 7) >> 3
    expect(Array.from(buf.subarray(0, used))).toEqual([0x00, 0x01])
  })

  it('does not decode legacy fixed five-octet stub as value 1', () => {
    const upper = 1_099_511_627_775
    const stub = Uint8Array.from([0x00, 0x00, 0x00, 0x00, 0x01])
    const cur = new BitCursor(stub)
    const got = readConstrainedInteger(cur, 0, upper)
    expect(got?.value).not.toBe(1)
  })

  it('manual decode of 00 00 01 via boolean + integer readers matches schema decode', () => {
    const wire = Uint8Array.from([0x00, 0x00, 0x01])
    const cur = new BitCursor(wire)
    const flag = readBoolean(cur)
    expect(flag?.value).toBe(false)
    const id = readConstrainedInteger(cur, 0, 65535)
    expect(id?.value).toBe(1)
    expect(cur.bitOffset).toBe(24)
  })
})
