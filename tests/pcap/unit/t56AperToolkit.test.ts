/**
 * T56 — APER BitCursor, schema decode/encode, bit PatchCompiler (no S1AP/NGAP).
 */
import { describe, expect, it } from 'vitest'
import {
  BitCursor,
  constrainedBitWidth,
  decodeAper,
  encodeAper,
  compileBitRewrites,
  applyCompiledPatches,
  physicalByteRanges,
  readConstrainedInteger,
  writeConstrainedInteger,
  TOY_MODULE_A,
  TOY_MODULE_B,
  getAperSchema,
  APER_SCHEMA_REGISTRY,
  rewriteConstrainedIntegerLeaf,
} from '../../../src/pcap/protocols/asn1/aper'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'

describe('T56 registry / engine', () => {
  it('exposes two toy schemas and engine 2.36.1 with S1AP/NGAP schemas (T57/T58)', () => {
    expect(APER_SCHEMA_REGISTRY.size).toBe(4)
    expect(getAperSchema(TOY_MODULE_A.id)?.revision).toBe('t56-1')
    expect(getAperSchema(TOY_MODULE_B.id)?.root.kind).toBe('choice')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T56 BitCursor', () => {
  it('never reads past lease; aligns to octets', () => {
    const buf = new Uint8Array([0b1011_0000, 0xff])
    const cur = new BitCursor(buf, 0, 1)
    expect(cur.readBits(4)).toBe(0b1011)
    expect(cur.remainingBits).toBe(4)
    expect(cur.readBits(8)).toBeNull()
    expect(cur.issue?.code).toBe('bits-oob')
    cur.clearIssue()
    expect(cur.seekBit(4)).toBe(true)
    expect(cur.align()).toBe(true)
    expect(cur.bitOffset).toBe(8)
    expect(cur.remainingBits).toBe(0)
  })

  it('writes bits MSB-first without disturbing neighbors', () => {
    const buf = new Uint8Array([0b1111_1111])
    const cur = new BitCursor(buf)
    expect(cur.seekBit(2)).toBe(true)
    expect(cur.writeBits(4, 0b0000)).toBe(true)
    expect(buf[0]).toBe(0b1100_0011)
  })
})

describe('T56 constrained integers', () => {
  it('round-trips and reports exact bit spans', () => {
    expect(constrainedBitWidth(16)).toBe(4)
    const buf = new Uint8Array(4)
    const w = new BitCursor(buf)
    expect(writeConstrainedInteger(w, 0, 15, 10)).toBe(true)
    const r = new BitCursor(buf)
    const got = readConstrainedInteger(r, 0, 15)
    expect(got?.value).toBe(10)
    expect(got?.span.bitLength).toBe(4)
  })

  it('rejects truncation / OOB length claims', () => {
    const buf = new Uint8Array(0)
    const cur = new BitCursor(buf)
    // need 8 bits for range 256; empty lease → OOB
    expect(readConstrainedInteger(cur, 0, 255)).toBeNull()
    expect(cur.issue?.code).toBe('bits-oob')
  })

  it('round-trips AMF-sized range (0..2^40-1) with §13.2.6 length + min octets', () => {
    const upper = 1_099_511_627_775 // 2^40-1
    const cases = [1, 65_536, 4_294_967_297, upper] as const
    for (const value of cases) {
      const buf = new Uint8Array(16)
      const w = new BitCursor(buf)
      expect(writeConstrainedInteger(w, 0, upper, value)).toBe(true)
      const encodedBits = w.bitOffset
      const r = new BitCursor(buf)
      const got = readConstrainedInteger(r, 0, upper)
      expect(got?.value).toBe(value)
      expect(got?.span.bitLength).toBe(encodedBits)
      expect(r.bitOffset).toBe(encodedBits)
    }
  })
})

describe('T56 schema SEQUENCE (module A)', () => {
  it('encodes/decodes optional ueId sharing byte with status enum', () => {
    const encoded = encodeAper(TOY_MODULE_A.root, {
      procedureCode: 42,
      ueId: 7,
      status: 'ok',
    })
    expect(encoded).not.toBeNull()
    const dec = decodeAper(encoded!, 0, encoded!.length, TOY_MODULE_A.root)
    expect(dec.ok).toBe(true)
    const ue = dec.leaves.find((l) => l.path === 'ueId')
    const st = dec.leaves.find((l) => l.path === 'status')
    const pc = dec.leaves.find((l) => l.path === 'procedureCode')
    expect(pc?.value).toBe(42)
    expect(ue?.value).toBe(7)
    expect(st?.value).toBe('ok')
    // ueId (4 bits) and status (2 bits for 3 enums) may share a physical byte with optional bit
    expect(ue && st).toBeTruthy()
    const ranges = physicalByteRanges([ue!.span, st!.span])
    expect(ranges.length).toBeGreaterThanOrEqual(1)
  })

  it('rewrites only ueId bits; status enum stays valid', () => {
    const encoded = encodeAper(TOY_MODULE_A.root, {
      procedureCode: 1,
      ueId: 3,
      status: 'reject',
    })!
    const before = decodeAper(encoded, 0, encoded.length, TOY_MODULE_A.root)
    const ue = before.leaves.find((l) => l.path === 'ueId')!
    const rw = rewriteConstrainedIntegerLeaf(encoded, ue.span, 0, 15, 12)
    expect(rw.ok).toBe(true)
    if (!rw.ok) return
    const compiled = compileBitRewrites(encoded, [
      { span: ue.span, value: 12 },
    ])
    expect(compiled.issues).toHaveLength(0)
    const collector = new PatchCollector(encoded.length)
    applyCompiledPatches(collector, compiled.patches)
    const out = encoded.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    const after = decodeAper(out, 0, out.length, TOY_MODULE_A.root)
    expect(after.ok).toBe(true)
    expect(after.leaves.find((l) => l.path === 'ueId')?.value).toBe(12)
    expect(after.leaves.find((l) => l.path === 'status')?.value).toBe('reject')
    expect(after.leaves.find((l) => l.path === 'procedureCode')?.value).toBe(1)
  })
})

describe('T56 schema CHOICE (module B)', () => {
  it('onboards second schema without codec API change', () => {
    const enc = encodeAper(TOY_MODULE_B.root, { alt: 'id', value: 5 })!
    const dec = decodeAper(enc, 0, enc.length, TOY_MODULE_B.root)
    expect(dec.ok).toBe(true)
    expect(dec.leaves.some((l) => l.path === 'id' && l.value === 5)).toBe(true)

    const tok = encodeAper(TOY_MODULE_B.root, {
      alt: 'token',
      value: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    })!
    const decTok = decodeAper(tok, 0, tok.length, TOY_MODULE_B.root)
    expect(decTok.ok).toBe(true)
    const leaf = decTok.leaves.find((l) => l.path === 'token')
    expect(leaf?.role).toBe('mask')
    expect(leaf?.value).toBeInstanceOf(Uint8Array)
  })
})

describe('T56 PatchCompiler collisions', () => {
  it('rejects colliding bit rewrites on the same bits', () => {
    const buf = new Uint8Array([0xff])
    const r = compileBitRewrites(buf, [
      { span: { bitOffset: 0, bitLength: 4 }, value: 1 },
      { span: { bitOffset: 2, bitLength: 4 }, value: 2 },
    ])
    expect(r.issues).toContain('bit-rewrite-collision')
    expect(r.patches).toHaveLength(0)
  })

  it('allows adjacent fields sharing a byte without bit collision', () => {
    const buf = new Uint8Array([0x00])
    const r = compileBitRewrites(buf, [
      { span: { bitOffset: 0, bitLength: 4 }, value: 0b1010 },
      { span: { bitOffset: 4, bitLength: 4 }, value: 0b0101 },
    ])
    expect(r.issues).toHaveLength(0)
    expect(r.patches).toHaveLength(1)
    expect(r.patches[0]!.data[0]).toBe(0b1010_0101)
  })
})

describe('T56 open-type / depth caps', () => {
  it('marks opaque open-type without nested schema', () => {
    const type = { kind: 'open-type' as const }
    const inner = new Uint8Array([1, 2, 3, 4])
    const enc = encodeAper(type, inner)!
    const dec = decodeAper(enc, 0, enc.length, type)
    expect(dec.ok).toBe(true)
    expect(dec.leaves[0]?.role).toBe('opaque')
    expect(dec.leaves[0]?.span.bitLength).toBe(32)
  })
})
