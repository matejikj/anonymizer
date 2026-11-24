/**
 * P1 privacy canaries V04 (ARI headers), V06 (USP unknown fixed64), V07 (Modbus FC06 value),
 * V09 (PostgreSQL dollar-quotes) — independent of protocol unit suites; real sanitize + export,
 * both diagnostic and high-privacy levels.
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { findSqlLiteralSpans } from '../../../src/pcap/protocols/application/textproto/literalMask'

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: {
      ticks: 1_700_000_000_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function packetInput(data: Uint8Array) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

describe('V04 ARI Cookie / unknown header', () => {
  const COOKIE = 'AUDIT_ARI_COOKIE_77319'
  const TOKEN = 'AUDIT_ARI_HEADER_77319'

  function ariPayload(): Uint8Array {
    const req = [
      'POST /ari/channels HTTP/1.1',
      'Host: pbx.example.invalid',
      `Cookie: session=${COOKIE}`,
      `X-Private-Token: ${TOKEN}`,
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n')
    return new TextEncoder().encode(req)
  }

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`masks Cookie and X-Private-Token via sanitize (${level})`, () => {
      const payload = ariPayload()
      const pkt = buildEthIpTcp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 8088, 1, payload)
      const mapping = new SessionMapping(undefined, { seed: `v04-ari-${level}` })
      const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      expect(result.coverage.some((c) => c.protocol.startsWith('ari'))).toBe(true)
      const out = latin1(applyPatches(pkt, result))
      expect(out.includes(COOKIE)).toBe(false)
      expect(out.includes(TOKEN)).toBe(false)
    })

    it(`masks Cookie and X-Private-Token via export pipeline (${level})`, () => {
      const pkt = envelope(
        buildEthIpTcp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 8088, 1, ariPayload()),
      )
      const exported = runExportPipeline([pkt], level, 'v04-ari.pcap', `v04-ari-${level}`, {
        mappingSeed: `v04-export-${level}`,
      })
      const text = latin1(exported.built.packets[0]!.data)
      expect(text.includes(COOKIE)).toBe(false)
      expect(text.includes(TOKEN)).toBe(false)
    })
  }
})

describe('V06 USP unknown fixed64 extension', () => {
  const CANARY = 'X9Y8Z7Q6'

  /** Same framing as audit probe: version 1.3 + field 100 fixed64 carrying canary bytes. */
  function uspUnknownFixed64(): Uint8Array {
    const enc = new TextEncoder()
    return new Uint8Array([0x0a, 3, ...enc.encode('1.3'), 0xa1, 6, ...enc.encode(CANARY)])
  }

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`masks unknown fixed64 payload via sanitize (${level})`, () => {
      const payload = uspUnknownFixed64()
      const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 40_003, 1, payload)
      const mapping = new SessionMapping(undefined, { seed: `v06-usp-${level}` })
      const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      expect(result.coverage.some((c) => c.protocol.startsWith('usp'))).toBe(true)
      const out = latin1(applyPatches(pkt, result))
      expect(out.includes(CANARY)).toBe(false)
      expect(result.issues.some((i) => i.includes('unknown') || i.includes('fixed64'))).toBe(true)
    })

    it(`masks unknown fixed64 via export pipeline (${level})`, () => {
      const pkt = envelope(
        buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 40_003, 1, uspUnknownFixed64()),
      )
      const exported = runExportPipeline([pkt], level, 'v06-usp.pcap', `v06-usp-${level}`, {
        mappingSeed: `v06-export-${level}`,
      })
      expect(latin1(exported.built.packets[0]!.data).includes(CANARY)).toBe(false)
    })
  }
})

describe('V07 Modbus FC 06 write value', () => {
  /** MBAP + Write Single Register: FC=06, addr=0x0010, value=0x5156 ('QV'). */
  function modbusFc06(): Uint8Array {
    return new Uint8Array([0, 1, 0, 0, 0, 6, 1, 6, 0, 16, 0x51, 0x56])
  }

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`masks FC06 register value via sanitize (${level})`, () => {
      const payload = modbusFc06()
      const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 502, 1, payload)
      const mapping = new SessionMapping(undefined, { seed: `v07-mb-${level}` })
      const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      expect(result.coverage.some((c) => c.protocol === 'modbus-values')).toBe(true)
      const out = applyPatches(pkt, result)
      const start = 14 + 20 + 20
      expect(out[start + 7]).toBe(0x06) // FC preserved
      expect(out[start + 8]).toBe(0x00) // address hi
      expect(out[start + 9]).toBe(0x10) // address lo
      expect(out[start + 10]).not.toBe(0x51)
      expect(out[start + 11]).not.toBe(0x56)
      expect(latin1(out).includes('QV')).toBe(false)
    })

    it(`masks FC06 value via export pipeline (${level})`, () => {
      const pkt = envelope(
        buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 502, 1, modbusFc06()),
      )
      const exported = runExportPipeline([pkt], level, 'v07-mb.pcap', `v07-mb-${level}`, {
        mappingSeed: `v07-export-${level}`,
      })
      expect(latin1(exported.built.packets[0]!.data).includes('QV')).toBe(false)
    })
  }

  it('masks FC05 coil value while preserving address', () => {
    // Write Single Coil: addr 0x0001, value 0xFF00 (on)
    const payload = new Uint8Array([0, 2, 0, 0, 0, 6, 1, 5, 0, 1, 0xff, 0x00])
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 502, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 'v07-fc05' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(pkt, result)
    const start = 14 + 20 + 20
    expect(out[start + 7]).toBe(0x05)
    expect(out[start + 8]).toBe(0x00)
    expect(out[start + 9]).toBe(0x01)
    expect(out[start + 10]).not.toBe(0xff)
  })
})

describe('V09 PostgreSQL dollar-quoted literal', () => {
  const SECRET = 'AUDIT_DOLLAR_SECRET'

  function pgDollarQuery(): Uint8Array {
    const sql = new TextEncoder().encode(`SELECT $$${SECRET}$$;\0`)
    const pg = new Uint8Array(5 + sql.length)
    pg[0] = 0x51 // Query
    new DataView(pg.buffer).setUint32(1, 4 + sql.length)
    pg.set(sql, 5)
    return pg
  }

  it('findSqlLiteralSpans detects postgres dollar quotes', () => {
    const body = new TextEncoder().encode(`SELECT $$${SECRET}$$`)
    const spans = findSqlLiteralSpans(body, 0, { dialect: 'postgres' })
    expect(spans.some((s) => s.kind === 'sql-dollar-string')).toBe(true)
    const dollar = spans.find((s) => s.kind === 'sql-dollar-string')!
    expect(latin1(body.subarray(dollar.absoluteOffset, dollar.absoluteOffset + dollar.byteLength))).toBe(
      SECRET,
    )
  })

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`masks dollar-quoted content via sanitize (${level})`, () => {
      const payload = pgDollarQuery()
      const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5432, 1, payload)
      const mapping = new SessionMapping(undefined, { seed: `v09-pg-${level}` })
      const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
      const result = sanitizePacket(packetInput(pkt), policy, mapping)
      expect(result.coverage.some((c) => c.protocol === 'postgres-sql')).toBe(true)
      const out = latin1(applyPatches(pkt, result))
      expect(out.includes(SECRET)).toBe(false)
      if (level === 'diagnostic') {
        expect(out.includes('SELECT')).toBe(true)
      }
    })

    it(`masks dollar-quoted content via export pipeline (${level})`, () => {
      const pkt = envelope(
        buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5432, 1, pgDollarQuery()),
      )
      const exported = runExportPipeline([pkt], level, 'v09-pg.pcap', `v09-pg-${level}`, {
        mappingSeed: `v09-export-${level}`,
      })
      expect(latin1(exported.built.packets[0]!.data).includes(SECRET)).toBe(false)
    })
  }

  it('masks tagged dollar quotes ($tag$…$tag$)', () => {
    const sql = new TextEncoder().encode("SELECT $audit$TAGGED_DOLLAR_CANARY$audit$;\0")
    const pg = new Uint8Array(5 + sql.length)
    pg[0] = 0x51
    new DataView(pg.buffer).setUint32(1, 4 + sql.length)
    pg.set(sql, 5)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5432, 1, pg)
    const mapping = new SessionMapping(undefined, { seed: 'v09-tagged' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(latin1(applyPatches(pkt, result)).includes('TAGGED_DOLLAR_CANARY')).toBe(false)
  })
})
