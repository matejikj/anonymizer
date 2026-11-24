/**
 * T29 — PostgreSQL / MySQL / TDS / Redis / MongoDB auth and SQL/value canaries.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'

function packetInput(data: Uint8Array) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function writeU32be(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 24) & 0xff
  buf[o + 1] = (v >>> 16) & 0xff
  buf[o + 2] = (v >>> 8) & 0xff
  buf[o + 3] = v & 0xff
}

function writeU16le(buf: Uint8Array, o: number, v: number): void {
  buf[o] = v & 0xff
  buf[o + 1] = (v >>> 8) & 0xff
}

function writeU32le(buf: Uint8Array, o: number, v: number): void {
  buf[o] = v & 0xff
  buf[o + 1] = (v >>> 8) & 0xff
  buf[o + 2] = (v >>> 16) & 0xff
  buf[o + 3] = (v >>> 24) & 0xff
}

describe('T29 registry', () => {
  it('registers database handlers, family, ports, and engine 2.35.0', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(
      expect.arrayContaining(['postgres', 'mysql', 'tds', 'redis', 'mongodb']),
    )
    expect(familyForProtocol('postgres').familyId).toBe('database')
    expect(familyForProtocol('mysql-auth').familyId).toBe('database')
    expect(familyForProtocol('redis-auth').familyId).toBe('database')
    expect(familyForProtocol('mongodb-body').familyId).toBe('database')
    expect(SEMANTIC_SERVICE_PORTS.has(5432)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(3306)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(6379)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })
})

describe('T29 PostgreSQL', () => {
  it('masks PasswordMessage and SQL string literal canary', () => {
    const password = new TextEncoder().encode('PG-PASS-CANARY\0')
    const passMsg = new Uint8Array(1 + 4 + password.length)
    passMsg[0] = 0x70 // 'p'
    writeU32be(passMsg, 1, 4 + password.length)
    passMsg.set(password, 5)

    const sql = new TextEncoder().encode("SELECT * FROM t WHERE secret='SQL-CANARY-VALUE'\0")
    const query = new Uint8Array(1 + 4 + sql.length)
    query[0] = 0x51 // 'Q'
    writeU32be(query, 1, 4 + sql.length)
    query.set(sql, 5)

    const payload = new Uint8Array(passMsg.length + query.length)
    payload.set(passMsg, 0)
    payload.set(query, passMsg.length)

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5432, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't29-pg' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'postgres-auth')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'postgres-sql')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('PG-PASS-CANARY')).toBe(false)
    expect(latin1(out).includes('SQL-CANARY-VALUE')).toBe(false)
    expect(latin1(out).includes('SELECT')).toBe(true)
  })
})

describe('T29 MySQL', () => {
  it('masks COM_QUERY string literal canary', () => {
    const sql = new TextEncoder().encode("SELECT 'MYSQL-SQL-CANARY'")
    const body = new Uint8Array(1 + sql.length)
    body[0] = 0x03 // COM_QUERY
    body.set(sql, 1)
    const payload = new Uint8Array(4 + body.length)
    payload[0] = body.length & 0xff
    payload[1] = (body.length >> 8) & 0xff
    payload[2] = (body.length >> 16) & 0xff
    payload[3] = 0 // seq
    payload.set(body, 4)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 3306, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't29-mysql' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'mysql-sql' || c.protocol === 'mysql')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('MYSQL-SQL-CANARY')).toBe(false)
    expect(latin1(out).includes('SELECT')).toBe(true)
  })
})

describe('T29 Redis AUTH', () => {
  it('masks AUTH password argument', () => {
    // *2\r\n$4\r\nAUTH\r\n$15\r\nREDIS-PASS-CANARY\r\n
    const payload = new TextEncoder().encode(
      '*2\r\n$4\r\nAUTH\r\n$15\r\nREDIS-PASS-CANARY\r\n',
    )
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 6379, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't29-redis' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'redis-auth')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('REDIS-PASS-CANARY')).toBe(false)
    expect(latin1(out).includes('AUTH')).toBe(true)
  })
})

describe('T29 MongoDB', () => {
  it('masks OP_MSG BSON body containing sasl canary', () => {
    // Minimal OP_MSG: header + flags + section0 + tiny BSON with saslStart key
    const bsonInner = new TextEncoder().encode('saslStart\0MONGO-SASL-CANARY\0')
    // document: int32 length + elements + NUL — approximate
    const doc = new Uint8Array(4 + 1 + bsonInner.length + 1)
    writeU32le(doc, 0, doc.length)
    doc[4] = 0x02 // string type (simplified — not valid BSON layout; sanitizer masks whole)
    doc.set(bsonInner, 5)
    doc[doc.length - 1] = 0

    const body = new Uint8Array(4 + 1 + doc.length)
    writeU32le(body, 0, 0) // flags
    body[4] = 0 // section kind body
    body.set(doc, 5)

    const msg = new Uint8Array(16 + body.length)
    writeU32le(msg, 0, msg.length)
    writeU32le(msg, 4, 1) // requestId
    writeU32le(msg, 8, 0) // responseTo
    writeU32le(msg, 12, 2013) // OP_MSG
    msg.set(body, 16)

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 27_017, 1, msg)
    const mapping = new SessionMapping(undefined, { seed: 't29-mongo' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('mongodb'))).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('MONGO-SASL-CANARY')).toBe(false)
  })
})

describe('T29 TDS LOGIN7 password', () => {
  it('masks LOGIN7 password field canary', () => {
    // Minimal LOGIN7-shaped body with password at ib=80, cch=8 (16 bytes UTF-16)
    const pass = 'TDS-PASS!' // 8 chars
    const passUtf16 = new Uint8Array(pass.length * 2)
    for (let i = 0; i < pass.length; i++) {
      passUtf16[i * 2] = pass.charCodeAt(i) & 0xff
      passUtf16[i * 2 + 1] = 0
    }
    const varOff = 80
    const body = new Uint8Array(varOff + passUtf16.length)
    writeU32le(body, 0, body.length)
    // ibPassword / cchPassword at 44/46
    writeU16le(body, 44, varOff)
    writeU16le(body, 46, pass.length)
    body.set(passUtf16, varOff)

    const pktLen = 8 + body.length
    const payload = new Uint8Array(pktLen)
    payload[0] = 0x10 // LOGIN7
    payload[1] = 0x01 // EOM
    payload[2] = (pktLen >> 8) & 0xff
    payload[3] = pktLen & 0xff
    payload.set(body, 8)

    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 1433, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't29-tds' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'tds-auth')).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('TDS-PASS!')).toBe(false)
  })
})
