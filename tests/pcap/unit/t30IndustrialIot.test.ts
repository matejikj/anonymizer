/**
 * T30 — MQTT / CoAP / Modbus / IEC104 / DNP3 / OPC UA industrial IoT canaries.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { dnp3Crc16 } from '../../../src/pcap/sanitize/industrial/dnp3'
import { CoapBlock2Session } from '../../../src/pcap/sanitize/industrial/coapBlock2Session.ts'
import { OpcuaChannelSession } from '../../../src/pcap/sanitize/industrial/opcuaChannelSession.ts'
import { sanitizeOpcua } from '../../../src/pcap/sanitize/industrial/opcua'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification'

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

function writeU16be(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 8) & 0xff
  buf[o + 1] = v & 0xff
}

describe('T30 registry', () => {
  it('registers industrial handlers, family, ports, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(
      expect.arrayContaining(['mqtt', 'coap', 'modbus', 'iec104', 'dnp3', 'opcua']),
    )
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('mqtt')
    expect(familyForProtocol('mqtt').familyId).toBe('industrial')
    expect(familyForProtocol('modbus-values').familyId).toBe('industrial')
    expect(familyForProtocol('dnp3-addr').familyId).toBe('industrial')
    expect(SEMANTIC_SERVICE_PORTS.has(1883)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(502)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(20_000)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T30 MQTT CONNECT', () => {
  it('masks CONNECT password canary', () => {
    const proto = new TextEncoder().encode('MQTT')
    const clientId = new TextEncoder().encode('cid1')
    const user = new TextEncoder().encode('u1')
    const pass = new TextEncoder().encode('MQTT-PASS-CANARY')
    const flags = 0xc0
    const variable = new Uint8Array(
      2 + proto.length + 1 + 1 + 2 + 2 + clientId.length + 2 + user.length + 2 + pass.length,
    )
    let p = 0
    writeU16be(variable, p, proto.length)
    p += 2
    variable.set(proto, p)
    p += proto.length
    variable[p++] = 4
    variable[p++] = flags
    writeU16be(variable, p, 60)
    p += 2
    writeU16be(variable, p, clientId.length)
    p += 2
    variable.set(clientId, p)
    p += clientId.length
    writeU16be(variable, p, user.length)
    p += 2
    variable.set(user, p)
    p += user.length
    writeU16be(variable, p, pass.length)
    p += 2
    variable.set(pass, p)
    const connect = new Uint8Array(2 + variable.length)
    connect[0] = 0x10
    connect[1] = variable.length
    connect.set(variable, 2)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 1883, 1, connect)
    const mapping = new SessionMapping(undefined, { seed: 't30-mqtt' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'mqtt-auth')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('MQTT-PASS-CANARY')).toBe(false)
  })

  it('preserves PUBLISH topic slash separators', () => {
    const topic = new TextEncoder().encode('a/b/c')
    const pubPayload = new TextEncoder().encode('x')
    const pubVar = new Uint8Array(2 + topic.length + pubPayload.length)
    writeU16be(pubVar, 0, topic.length)
    pubVar.set(topic, 2)
    pubVar.set(pubPayload, 2 + topic.length)
    const publish = new Uint8Array(2 + pubVar.length)
    publish[0] = 0x30
    publish[1] = pubVar.length
    publish.set(pubVar, 2)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 1883, 1, publish)
    const mapping = new SessionMapping(undefined, { seed: 't30-mqtt-pub' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'mqtt-topic')).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('/')).toBe(true)
  })
})

describe('T30 Modbus values', () => {
  it('masks register values while preserving function code', () => {
    // MBAP + read holding registers response: FC=03, byteCount=2, value canary
    const pdu = new Uint8Array([0x03, 0x02, 0xca, 0xfe])
    const payload = new Uint8Array(7 + pdu.length)
    writeU16be(payload, 0, 1) // tx
    writeU16be(payload, 2, 0) // proto
    writeU16be(payload, 4, 1 + pdu.length)
    payload[6] = 1 // unit
    payload.set(pdu, 7)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 502, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't30-modbus' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'modbus-values')).toBe(true)
    const out = applyPatches(pkt, result)
    const start = 14 + 20 + 20 // eth + ipv4 + tcp
    expect(out[start + 7]).toBe(0x03) // function code preserved
    expect(out[start + 9]).not.toBe(0xca)
    expect(out[start + 10]).not.toBe(0xfe)
  })
})

describe('T30 DNP3 CRC', () => {
  it('recomputes header CRC after address mapping', () => {
    // Minimal DNP3 data-link frame: header only (len=5 → no user data)
    const frame = new Uint8Array(10)
    frame[0] = 0x05
    frame[1] = 0x64
    frame[2] = 5 // ctrl+dest+src
    frame[3] = 0xc4 // ctrl
    frame[4] = 0x34 // dest lo
    frame[5] = 0x12 // dest hi = 0x1234
    frame[6] = 0x78
    frame[7] = 0x56 // src = 0x5678
    const hdrCrc = dnp3Crc16(frame.subarray(0, 8))
    frame[8] = hdrCrc & 0xff
    frame[9] = (hdrCrc >>> 8) & 0xff

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 20_000, 1, frame)
    const mapping = new SessionMapping(undefined, { seed: 't30-dnp3' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'dnp3-addr' || c.protocol === 'dnp3')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    // TCP payload offset (eth 14 + ipv4 20 + tcp 20) — avoid false 0x05 in headers.
    const start = 14 + 20 + 20
    expect(out[start]).toBe(0x05)
    expect(out[start + 1]).toBe(0x64)
    const hdr = out.subarray(start, start + 8)
    const expectCrc = dnp3Crc16(hdr)
    const got = out[start + 8]! | (out[start + 9]! << 8)
    expect(got).toBe(expectCrc)
  })
})

function writeU32le(buf: Uint8Array, o: number, v: number): void {
  buf[o] = v & 0xff
  buf[o + 1] = (v >>> 8) & 0xff
  buf[o + 2] = (v >>> 16) & 0xff
  buf[o + 3] = (v >>> 24) & 0xff
}

function writeUaString(buf: Uint8Array, o: number, text: Uint8Array): number {
  writeU32le(buf, o, text.length)
  buf.set(text, o + 4)
  return o + 4 + text.length
}

function writeUaByteString(buf: Uint8Array, o: number, data: Uint8Array | null): number {
  if (!data) {
    writeU32le(buf, o, -1)
    return o + 4
  }
  writeU32le(buf, o, data.length)
  buf.set(data, o + 4)
  return o + 4 + data.length
}

function buildOpcuaChunk(msgType: string, body: Uint8Array): Uint8Array {
  const msgSize = 8 + body.length
  const out = new Uint8Array(msgSize)
  out[0] = msgType.charCodeAt(0)
  out[1] = msgType.charCodeAt(1)
  out[2] = msgType.charCodeAt(2)
  out[3] = 0x46
  writeU32le(out, 4, msgSize)
  out.set(body, 8)
  return out
}

function buildOpcuaOpnSign(extra: Uint8Array = new Uint8Array(0)): Uint8Array {
  const openInner = new Uint8Array(24 + extra.length)
  let p = 0
  writeU32le(openInner, p, 0)
  p += 4
  writeU32le(openInner, p, 0)
  p += 4
  writeU32le(openInner, p, 2)
  p += 4
  p = writeUaByteString(openInner, p, null)
  writeU32le(openInner, p, 3_600_000)
  p += 4
  openInner.set(extra, p)
  p += extra.length
  const openBody = openInner.subarray(0, p)

  const ext = new Uint8Array(1 + 4 + 1 + 4 + openBody.length)
  let e = 0
  ext[e++] = 0x01
  ext[e++] = 0x00
  ext[e++] = 0xbe
  ext[e++] = 0x01
  ext[e++] = 0x01
  writeU32le(ext, e, openBody.length)
  e += 4
  ext.set(openBody, e)

  const body = new Uint8Array(4 + 4 + 4 + 4 + 8 + ext.length)
  let b = 0
  writeU32le(body, b, 9)
  b += 4
  b = writeUaString(body, b, new Uint8Array(0))
  b = writeUaByteString(body, b, null)
  b = writeUaByteString(body, b, null)
  writeU32le(body, b, 1)
  b += 4
  writeU32le(body, b, 1)
  b += 4
  body.set(ext, b)
  return buildOpcuaChunk('OPN', body)
}

function buildOpcuaMsgSignAudit(audit: Uint8Array): Uint8Array {
  const header = new Uint8Array(24)
  writeU32le(header, 0, 9)
  writeU32le(header, 4, 1)
  writeU32le(header, 8, 1)
  writeU32le(header, 12, 1)
  writeU32le(header, 16, 2)
  writeU32le(header, 20, 2)

  const service = new Uint8Array(128)
  let s = 0
  service[s++] = 0x01
  service[s++] = 0x00
  service[s++] = 0x77
  service[s++] = 0x02
  service[s++] = 0x00
  writeU32le(service, s, 0)
  s += 8
  writeU32le(service, s, 1)
  s += 4
  writeU32le(service, s, 0)
  s += 4
  s = writeUaString(service, s, audit)
  writeU32le(service, s, 0)
  s += 4
  service[s++] = 0x00

  const body = new Uint8Array(header.length + s)
  body.set(header, 0)
  body.set(service.subarray(0, s), header.length)
  return buildOpcuaChunk('MSG', body)
}

describe('T30 OPC UA HEL', () => {
  it('maps EndpointUrl host and does not leave canary hostname', () => {
    const url = new TextEncoder().encode('opc.tcp://opcua-canary-host:4840/path')
    const body = new Uint8Array(20 + 4 + url.length)
    // version + 4 sizes
    body[0] = 0
    writeU16be(body, 4, 0x1000) // dummy sizes region
    const strLen = url.length
    body[20] = strLen & 0xff
    body[21] = (strLen >> 8) & 0xff
    body[22] = (strLen >> 16) & 0xff
    body[23] = (strLen >> 24) & 0xff
    body.set(url, 24)
    const msgSize = 8 + body.length
    const payload = new Uint8Array(msgSize)
    payload[0] = 0x48 // H
    payload[1] = 0x45 // E
    payload[2] = 0x4c // L
    payload[3] = 0x46 // F
    payload[4] = msgSize & 0xff
    payload[5] = (msgSize >> 8) & 0xff
    payload[6] = (msgSize >> 16) & 0xff
    payload[7] = (msgSize >> 24) & 0xff
    payload.set(body, 8)

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 4840, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't30-opcua' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('opcua'))).toBe(true)
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('opcua-canary-host')).toBe(false)
  })
})

describe('T30 OPC UA MSG Sign', () => {
  it('walks Sign plaintext RequestHeader auditEntryId (T30.opcua.sign)', () => {
    const opn = buildOpcuaOpnSign()
    const audit = new TextEncoder().encode('T30-OPC-AUDIT-SECRET')
    const msg = buildOpcuaMsgSignAudit(audit)
    const payload = new Uint8Array(opn.length + msg.length)
    payload.set(opn, 0)
    payload.set(msg, opn.length)
    const session = new OpcuaChannelSession()
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 4840, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't30-opcua-sign' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping, {
      opcuaChannel: session,
      generationId: 't30-opcua-sign',
      sourceId: 'test.pcap',
    })
    expect(result.issues).toContain('opcua-opn-security-mode')
    expect(result.issues).toContain('opcua-msg-sign-plaintext')
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('T30-OPC-AUDIT-SECRET')).toBe(false)
  })

  it('masks the OpenSecureChannel request body it reports as redacted', () => {
    // Handler level: the engine's generic in-place fallback must not be what hides the canary.
    const canary = new TextEncoder().encode('OPN-REQUEST-HEADER-CANARY')
    const opn = buildOpcuaOpnSign(canary)
    const mapping = new SessionMapping(undefined, { seed: 't30-opcua-opn-body' })
    const collector = new PatchCollector(opn.length)
    const result = sanitizeOpcua(opn, 0, opn.length, 40_000, 4840, collector, mapping, 0, false, undefined, {
      opcuaChannel: new OpcuaChannelSession(),
    })
    expect(result?.issues).toContain('opcua-opn-parsed')
    expect(result?.coverage.some((c) => c.protocol === 'opcua-auth' && c.status === 'redacted')).toBe(true)
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = opn.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    expect(latin1(out).includes('OPN-REQUEST-HEADER-CANARY')).toBe(false)
  })

  it('fail-closed masks SignAndEncrypt MSG body', () => {
    const session = new OpcuaChannelSession()
    session.setSecurityMode(
      session.flowKey({ srcIp: '192.0.2.1', dstIp: '192.0.2.2' }, 40_000, 4840),
      'sign-and-encrypt',
    )
    const body = new Uint8Array(32)
    body.fill(0xab)
    const msg = buildOpcuaChunk('MSG', body)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 4840, 1, msg)
    const mapping = new SessionMapping(undefined, { seed: 't30-opcua-enc' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping, {
      opcuaChannel: session,
    })
    expect(result.issues).toContain('opcua-msg-encrypted')
  })
})

describe('T30 DNP3 object dictionary', () => {
  it('masks G30V1 values with valid block CRC (T30.dnp3.dict)', () => {
    const app = new Uint8Array([
      0xc0, 0xc0, 0x81, 0x1e, 0x01, 0x03, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01,
    ])
    const userLen = app.length + 2
    const frame = new Uint8Array(10 + userLen)
    frame[0] = 0x05
    frame[1] = 0x64
    frame[2] = 5 + userLen
    frame[3] = 0xc4
    frame[4] = 0x34
    frame[5] = 0x12
    frame[6] = 0x78
    frame[7] = 0x56
    const hdrCrc = dnp3Crc16(frame.subarray(0, 8))
    frame[8] = hdrCrc & 0xff
    frame[9] = (hdrCrc >>> 8) & 0xff
    frame.set(app, 10)
    const blockCrc = dnp3Crc16(app)
    frame[10 + app.length] = blockCrc & 0xff
    frame[10 + app.length + 1] = (blockCrc >>> 8) & 0xff

    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 20_000, 1, frame)
    const mapping = new SessionMapping(undefined, { seed: 't30-dnp3-dict' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues).toContain('dnp3-object-dictionary-walk')
    const out = applyPatches(pkt, result)
    const start = 14 + 20 + 20
    expect(out[start + 10 + 7]).not.toBe(0xde)
    const block = out.subarray(start + 10, start + 10 + app.length)
    const expectCrc = dnp3Crc16(block)
    const got = out[start + 10 + app.length]! | (out[start + 10 + app.length + 1]! << 8)
    expect(got).toBe(expectCrc)
  })
})

describe('T30 MQTT 5 properties', () => {
  it('masks User Property value while walking known property id', () => {
    const proto = new TextEncoder().encode('MQTT')
    const clientId = new TextEncoder().encode('c1')
    const key = new TextEncoder().encode('k')
    const secret = new TextEncoder().encode('T30-USER-PROP-SECRET')
    const prop = new Uint8Array(1 + 2 + 1 + 2 + 2 + secret.length)
    let q = 0
    prop[q++] = 38
    writeU16be(prop, q, 1)
    q += 2
    prop[q++] = 0x6b // "k"
    writeU16be(prop, q, secret.length)
    q += 2
    prop.set(secret, q)
    const flags = 0x02
    const variable = new Uint8Array(
      2 + proto.length + 1 + 1 + 2 + 1 + prop.length + 2 + clientId.length,
    )
    let p = 0
    writeU16be(variable, p, proto.length)
    p += 2
    variable.set(proto, p)
    p += proto.length
    variable[p++] = 5
    variable[p++] = flags
    writeU16be(variable, p, 30)
    p += 2
    variable[p++] = prop.length
    variable.set(prop, p)
    p += prop.length
    writeU16be(variable, p, clientId.length)
    p += 2
    variable.set(clientId, p)
    const connect = new Uint8Array(2 + variable.length)
    connect[0] = 0x10
    connect[1] = variable.length
    connect.set(variable, 2)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 1883, 1, connect)
    const mapping = new SessionMapping(undefined, { seed: 't30-mqtt5-prop' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues).toContain('mqtt-user-property-sanitized')
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('T30-USER-PROP-SECRET')).toBe(false)
  })
})

function buildCoapBlock2Pdu(blockByte: number, payload: Uint8Array, mid: number): Uint8Array {
  const opt = new Uint8Array(2 + 1)
  opt[0] = (13 << 4) | 1
  opt[1] = 10
  opt[2] = blockByte
  const coap = new Uint8Array(4 + opt.length + 1 + payload.length)
  coap[0] = 0x40
  coap[1] = 0x45
  coap[2] = (mid >>> 8) & 0xff
  coap[3] = mid & 0xff
  coap.set(opt, 4)
  coap[4 + opt.length] = 0xff
  coap.set(payload, 4 + opt.length + 1)
  return coap
}

describe('T30 CoAP URI', () => {
  it('maps Uri-Host option', () => {
    // ver=1, type=0 CON, tkl=0, code GET=1, mid=1, option Uri-Host "coap-host"
    const host = new TextEncoder().encode('coap-canary')
    // option: delta=3 (Uri-Host), len=host.length
    const opt = new Uint8Array(1 + host.length)
    opt[0] = (3 << 4) | host.length
    opt.set(host, 1)
    const payload = new Uint8Array(4 + opt.length)
    payload[0] = 0x40 // ver1 CON tkl0
    payload[1] = 0x01 // GET
    payload[2] = 0x00
    payload[3] = 0x01
    payload.set(opt, 4)
    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5683, payload)
    const mapping = new SessionMapping(undefined, { seed: 't30-coap' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'coap-uri' || c.protocol === 'coap')).toBe(
      true,
    )
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('coap-canary')).toBe(false)
  })

  it('masks single Block2 datagram payload (T30.coap.block)', () => {
    const payload = new TextEncoder().encode('T30-COAP-BLOCK-SECRET')
    const coap = buildCoapBlock2Pdu(0x00, payload, 2)
    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5683, coap)
    const mapping = new SessionMapping(undefined, { seed: 't30-coap-block' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues).not.toContain('coap-block2-pending')
    const out = applyPatches(pkt, result)
    expect(latin1(out).includes('T30-COAP-BLOCK-SECRET')).toBe(false)
  })

  it('honest requires-reassembly for partial Block2 until capture completes', () => {
    const session = new CoapBlock2Session()
    const payload0 = new TextEncoder().encode('T30-COAP-A')
    const payload1 = new TextEncoder().encode('T30-COAP-B')
    const pkt0 = buildEthIpUdp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      5683,
      buildCoapBlock2Pdu(0x08, payload0, 10),
    )
    const pkt1 = buildEthIpUdp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      5683,
      buildCoapBlock2Pdu(0x10, payload1, 11),
    )
    const mapping = new SessionMapping(undefined, { seed: 't30-coap-block2' })
    const r0 = sanitizePacket(packetInput(pkt0), DIAGNOSTIC_POLICY, mapping, {
      coapBlock2: session,
      generationId: 't30-coap-block2',
      sourceId: 'test.pcap',
    })
    expect(r0.issues).toContain('coap-block2-pending')
    expect(r0.coverage.some((c) => c.status === 'requires-reassembly')).toBe(true)
    const r1 = sanitizePacket(
      { ...packetInput(pkt1), index: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { coapBlock2: session, generationId: 't30-coap-block2', sourceId: 'test.pcap' },
    )
    const discovery = [
      {
        packetIndex: 0,
        packetNumber: 1,
        intents: [],
        coverage: r0.coverage,
        issues: [...r0.issues],
        drop: false,
        frozenPlan: {} as import('../../../src/pcap/discovery/types.ts').PacketDiscoveryResult['frozenPlan'],
        resolvePatches: () => r0.patches,
      },
      {
        packetIndex: 1,
        packetNumber: 2,
        intents: [],
        coverage: r1.coverage,
        issues: [...r1.issues],
        drop: false,
        frozenPlan: {} as import('../../../src/pcap/discovery/types.ts').PacketDiscoveryResult['frozenPlan'],
        resolvePatches: () => r1.patches,
      },
    ]
    session.finalizeDiscovery(discovery)
    expect(discovery[0]!.issues).toContain('coap-block2-reassembled')
    expect(discovery[0]!.coverage.some((c) => c.status === 'requires-reassembly')).toBe(false)
  })
})
