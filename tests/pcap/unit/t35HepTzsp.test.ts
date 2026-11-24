/**
 * T35 — HEP/EEP and TZSP capture encapsulations.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { createPayloadTimeSession } from '../../../src/pcap/kernel/payloadTimeCodec'

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

function hep3Chunk(type: number, value: Uint8Array, vendor = 0): Uint8Array {
  const len = 6 + value.length
  const out = new Uint8Array(len)
  out[0] = (vendor >> 8) & 0xff
  out[1] = vendor & 0xff
  out[2] = (type >> 8) & 0xff
  out[3] = type & 0xff
  out[4] = (len >> 8) & 0xff
  out[5] = len & 0xff
  out.set(value, 6)
  return out
}

function buildHep3(chunks: Uint8Array[]): Uint8Array {
  let bodyLen = 0
  for (const c of chunks) bodyLen += c.length
  const total = 6 + bodyLen
  const out = new Uint8Array(total)
  out[0] = 0x48 // H
  out[1] = 0x45 // E
  out[2] = 0x50 // P
  out[3] = 0x33 // 3
  out[4] = (total >> 8) & 0xff
  out[5] = total & 0xff
  let o = 6
  for (const c of chunks) {
    out.set(c, o)
    o += c.length
  }
  return out
}

describe('T35 registry', () => {
  it('registers HEP/TZSP handlers and catalog ports', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['hep', 'tzsp']))
    expect(familyForProtocol('hep').familyId).toBe('tunnels')
    expect(familyForProtocol('tzsp').familyId).toBe('tunnels')
    expect(SEMANTIC_SERVICE_PORTS.has(9060)).toBe(true)
    expect(SEMANTIC_SERVICE_PORTS.has(37008)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T35 HEP', () => {
  it('maps captured IPv4/port chunks and strips SIP canary via nested sanitizer', () => {
    const sip = new TextEncoder().encode(
      'INVITE sip:canary-user@10.9.8.7 SIP/2.0\r\n'
        + 'Via: SIP/2.0/UDP 10.9.8.7:5060;branch=z9hG4bK-canary\r\n'
        + 'From: <sip:canary-user@10.9.8.7>;tag=canarytag\r\n'
        + 'To: <sip:other@10.9.8.7>\r\n'
        + 'Call-ID: hep-call-canary-001\r\n'
        + 'CSeq: 1 INVITE\r\n'
        + 'Content-Length: 0\r\n'
        + '\r\n',
    )
    const payload = buildHep3([
      hep3Chunk(0x0001, new Uint8Array([2])), // IPv4 family
      hep3Chunk(0x0002, new Uint8Array([17])), // UDP
      hep3Chunk(0x0003, new Uint8Array([10, 9, 8, 7])), // src
      hep3Chunk(0x0004, new Uint8Array([10, 9, 8, 8])), // dst
      hep3Chunk(0x0007, new Uint8Array([0x13, 0xc4])), // 5060
      hep3Chunk(0x0008, new Uint8Array([0x13, 0xc4])),
      hep3Chunk(0x000b, new Uint8Array([1])), // SIP
      hep3Chunk(0x000c, new Uint8Array([0xde, 0xad, 0xbe, 0xef])), // capt id
      hep3Chunk(0x000e, new TextEncoder().encode('AUTH-KEY-CANARY')),
      hep3Chunk(0x0012, new TextEncoder().encode('corr-canary-xyz')),
      hep3Chunk(0x000f, sip),
    ])
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 9060, 9060, payload)
    const mapping = new SessionMapping(undefined, { seed: 't35-hep' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'hep')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('canary-user')).toBe(false)
    expect(text.includes('AUTH-KEY-CANARY')).toBe(false)
    expect(text.includes('corr-canary-xyz')).toBe(false)
    expect(text.includes('hep-call-canary-001')).toBe(false)
    expect(text.includes('10.9.8.7')).toBe(false)
  })

  it('keeps correlation opaque alias stable across packets with same id', () => {
    const corr = new TextEncoder().encode('same-corr-id')
    const payload = buildHep3([
      hep3Chunk(0x0001, new Uint8Array([2])),
      hep3Chunk(0x0002, new Uint8Array([17])),
      hep3Chunk(0x0012, corr),
      hep3Chunk(0x000f, new TextEncoder().encode('OPTIONS sip:x@y SIP/2.0\r\nContent-Length: 0\r\n\r\n')),
    ])
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 9060, 9060, payload)
    const mapping = new SessionMapping(undefined, { seed: 't35-corr' })
    const r1 = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out1 = applyPatches(frame, r1)
    const r2 = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out2 = applyPatches(frame, r2)
    // Correlation chunk value starts after HEP3(6) + ipfam(7) + ipproto(7) + corr hdr(6)
    const corrOff = 14 + 20 + 8 + 6 + 7 + 7 + 6
    expect([...out1.subarray(corrOff, corrOff + corr.length)]).toEqual(
      [...out2.subarray(corrOff, corrOff + corr.length)],
    )
    expect(new TextDecoder('latin1').decode(out1).includes('same-corr-id')).toBe(false)
  })

  it('shifts HEP timestamp when payloadTime is bound', () => {
    const sec = 1_700_000_000
    const payload = buildHep3([
      hep3Chunk(0x0009, new Uint8Array([
        (sec >>> 24) & 0xff,
        (sec >>> 16) & 0xff,
        (sec >>> 8) & 0xff,
        sec & 0xff,
      ])),
      hep3Chunk(0x000a, new Uint8Array([0, 0, 0, 1])),
      hep3Chunk(0x000b, new Uint8Array([0xff])), // unknown payload type
      hep3Chunk(0x000f, new Uint8Array([0xaa, 0xbb])),
    ])
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 9060, 9060, payload)
    const mapping = new SessionMapping(undefined, { seed: 't35-ts' })
    const payloadTime = createPayloadTimeSession('relative', 't35-ts')
    payloadTime.bindCaptureReference({
      ticks: BigInt(sec) * 1000n,
      unitsPerSecond: 1000n,
      offsetSeconds: 0n,
    })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping, {
      payloadTime,
    })
    const out = applyPatches(frame, result)
    // Structure: eth+ip+udp + HEP3(6) + TS_SEC chunk hdr(6) → sec value
    const secOff = 14 + 20 + 8 + 6 + 6
    const newSec =
      ((out[secOff]! << 24)
        | (out[secOff + 1]! << 16)
        | (out[secOff + 2]! << 8)
        | out[secOff + 3]!) >>> 0
    expect(newSec).not.toBe(sec)
  })
})

describe('T35 TZSP', () => {
  it('maps sensor MAC tag and inner Ethernet IPv4', () => {
    // Minimal IPv4 echo inside Ethernet (no UDP app)
    const eth = new Uint8Array(14 + 20)
    // dst/src MAC
    eth.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0)
    eth.set([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 6)
    eth[12] = 0x08
    eth[13] = 0x00
    eth[14] = 0x45 // IPv4 vhl
    eth[15] = 0x00
    eth[16] = 0
    eth[17] = 20 // total length
    eth[22] = 64 // ttl
    eth[23] = 1 // ICMP
    eth.set([10, 1, 2, 3], 26) // src
    eth.set([10, 1, 2, 4], 30) // dst

    // Avoid MAC fixed-point 01:02:03:04:05:06 under this seed
    const sensor = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    const tzsp = new Uint8Array(4 + 2 + 6 + 1 + eth.length)
    tzsp[0] = 1 // ver
    tzsp[1] = 0 // RX
    tzsp[2] = 0
    tzsp[3] = 1 // Ethernet
    tzsp[4] = 0x1f // sensor MAC tag
    tzsp[5] = 6
    tzsp.set(sensor, 6)
    tzsp[12] = 0x01 // END
    tzsp.set(eth, 13)

    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 37008, 37008, tzsp)
    const mapping = new SessionMapping(undefined, { seed: 't35-tzsp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'tzsp')).toBe(true)
    const out = applyPatches(frame, result)
    const udpOff = 14 + 20 + 8
    expect([...out.subarray(udpOff + 6, udpOff + 12)]).not.toEqual([...sensor])
    // Inner src IP 10.1.2.3 must change
    const innerIpOff = udpOff + 13 + 14 + 12
    expect([...out.subarray(innerIpOff, innerIpOff + 4)]).not.toEqual([10, 1, 2, 3])
  })

  it('masks unknown tag body without claiming covered', () => {
    const canary = new TextEncoder().encode('TZSP-TAG-CANARY!!')
    const tzsp = new Uint8Array(4 + 2 + canary.length + 1)
    tzsp[0] = 1
    tzsp[1] = 0
    tzsp[2] = 0
    tzsp[3] = 1
    tzsp[4] = 0xfe // unknown
    tzsp[5] = canary.length
    tzsp.set(canary, 6)
    tzsp[6 + canary.length] = 0x01 // END
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 37008, 37008, tzsp)
    const mapping = new SessionMapping(undefined, { seed: 't35-unk' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('TZSP-TAG-CANARY')).toBe(false)
  })
})
