/**
 * T34/T35/T36 — processCapture → plan → export synthetic regression (canaries + nested wire).
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { runProcessCaptureExportPipeline } from '../helpers/processCaptureExportPipeline'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { webSocketAcceptFromKey } from '../../../src/crypto/sha1'

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function envelope(data: Uint8Array, index = 0, linkType = 1): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: {
      ticks: 1_700_000_000_000_000n + BigInt(index),
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    },
    capturedLength: data.length,
    originalLength: data.length,
    linkType,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
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
  out[0] = 0x48
  out[1] = 0x45
  out[2] = 0x50
  out[3] = 0x33
  out[4] = (total >> 8) & 0xff
  out[5] = total & 0xff
  let o = 6
  for (const c of chunks) {
    out.set(c, o)
    o += c.length
  }
  return out
}

function wsClientTextFrame(text: string, maskKey: number[] = [0x11, 0x22, 0x33, 0x44]): Uint8Array {
  const payload = new TextEncoder().encode(text)
  const masked = new Uint8Array(payload.length)
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i]! ^ maskKey[i & 3]!
  const hdr = new Uint8Array(2 + 4 + masked.length)
  hdr[0] = 0x81
  hdr[1] = 0x80 | payload.length
  hdr.set(maskKey, 2)
  hdr.set(masked, 6)
  return hdr
}

describe('T34 link encapsulation export (processCapture)', () => {
  it('export masks L2TP Challenge AVP canary (T34.export)', async () => {
    const challenge = new TextEncoder().encode('T34-L2TP-CHAL-EXPORT')
    const avpLen = 6 + challenge.length
    const hdr = new Uint8Array(2 + 2 + 4 + avpLen)
    hdr[0] = 0xc0
    hdr[1] = 0x02
    hdr[2] = 0
    hdr[3] = hdr.length
    hdr[4] = 0x12
    hdr[5] = 0x34
    hdr[6] = 0x56
    hdr[7] = 0x78
    hdr[8] = 0x80
    hdr[9] = avpLen & 0xff
    hdr[13] = 11
    hdr.set(challenge, 14)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1701, 1701, hdr)

    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't34-export-l2tp.pcap',
      't34-export-l2tp',
      { mappingSeed: 't34-export-l2tp' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'l2tp')).toBe(
      true,
    )
    const wire = built.packets[0]!.data
    expect(latin1(wire).includes('T34-L2TP-CHAL-EXPORT')).toBe(false)
    assertCaptureHasNoPrivacyLeaks(wire.buffer, ['T34-L2TP-CHAL-EXPORT'])
  })

  it('export remaps PPPoE session and nested IPv4 src (T34.export)', async () => {
    const innerSrc = [10, 44, 55, 66] as const
    const ip = new Uint8Array(20)
    ip[0] = 0x45
    ip[3] = 20
    ip[9] = 1
    ip.set(innerSrc, 12)
    ip.set([10, 4, 5, 6], 16)
    const ppp = new Uint8Array(2 + ip.length)
    ppp[0] = 0x00
    ppp[1] = 0x21
    ppp.set(ip, 2)
    const pppoe = new Uint8Array(6 + ppp.length)
    pppoe[0] = 0x11
    pppoe[2] = 0xab
    pppoe[3] = 0xcd
    pppoe[4] = 0
    pppoe[5] = ppp.length
    pppoe.set(ppp, 6)
    const frame = new Uint8Array(14 + pppoe.length)
    frame.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], 6)
    frame[12] = 0x88
    frame[13] = 0x64
    frame.set(pppoe, 14)

    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't34-export-pppoe.pcap',
      't34-export-pppoe',
      { mappingSeed: 't34-export-pppoe' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'pppoe')).toBe(
      true,
    )
    const out = built.packets[0]!.data
    expect(out[14 + 2]).not.toBe(0xab)
    const innerOff = 14 + 6 + 2 + 12
    expect([...out.subarray(innerOff, innerOff + 4)]).not.toEqual([...innerSrc])
    assertCaptureHasNoPrivacyLeaks(out.buffer, ['10.44.55.66'])
  })
})

describe('T35 HEP/TZSP export (processCapture)', () => {
  it('export strips HEP metadata and nested SIP canaries (T35.export)', async () => {
    const callId = 'hep-export-call-canary-001'
    const authKey = 'HEP-AUTH-KEY-EXPORT'
    const corr = 'hep-corr-export-xyz'
    const sip = new TextEncoder().encode(
      `INVITE sip:hep-export-user@10.9.8.7 SIP/2.0\r\n`
        + `Call-ID: ${callId}\r\n`
        + `Content-Length: 0\r\n\r\n`,
    )
    const payload = buildHep3([
      hep3Chunk(0x0001, new Uint8Array([2])),
      hep3Chunk(0x0002, new Uint8Array([17])),
      hep3Chunk(0x0003, new Uint8Array([10, 9, 8, 7])),
      hep3Chunk(0x0004, new Uint8Array([10, 9, 8, 8])),
      hep3Chunk(0x0007, new Uint8Array([0x13, 0xc4])),
      hep3Chunk(0x0008, new Uint8Array([0x13, 0xc4])),
      hep3Chunk(0x000b, new Uint8Array([1])),
      hep3Chunk(0x000e, new TextEncoder().encode(authKey)),
      hep3Chunk(0x0012, new TextEncoder().encode(corr)),
      hep3Chunk(0x000f, sip),
    ])
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 9060, 9060, payload)

    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't35-export-hep.pcap',
      't35-export-hep',
      { mappingSeed: 't35-export-hep' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'hep')).toBe(
      true,
    )
    const wire = latin1(built.packets[0]!.data)
    expect(wire.includes('hep-export-user')).toBe(false)
    expect(wire.includes(callId)).toBe(false)
    expect(wire.includes(authKey)).toBe(false)
    expect(wire.includes(corr)).toBe(false)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data.buffer, [
      'hep-export-user',
      callId,
      authKey,
      corr,
    ])
  })

  it('export maps TZSP sensor MAC and inner IPv4 (T35.export)', async () => {
    const sensor = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    const innerSrc = [10, 1, 2, 3] as const
    const eth = new Uint8Array(14 + 20)
    eth.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0)
    eth.set([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 6)
    eth[12] = 0x08
    eth[13] = 0x00
    eth[14] = 0x45
    eth[17] = 20
    eth[23] = 1
    eth.set(innerSrc, 26)
    eth.set([10, 1, 2, 4], 30)
    const tzsp = new Uint8Array(4 + 2 + 6 + 1 + eth.length)
    tzsp[0] = 1
    tzsp[3] = 1
    tzsp[4] = 0x1f
    tzsp[5] = 6
    tzsp.set(sensor, 6)
    tzsp[12] = 0x01
    tzsp.set(eth, 13)
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 37008, 37008, tzsp)

    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't35-export-tzsp.pcap',
      't35-export-tzsp',
      { mappingSeed: 't35-export-tzsp' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'tzsp')).toBe(
      true,
    )
    const out = built.packets[0]!.data
    const udpOff = 14 + 20 + 8
    expect([...out.subarray(udpOff + 6, udpOff + 12)]).not.toEqual([...sensor])
    const innerIpOff = udpOff + 13 + 14 + 12
    expect([...out.subarray(innerIpOff, innerIpOff + 4)]).not.toEqual([...innerSrc])
    assertCaptureHasNoPrivacyLeaks(out.buffer, ['10.1.2.3'])
  })
})

describe('T36 WebSocket / HTTP2 / gRPC export (processCapture)', () => {
  it('export unmasks WebSocket SIP canary on wire (T36.export)', async () => {
    const callId = 'ws-export-call-canary-001'
    const sip =
      `INVITE sip:ws-export-user@10.1.2.3 SIP/2.0\r\n`
      + `Call-ID: ${callId}\r\n`
      + `Content-Length: 0\r\n\r\n`
    const mask = [0xde, 0xad, 0xbe, 0xef]
    const frame = wsClientTextFrame(sip, mask)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_000, 8080, 1, frame)

    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(pkt)],
      'diagnostic',
      't36-export-ws.pcap',
      't36-export-ws',
      { mappingSeed: 't36-export-ws' },
    )
    expect(built.validationValid).toBe(true)
    expect(
      session.discovery.packetDiscovery[0]?.coverage.some(
        (c) => c.protocol === 'websocket' || c.protocol === 'sip',
      ),
    ).toBe(true)
    const out = built.packets[0]!.data
    expect(latin1(out).includes('ws-export-user')).toBe(false)
    expect(latin1(out).includes(callId)).toBe(false)
    assertCaptureHasNoPrivacyLeaks(out.buffer, ['ws-export-user', callId])
  })

  it('export maps Sec-WebSocket-Key and derived Accept (T36.export)', async () => {
    const key = 'dGhlIHNhbXBsZSBub25jZQ=='
    const accept = webSocketAcceptFromKey(key)
    const http =
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\n'
      + 'Connection: Upgrade\r\n'
      + `Sec-WebSocket-Key: ${key}\r\n`
      + `Sec-WebSocket-Accept: ${accept}\r\n`
      + '\r\n'
    const body = wsClientTextFrame('OPTIONS sip:x@y SIP/2.0\r\nContent-Length: 0\r\n\r\n')
    const payload = new Uint8Array(http.length + body.length)
    payload.set(new TextEncoder().encode(http), 0)
    payload.set(body, http.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_001, 8080, 1, payload)

    const { built } = await runProcessCaptureExportPipeline(
      [envelope(pkt)],
      'diagnostic',
      't36-export-ws-hs.pcap',
      't36-export-ws-hs',
      { mappingSeed: 't36-export-ws-hs' },
    )
    expect(built.validationValid).toBe(true)
    expect(latin1(built.packets[0]!.data).includes(key)).toBe(false)
  })

  it('export masks HTTP/2 HPACK block canary (T36.export)', async () => {
    const canary = 'CANARY-H2-EXPORT-BLOCK!!'
    const preface = new TextEncoder().encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    const settings = new Uint8Array([0, 0, 0, 0x04, 0, 0, 0, 0, 0])
    const block = new TextEncoder().encode(canary)
    const headers = new Uint8Array(9 + block.length)
    headers[2] = block.length & 0xff
    headers[3] = 0x01
    headers[4] = 0x05
    headers[8] = 1
    headers.set(block, 9)
    const payload = new Uint8Array(preface.length + settings.length + headers.length)
    payload.set(preface, 0)
    payload.set(settings, preface.length)
    payload.set(headers, preface.length + settings.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_002, 80, 1, payload)

    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(pkt)],
      'diagnostic',
      't36-export-h2.pcap',
      't36-export-h2',
      { mappingSeed: 't36-export-h2' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'http2')).toBe(
      true,
    )
    expect(latin1(built.packets[0]!.data).includes(canary)).toBe(false)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data.buffer, [canary])
  })

  it('export masks gRPC message body keeping length prefix (T36.export)', async () => {
    const canary = 'GRPC-EXPORT-CANARY-BODY'
    const preface = new TextEncoder().encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    const settings = new Uint8Array([0, 0, 0, 0x04, 0, 0, 0, 0, 0])
    const msg = new TextEncoder().encode(canary)
    const grpc = new Uint8Array(5 + msg.length)
    grpc[4] = msg.length & 0xff
    grpc.set(msg, 5)
    const data = new Uint8Array(9 + grpc.length)
    data[2] = grpc.length & 0xff
    data[3] = 0x00
    data[4] = 0x01
    data[8] = 1
    data.set(grpc, 9)
    const payload = new Uint8Array(preface.length + settings.length + data.length)
    payload.set(preface, 0)
    payload.set(settings, preface.length)
    payload.set(data, preface.length + settings.length)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 50_003, 80, 1, payload)

    const { built } = await runProcessCaptureExportPipeline(
      [envelope(pkt)],
      'diagnostic',
      't36-export-grpc.pcap',
      't36-export-grpc',
      { mappingSeed: 't36-export-grpc' },
    )
    expect(built.validationValid).toBe(true)
    expect(latin1(built.packets[0]!.data).includes(canary)).toBe(false)
    assertCaptureHasNoPrivacyLeaks(built.packets[0]!.data.buffer, [canary])
  })
})
