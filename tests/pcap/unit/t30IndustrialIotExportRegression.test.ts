/**
 * T30 — processCapture → plan → export synthetic regression (MQTT/Modbus/DNP3 canaries).
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { runProcessCaptureExportPipeline } from '../helpers/processCaptureExportPipeline'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { dnp3Crc16 } from '../../../src/pcap/sanitize/industrial/dnp3'

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: {
      ticks: 1_700_000_000_000_000n + BigInt(index),
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

function writeU16be(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 8) & 0xff
  buf[o + 1] = v & 0xff
}

function mqtt5ConnectWithUserProperty(): Uint8Array {
  const proto = new TextEncoder().encode('MQTT')
  const clientId = new TextEncoder().encode('cid-export')
  const userPropKey = new TextEncoder().encode('site-id')
  const userPropVal = new TextEncoder().encode('T30-MQTT-USER-SECRET')
  // Property: User Property (38) = UTF-8 string pair
  const propBody = new Uint8Array(1 + 2 + 2 + userPropKey.length + 2 + userPropVal.length)
  let q = 0
  propBody[q++] = 38
  writeU16be(propBody, q, userPropKey.length)
  q += 2
  propBody.set(userPropKey, q)
  q += userPropKey.length
  writeU16be(propBody, q, userPropVal.length)
  q += 2
  propBody.set(userPropVal, q)

  const flags = 0x02 // clean session only
  const variable = new Uint8Array(
    2 + proto.length + 1 + 1 + 2 + 1 + propBody.length + 2 + clientId.length,
  )
  let p = 0
  writeU16be(variable, p, proto.length)
  p += 2
  variable.set(proto, p)
  p += proto.length
  variable[p++] = 5 // MQTT 5
  variable[p++] = flags
  writeU16be(variable, p, 60)
  p += 2
  variable[p++] = propBody.length
  variable.set(propBody, p)
  p += propBody.length
  writeU16be(variable, p, clientId.length)
  p += 2
  variable.set(clientId, p)
  p += clientId.length

  const connect = new Uint8Array(2 + variable.length)
  connect[0] = 0x10
  connect[1] = variable.length
  connect.set(variable, 2)
  return connect
}

describe('T30 industrial IoT export (processCapture)', () => {
  it('export masks MQTT 5 User Property secret (T30.export)', async () => {
    const frame = buildEthIpTcp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      1883,
      1,
      mqtt5ConnectWithUserProperty(),
    )
    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't30-mqtt-export.pcap',
      't30-mqtt-export',
      { mappingSeed: 't30-mqtt-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'mqtt-auth')).toBe(
      true,
    )
    const wire = built.packets[0]!.data
    expect(latin1(wire).includes('T30-MQTT-USER-SECRET')).toBe(false)
    assertCaptureHasNoPrivacyLeaks(wire.buffer, ['T30-MQTT-USER-SECRET'])
  })

  it('export masks Modbus FC06 write value (T30.export)', async () => {
    const payload = new Uint8Array([0, 1, 0, 0, 0, 6, 1, 6, 0, 16, 0x51, 0x56])
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 502, 1, payload)
    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'high-privacy',
      't30-modbus-export.pcap',
      't30-modbus-export',
      { mappingSeed: 't30-modbus-export' },
    )
    expect(built.validationValid).toBe(true)
    const wire = built.packets[0]!.data
    expect(latin1(wire).includes('QV')).toBe(false)
  })

  function buildCoapBlock2Pdu(blockByte: number, payload: Uint8Array, mid: number): Uint8Array {
    const opt = new Uint8Array(3)
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

  it('export masks CoAP Block2 split payload across datagrams (T30.coap.block export)', async () => {
    const secretA = new TextEncoder().encode('T30-COAP-BLK-A')
    const secretB = new TextEncoder().encode('T30-COAP-BLK-B')
    const frame0 = buildEthIpUdp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      5683,
      buildCoapBlock2Pdu(0x08, secretA, 20),
    )
    const frame1 = buildEthIpUdp(
      [192, 0, 2, 1],
      [192, 0, 2, 2],
      40_000,
      5683,
      buildCoapBlock2Pdu(0x10, secretB, 21),
    )
    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame0), envelope(frame1, 1)],
      'diagnostic',
      't30-coap-block2-export.pcap',
      't30-coap-block2-export',
      { mappingSeed: 't30-coap-block2-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery.some((pd) => pd.issues.includes('coap-block2-reassembled'))).toBe(
      true,
    )
    for (const pkt of built.packets) {
      const wire = latin1(pkt.data)
      expect(wire.includes('T30-COAP-BLK-A')).toBe(false)
      expect(wire.includes('T30-COAP-BLK-B')).toBe(false)
    }
    assertCaptureHasNoPrivacyLeaks(
      built.packets[0]!.data.buffer,
      ['T30-COAP-BLK-A', 'T30-COAP-BLK-B'],
    )
  })

  it('export walks DNP3 G30V1 object dictionary (T30.dnp3.dict export)', async () => {
    const app = new Uint8Array([
      0xc0, 0xc0, 0x81, 0x1e, 0x01, 0x03, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01,
    ])
    const userLen = app.length + 2
    const frameBody = new Uint8Array(10 + userLen)
    frameBody[0] = 0x05
    frameBody[1] = 0x64
    frameBody[2] = 5 + userLen
    frameBody[3] = 0xc4
    frameBody[4] = 0x34
    frameBody[5] = 0x12
    frameBody[6] = 0x78
    frameBody[7] = 0x56
    const hdrCrc = dnp3Crc16(frameBody.subarray(0, 8))
    frameBody[8] = hdrCrc & 0xff
    frameBody[9] = (hdrCrc >>> 8) & 0xff
    frameBody.set(app, 10)
    const blockCrc = dnp3Crc16(app)
    frameBody[10 + app.length] = blockCrc & 0xff
    frameBody[10 + app.length + 1] = (blockCrc >>> 8) & 0xff
    const frame = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 20_000, 1, frameBody)
    const { built, session } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't30-dnp3-dict-export.pcap',
      't30-dnp3-dict-export',
      { mappingSeed: 't30-dnp3-dict-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(session.discovery.packetDiscovery[0]?.issues).toContain('dnp3-object-dictionary-walk')
    const wire = latin1(built.packets[0]!.data)
    expect(wire.includes('\xde\xad\xbe\xef')).toBe(false)
  })

  it('export remaps DNP3 link addresses with valid header CRC (T30.export)', async () => {
    const frameBody = new Uint8Array(10)
    frameBody[0] = 0x05
    frameBody[1] = 0x64
    frameBody[2] = 5
    frameBody[3] = 0xc4
    frameBody[4] = 0x34
    frameBody[5] = 0x12
    frameBody[6] = 0x78
    frameBody[7] = 0x56
    const crc = dnp3Crc16(frameBody.subarray(0, 8))
    frameBody[8] = crc & 0xff
    frameBody[9] = (crc >>> 8) & 0xff
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 20_000, frameBody)
    const { built } = await runProcessCaptureExportPipeline(
      [envelope(frame)],
      'diagnostic',
      't30-dnp3-export.pcap',
      't30-dnp3-export',
      { mappingSeed: 't30-dnp3-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(built.packets[0]!.data.length).toBe(frame.length)
  })
})
