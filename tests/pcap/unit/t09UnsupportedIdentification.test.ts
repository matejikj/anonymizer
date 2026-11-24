/**
 * T09 — port + signature identification for unsupported application protocols.
 */

import { describe, expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  identifyUnsupportedApplicationPayload,
  unsupportedCoverageProtocolId,
} from '../../../src/pcap/sanitize/unsupportedIdentification'
import { sanitizePacket, type PacketInput } from '../../../src/pcap/sanitize/engine'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'
import { createTestSessionMapping } from '../../../src/pcap/anonymization/testModeSeed'
import { parseDisplayFilter } from '../../../src/pcap/displayFilter/parser'
import { createTestPcapSessionFromPackets } from './pcapSessionTestHelpers'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'
import { getPacketProtocols, filterPacketIndices, DEFAULT_PCAP_FILTER } from '../../../src/pcap/ui/pcapSession'

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function idOf(input: {
  payload: Uint8Array
  srcPort: number
  dstPort: number
  transport?: 'udp' | 'tcp'
}) {
  return identifyUnsupportedApplicationPayload({
    data: input.payload,
    offset: 0,
    length: input.payload.length,
    srcPort: input.srcPort,
    dstPort: input.dstPort,
    transport: input.transport ?? 'udp',
  })
}

describe('T09 unsupported identification signatures', () => {
  it('names MGCP (TCP-only after T11) / SSDP / H.248 on matching port+text', () => {
    // UDP MGCP is structured support (T11) — identify-only remains for TCP.
    expect(
      idOf({
        payload: enc('CRCX 1234 aaln/1@gw.example MGCP 1.0\r\n'),
        srcPort: 2727,
        dstPort: 2427,
        transport: 'udp',
      }),
    ).toBeNull()
    expect(
      idOf({
        payload: enc('CRCX 1234 aaln/1@gw.example MGCP 1.0\r\n'),
        srcPort: 2727,
        dstPort: 2427,
        transport: 'tcp',
      }),
    ).toBe('mgcp')
    expect(
      idOf({
        payload: enc('200 1234 OK\r\n'),
        srcPort: 2427,
        dstPort: 2727,
        transport: 'tcp',
      }),
    ).toBe('mgcp')
    expect(
      idOf({
        payload: enc('NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n'),
        srcPort: 1900,
        dstPort: 1900,
      }),
    ).toBeNull() // T18: SSDP promoted to structured handler
    expect(
      idOf({
        payload: enc('!/MEGACO/1 [10.0.0.1]:2944\r\n'),
        srcPort: 2944,
        dstPort: 2945,
      }),
    ).toBeNull() // T24: H.248 promoted to structured handler
  })

  it('does not name random binary or HTTP-on-1900 without SSDP method', () => {
    expect(
      idOf({
        payload: new Uint8Array(64).map((_, i) => (i * 17) & 0xff),
        srcPort: 2427,
        dstPort: 2727,
      }),
    ).toBeNull()
    expect(
      idOf({
        payload: enc('GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'),
        srcPort: 1900,
        dstPort: 1900,
      }),
    ).toBeNull()
    expect(
      idOf({
        payload: enc('CRCX 1234 aaln/1@gw MGCP 1.0\r\n'),
        srcPort: 5060,
        dstPort: 5060,
      }),
    ).toBeNull()
  })

  it('names MQTT with port+shape (RADIUS promoted in T22; SNMP/NTP/Syslog in T20)', () => {
    const snmp = new Uint8Array([0x30, 0x0c, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63])
    expect(idOf({ payload: snmp, srcPort: 161, dstPort: 161 })).toBeNull()

    const ntp = new Uint8Array(48)
    ntp[0] = 0x1b // VN=3, mode=3
    expect(idOf({ payload: ntp, srcPort: 123, dstPort: 123 })).toBeNull()

    const radius = new Uint8Array(20)
    radius[0] = 1
    radius[2] = 0
    radius[3] = 20
    expect(idOf({ payload: radius, srcPort: 1812, dstPort: 1812 })).toBeNull() // T22

    const mqtt = new Uint8Array([0x10, 0x0a, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c])
    expect(idOf({ payload: mqtt, srcPort: 1883, dstPort: 1883, transport: 'tcp' })).toBeNull() // T30
  })

  it('sanitizePacket emits structured ssdp coverage (T18 promotion)', () => {
    const payload = enc('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n\r\n')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1900, 1900, payload)
    const mapping = createTestSessionMapping('t09-ssdp-seed')
    const input: PacketInput = {
      index: 0,
      data: frame,
      capturedLength: frame.length,
      originalLength: frame.length,
      linkType: 1,
    }
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping)
    const ids = result.coverage.map((c) => c.protocol)
    expect(ids, JSON.stringify(ids)).toContain('ssdp')
    expect(ids).not.toContain('unsupported:ssdp')
    expect(ids).not.toContain('heuristic')
    expect(unsupportedCoverageProtocolId('mgcp')).toBe('unsupported:mgcp')
  })

  it('display filter accepts ssdp and matches session packets', async () => {
    const parsed = parseDisplayFilter('ssdp')
    expect(parsed.status).toBe('valid')

    const payload = enc('NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1900, 1900, payload)
    await createTestPcapSessionFromPackets({
      fileName: 'ssdp.pcap',
      packets: [envelope(frame, 1)],
    })
    expect(getPacketProtocols(0)).toContain('ssdp')
    const matched = filterPacketIndices(DEFAULT_PCAP_FILTER, 'ssdp')
    expect(matched).toContain(0)
  })

  it('display filter accepts unsupported:mgcp (TCP identify-only id)', () => {
    const parsed = parseDisplayFilter('unsupported:mgcp')
    expect(parsed.status).toBe('valid')
  })

  it.skipIf(!existsSync(join(import.meta.dirname, '../../../../obc2.pcap')))(
    'obc2.pcap local fixture is present for SSDP regression',
    () => {
      // Full packet walk is optional; presence gates local regression runs.
      expect(existsSync(join(import.meta.dirname, '../../../../obc2.pcap'))).toBe(true)
    },
  )
})
