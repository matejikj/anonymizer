/**
 * T50/T52 + R08 — discovery→plan→export regression (synthetic TCP captures).
 * EventList transport scope, SMPP account-scoped message_id, and secret canaries.
 */
import { describe, expect, it, beforeEach } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import { resetProtocolGraphStateRegistryForTests } from '../../../src/pcap/sanitize/protocolGraphState'

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: {
      ticks: BigInt(1_700_000_000_000_000 + index),
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

function writeU32(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 24) & 0xff
  buf[o + 1] = (v >>> 16) & 0xff
  buf[o + 2] = (v >>> 8) & 0xff
  buf[o + 3] = v & 0xff
}

function cOctet(s: string): Uint8Array {
  const out = new Uint8Array(s.length + 1)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  out[s.length] = 0
  return out
}

function wrapSmppPdu(commandId: number, status: number, seq: number, body: Uint8Array): Uint8Array {
  const len = 16 + body.length
  const out = new Uint8Array(len)
  writeU32(out, 0, len)
  writeU32(out, 4, commandId)
  writeU32(out, 8, status)
  writeU32(out, 12, seq)
  out.set(body, 16)
  return out
}

describe('T50 AMI export regression', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  const AMI_SECRET = 'EXPORT-AMI-SECRET-CANARY-001'

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`masks Login Secret via export pipeline (${level})`, () => {
      const ami = [
        'Action: Login',
        'Username: export-user',
        `Secret: ${AMI_SECRET}`,
        '',
      ].join('\r\n')
      const pkt = envelope(
        buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5038, 1, new TextEncoder().encode(ami)),
      )
      const exported = runExportPipeline([pkt], level, 't50-ami-export.pcap', `t50-ami-export-${level}`, {
        mappingSeed: `t50-ami-export-${level}`,
      })
      const wire = latin1(exported.built.packets[0]!.data)
      expect(wire.includes(AMI_SECRET)).toBe(false)
      assertCaptureHasNoPrivacyLeaks(exported.built.packets, [AMI_SECRET])
    })

    it(`EventList child events stay scoped to TCP transport (${level})`, () => {
      const startA = [
        'Action: Status',
        'ActionID: export-shared-act',
        'EventList: start',
        'ListItems: 1',
        '',
      ].join('\r\n')
      const strayB = [
        'Event: StatusComplete',
        'ActionID: export-shared-act',
        '',
      ].join('\r\n')
      const childA = [
        'Event: StatusComplete',
        'ActionID: export-shared-act',
        '',
      ].join('\r\n')
      const packets = [
        envelope(
          buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 5038, 1, new TextEncoder().encode(startA)),
          0,
        ),
        envelope(
          buildEthIpTcp([10, 0, 1, 1], [10, 0, 1, 2], 40_001, 5038, 2, new TextEncoder().encode(strayB)),
          1,
        ),
        envelope(
          buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 5038, 3, new TextEncoder().encode(childA)),
          2,
        ),
      ]
      const exported = runExportPipeline(
        packets,
        level,
        't50-eventlist-export.pcap',
        `t50-eventlist-export-${level}`,
        { mappingSeed: `t50-el-export-${level}` },
      )
      const discoveryIssues = exported.discovery.packetDiscovery.flatMap((p) => p.issues ?? [])
      expect(discoveryIssues.some((i) => i.includes('eventlist-items'))).toBe(true)
      expect(
        discoveryIssues.some((i) => i.includes('eventlist-child') || i.includes('eventlist-complete')),
      ).toBe(true)
      const pktB = exported.discovery.packetDiscovery[1]
      expect(pktB?.issues?.some((i) => i.includes('eventlist-child'))).toBe(false)
    })
  }
})

describe('T52 SMPP export regression', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  const SMPP_PASS = 'EXPORT-SMPP-PASS-CANARY-002'
  const SHARED_MID = 'export-shared-smsc-mid-001'

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`masks bind password via export pipeline (${level})`, () => {
      const bindBody = new Uint8Array([
        ...cOctet('export-smpp-user'),
        ...cOctet(SMPP_PASS),
        ...cOctet(''),
        0x34,
        0x00,
        0x00,
        ...cOctet(''),
      ])
      const pdu = wrapSmppPdu(0x00000002, 0, 1, bindBody)
      const pkt = envelope(
        buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 2775, 1, pdu),
      )
      const exported = runExportPipeline([pkt], level, 't52-bind-export.pcap', `t52-bind-export-${level}`, {
        mappingSeed: `t52-bind-export-${level}`,
      })
      expect(latin1(exported.built.packets[0]!.data).includes(SMPP_PASS)).toBe(false)
      assertCaptureHasNoPrivacyLeaks(exported.built.packets, [SMPP_PASS])
    })

    it(`maps submit_sm_resp message_id per account scope (${level})`, () => {
      const bindA = wrapSmppPdu(
        0x00000002,
        0,
        1,
        new Uint8Array([
          ...cOctet('export-accountA'),
          ...cOctet('secret-a'),
          ...cOctet(''),
          0x34,
          0x00,
          0x00,
          ...cOctet(''),
        ]),
      )
      const bindB = wrapSmppPdu(
        0x00000002,
        0,
        1,
        new Uint8Array([
          ...cOctet('export-accountB'),
          ...cOctet('secret-b'),
          ...cOctet(''),
          0x34,
          0x00,
          0x00,
          ...cOctet(''),
        ]),
      )
      const respA = wrapSmppPdu(0x80000004, 0, 2, cOctet(SHARED_MID))
      const respB = wrapSmppPdu(0x80000004, 0, 2, cOctet(SHARED_MID))
      const packets = [
        envelope(buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 2775, 1, bindA), 0),
        envelope(buildEthIpTcp([192, 0, 2, 3], [192, 0, 2, 4], 40_001, 2775, 2, bindB), 1),
        envelope(
          buildEthIpTcp([192, 0, 2, 2], [192, 0, 2, 1], 2775, 40_000, 3, respA),
          2,
        ),
        envelope(
          buildEthIpTcp([192, 0, 2, 4], [192, 0, 2, 3], 2775, 40_001, 4, respB),
          3,
        ),
      ]
      const exported = runExportPipeline(
        packets,
        level,
        't52-scope-export.pcap',
        `t52-scope-export-${level}`,
        { mappingSeed: `t52-scope-export-${level}` },
      )
      const outA = latin1(exported.built.packets[2]!.data)
      const outB = latin1(exported.built.packets[3]!.data)
      expect(outA.includes(SHARED_MID)).toBe(false)
      expect(outB.includes(SHARED_MID)).toBe(false)
      const midA = outA.slice(-SHARED_MID.length - 1, -1)
      const midB = outB.slice(-SHARED_MID.length - 1, -1)
      expect(midA).not.toBe(midB)
    })
  }
})
