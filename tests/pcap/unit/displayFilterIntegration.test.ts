/**
 * Display filter integration — protocols and fields against real session pipeline.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import {
  clearPcapSession,
  DEFAULT_PCAP_FILTER,
  filterPacketIndices,
  getPacketProtocols,
  getPcapSession,
} from '../../../src/pcap/ui/pcapSession'
import { parseDisplayFilter } from '../../../src/pcap/displayFilter'
import { createTestPcapSessionFromPackets } from './pcapSessionTestHelpers'
import {
  VOIP_SEED,
  buildEthIpUdp,
  buildRtpPayload,
  buildRtcpSdes,
  buildSipInviteWithSdp,
  envelope,
  voipCorpusScenarios,
} from '../fixtures/voipCorpus'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'

function makeBareIpv4Udp(src: number[], dst: number[], n: number): PacketEnvelope {
  const data = new Uint8Array(42)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 28
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(n) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function expectFilter(expr: string, expectedCount: number): void {
  const parsed = parseDisplayFilter(expr)
  expect(parsed.status, `parse ${expr}`).toBe('valid')
  expect(filterPacketIndices(DEFAULT_PCAP_FILTER, expr).length, `filter ${expr}`).toBe(expectedCount)
}

describe('displayFilter integration (session pipeline)', () => {
  beforeEach(() => {
    clearPcapSession()
  })

  it('matches sanitizer-only protocols on VoIP UDP call flow', async () => {
    const src = VOIP_SEED.ip.split('.').map((p) => Number.parseInt(p, 10))
    const dst = [10, 0, 0, 2]
    const packets = [
      envelope(buildEthIpUdp(src, dst, 5060, 5060, buildSipInviteWithSdp()), 0),
      envelope(buildEthIpUdp(src, dst, VOIP_SEED.mediaPort, 40000, buildRtpPayload()), 1),
      envelope(buildEthIpUdp(src, dst, VOIP_SEED.mediaPort + 1, 40001, buildRtcpSdes()), 2),
      makeBareIpv4Udp([192, 168, 1, 1], [192, 168, 1, 2], 3),
    ]
    await createTestPcapSessionFromPackets({ fileName: 'voip-mix.pcap', packets })

    expect(getPacketProtocols(0)).toContain('sip')
    expect(getPacketProtocols(1)).toContain('rtp')
    expect(getPacketProtocols(2)).toContain('rtcp')
    expect(getPacketProtocols(3)).not.toContain('sip')

    expectFilter('sip', 1)
    expectFilter('rtp', 1)
    expectFilter('rtcp', 1)
    expectFilter('udp', 4)
    expectFilter('ipv4', 4)
    expectFilter('sip or rtp or rtcp', 3)
    expectFilter('udp and not sip', 3)
  })

  it('matches TCP SIP segments and reassembled invite', async () => {
    const scenario = voipCorpusScenarios().find((s) => s.id === 'tcp-segmented-invite')!
    await createTestPcapSessionFromPackets({
      fileName: 'tcp-sip.pcap',
      packets: [...scenario.packets],
    })

    const sipIndices = filterPacketIndices(DEFAULT_PCAP_FILTER, 'sip')
    expect(sipIndices.length).toBeGreaterThan(0)
    for (const i of sipIndices) {
      expect(getPacketProtocols(i)).toContain('sip')
    }
    expectFilter('tcp', 2)
    expectFilter('tcp and sip', sipIndices.length)
  })

  it('matches TLS on SIP port and malformed SIP issue packets', async () => {
    const tlsScenario = voipCorpusScenarios().find((s) => s.id === 'sip-tls-port-hint')!
    await createTestPcapSessionFromPackets({
      fileName: 'sip-tls.pcap',
      packets: [...tlsScenario.packets],
    })
    // CF-10: TLS shape on 5061 uses unified TLS path (not sip-tls/encrypted shortcut)
    const protocols = getPacketProtocols(0)
    expect(protocols.some((p) => p === 'tls' || p.startsWith('tls-'))).toBe(true)
    expect(protocols).not.toContain('sip-tls')
    const parsedTls = parseDisplayFilter('tls')
    expect(parsedTls.status).toBe('valid')

    clearPcapSession()
    const malformedScenario = voipCorpusScenarios().find((s) => s.id === 'malformed-content-length')!
    await createTestPcapSessionFromPackets({
      fileName: 'malformed.pcap',
      packets: [...malformedScenario.packets],
    })
    expectFilter('sip', 1)
    expectFilter('frame.issue == true', 1)
    expectFilter('sip and frame.issue == true', 1)
  })

  it('filters IP, port, MAC, frame, and protocol field comparisons', async () => {
    const src = VOIP_SEED.ip.split('.').map((p) => Number.parseInt(p, 10))
    const dst = [10, 0, 0, 2]
    const packets = [
      envelope(buildEthIpUdp(src, dst, 5060, 5060, buildSipInviteWithSdp()), 0),
      makeBareIpv4Udp([192, 168, 1, 10], [10, 0, 0, 1], 1),
    ]
    await createTestPcapSessionFromPackets({ fileName: 'fields.pcap', packets })
    const nums = getPcapSession()!.descriptors.map((d) => d.packetNumber)
    const sipNum = nums[0]!
    const otherNum = nums[1]!

    expectFilter(`ip.src == ${VOIP_SEED.ip}`, 1)
    expectFilter('ip.dst == 10.0.0.2', 1)
    expectFilter(`ip.addr == ${VOIP_SEED.ip}`, 1)
    expectFilter('udp.port == 5060', 1)
    expectFilter('udp.port == 40000', 0)
    expectFilter(`frame.number == ${sipNum}`, 1)
    expectFilter(`frame.number >= ${otherNum}`, 1)
    expectFilter('frame.len > 100', 1)
    expectFilter('frame.changed == true', 2)
    expectFilter('protocol contains sip', 1)
    expectFilter('eth.addr == aa:bb:cc:dd:ee:ff', 2)
  })

  it('filters every VoIP corpus scenario by its coverage protocols', async () => {
    for (const scenario of voipCorpusScenarios()) {
      clearPcapSession()
      const session = await createTestPcapSessionFromPackets({
        fileName: `${scenario.id}.pcap`,
        packets: [...scenario.packets],
      })

      const protocolToPackets = new Map<string, number[]>()
      for (let i = 0; i < session.descriptors.length; i++) {
        for (const p of getPacketProtocols(i)) {
          if (p === 'payload') continue
          const list = protocolToPackets.get(p) ?? []
          list.push(i)
          protocolToPackets.set(p, list)
        }
      }

      for (const [protocol, indices] of protocolToPackets) {
        const parsed = parseDisplayFilter(protocol)
        expect(parsed.status, `${scenario.id} parse ${protocol}`).toBe('valid')
        const matched = filterPacketIndices(DEFAULT_PCAP_FILTER, protocol)
        for (const idx of indices) {
          expect(matched, `${scenario.id} filter ${protocol} includes packet ${idx}`).toContain(idx)
        }
      }
    }
  })
})
