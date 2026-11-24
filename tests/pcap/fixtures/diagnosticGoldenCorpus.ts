/**
 * Synthetic golden corpus for diagnostic equivalence (step 10).
 * Covers Ethernet/VLAN/ARP, IPv4/IPv6, ICMP, DNS, DHCP, TCP, UDP, TLS,
 * SIP/SDP, RTP/RTCP, fragmentation, tunnels, classic PCAP + PCAPNG wrappers.
 */

import {
  CaptureFormat,
  Endian,
  TimestampResolution,
  type PacketEnvelope,
  type ClassicPcapHeader,
  type PcapngSectionInfo,
  type PcapngInterfaceInfo,
} from '../../../src/pcap/domain/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { writePcapng } from '../../../src/pcap/capture/pcapngWriter'
import {
  buildEthIpTcp,
  buildEthIpUdp,
  buildRtpPayload,
  buildRtcpSdes,
  buildSipInviteWithSdp,
  envelope,
  VOIP_SEED,
  VOIP_SEED_TOKENS,
} from './voipCorpus'
import { DIAGNOSTIC_SEED, DIAGNOSTIC_SEED_TOKENS } from './diagnosticIncidents'
import { diagnosticIncidents } from './diagnosticIncidents'

function ipParts(ip: string): number[] {
  return ip.split('.').map((p) => Number.parseInt(p, 10))
}

function buildVlanEthIpUdp(
  vlanId: number,
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const inner = buildEthIpUdp(srcIp, dstIp, srcPort, dstPort, payload)
  const out = new Uint8Array(inner.length + 4)
  out.set(inner.subarray(0, 12), 0)
  out[12] = 0x81
  out[13] = 0x00
  out[14] = (vlanId >> 8) & 0x0f
  out[15] = vlanId & 0xff
  out.set(inner.subarray(12), 16)
  return out
}

function buildArpRequest(sha: number[], spa: number[], tpa: number[]): Uint8Array {
  const buf = new Uint8Array(42)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set(sha, 6)
  buf[12] = 0x08
  buf[13] = 0x06
  buf[14] = 0
  buf[15] = 1
  buf[16] = 0x08
  buf[17] = 0
  buf[18] = 6
  buf[19] = 4
  buf[20] = 0
  buf[21] = 1
  buf.set(sha, 22)
  buf.set(spa, 28)
  buf.set(tpa, 38)
  return buf
}

function buildIcmpEcho(srcIp: number[], dstIp: number[]): Uint8Array {
  const buf = new Uint8Array(14 + 20 + 8)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  buf[16] = 0
  buf[17] = 28
  buf[23] = 1
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  buf[34] = 8 // echo request
  buf[35] = 0
  return buf
}

function buildIpv6Udp(payload: Uint8Array): Uint8Array {
  const buf = new Uint8Array(14 + 40 + 8 + payload.length)
  buf.set([0x33, 0x33, 0, 0, 0, 1], 0)
  buf.set([0, 0x11, 0x22, 0x33, 0x44, 0x55], 6)
  buf[12] = 0x86
  buf[13] = 0xdd
  buf[14] = 0x60
  const plen = 8 + payload.length
  buf[18] = (plen >> 8) & 0xff
  buf[19] = plen & 0xff
  buf[20] = 17
  buf[21] = 64
  buf[22] = 0xfe
  buf[23] = 0x80
  buf[37] = 1
  buf[38] = 0xff
  buf[39] = 0x02
  buf[53] = 1
  const udp = 54
  buf[udp] = 0xc0
  buf[udp + 1] = 0x00
  buf[udp + 2] = 0
  buf[udp + 3] = 53
  const udpLen = 8 + payload.length
  buf[udp + 4] = (udpLen >> 8) & 0xff
  buf[udp + 5] = udpLen & 0xff
  buf.set(payload, udp + 8)
  return buf
}

function buildDnsQuery(name: string): Uint8Array {
  const labels = name.split('.')
  let qnameLen = 1
  for (const l of labels) qnameLen += 1 + l.length
  const dns = new Uint8Array(12 + qnameLen + 4)
  dns[0] = 0x12
  dns[1] = 0x34
  dns[2] = 0x01
  dns[5] = 1
  let pos = 12
  for (const label of labels) {
    dns[pos++] = label.length
    for (let i = 0; i < label.length; i++) dns[pos++] = label.charCodeAt(i)
  }
  dns[pos++] = 0
  dns[pos + 1] = 1
  dns[pos + 3] = 1
  return dns
}

function buildGreUdp(inner: Uint8Array): Uint8Array {
  const src = ipParts(DIAGNOSTIC_SEED.ipClient)
  const dst = ipParts(DIAGNOSTIC_SEED.ipServer)
  const greLen = 4
  const total = 14 + 20 + greLen + inner.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotal = 20 + greLen + inner.length
  buf[16] = (ipTotal >> 8) & 0xff
  buf[17] = ipTotal & 0xff
  buf[23] = 47
  buf.set(src, 26)
  buf.set(dst, 30)
  buf[36] = 0x08
  buf[37] = 0x00
  buf.set(inner, 38)
  return buf
}

export interface DiagnosticGoldenScenario {
  readonly id: string
  readonly packets: readonly PacketEnvelope[]
  readonly seeds: readonly string[]
  readonly formats: readonly ('pcap' | 'pcapng')[]
}

export function diagnosticGoldenScenarios(): readonly DiagnosticGoldenScenario[] {
  const src = ipParts(DIAGNOSTIC_SEED.ipClient)
  const dst = ipParts(DIAGNOSTIC_SEED.ipServer)
  const voipSrc = ipParts(VOIP_SEED.ip)
  const voipDst = [10, 0, 0, 2]

  const matrix: PacketEnvelope[] = [
    envelope(buildVlanEthIpUdp(111, src, dst, 53000, 53, buildDnsQuery(DIAGNOSTIC_SEED.hostname)), 0),
    envelope(buildArpRequest([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11], src, dst), 1),
    envelope(buildIcmpEcho(src, dst), 2),
    envelope(buildIpv6Udp(buildDnsQuery('ipv6.' + DIAGNOSTIC_SEED.hostname)), 3),
    envelope(buildEthIpTcp(src, dst, 40000, 443, 1, new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x01, 0x01])), 4),
    envelope(buildEthIpUdp(voipSrc, voipDst, 5060, 5060, buildSipInviteWithSdp({ withIce: true })), 5),
    envelope(buildEthIpUdp(voipSrc, voipDst, VOIP_SEED.mediaPort, 40000, buildRtpPayload(0)), 6),
    envelope(buildEthIpUdp(voipSrc, voipDst, VOIP_SEED.mediaPort + 1, 40001, buildRtcpSdes()), 7),
    envelope(buildGreUdp(buildEthIpUdp(src, dst, 5060, 5060, buildSipInviteWithSdp()).subarray(14)), 8),
  ]

  const incidents = diagnosticIncidents().map((inc) => ({
    id: `incident-${inc.id}`,
    packets: inc.packets,
    seeds: inc.seeds,
    formats: ['pcap'] as const,
  }))

  return [
    {
      id: 'protocol-matrix',
      packets: matrix,
      seeds: [...DIAGNOSTIC_SEED_TOKENS, ...VOIP_SEED_TOKENS],
      formats: ['pcap', 'pcapng'],
    },
    ...incidents,
  ]
}

export function wrapPacketsAsClassicPcap(packets: readonly PacketEnvelope[]): ArrayBuffer {
  const header: ClassicPcapHeader = {
    format: CaptureFormat.ClassicPcap,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  }
  return writeClassicPcap({ header, packets: [...packets] })
}

export function wrapPacketsAsPcapng(packets: readonly PacketEnvelope[]): ArrayBuffer {
  const section: PcapngSectionInfo = {
    sectionIndex: 0,
    endian: Endian.Little,
    versionMajor: 1,
    versionMinor: 0,
    sectionLength: -1n,
  }
  const iface: PcapngInterfaceInfo = {
    interfaceId: 0,
    sectionIndex: 0,
    linkType: 1,
    snapLen: 65535,
    tsResol: TimestampResolution.Microseconds,
    tsResolValue: 6,
    tsOffset: 0n,
  }
  return writePcapng({
    sections: [section],
    interfaces: [iface],
    packets: packets.map((p, i) => ({ ...p, packetNumber: i, interfaceId: 0, sectionIndex: 0 })),
  })
}
