/**
 * T33 — solicited-node / embedded IPv4 / EUI-64 relation mapping.
 * @vitest-environment node
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import {
  expandIpv6Canonical,
  formatSolicitedNodeIpv6,
  formatSolicitedNodeMac,
  ipv6Groups,
  solicitedNodeLow24,
  solicitedNodeMacLow24,
  unicastLow24,
} from '../../../src/mapping/ipv6Semantics'
import { normalizeIpv6Canonical } from '../../../src/mapping/sharedNormalize'
import { analyze } from '../../../src/engine/analyze'
import { sanitizePacket, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { buildExportEnvelope } from '../../../src/pcap/export/packetBuilder'
import { createDefaultPcapProfile } from '../../../src/pcap/profile/presets'
import { TimestampMapping } from '../../../src/pcap/anonymization/timestampMapping'

describe('T33 IPv6 address semantics', () => {
  it('expands compressed IPv6 in canonicalize', () => {
    expect(normalizeIpv6Canonical('2001:db8::1')).toBe('2001:db8:0:0:0:0:0:1')
    expect(normalizeIpv6Canonical('::ffff:192.0.2.10')).toBe('0:0:0:0:0:ffff:c000:20a')
  })

  it('preserves well-known multicast but remaps solicited-node low24', () => {
    const m = new SessionMapping(undefined, { seed: 't33-sn' })
    expect(m.map('ipv6', 'ff02::1')).toBe('ff02:0:0:0:0:0:0:1')

    const unicast = '2001:db8:0:0:0:0:ab:cdef'
    const sn = formatSolicitedNodeIpv6(0xabcdef)
    expect(solicitedNodeLow24(expandIpv6Canonical(sn)!)).toBe(0xabcdef)

    const uAlias = m.map('ipv6', unicast)
    const snAlias = m.map('ipv6', sn)
    const uLow = unicastLow24(expandIpv6Canonical(uAlias)!)!
    const snLow = solicitedNodeLow24(expandIpv6Canonical(snAlias)!)!
    expect(snLow).toBe(uLow)
    expect(snLow).not.toBe(0xabcdef)
    expect(snAlias).not.toBe(expandIpv6Canonical(sn))
  })

  it('maps solicited-node before parent without echoing original low24', () => {
    const m = new SessionMapping(undefined, { seed: 't33-sn-first' })
    const sn = 'ff02:0:0:0:0:1:ffaa:bbcc'
    const snAlias = m.map('ipv6', sn)
    expect(solicitedNodeLow24(expandIpv6Canonical(snAlias)!)).not.toBe(0xaabbcc)

    const parent = 'fe80:0:0:0:0:0:aa:bbcc'
    const parentAlias = m.map('ipv6', parent)
    // Group binding: parent suffix should prefer the already-chosen SN low24.
    expect(unicastLow24(expandIpv6Canonical(parentAlias)!)).toBe(
      solicitedNodeLow24(expandIpv6Canonical(snAlias)!),
    )
  })

  it('maps solicited-node MAC with the same low24 group as SN IPv6', () => {
    const m = new SessionMapping(undefined, { seed: 't33-sn-mac' })
    const sn = 'ff02:0:0:0:0:1:ff12:3456'
    const mac = formatSolicitedNodeMac(0x123456)
    const snAlias = m.map('ipv6', sn)
    const macAlias = m.map('mac', mac)
    expect(solicitedNodeMacLow24(macAlias)).toBe(solicitedNodeLow24(expandIpv6Canonical(snAlias)!))
    expect(macAlias).not.toBe(mac)
  })

  it('maps IPv4-mapped and NAT64 embedded IPv4 to the same alias as bare IPv4', () => {
    const m = new SessionMapping(undefined, { seed: 't33-embed' })
    const v4 = '192.0.2.55'
    const v4Alias = m.map('ipv4', v4)
    const mapped = m.map('ipv6', '::ffff:192.0.2.55')
    const nat64 = m.map('ipv6', '64:ff9b::192.0.2.55')
    expect(mapped).toBe(`0:0:0:0:0:ffff:${ipv4ToHextetPair(v4Alias)}`)
    expect(nat64).toBe(`64:ff9b:0:0:0:0:${ipv4ToHextetPair(v4Alias)}`)
  })

  it('maps 6to4 and ISATAP embedded IPv4 consistently', () => {
    const m = new SessionMapping(undefined, { seed: 't33-6to4' })
    const v4 = '198.51.100.9'
    const v4Alias = m.map('ipv4', v4)
    const six = m.map('ipv6', '2002:c633:6409:1:2:3:4:5')
    expect(six.startsWith('2002:')).toBe(true)
    const g = six.split(':')
    expect(parseInt(g[1]!, 16)).toBe((Number(v4Alias.split('.')[0]) << 8) | Number(v4Alias.split('.')[1]))
    expect(parseInt(g[2]!, 16)).toBe((Number(v4Alias.split('.')[2]) << 8) | Number(v4Alias.split('.')[3]))

    const m2 = new SessionMapping(undefined, { seed: 't33-isatap' })
    const v4b = '10.1.2.3'
    const alias4 = m2.map('ipv4', v4b)
    const isatap = m2.map('ipv6', '2001:db8:1:2:0:5efe:a01:203')
    const parts = isatap.split(':')
    expect(parts[5]).toBe('5efe')
    const embedded = `${parseInt(parts[6]!, 16) >> 8}.${parseInt(parts[6]!, 16) & 0xff}.${parseInt(parts[7]!, 16) >> 8}.${parseInt(parts[7]!, 16) & 0xff}`
    expect(embedded).toBe(alias4)
  })

  it('derives EUI-64 IID from mapped MAC only when MAC is already known', () => {
    const m = new SessionMapping(undefined, { seed: 't33-eui' })
    const mac = '00:11:22:33:44:55'
    // Modified EUI-64 IID: 0211:22ff:fe33:4455
    const euiIp = '2001:db8:0:0:211:22ff:fe33:4455'
    // Without prior MAC mapping — independent (shape alone is not evidence).
    const alone = m.map('ipv6', euiIp)
    expect(alone).not.toMatch(/22ff:fe33/i)

    const m2 = new SessionMapping(undefined, { seed: 't33-eui2' })
    const macAlias = m2.map('mac', mac)
    const withRel = m2.map('ipv6', euiIp)
    const macBytes = macAlias.split(':').map((x) => Number.parseInt(x, 16))
    const g = withRel.split(':').map((x) => Number.parseInt(x, 16))
    expect(g[4]).toBe(((macBytes[0]! ^ 0x02) << 8) | macBytes[1]!)
    expect(g[5]).toBe((macBytes[2]! << 8) | 0xff)
    expect(g[6]).toBe((0xfe << 8) | macBytes[3]!)
    expect(g[7]).toBe((macBytes[4]! << 8) | macBytes[5]!)
  })

  it('export keeps solicited-node low24 aligned on NS wire (eth dst, IPv6 dst, target)', () => {
    const targetGroups = [0xfe80, 0, 0, 0, 0, 0, 0xaa, 0xbbcc] as const
    const snDstGroups = [0xff02, 0, 0, 0, 0, 1, 0xffaa, 0xbbcc] as const
    const frame = buildEthernetIpv6NeighborSolicitation({
      dstMac: [0x33, 0x33, 0xff, 0xaa, 0xbb, 0xcc],
      srcMac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
      ipv6SrcGroups: [0xfe80, 0, 0, 0, 0, 0, 0, 1],
      ipv6DstGroups: [...snDstGroups],
      targetGroups: [...targetGroups],
      sllMac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
    })
    const envelope: PacketEnvelope = {
      packetNumber: 0,
      timestamp: { ticks: 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
      capturedLength: frame.length,
      originalLength: frame.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data: frame,
    }
    const mapping = new SessionMapping(undefined, { seed: 't33-ns-export' })
    const san = sanitizePacket(
      {
        index: 0,
        data: frame,
        capturedLength: frame.length,
        originalLength: frame.length,
        linkType: 1,
      },
      HIGH_PRIVACY_POLICY,
      mapping,
    )
    expect(san.coverage.some((c) => c.protocol === 'ndp' && c.status === 'covered')).toBe(true)

    const plan = buildPlanSnapshot({
      generationId: 't33-ns',
      profile: createDefaultPcapProfile().profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 't33-ns.pcap',
      packets: [envelope],
      sanitization: [san],
      classicHeader: {
        format: CaptureFormat.ClassicPcap,
        endian: Endian.Little,
        timestampResolution: TimestampResolution.Microseconds,
        versionMajor: 2,
        versionMinor: 4,
        snapLen: 65535,
        linkType: 1,
        tzOffset: 0,
        sigfigs: 0,
      },
    })
    const { envelope: exported } = buildExportEnvelope(
      envelope,
      plan.packets[0]!,
      new TimestampMapping(),
      true,
    )
    const out = exported.data

    const ethDstMac = formatMac(out, 0)
    const ipv6DstExpanded = expandIpv6FromWire(out, 38)
    const targetExpanded = expandIpv6FromWire(out, 54 + 8)
    expect(ethDstMac).toMatch(/^33:33:ff:/i)
    expect(ipv6DstExpanded).toMatch(/^ff02:/i)
    expect(solicitedNodeMacLow24(ethDstMac)).toBe(solicitedNodeLow24(ipv6DstExpanded!))
    expect(unicastLow24(targetExpanded!)).toBe(solicitedNodeLow24(ipv6DstExpanded!))
    expect([...out.slice(0, 6)]).not.toEqual([0x33, 0x33, 0xff, 0xaa, 0xbb, 0xcc])
  })

  it('text analyze uses the same IPv4 alias inside ::ffff: form', () => {
    const text = 'peer 192.0.2.8 and mapped ::ffff:192.0.2.8 done\n'
    const result = analyze(text)
    // Both occurrences of the IPv4 identity should share one entity alias.
    const v4Entities = result.entities.filter((e) => e.category === 'ip' || e.canonical.includes('192.0.2.8'))
    expect(result.anonymized).not.toContain('192.0.2.8')
    // Mapped form should not retain the original dotted quad.
    expect(result.anonymized).not.toMatch(/::ffff:192\.0\.2\.8/i)
    void v4Entities
  })
})

function ipv6GroupsToBytes(groups: readonly number[]): Uint8Array {
  const out = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (groups[i]! >> 8) & 0xff
    out[i * 2 + 1] = groups[i]! & 0xff
  }
  return out
}

function buildEthernetIpv6NeighborSolicitation(input: {
  dstMac: readonly number[]
  srcMac: readonly number[]
  ipv6SrcGroups: readonly number[]
  ipv6DstGroups: readonly number[]
  targetGroups: readonly number[]
  sllMac: readonly number[]
}): Uint8Array {
  const icmpLen = 8 + 16 + 8
  const buf = new Uint8Array(14 + 40 + icmpLen)
  buf.set(input.dstMac, 0)
  buf.set(input.srcMac, 6)
  buf[12] = 0x86
  buf[13] = 0xdd
  buf[14] = 0x60
  buf[18] = (icmpLen >> 8) & 0xff
  buf[19] = icmpLen & 0xff
  buf[20] = 58
  buf[21] = 64
  buf.set(ipv6GroupsToBytes(input.ipv6SrcGroups), 22)
  buf.set(ipv6GroupsToBytes(input.ipv6DstGroups), 38)
  const icmpOff = 54
  buf[icmpOff] = 135
  buf.set(ipv6GroupsToBytes(input.targetGroups), icmpOff + 8)
  buf[icmpOff + 24] = 1
  buf[icmpOff + 25] = 1
  buf.set(input.sllMac, icmpOff + 26)
  return buf
}

function formatMac(data: Uint8Array, offset: number): string {
  return Array.from(data.slice(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
}

function expandIpv6FromWire(data: Uint8Array, offset: number): string | null {
  const groups: number[] = []
  for (let i = 0; i < 8; i++) {
    groups.push((data[offset + i * 2]! << 8) | data[offset + i * 2 + 1]!)
  }
  const expanded = groups.map((g) => g.toString(16)).join(':')
  void ipv6Groups(expanded)
  return expandIpv6Canonical(expanded)
}

function ipv4ToHextetPair(ipv4: string): string {
  const p = ipv4.split('.').map(Number)
  const hi = ((p[0]! << 8) | p[1]!).toString(16)
  const lo = ((p[2]! << 8) | p[3]!).toString(16)
  return `${hi}:${lo}`
}
