/**
 * @vitest-environment node
 *
 * Step 2 — discovery → mapping snapshot → plan contract:
 * identity aggregation, mapping closure validation, no silent drop on MappingLookupError.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { identitiesFromDiscovery, runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import type { EntityReplacementIntent, SourceDiscovery, TransformationIntent } from '../../../src/pcap/discovery/types'
import { DIAGNOSTIC_POLICY, createPresetProfile } from '../../../src/pcap/profile/presets'
import {
  buildDeterministicPlan,
  buildSanitizationFromSnapshot,
  PlanInvariantError,
  validateMappingClosure,
  resolveSnapshotWithMappingClosure,
  mergePatchesStrict,
} from '../../../src/pcap/plan'
import { SnapshotMappingAdapter } from '../../../src/pcap/plan/snapshotMappingAdapter'
import { MappingLookupError } from '../../../src/pcap/anonymization/mappingErrors'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import type { MappingSnapshot } from '../../../src/mapping/types'
import { sanitizePacket } from '../../../src/pcap/sanitize/engine'
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  const ip = 14
  buf[ip] = 0x45
  buf[ip + 1] = 0
  const ipLen = 20 + 8 + payload.length
  buf[ip + 2] = (ipLen >> 8) & 0xff
  buf[ip + 3] = ipLen & 0xff
  buf[ip + 8] = 64
  buf[ip + 9] = 17
  buf.set(srcIp, ip + 12)
  buf.set(dstIp, ip + 16)
  const udp = ip + 20
  buf[udp] = (srcPort >> 8) & 0xff
  buf[udp + 1] = srcPort & 0xff
  buf[udp + 2] = (dstPort >> 8) & 0xff
  buf[udp + 3] = dstPort & 0xff
  const udpLen = 8 + payload.length
  buf[udp + 4] = (udpLen >> 8) & 0xff
  buf[udp + 5] = udpLen & 0xff
  buf.set(payload, udp + 8)
  return buf
}

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 20 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 20 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 6
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const tcp = 34
  buf[tcp] = (srcPort >> 8) & 0xff
  buf[tcp + 1] = srcPort & 0xff
  buf[tcp + 2] = (dstPort >> 8) & 0xff
  buf[tcp + 3] = dstPort & 0xff
  buf[tcp + 12] = 0x50
  buf.set(payload, tcp + 20)
  return buf
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function classicHeader(): ClassicPcapHeader {
  return {
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
}

function discoveryWithIntents(intents: readonly TransformationIntent[]): SourceDiscovery {
  return {
    generationId: 'g',
    sourceId: 'src',
    totalPackets: 2,
    analysis: {
      histogram: { counts: new Map() },
      coverage: [],
      entities: [],
      summaries: [],
      totalPackets: 2,
      decodedPackets: 2,
      unsupportedLinkTypes: new Set(),
      entityOverflow: false,
      structuralSpans: [],
      entityOccurrenceLists: new Map(),
    },
    intents,
    packetDiscovery: [],
    exactOccurrences: [],
    unifiedCoverage: {
      perPacket: [],
      byProtocol: [],
      dominantStatus: 'covered',
    },
    entityOccurrenceIndex: {
      packetsForEntity: () => [],
      entitiesForPacket: () => [],
    },
  }
}

describe('mapping closure + identity aggregation (step 2)', () => {
  it('identitiesFromDiscovery aggregates all constraints and originalSpellings', () => {
    const intents: EntityReplacementIntent[] = [
      {
        kind: 'entity-replacement',
        packetIndex: 0,
        offset: 10,
        byteLength: 11,
        category: 'hostname',
        canonical: 'example.com',
        constraint: { kind: 'text-ascii', byteLength: 11 },
        originalSpelling: 'Example.COM',
      },
      {
        kind: 'entity-replacement',
        packetIndex: 1,
        offset: 10,
        byteLength: 11,
        category: 'hostname',
        canonical: 'example.com',
        constraint: { kind: 'text-ascii', byteLength: 11 },
        originalSpelling: 'example.com',
      },
      {
        kind: 'entity-replacement',
        packetIndex: 0,
        offset: 0,
        byteLength: 4,
        category: 'hostname',
        canonical: 'example.com',
        constraint: { kind: 'text-ascii', byteLength: 15 },
        originalSpelling: 'example.com.long',
      },
    ]
    const identities = identitiesFromDiscovery(discoveryWithIntents(intents))
    const host = identities.filter((i) => i.category === 'hostname' && i.canonical === 'example.com')
    expect(host.length).toBe(3)
    const spellings = new Set(host.map((i) => i.originalSpelling))
    expect(spellings.has('Example.COM')).toBe(true)
    expect(spellings.has('example.com')).toBe(true)
    expect(spellings.has('example.com.long')).toBe(true)
    const lengths = new Set(
      host.map((i) => (i.constraint.kind === 'text-ascii' ? i.constraint.byteLength : -1)),
    )
    expect(lengths.has(11)).toBe(true)
    expect(lengths.has(15)).toBe(true)
  })

  it('does not drop packets when alias is missing — throws PlanInvariantError instead', () => {
    const pkt = envelope(
      buildEthIpUdp([10, 0, 0, 1], [8, 8, 8, 8], 53000, 53, latin1('x')),
      0,
    )
    const emptySnapshot: MappingSnapshot = {
      scope: 'session',
      revision: 1,
      mappingRevision: 1,
      canonicalizationVersion: 1,
      generationId: 'g',
      sourceId: 'src',
      overflow: false,
      entries: [],
    }

    // T04: empty snapshot fail-closes fields instead of aborting sanitization.
    expect(() =>
      buildSanitizationFromSnapshot([pkt], DIAGNOSTIC_POLICY, emptySnapshot),
    ).not.toThrow()

    const adapter = new SnapshotMappingAdapter(emptySnapshot)
    expect(() => adapter.map('ipv4', '10.0.0.1')).toThrow(MappingLookupError)
    const emptyResult = sanitizePacket(
      {
        index: 0,
        data: pkt.data,
        capturedLength: pkt.capturedLength,
        originalLength: pkt.originalLength,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      adapter,
    )
    expect(emptyResult.drop).toBe(false)
    expect(emptyResult.patches.length).toBeGreaterThan(0)
    // Original IPv4 octets must not be written back as the patch payload.
    const originalIp = Uint8Array.of(10, 0, 0, 1)
    for (const patch of emptyResult.patches) {
      if (patch.data.length === 4) {
        expect(Buffer.from(patch.data).equals(Buffer.from(originalIp))).toBe(false)
      }
    }
  })

  it('artificially removed snapshot entry fail-closes fields with incidents', () => {
    const pkt = envelope(
      buildEthIpUdp([192, 168, 55, 10], [8, 8, 8, 8], 53000, 1234, latin1('payload')),
      0,
    )
    const packets = [pkt]
    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'g', 'src.pcap')
    expect(snapshot.entries.some((e) => e.category === 'ipv4')).toBe(true)

    const stripped: MappingSnapshot = {
      ...snapshot,
      entries: snapshot.entries.filter((e) => e.category !== 'ipv4'),
    }

    const intents: TransformationIntent[] = [
      {
        kind: 'entity-replacement',
        packetIndex: 0,
        offset: 26,
        byteLength: 4,
        category: 'ipv4',
        canonical: '192.168.55.10',
        constraint: { kind: 'ipv4-binary' },
      },
    ]
    const closure = validateMappingClosure(intents, stripped)
    expect(closure.ok).toBe(false)
    if (closure.ok) return
    expect(closure.failures[0]?.category).toBe('ipv4')
    expect(closure.failures[0]?.packetIndex).toBe(0)

    const profile = createPresetProfile('diagnostic')
    const plan = buildDeterministicPlan({
      generationId: 'g',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'gate.pcap',
      packets,
      policy: DIAGNOSTIC_POLICY,
      snapshot: stripped,
      classicHeader: classicHeader(),
      unresolvedClosureFailures: closure.failures,
    })
    expect(plan.incidents?.totalFailures).toBeGreaterThan(0)
    expect(plan.incidents?.incidents.some((i) => i.reason === 'mapping-alias-missing')).toBe(true)
    const serialized = JSON.stringify(plan.incidents)
    expect(serialized).not.toContain('192.168.55.10')
    // Original src IP bytes must not appear in planned patches.
    for (const p of plan.packets) {
      for (const patch of p.patches) {
        expect(Buffer.from(patch.data).includes(Buffer.from([192, 168, 55, 10]))).toBe(false)
      }
    }
  })

  it('resolveSnapshotWithMappingClosure tops up once then soft-fails remaining gaps', async () => {
    const intent: EntityReplacementIntent = {
      kind: 'entity-replacement',
      packetIndex: 0,
      offset: 0,
      byteLength: 4,
      category: 'ipv4',
      canonical: '10.1.2.3',
      constraint: { kind: 'ipv4-binary' },
      originalSpelling: '10.1.2.3',
    }

    let resolveCount = 0
    const result = await resolveSnapshotWithMappingClosure({
      generationId: 'g',
      sourceId: 'src',
      identities: [],
      intents: [intent],
      resolve: async () => {
        resolveCount++
        return {
          scope: 'session',
          revision: resolveCount,
          mappingRevision: resolveCount,
          canonicalizationVersion: 1,
          generationId: 'g',
          sourceId: 'src',
          overflow: false,
          entries: [],
        }
      },
      packetNumberForIndex: () => 1,
    })
    expect(resolveCount).toBe(2)
    expect(result.unresolvedFailures).toHaveLength(1)
    expect(result.unresolvedFailures[0]?.category).toBe('ipv4')
    expect(result.unresolvedFailures[0]?.packetIndex).toBe(0)
    // Failures must not embed the original identity value in reason codes alone — category only.
    expect(JSON.stringify(result.unresolvedFailures[0]?.reason)).not.toContain('10.1.2.3')
  })

  it('mergePatchesStrict fails closed on overlap instead of dropping a patch', () => {
    expect(() =>
      mergePatchesStrict(32, 7, [
        { offset: 0, data: new Uint8Array([1, 2, 3, 4]) },
        { offset: 2, data: new Uint8Array([9, 9]) },
      ]),
    ).toThrow(PlanInvariantError)
  })

  it('supported packet is not dropped when snapshot is complete', () => {
    const pkt = envelope(
      buildEthIpUdp([10, 0, 0, 9], [1, 1, 1, 1], 12345, 53, latin1('x')),
      0,
    )
    const snapshot = resolveSnapshotForPackets([pkt], DIAGNOSTIC_POLICY, 'g', 'ok.pcap')
    const results = buildSanitizationFromSnapshot([pkt], DIAGNOSTIC_POLICY, snapshot)
    expect(results[0]?.drop).toBe(false)
  })

  it('top-up resolve recovers missing constraint alias then builds plan', async () => {
    const pkt = envelope(
      buildEthIpUdp([10, 9, 8, 7], [1, 2, 3, 4], 40000, 80, latin1('hi')),
      0,
    )
    const profile = createPresetProfile('diagnostic')
    const authority = new MappingAuthority({
      ip: profile.mapping.ip,
      mac: profile.mapping.mac,
      timestamps: profile.mapping.timestamps,
      ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
      vlan: profile.mapping.vlan,
    })

    // Full packet identities minus the src IPv4 — closure must top-up that one.
    const fullSnapshot = resolveSnapshotForPackets([pkt], DIAGNOSTIC_POLICY, 'g', 'src')
    const identities = fullSnapshot.entries
      .filter((e) => !(e.category === 'ipv4' && e.canonical === '10.9.8.7'))
      .map((e) => ({
        category: e.category,
        canonical: e.canonical,
        originalSpelling: e.originalSpelling,
        constraint: e.constraint,
      }))

    const intent: EntityReplacementIntent = {
      kind: 'entity-replacement',
      packetIndex: 0,
      offset: 26,
      byteLength: 4,
      category: 'ipv4',
      canonical: '10.9.8.7',
      constraint: { kind: 'ipv4-binary' },
      originalSpelling: '10.9.8.7',
    }

    const { snapshot, unresolvedFailures } = await resolveSnapshotWithMappingClosure({
      generationId: 'g',
      sourceId: 'src',
      identities,
      intents: [intent],
      resolve: async (ids) => {
        const result = authority.resolve({
          generationId: 'g',
          sourceId: 'src',
          identities: ids,
        })
        if (!result.ok) throw new Error(result.message)
        return result.snapshot
      },
    })

    expect(unresolvedFailures).toHaveLength(0)
    expect(snapshot.entries.some((e) => e.category === 'ipv4' && e.canonical === '10.9.8.7')).toBe(true)
    const results = buildSanitizationFromSnapshot([pkt], DIAGNOSTIC_POLICY, snapshot)
    expect(results[0]?.drop).toBe(false)
  })

  it('HTTP Host is recorded into discovery so snapshot plan does not throw missing hostname', () => {
    const http = latin1('GET /path HTTP/1.1\r\nHost: secret-internal.example\r\n\r\n')
    const pkt = envelope(
      buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, http),
      0,
    )
    const discovery = runDiscoveryPipeline([pkt], DIAGNOSTIC_POLICY, 'g', 'http.pcap')
    expect(
      discovery.intents.some(
        (i) =>
          i.kind === 'entity-replacement'
          && i.category === 'hostname'
          && i.canonical === 'secret-internal.example',
      ),
    ).toBe(true)
    const snapshot = resolveSnapshotForPackets([pkt], DIAGNOSTIC_POLICY, 'g', 'http.pcap')
    expect(snapshot.entries.some((e) => e.category === 'hostname' && e.canonical === 'secret-internal.example')).toBe(true)
    expect(() => buildSanitizationFromSnapshot([pkt], DIAGNOSTIC_POLICY, snapshot)).not.toThrow()
    const results = buildSanitizationFromSnapshot([pkt], DIAGNOSTIC_POLICY, snapshot)
    expect(results[0]?.drop).toBe(false)
  })
})
