import { describe, expect, it, beforeEach } from 'vitest'
import { CaptureFormat, type PacketEnvelope } from '../../src/pcap/domain/types'
import {
  buildUnifiedCoverageModel,
  mergePacketSpans,
  mergeSpanPair,
  SANITIZER_PROTOCOL_IDS,
} from '../../src/pcap/coverage'
import { runDiscoveryPipeline } from '../../src/pcap/discovery/discoveryPipeline'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../src/pcap/sanitize'
import {
  clearPcapSession,
  filterPacketIndices,
  computeStatusesFromDiscovery,
  DEFAULT_PCAP_FILTER,
  countUnsupportedLayers,
} from '../../src/pcap/ui/pcapSession'
import { createPresetProfile } from '../../src/pcap/profile/presets'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'
import { buildExportReport } from '../../src/pcap/export/report'
import type { ExportValidationOutcome } from '../../src/pcap/export/incremental/baselineCompare'
import { emptyChecksumCounts } from '../../src/pcap/checksums/types'
import { analyzePackets } from '../../src/pcap/protocols/analysis'

function mockValidation(valid = true): ExportValidationOutcome {
  return {
    valid,
    exportValidation: { valid, packetCount: 0, issues: [] },
    exportIssues: [],
    newBlockingIssues: [],
    preservedBaselineIssues: [],
    validationValid: valid,
    validationIssueCount: 0,
  }
}

function makeEthIpUdpPacket(
  src: number[],
  dst: number[],
  srcPort: number,
  dstPort: number,
  packetNumber: number,
  payload: Uint8Array,
): PacketEnvelope {
  const ethLen = 14
  const ipLen = 20
  const udpLen = 8
  const data = new Uint8Array(ethLen + ipLen + udpLen + payload.length)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  const ipTotalLen = ipLen + udpLen + payload.length
  data[16] = (ipTotalLen >> 8) & 0xff
  data[17] = ipTotalLen & 0xff
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  const udpStart = 34
  data[udpStart] = (srcPort >> 8) & 0xff
  data[udpStart + 1] = srcPort & 0xff
  data[udpStart + 2] = (dstPort >> 8) & 0xff
  data[udpStart + 3] = dstPort & 0xff
  const udpTotalLen = udpLen + payload.length
  data[udpStart + 4] = (udpTotalLen >> 8) & 0xff
  data[udpStart + 5] = udpTotalLen & 0xff
  data.set(payload, udpStart + 8)
  return {
    packetNumber,
    timestamp: { ticks: BigInt(packetNumber) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function makeEthIpPacket(src: number[], dst: number[], packetNumber: number, payload = new Uint8Array(0)): PacketEnvelope {
  return makeEthIpUdpPacket(src, dst, 12345, 9999, packetNumber, payload)
}

function buildDnsQuery(hostname: string): Uint8Array {
  const labels = hostname.split('.')
  let qnameLen = 0
  for (const l of labels) qnameLen += 1 + l.length
  qnameLen += 1
  const dns = new Uint8Array(12 + qnameLen + 4)
  dns[0] = 0x12
  dns[1] = 0x34
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

function makeDnsPacket(packetNumber: number): PacketEnvelope {
  const payload = buildDnsQuery('golden.release.example.invalid')
  return makeEthIpUdpPacket([192, 168, 1, 1], [8, 8, 8, 8], 12345, 53, packetNumber, payload)
}

describe('Stage 10 — unified coverage model', () => {
  it.each([false, true])('keeps malformed aggregate evidence with sanitizer coverage=%s', sanitizer => {
    const analysis = { ...analyzePackets([]),
      coverage: [{ protocolId: 'sip', packetCount: 1, unsupportedCount: 0, issues: ['malformed-test'] }],
      summaries: [{ packetNumber: 0, protocols: ['sip'], issues: [], hasUnsupported: false }],
    }
    const model = buildUnifiedCoverageModel({ packetCount: 1, analysis,
      packetDiscovery: sanitizer ? [{ packetIndex: 0, packetNumber: 0, drop: false, issues: [], intents: [],
        coverage: [{ protocol: 'sip', offset: 0, length: 10, status: 'covered' }] }] : [],
    })
    expect(model.byProtocol.find(p => p.protocol === 'sip')).toMatchObject({
      dominantStatus: 'malformed', packetCount: 1, issues: ['malformed-test'],
    })
  })
  beforeEach(() => {
    clearPcapSession()
  })

  it('golden DNS packet appears in unified histogram, byProtocol and filter', async () => {
    const profile = createPresetProfile('diagnostic')
    const session = await createTestPcapSessionFromPackets({
      fileName: 'dns-golden.pcap',
      packets: [makeDnsPacket(1)],
      profile,
    })

    const dnsSummary = session.unifiedCoverage.byProtocol.find((p) => p.protocol === 'dns')
    expect(dnsSummary).toBeDefined()
    expect(dnsSummary!.sanitizerSpanCount).toBeGreaterThan(0)
    expect(session.unifiedCoverage.histogram.has('dns')).toBe(true)

    const filtered = filterPacketIndices({ ...DEFAULT_PCAP_FILTER, protocol: 'dns' })
    expect(filtered).toEqual([0])
  })

  it('entity filter returns only packets with exact entity occurrence', async () => {
    const sharedSrc = [192, 168, 50, 1]
    const packets = [
      makeEthIpPacket(sharedSrc, [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 50, 2], [10, 0, 0, 2], 2),
      makeEthIpPacket(sharedSrc, [10, 0, 0, 3], 3),
    ]
    const session = await createTestPcapSessionFromPackets({ fileName: 'entity.pcap', packets })
    const entity = session.analysis.entities.find((e) => e.value === '192.168.50.1')
    expect(entity).toBeDefined()

    const filtered = filterPacketIndices({ ...DEFAULT_PCAP_FILTER, entityKey: entity!.key })
    expect(filtered.sort()).toEqual([0, 2])
    expect(filtered).not.toContain(1)
  })

  it('unsupported sanitizer span is not overridden by structural covered', () => {
    const merged = mergePacketSpans([
      {
        packetIndex: 0,
        protocol: 'udp',
        source: 'structural',
        offset: 42,
        length: 20,
        status: 'covered',
        issues: [],
      },
      {
        packetIndex: 0,
        protocol: 'udp',
        source: 'sanitizer',
        offset: 42,
        length: 20,
        status: 'unsupported',
        issues: [],
      },
    ])
    expect(merged.some((s) => s.status === 'unsupported')).toBe(true)
    expect(mergeSpanPair(merged[0]!, merged[0]!).status).toBe('unsupported')
  })

  it('registry lists all sanitizer protocols in byProtocol even with zero packets', () => {
    const model = buildUnifiedCoverageModel({
      packetCount: 0,
      analysis: {
        histogram: { counts: new Map() },
        coverage: [],
        entities: [],
        summaries: [],
        totalPackets: 0,
        decodedPackets: 0,
        unsupportedLinkTypes: new Set(),
        entityOverflow: false,
        structuralSpans: [],
        entityOccurrenceLists: new Map(),
      },
      packetDiscovery: [],
    })
    for (const id of SANITIZER_PROTOCOL_IDS) {
      expect(model.byProtocol.some((p) => p.protocol === id)).toBe(true)
    }
  })

  it('level status snapshots for same synthetic capture', () => {
    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1, new Uint8Array(32))]
    const discoveryHp = runDiscoveryPipeline(packets, HIGH_PRIVACY_POLICY, 'g1', 's.pcap')
    const discoveryDiag = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'g2', 's.pcap')

    const plan = {
      generationId: 'g',
      pcapLevel: 'diagnostic' as const,
      profileId: 'p',
      profileHash: 'h',
      format: CaptureFormat.ClassicPcap,
      fileName: 's.pcap',
      engineVersion: '1',
      packets: [],
      droppedPacketNumbers: [],
        timestamps: 'relative',
        timestampAnchorSeed: 'test-anchor-seed',
        changeCategoryTotals: {
          mapped: 0,
          redacted: 0,
          'masked-content': 0,
          'preserved-encrypted': 0,
          'preserved-for-diagnostics': 0,
          'user-requested-drop': 0,
          blocked: 0,
        },
        maskedByteCount: 0,
        dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
        dropsByProtocol: {},
    }

    const hp = computeStatusesFromDiscovery({
      issues: [],
      analysis: discoveryHp.analysis,
      packetDiscovery: discoveryHp.packetDiscovery,
      unifiedCoverage: discoveryHp.unifiedCoverage,
      plan,
      policy: HIGH_PRIVACY_POLICY,
    })
    const diag = computeStatusesFromDiscovery({
      issues: [],
      analysis: discoveryDiag.analysis,
      packetDiscovery: discoveryDiag.packetDiscovery,
      unifiedCoverage: discoveryDiag.unifiedCoverage,
      plan,
      policy: DIAGNOSTIC_POLICY,
    })

    expect([hp.anonymization, diag.anonymization]).toEqual(['covered', 'covered'])
  })

  it('export report uses unified protocol coverage', async () => {
    const session = await createTestPcapSessionFromPackets({
      fileName: 'report.pcap',
      packets: [makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1)],
    })
    expect(countUnsupportedLayers()).toBe(session.unifiedCoverage.totalUnsupportedSpans)

    const report = buildExportReport({
      plan: session.plan,
      exportedFileName: 'report.anonymized.pcap',
      changedPackets: session.statuses.changedCount,
      truncatedPayloads: session.statuses.truncatedCount,
      unsupportedLayers: countUnsupportedLayers(),
      protocolCoverage: session.unifiedCoverage.byProtocol.filter((p) => p.packetCount > 0),
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: mockValidation(),
    })
    expect(report.protocolCoverage.length).toBeGreaterThan(0)
    expect(report.unsupportedLayers).toBe(session.unifiedCoverage.totalUnsupportedSpans)
  })
})
