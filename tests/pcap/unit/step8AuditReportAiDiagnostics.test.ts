/**
 * Step 8 — auditable plan disposition, safe export report, AI diagnostics manifest.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketEnvelope } from '../../../src/pcap/domain/types'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { createPresetProfile } from '../../../src/pcap/profile/presets'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket } from '../../../src/pcap/sanitize/engine'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import {
  assertArtifactHasNoCanaryLeaks,
  assertReportHasNoOriginalIdentifiers,
  buildExportReport,
} from '../../../src/pcap/export/report'
import {
  aiDiagnosticsFileName,
  buildAiDiagnosticsManifest,
} from '../../../src/pcap/export/aiDiagnostics'
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types'
import { derivePlanPacketAccounting } from '../../../src/pcap/plan/planDisposition'
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers'

function latin1(s: string): Uint8Array {
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff
  return out
}

function buildEthIpUdp(
  src: number[],
  dst: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const data = new Uint8Array(14 + 20 + 8 + payload.length)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0)
  data.set([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  const ipTotal = 20 + 8 + payload.length
  data[16] = (ipTotal >> 8) & 0xff
  data[17] = ipTotal & 0xff
  data[22] = 64
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  data[34] = (srcPort >> 8) & 0xff
  data[35] = srcPort & 0xff
  data[36] = (dstPort >> 8) & 0xff
  data[37] = dstPort & 0xff
  const udpLen = 8 + payload.length
  data[38] = (udpLen >> 8) & 0xff
  data[39] = udpLen & 0xff
  data.set(payload, 42)
  return data
}

function envelope(data: Uint8Array, packetNumber = 1): PacketEnvelope {
  return {
    packetNumber,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  }
}

function okValidation() {
  return {
    validationValid: true,
    validationIssueCount: 0,
    newBlockingIssues: [] as never[],
    preservedBaselineIssues: [] as never[],
  }
}

const CLASSIC_HEADER = {
  format: CaptureFormat.ClassicPcap,
  endian: 1 as const,
  timestampResolution: 1 as const,
  versionMajor: 2,
  versionMinor: 4,
  snapLen: 65535,
  linkType: 1,
  tzOffset: 0,
  sigfigs: 0,
}

describe('plan disposition (step 8)', () => {
  it('records dispositionReason and change categories on plan packets', () => {
    const pkt = envelope(
      buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 1], 12345, 53, latin1('x'.repeat(32))),
    )
    const san = sanitizePacket(
      {
        index: 0,
        data: pkt.data,
        capturedLength: pkt.capturedLength,
        originalLength: pkt.originalLength,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    const accounting = derivePlanPacketAccounting(san)
    expect(accounting.dispositionReason).toBe('exported')
    expect(accounting.changeCounts.mapped).toBeGreaterThan(0)
    expect(accounting.maskedByteCount).toBeGreaterThan(0)
    expect(accounting.changeCounts['masked-content']).toBeGreaterThan(0)
  })

  it('marks policy drops as user-requested-drop', () => {
    const accounting = derivePlanPacketAccounting({
      packetIndex: 0,
      patches: [],
      coverage: [{ protocol: 'rtp', offset: 0, length: 12, status: 'covered' }],
      drop: true,
      issues: ['media dropped by policy'],
    })
    expect(accounting.dispositionReason).toBe('user-requested-drop')
    expect(accounting.changeCounts['user-requested-drop']).toBe(1)
  })
})

describe('export report audit fields (step 8)', () => {
  it('omits original filename and includes input/output counts + categories', () => {
    const originalName = 'SECRET_CAPTURE_dt_canary.pcap'
    const profile = createPresetProfile('diagnostic')
    const packets = [
      envelope(
        buildEthIpUdp([192, 168, 1, 10], [8, 8, 8, 8], 53000, 53, latin1('aabb')),
        1,
      ),
    ]
    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'gen-step8', originalName)
    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'gen-step8', originalName)
    const plan = buildDeterministicPlan({
      generationId: 'gen-step8',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: originalName,
      packets,
      policy: DIAGNOSTIC_POLICY,
      snapshot,
      classicHeader: CLASSIC_HEADER,
    })

    expect(plan.packets[0]!.dispositionReason).toBe('exported')
    expect(plan.changeCategoryTotals.mapped).toBeGreaterThan(0)
    expect(plan.droppedPacketNumbers).toEqual([])

    const report = buildExportReport({
      plan,
      exportedFileName: 'SECRET_CAPTURE_dt_canary.anonymized.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: discovery.unifiedCoverage.byProtocol.filter((p) => p.packetCount > 0),
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: okValidation(),
      diagnosticPreset: true,
    })

    expect(report.schemaVersion).toBe(8)
    expect(report.inputPacketCount).toBe(1)
    expect(report.outputPacketCount).toBe(1)
    expect(report.packetCountDelta).toBe(0)
    expect(report.droppedPackets).toBe(0)
    expect(report.diagnosticInvariant?.ok).toBe(true)
    expect(report.exportedFileName).toBe('capture.anonymized.pcap')
    expect(report).not.toHaveProperty('sourceFileName')
    expect(report.changeCategoryTotals).toBeDefined()
    expect(report.maskedByteCount).toBeGreaterThanOrEqual(0)
    expect(report.lengthChanges.capturedLengthDeltaBytes).toBe(0)

    const json = JSON.stringify(report)
    assertArtifactHasNoCanaryLeaks(json, [
      originalName,
      'SECRET_CAPTURE',
      '192.168.1.10',
      'aa:bb:cc:dd:ee:ff',
      'alice@example.com',
    ])
  })

  it('fails diagnostic invariant when drops are present', () => {
    const profile = createPresetProfile('diagnostic')
    const packets = [
      envelope(buildEthIpUdp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, new Uint8Array(4)), 1),
    ]
    const snapshot = resolveSnapshotForPackets(packets, HIGH_PRIVACY_POLICY, 'gen-drop', 'x.pcap')
    const plan = buildDeterministicPlan({
      generationId: 'gen-drop',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'x.pcap',
      packets,
      policy: HIGH_PRIVACY_POLICY,
      snapshot,
      classicHeader: CLASSIC_HEADER,
    })
    const droppedPlan = {
      ...plan,
      packets: plan.packets.map((p) => ({
        ...p,
        drop: true,
        dispositionReason: 'user-requested-drop' as const,
        changeCounts: {
          ...p.changeCounts,
          'user-requested-drop': 1,
        },
      })),
      droppedPacketNumbers: [1],
      dropsByReason: {
        exported: 0,
        'user-requested-drop': 1,
        blocked: 0,
      },
      dropsByProtocol: { unknown: 1 },
    }
    expect(() =>
      buildExportReport({
        plan: droppedPlan,
        exportedFileName: 'x.anonymized.pcap',
        changedPackets: 0,
        truncatedPayloads: 0,
        unsupportedLayers: 0,
        protocolCoverage: [],
        checksum: { fields: [], counts: emptyChecksumCounts() },
        validation: okValidation(),
        diagnosticPreset: true,
      }),
    ).toThrow(/Diagnostic export invariant/)
  })
})

describe('AI diagnostics manifest (step 8)', () => {
  it('builds a sidecar without mapping or original identities', () => {
    const originalName = 'PHONEBOOK_host_example_invalid_capture.pcap'
    const profile = createPresetProfile('diagnostic')
    const packets = [
      envelope(
        buildEthIpUdp(
          [192, 168, 50, 7],
          [10, 0, 0, 9],
          5060,
          5060,
          latin1('INVITE sip:bob@evil.test SIP/2.0\r\n\r\n'),
        ),
        7,
      ),
    ]
    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'ai-gen', originalName)
    const snapshot = resolveSnapshotForPackets(packets, DIAGNOSTIC_POLICY, 'ai-gen', originalName)
    const plan = buildDeterministicPlan({
      generationId: 'ai-gen',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: originalName,
      packets,
      policy: DIAGNOSTIC_POLICY,
      snapshot,
      classicHeader: CLASSIC_HEADER,
    })

    const manifest = buildAiDiagnosticsManifest({
      plan,
      protocolCoverage: discovery.unifiedCoverage.byProtocol,
      warnings: ['sample-warning'],
    })
    expect(manifest.format).toBe('rnd-log-anonymizer-pcap-ai-diagnostics')
    expect(manifest.schemaVersion).toBe(5)
    expect(manifest.validity).toEqual({
      capture_structure: 'VALID',
      network_checksums: 'UNKNOWN',
      application_structure: 'VALID',
      cryptographic_integrity: 'UNKNOWN',
    })
    expect(manifest.gate).toBe('AI_READY')
    expect(manifest.exportAllowed).toBe(true)
    expect(manifest.safeForAi).toBe(true)
    expect(manifest.gateBadge).toBe('AI_READY')
    expect(manifest.inputPacketCount).toBe(1)
    expect(manifest.outputPacketCount).toBe(1)
    expect(manifest.packetSummaries[0]!.packetNumber).toBe(7)
    expect(manifest.packetSummaries[0]!.dispositionReason).toBe('exported')
    expect(aiDiagnosticsFileName('foo.anonymized.pcap')).toBe('foo.anonymized.ai-diagnostics.json')

    const json = JSON.stringify(manifest)
    assertReportHasNoOriginalIdentifiers(json)
    assertArtifactHasNoCanaryLeaks(json, [
      originalName,
      'PHONEBOOK',
      'host_example_invalid',
      '192.168.50.7',
      'bob@evil.test',
      'sip:bob',
    ])
  })
})
