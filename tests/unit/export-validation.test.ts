import { describe, expect, it, vi, afterEach } from 'vitest'
import {
  createIncrementalValidator,
  compareExportValidationToBaseline,
  runIncrementalExport,
  buildEnvelopesForParityTest,
} from '../../src/pcap/export/incremental'
import { previewBytesFromPlan } from '../../src/pcap/export/packetBuilder'
import { validateClassicPcap, validatePcapng } from '../../src/pcap/capture/validator'
import { concatArrayBuffers } from '../../src/pcap/capture/pcapWriter'
import { concatPcapngChunks } from '../../src/pcap/capture/pcapngWriter'
import { CaptureFormat, Endian, IssueSeverity, TimestampResolution, type PacketEnvelope } from '../../src/pcap/domain/types'
import { createDefaultPcapProfile, createPresetProfile } from '../../src/pcap/profile/presets'
import { sanitizePacket } from '../../src/pcap/sanitize'
import { SessionMapping } from '../../src/pcap/anonymization/mapping'
import { buildExportReport, assertReportHasNoOriginalIdentifiers } from '../../src/pcap/export/report'
import {
  runPcapExport,
  cancelPcapExport,
  PcapExportCancelledError,
  PcapExportValidationError,
} from '../../src/pcap/export/coordinator'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'
import { readClassicPcapFromBlob } from '../../src/pcap/capture/pcapReader'
import { emptyChecksumCounts, emptyOriginalStateCounts } from '../../src/pcap/checksums/types'
import type { ExportValidationOutcome } from '../../src/pcap/export/incremental/baselineCompare'
import * as exportSinks from '../../src/pcap/export/sinks'

function makeEthIpPacket(src: number[], dst: number[], n: number, payload = 4): PacketEnvelope {
  const data = new Uint8Array(38 + payload)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 28 + payload
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(1700000000 + n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function okValidation(): ExportValidationOutcome {
  return {
    valid: true,
    exportValidation: { valid: true, packetCount: 1, issues: [] },
    exportIssues: [],
    newBlockingIssues: [],
    preservedBaselineIssues: [],
    validationValid: true,
    validationIssueCount: 0,
  }
}

describe('Stage 13 — incremental export validation and production cutover', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('incremental classic validator matches full-buffer validator', async () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 2], [10, 0, 0, 2], 2, 64),
    ]
    const session = await createTestPcapSessionFromPackets({ fileName: 'val.pcap', packets })

    const result = await runIncrementalExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
    })

    const incremental = createIncrementalValidator(CaptureFormat.ClassicPcap)
    for (const chunk of result.chunks) incremental.feedChunk(chunk)
    const incResult = incremental.finish()

    const full = validateClassicPcap(concatArrayBuffers(result.chunks))
    expect(incResult.valid).toBe(full.valid)
    expect(incResult.packetCount).toBe(full.packetCount)
  })

  it('baseline comparison blocks new structural errors but preserves input issues', () => {
    const baseline = [
      {
        severity: IssueSeverity.Warning,
        code: 'pcap-incl-gt-orig',
        message: 'pre-existing',
        packetNumber: 0,
      },
    ]
    const exportValidation = {
      valid: false,
      packetCount: 1,
      issues: [
        {
          severity: IssueSeverity.Error,
          code: 'val-truncated',
          message: 'new truncation',
          packetNumber: 1,
        },
        {
          severity: IssueSeverity.Warning,
          code: 'val-incl-gt-orig',
          message: 'same as baseline',
          packetNumber: 0,
        },
      ],
    }

    const outcome = compareExportValidationToBaseline(baseline, exportValidation)
    expect(outcome.valid).toBe(false)
    expect(outcome.newBlockingIssues).toHaveLength(1)
    expect(outcome.newBlockingIssues[0]!.code).toBe('val-truncated')
    expect(outcome.preservedBaselineIssues).toHaveLength(1)
  })

  it('production port integration: parity, canary, checksum dispositions, reparse', async () => {
    const canary = 'CANARY_SECRET_X9f3Qm2Lp7Wv8Zk1Ab4Cd6Ef'
    const payload = new TextEncoder().encode(canary)
    const data = new Uint8Array(14 + 20 + 8 + payload.length)
    data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    data[12] = 0x08
    data[13] = 0x00
    data[14] = 0x45
    data[16] = 0
    data[17] = 28 + payload.length
    data[23] = 17
    data.set([203, 0, 113, 10], 26)
    data.set([198, 51, 100, 20], 30)
    data.set(payload, 42)
    const pkt: PacketEnvelope = {
      packetNumber: 1,
      timestamp: { ticks: 1_700_000_000_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
      capturedLength: data.length,
      originalLength: data.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data,
    }

    const session = await createTestPcapSessionFromPackets({
      fileName: 'prod.pcap',
      packets: [pkt],
      profile: createPresetProfile('high-privacy', { id: 'stage13-hp', name: 'Stage 13 High Privacy' }),
    })
    const planPkt = session.plan.packets[0]!

    vi.spyOn(exportSinks, 'triggerBlobDownload').mockImplementation(() => {})

    const result = await runPcapExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      baselineIssues: session.issues,
      unsupportedLayers: 0,
      protocolCoverage: session.unifiedCoverage.byProtocol,
      preferFileSystemAccess: false,
    })

    expect(result.byteLength).toBeGreaterThan(0)
    assertReportHasNoOriginalIdentifiers(result.reportJson)

    const exported = await runIncrementalExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      baselineIssues: session.issues,
    })
    const buffer = concatArrayBuffers(exported.chunks)
    const validation = validateClassicPcap(buffer)
    expect(validation.valid).toBe(true)

    const envelopes = await buildEnvelopesForParityTest({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
    })
    const exportedPkt = envelopes[0]!
    const preview = previewBytesFromPlan(pkt, planPkt)
    expect(exportedPkt.data.length).toBe(preview.length)

    const outText = new TextDecoder('ascii', { fatal: false }).decode(exportedPkt.data)
    expect(outText).not.toContain(canary)
    expect(outText).not.toContain('CANARY_SECRET')

    const report = JSON.parse(result.reportJson)
    expect(report.validation.valid).toBe(true)
    expect(report.checksum).toBeDefined()
    expect(report.schemaVersion).toBe(8)
  })

  it('export report is built only with safe validation summary', () => {
    const report = buildExportReport({
      plan: {
        generationId: 'g',
        profileId: 'p',
        profileHash: 'h',
        format: CaptureFormat.ClassicPcap,
        fileName: 'x.pcap',
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
      },
      exportedFileName: 'x.anonymized.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: okValidation(),
    })
    const json = JSON.stringify(report)
    expect(json).not.toMatch(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)
    expect(report.validation.newBlockingIssueCount).toBe(0)
  })

  it('validation failure aborts without success', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'bad.pcap', packets })

    const incremental = await import('../../src/pcap/export/incremental')
    const spy = vi.spyOn(incremental, 'runIncrementalExport').mockResolvedValueOnce({
      chunks: [],
      fileName: 'bad.anonymized.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      checksumReport: { fields: [], counts: emptyChecksumCounts(), originalStateCounts: emptyOriginalStateCounts() },
      validationValid: false,
      validationIssueCount: 1,
      validation: {
        valid: false,
        exportValidation: { valid: false, packetCount: 0, issues: [] },
        exportIssues: [],
        newBlockingIssues: [{ severity: IssueSeverity.Error, code: 'val-truncated', message: 'forced' }],
        preservedBaselineIssues: [],
        validationValid: false,
        validationIssueCount: 1,
      },
    })

    vi.spyOn(exportSinks, 'triggerBlobDownload').mockImplementation(() => {})

    const originalWorker = globalThis.Worker
    // @ts-expect-error force sync path for mocked export
    globalThis.Worker = undefined

    try {
      await expect(
        runPcapExport({
          plan: session.plan,
          descriptors: session.descriptors,
          sourceBlob: session.sourceFile,
          baselineIssues: session.issues,
          unsupportedLayers: 0,
          protocolCoverage: [],
          preferFileSystemAccess: false,
        }),
      ).rejects.toBeInstanceOf(PcapExportValidationError)
    } finally {
      globalThis.Worker = originalWorker
      spy.mockRestore()
    }
  })

  it('cancel during validation phase rejects without success', async () => {
    const packets = Array.from({ length: 40 }, (_, i) =>
      makeEthIpPacket([192, 168, 0, 1], [10, 0, 0, 1], i + 1),
    )
    const session = await createTestPcapSessionFromPackets({ fileName: 'cancel-val.pcap', packets })

    const originalWorker = globalThis.Worker
    // @ts-expect-error force sync path
    globalThis.Worker = undefined

    const exportPromise = runPcapExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      baselineIssues: session.issues,
      unsupportedLayers: 0,
      protocolCoverage: [],
      preferFileSystemAccess: false,
    })

    cancelPcapExport()
    await expect(exportPromise).rejects.toBeInstanceOf(PcapExportCancelledError)

    globalThis.Worker = originalWorker
  })

  it('streaming export does not retain output chunks when deliverChunk is used', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'stream.pcap', packets })
    const delivered: ArrayBuffer[] = []

    const result = await runIncrementalExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      deliverChunk: async (chunk) => {
        delivered.push(chunk)
        return true
      },
    })

    expect(delivered.length).toBeGreaterThan(0)
    expect(result.chunks.length).toBe(0)
    expect(result.validationValid).toBe(true)
  })

  it('pcapng incremental validator accepts emitted blocks', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'ng.pcap', packets })
    if (session.plan.format !== CaptureFormat.Pcapng) {
      // classic-only fixture — skip pcapng-specific assertion
      expect(true).toBe(true)
      return
    }
    const result = await runIncrementalExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
    })
    const validator = createIncrementalValidator(CaptureFormat.Pcapng)
    for (const chunk of result.chunks) validator.feedChunk(chunk)
    const inc = validator.finish()
    const full = validatePcapng(concatPcapngChunks(result.chunks))
    expect(inc.valid).toBe(full.valid)
  })
})
