/**
 * PCAP export engine — builds capture from immutable plan snapshot.
 */

import { CaptureFormat } from '../domain/types'
import type { PacketEnvelope } from '../domain/types'
import { writeClassicPcap } from '../capture/pcapWriter'
import { writePcapng } from '../capture/pcapngWriter'
import { validateClassicPcap, validatePcapng } from '../capture/validator'
import { aggregateChecksumReports } from '../checksums/types'
import type { ChecksumReport } from '../checksums/types'
import { createTimestampMappingForPlan } from '../anonymization/timestampMapping'
import type { PcapPlanSnapshot } from './planSnapshot'
import { buildExportEnvelope } from './packetBuilder'
import { buildExportReport } from './report'
import { anonymizedPcapFileName } from './fileName'
import type { UnifiedProtocolSummary } from '../coverage/types'
import {
  assertPrivacyReportMatchesPlan,
  buildPrivacyReport,
  type BuildPrivacyReportInput,
} from '../privacy/privacyReport'
import {
  aggregateDispositionRanges,
  buildExportPacketLedger,
  emptyDispositionAggregate,
  type DispositionLedgerAggregate,
} from './dispositionLedger'

export interface ExportBuildResult {
  readonly buffer: ArrayBuffer
  readonly packets: PacketEnvelope[]
  readonly checksumReport: ChecksumReport
  readonly fileName: string
  readonly changedPackets: number
  readonly truncatedPayloads: number
  readonly validationValid: boolean
  readonly validationIssueCount: number
  /** T62 — disposition aggregates recomputed after patches (I2). */
  readonly dispositionLedger: DispositionLedgerAggregate
}

export function buildCaptureFromPlan(
  plan: PcapPlanSnapshot,
  originals: readonly PacketEnvelope[],
  options: { applyTimestamps?: boolean } = {},
): ExportBuildResult {
  const applyTimestamps = options.applyTimestamps ?? true
  const tsMapping = createTimestampMappingForPlan(
    plan.timestamps,
    plan.timestampAnchorSeed,
  )
  const built: PacketEnvelope[] = []
  const checksumReports: ChecksumReport[] = []
  let changedPackets = 0
  let truncatedPayloads = 0

  // T62 — ledger after plan patches (residual already applied at plan build).
  const ledgerAcc = {
    byDisposition: { ...emptyDispositionAggregate().byDisposition },
    byProtocol: {} as Record<string, number>,
    byReason: {} as Record<string, number>,
  }
  let exportLedgerPackets = 0

  for (const planPkt of plan.packets) {
    if (planPkt.drop) continue
    const original = originals[planPkt.index]!
    if (planPkt.patches.length > 0 || planPkt.truncatedLength !== undefined) changedPackets++
    if (planPkt.truncatedLength !== undefined) truncatedPayloads++

    const exportLen = planPkt.truncatedLength ?? planPkt.originalCapturedLength
    const packetLedger = buildExportPacketLedger({
      packetIndex: planPkt.index,
      length: exportLen,
      drop: false,
      truncatedLength: planPkt.truncatedLength,
      patches: planPkt.patches,
    })
    aggregateDispositionRanges(packetLedger.ranges, ledgerAcc)
    exportLedgerPackets += 1

    const { envelope, checksumReport } = buildExportEnvelope(
      original,
      planPkt,
      tsMapping,
      applyTimestamps,
    )
    built.push(envelope)
    checksumReports.push(checksumReport)
  }

  const format = plan.format === CaptureFormat.Pcapng ? 'pcapng' : 'pcap'
  const fileName = anonymizedPcapFileName(plan.fileName, format)

  let buffer: ArrayBuffer
  if (plan.format === CaptureFormat.ClassicPcap) {
    if (!plan.classicHeader) throw new Error('Missing classic PCAP header for export')
    buffer = writeClassicPcap({ header: plan.classicHeader, packets: built })
  } else {
    buffer = writePcapng({
      sections: plan.pcapngSections ?? [],
      interfaces: plan.pcapngInterfaces ?? [],
      packets: built,
    })
  }

  const validation =
    plan.format === CaptureFormat.ClassicPcap
      ? validateClassicPcap(buffer)
      : validatePcapng(buffer)

  const dispositionLedger: DispositionLedgerAggregate = plan.dispositionLedger ?? {
    byDisposition: ledgerAcc.byDisposition,
    byProtocol: ledgerAcc.byProtocol,
    byReason: ledgerAcc.byReason,
    unclaimedBytesBeforeSweep: 0,
    residualMaskedBytes: 0,
    residualTruncatedBytes: 0,
    packetCount: exportLedgerPackets,
  }

  return {
    buffer,
    packets: built,
    checksumReport: aggregateChecksumReports(checksumReports),
    fileName,
    changedPackets,
    truncatedPayloads,
    validationValid: validation.valid,
    validationIssueCount: validation.issues.filter((i) => i.severity > 0).length,
    dispositionLedger,
  }
}

export function buildSafeReport(
  plan: PcapPlanSnapshot,
  build: {
    fileName: string
    changedPackets: number
    truncatedPayloads: number
    checksumReport: ChecksumReport
    validation: import('./incremental/baselineCompare').ExportValidationOutcome
    recoveryCreated?: boolean
    leakOriginals?: readonly import('../trust').LeakScanOriginal[]
    anonymizedBytes?: Uint8Array
    droppedMetadataBlocks?: number
    /** Safe sanitizer issue tokens (e.g. tls-branch:ech). */
    issues?: readonly string[]
  },
  unsupportedLayers: number,
  protocolCoverage: readonly UnifiedProtocolSummary[] = [],
  privacyInput?: BuildPrivacyReportInput,
) {
  const privacy = privacyInput
    ? (() => {
        const report = buildPrivacyReport(privacyInput)
        assertPrivacyReportMatchesPlan(report, privacyInput)
        return report
      })()
    : undefined

  return buildExportReport({
    plan,
    exportedFileName: build.fileName,
    changedPackets: build.changedPackets,
    truncatedPayloads: build.truncatedPayloads,
    unsupportedLayers,
    protocolCoverage,
    checksum: build.checksumReport,
    validation: build.validation,
    privacy,
    diagnosticPreset: privacyInput?.profile?.preset === 'diagnostic',
    recoveryCreated: build.recoveryCreated === true,
    coverage: privacyInput?.coverage,
    issues: build.issues,
    leakOriginals: build.leakOriginals,
    anonymizedBytes: build.anonymizedBytes,
    droppedMetadataBlocks: build.droppedMetadataBlocks,
  })
}

/** Split buffer into chunks for streaming sink with backpressure. */
export function chunkBuffer(buffer: ArrayBuffer, chunkSize = 256 * 1024): ArrayBuffer[] {
  const chunks: ArrayBuffer[] = []
  const bytes = new Uint8Array(buffer)
  for (let off = 0; off < bytes.length; off += chunkSize) {
    const end = Math.min(bytes.length, off + chunkSize)
    chunks.push(bytes.slice(off, end).buffer)
  }
  return chunks
}
