/**
 * Incremental PCAP export engine — plan + descriptors + Blob, bounded batches (Stage 11).
 * Never materializes full PacketEnvelope[] or full output ArrayBuffer.
 */

import { CaptureFormat } from '../../domain/types'
import type { PacketEnvelope, PacketRecordDescriptor } from '../../domain/types'
import { writeClassicPcapGlobalHeader, writeClassicPcapRecord } from '../../capture/pcapWriter'
import { createPcapngIncrementalWriter } from '../../capture/pcapngWriter'
import { createIncrementalValidator } from './incrementalValidator'
import { compareExportValidationToBaseline, type ExportValidationOutcome } from './baselineCompare'
import type { ParseIssue } from '../../domain/types'
import { aggregateChecksumReports } from '../../checksums/types'
import type { ChecksumReport } from '../../checksums/types'
import { createTimestampMappingForPlan } from '../../anonymization/timestampMapping'
import type { PcapPlanSnapshot } from '../planSnapshot'
import { buildExportEnvelope } from '../packetBuilder'
import { anonymizedPcapFileName } from '../fileName'
import { assertExportPlan } from './planGuard'
import { hydrateDescriptorForExport, createSequentialHydrator } from './hydrateSlice'
import { CancellationError } from '../../capture/cancellation'
import type { AnonymizedProvenanceRecorder } from '../anonymizedProvenance'
import {
  DEFAULT_EXPORT_BATCH_LIMITS,
  type ExportBatchLimits,
  type IncrementalExportProgress,
} from './types'

export interface IncrementalExportInput {
  readonly plan: PcapPlanSnapshot
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly sourceBlob: Blob
  readonly expectedGenerationId?: string
  readonly expectedProfileHash?: string
  readonly batchLimits?: Partial<ExportBatchLimits>
  readonly applyTimestamps?: boolean
  readonly isCancelled?: () => boolean
  readonly onProgress?: (progress: IncrementalExportProgress) => void
  readonly onChunk?: (chunk: ArrayBuffer, index: number) => void | Promise<void>
  /** Stage 12 — stream chunk to sink; return false to stop ACK (cancel/generation change). */
  readonly deliverChunk?: (chunk: ArrayBuffer, index: number) => Promise<boolean>
  /** Stage 13 — input parse issues for baseline comparison. */
  readonly baselineIssues?: readonly ParseIssue[]
  /** Step 3 — optional recovery sidecar (worker path only). */
  readonly recovery?: {
    readonly enabled: boolean
    /** Compact transferable seed for INDEX frames (step 4). */
    readonly indexSeed?: ArrayBuffer
    readonly copyAnon?: boolean
  }
  readonly onRecoveryChunk?: (chunk: ArrayBuffer, index: number) => void | Promise<void>
  readonly deliverRecoveryChunk?: (chunk: ArrayBuffer, index: number) => Promise<boolean>
  /**
   * Optional COPY_ANON provenance (step 9). Must not be constructed on the
   * recovery-off hot path. Recorder lives in pcap/export, not pcap/recovery.
   */
  readonly provenance?: AnonymizedProvenanceRecorder
}

export interface IncrementalExportResult {
  readonly chunks: readonly ArrayBuffer[]
  readonly fileName: string
  readonly changedPackets: number
  readonly truncatedPayloads: number
  readonly checksumReport: ChecksumReport
  readonly validationValid: boolean
  readonly validationIssueCount: number
  readonly validation: ExportValidationOutcome
  /** Step 5 — from worker wire; never includes hashes in shared report. */
  readonly recoveryCreated?: boolean
}

interface BatchState {
  packetCount: number
  byteCount: number
  startedAt: number
}

function batchExceeded(state: BatchState, limits: ExportBatchLimits): boolean {
  if (state.packetCount >= limits.maxPackets) return true
  if (state.byteCount >= limits.maxBytes) return true
  if (performance.now() - state.startedAt >= limits.maxTimeMs) return true
  return false
}

function resetBatch(): BatchState {
  return { packetCount: 0, byteCount: 0, startedAt: performance.now() }
}

export async function runIncrementalExport(input: IncrementalExportInput): Promise<IncrementalExportResult> {
  assertExportPlan({
    plan: input.plan,
    expectedGenerationId: input.expectedGenerationId,
    expectedProfileHash: input.expectedProfileHash,
  })

  const limits: ExportBatchLimits = { ...DEFAULT_EXPORT_BATCH_LIMITS, ...input.batchLimits }
  const applyTimestamps = input.applyTimestamps ?? true
  const tsMapping = createTimestampMappingForPlan(
    input.plan.timestamps,
    input.plan.timestampAnchorSeed,
  )
  const checksumReports: ChecksumReport[] = []
  const chunks: ArrayBuffer[] = []
  const streaming = !!input.deliverChunk
  const incrementalValidator = createIncrementalValidator(input.plan.format)
  let chunkIndex = 0
  let changedPackets = 0
  let truncatedPayloads = 0

  const exportPackets = input.plan.packets.filter((p) => !p.drop)
  const total = exportPackets.length

  const emit = async (buffer: ArrayBuffer) => {
    if (!streaming) chunks.push(buffer)
    incrementalValidator.feedChunk(buffer)
    const idx = chunkIndex++
    if (input.deliverChunk) {
      const ok = await input.deliverChunk(buffer, idx)
      if (!ok) throw new CancellationError('Incremental export cancelled')
    } else {
      const result = input.onChunk?.(buffer, idx)
      if (result instanceof Promise) await result
    }
  }

  const reportProgress = (phase: IncrementalExportProgress['phase'], packetsDone: number) => {
    input.onProgress?.({
      phase,
      packetsDone,
      packetsTotal: total,
      chunksEmitted: chunkIndex,
    })
  }

  input.isCancelled?.()
  reportProgress('rewriting', 0)

  const pcapngWriter =
    input.plan.format === CaptureFormat.Pcapng
      ? createPcapngIncrementalWriter({
          sections: input.plan.pcapngSections ?? [],
          interfaces: input.plan.pcapngInterfaces ?? [],
        })
      : null

  const noteRewrite = (byteLength: number) => {
    input.provenance?.recordRewrite(byteLength)
  }

  if (input.plan.format === CaptureFormat.ClassicPcap) {
    if (!input.plan.classicHeader) throw new Error('Missing classic PCAP header for export')
    const header = writeClassicPcapGlobalHeader(input.plan.classicHeader)
    await emit(header)
    noteRewrite(header.byteLength)
  }

  let batch = resetBatch()
  let done = 0
  // PF-09: one read-ahead window reused across the whole export loop instead of a fresh
  // Blob.slice().arrayBuffer() round-trip per packet — export visits packets in plan/file
  // order, so this is almost always a cache hit.
  const hydrateNext = createSequentialHydrator(input.sourceBlob)

  for (const planPkt of exportPackets) {
    if (input.isCancelled?.()) {
      throw new CancellationError('Incremental export cancelled')
    }

    if (batchExceeded(batch, limits)) {
      reportProgress('rewriting', done)
      batch = resetBatch()
      await yieldToEventLoop()
    }

    const descriptor = input.descriptors[planPkt.index]
    if (!descriptor) {
      throw new Error(`Missing descriptor for packet index ${planPkt.index}`)
    }

    const original = await hydrateNext(descriptor)
    if (planPkt.patches.length > 0 || planPkt.truncatedLength !== undefined) changedPackets++
    if (planPkt.truncatedLength !== undefined) truncatedPayloads++

    const { envelope, checksumReport } = buildExportEnvelope(original, planPkt, tsMapping, applyTimestamps)
    checksumReports.push(checksumReport)

    if (input.plan.format === CaptureFormat.ClassicPcap) {
      const record = writeClassicPcapRecord(input.plan.classicHeader!, envelope)
      await emit(record)
      recordClassicPacketProvenance(input.provenance, {
        recordBytes: record.byteLength,
        originalPayload: original.data,
        emittedPayload: envelope.data,
        originalFileOffset: descriptor.dataOffset,
      })
    } else {
      const blocks = pcapngWriter!.emitPacket(envelope)
      for (let b = 0; b < blocks.length; b++) {
        const block = blocks[b]!
        await emit(block)
        if (b < blocks.length - 1) {
          noteRewrite(block.byteLength)
        } else {
          recordPcapngEpbProvenance(input.provenance, {
            blockBytes: block.byteLength,
            originalPayload: original.data,
            emittedPayload: envelope.data,
            originalFileOffset: descriptor.dataOffset,
          })
        }
      }
    }

    batch.packetCount++
    batch.byteCount += envelope.capturedLength
    done++
  }

  reportProgress('checksums', total)
  reportProgress('assembling', total)

  const format = input.plan.format === CaptureFormat.Pcapng ? 'pcapng' : 'pcap'
  const fileName = anonymizedPcapFileName(input.plan.fileName, format)

  reportProgress('validating', total)
  const exportValidation = incrementalValidator.finish()
  const validation = compareExportValidationToBaseline(
    input.baselineIssues ?? [],
    exportValidation,
  )

  return {
    chunks,
    fileName,
    changedPackets,
    truncatedPayloads,
    checksumReport: aggregateChecksumReports(checksumReports),
    validationValid: validation.validationValid,
    validationIssueCount: validation.validationIssueCount,
    validation,
  }
}

async function hydrateAllForParity(input: {
  plan: PcapPlanSnapshot
  descriptors: readonly PacketRecordDescriptor[]
  sourceBlob: Blob
}): Promise<PacketEnvelope[]> {
  const tsMapping = createTimestampMappingForPlan(
    input.plan.timestamps,
    input.plan.timestampAnchorSeed,
  )
  const out: PacketEnvelope[] = []
  for (const planPkt of input.plan.packets) {
    if (planPkt.drop) continue
    const descriptor = input.descriptors[planPkt.index]!
    const original = await hydrateDescriptorForExport(input.sourceBlob, descriptor)
    const { envelope } = buildExportEnvelope(original, planPkt, tsMapping, true)
    out.push(envelope)
  }
  return out
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0))
}

export { hydrateAllForParity as buildEnvelopesForParityTest }

const CLASSIC_RECORD_HEADER_BYTES = 16
const PCAPNG_EPB_PREFIX_BYTES = 28
const PCAPNG_EPB_TRAILER_BYTES = 4

function recordClassicPacketProvenance(
  provenance: AnonymizedProvenanceRecorder | undefined,
  input: {
    recordBytes: number
    originalPayload: Uint8Array
    emittedPayload: Uint8Array
    originalFileOffset: number
  },
): void {
  if (!provenance) return
  const before = provenance.anonymizedOffset
  provenance.recordRewrite(CLASSIC_RECORD_HEADER_BYTES)
  provenance.recordVerifiedCopies({
    originalPayload: input.originalPayload,
    emittedPayload: input.emittedPayload,
    originalFileOffset: input.originalFileOffset,
  })
  const accounted = provenance.anonymizedOffset - before
  if (accounted !== input.recordBytes) {
    provenance.invalidate()
    provenance.recordRewrite(Math.max(0, input.recordBytes - accounted))
  }
}

function recordPcapngEpbProvenance(
  provenance: AnonymizedProvenanceRecorder | undefined,
  input: {
    blockBytes: number
    originalPayload: Uint8Array
    emittedPayload: Uint8Array
    originalFileOffset: number
  },
): void {
  if (!provenance) return
  const payloadLen = input.emittedPayload.byteLength
  const suffix = input.blockBytes - PCAPNG_EPB_PREFIX_BYTES - payloadLen
  if (suffix < PCAPNG_EPB_TRAILER_BYTES) {
    provenance.recordRewrite(input.blockBytes)
    return
  }
  const before = provenance.anonymizedOffset
  provenance.recordRewrite(PCAPNG_EPB_PREFIX_BYTES)
  provenance.recordVerifiedCopies({
    originalPayload: input.originalPayload,
    emittedPayload: input.emittedPayload,
    originalFileOffset: input.originalFileOffset,
  })
  provenance.recordRewrite(suffix)
  if (provenance.anonymizedOffset - before !== input.blockBytes) {
    provenance.invalidate()
  }
}
