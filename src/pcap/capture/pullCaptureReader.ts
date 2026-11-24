/**
 * Pull capture reader — yields leased record batches; never returns packets[] for the whole file.
 * Classic PCAP and PCAPNG share this contract. Whole-array APIs remain test/reference adapters.
 */

import { CaptureFormat } from '../domain/types'
import type {
  ClassicPcapHeader,
  PacketEnvelope,
  PacketRecordDescriptor,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
} from '../domain/types'
import { PCAP_KERNEL_BUDGETS } from '../../domain/capabilityContract'
import { parseClassicPcapFraming } from './classicPcapFraming'
import { parsePcapngFraming } from './pcapngFraming'
import { BlobSliceCursor } from './asyncCursor'
import { hydratePayloads } from './packetHydration'
import { BufferLeaseArena, type BufferLease } from '../kernel/leases'

export interface PullBatchRecord {
  readonly index: number
  readonly descriptor: PacketRecordDescriptor
  readonly lease: BufferLease
  readonly envelope: PacketEnvelope
}

export interface PullCaptureBatch {
  readonly records: readonly PullBatchRecord[]
  readonly bytesHydrated: number
  release(): void
}

export interface PullCaptureReader {
  readonly format: CaptureFormat
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly checkpoints: readonly SparseCheckpoint[]
  readonly issues: readonly ParseIssue[]
  readonly classicHeader?: ClassicPcapHeader
  readonly pcapngSections?: readonly PcapngSectionInfo[]
  readonly pcapngInterfaces?: readonly PcapngInterfaceInfo[]
  readonly totalFileBytes: number
  readonly leaseArena: BufferLeaseArena
  /**
   * Pull the next batch. Returns null at EOF.
   * Caller must release each batch before the next pull when under memory pressure.
   */
  pull(): Promise<PullCaptureBatch | null>
  /** Abort cooperative cancel between blocks. */
  get cancelled(): boolean
}

export interface OpenPullCaptureOptions {
  signal?: AbortSignal
  batchMaxBytes?: number
  batchMaxRecords?: number
  onProgress?: (bytesDone: number, bytesTotal: number) => void
  leaseArena?: BufferLeaseArena
}

/**
 * Frame the capture (descriptors only), then hydrate payloads in pull batches.
 * Progress fires at least every progressMaxIntervalMs while work continues.
 */
export async function openPullCaptureReader(
  blob: Blob,
  format: CaptureFormat,
  options: OpenPullCaptureOptions = {},
): Promise<PullCaptureReader> {
  options.signal?.throwIfAborted()
  const batchMaxBytes = options.batchMaxBytes ?? PCAP_KERNEL_BUDGETS.batchMaxBytes
  const batchMaxRecords = options.batchMaxRecords ?? PCAP_KERNEL_BUDGETS.batchMaxRecords
  const leaseArena = options.leaseArena ?? new BufferLeaseArena()
  let lastProgressAt = 0

  const reportProgress = (done: number) => {
    const now = Date.now()
    if (now - lastProgressAt >= PCAP_KERNEL_BUDGETS.progressMaxIntervalMs || done >= blob.size) {
      lastProgressAt = now
      options.onProgress?.(done, blob.size)
    }
  }

  reportProgress(0)
  const cursor = new BlobSliceCursor(blob)

  if (format === CaptureFormat.ClassicPcap) {
    const framed = await parseClassicPcapFraming(cursor, { retainPayload: false })
    reportProgress(Math.min(blob.size, framed.totalFileBytes))
    return createPullReaderFromFramed({
      blob,
      format,
      descriptors: framed.descriptors,
      checkpoints: framed.checkpoints,
      issues: framed.issues,
      classicHeader: framed.header ?? undefined,
      totalFileBytes: framed.totalFileBytes,
      batchMaxBytes,
      batchMaxRecords,
      leaseArena,
      signal: options.signal,
      reportProgress,
    })
  }

  const framed = await parsePcapngFraming(cursor, { retainPayload: false })
  reportProgress(Math.min(blob.size, framed.totalFileBytes))
  return createPullReaderFromFramed({
    blob,
    format,
    descriptors: framed.descriptors,
    checkpoints: framed.checkpoints,
    issues: framed.issues,
    pcapngSections: framed.sections,
    pcapngInterfaces: framed.interfaces,
    totalFileBytes: framed.totalFileBytes,
    batchMaxBytes,
    batchMaxRecords,
    leaseArena,
    signal: options.signal,
    reportProgress,
  })
}

function createPullReaderFromFramed(input: {
  blob: Blob
  format: CaptureFormat
  descriptors: readonly PacketRecordDescriptor[]
  checkpoints: readonly SparseCheckpoint[]
  issues: readonly ParseIssue[]
  classicHeader?: ClassicPcapHeader
  pcapngSections?: readonly PcapngSectionInfo[]
  pcapngInterfaces?: readonly PcapngInterfaceInfo[]
  totalFileBytes: number
  batchMaxBytes: number
  batchMaxRecords: number
  leaseArena: BufferLeaseArena
  signal?: AbortSignal
  reportProgress: (done: number) => void
}): PullCaptureReader {
  let cursor = 0
  let cancelled = false

  input.signal?.addEventListener('abort', () => {
    cancelled = true
  })

  return {
    format: input.format,
    descriptors: input.descriptors,
    checkpoints: input.checkpoints,
    issues: input.issues,
    classicHeader: input.classicHeader,
    pcapngSections: input.pcapngSections,
    pcapngInterfaces: input.pcapngInterfaces,
    totalFileBytes: input.totalFileBytes,
    leaseArena: input.leaseArena,
    get cancelled() {
      return cancelled || (input.signal?.aborted ?? false)
    },
    async pull() {
      if (this.cancelled) throw new Error('cancelled')
      if (cursor >= input.descriptors.length) return null

      const startIndex = cursor
      const slice: PacketRecordDescriptor[] = []
      let bytes = 0
      while (
        cursor < input.descriptors.length
        && slice.length < input.batchMaxRecords
        && (slice.length === 0 || bytes + input.descriptors[cursor]!.capturedLength <= input.batchMaxBytes)
      ) {
        // Oversized single record is always its own batch (≤ maxRecordSize).
        if (
          slice.length > 0
          && input.descriptors[cursor]!.capturedLength > input.batchMaxBytes
        ) {
          break
        }
        const d = input.descriptors[cursor]!
        slice.push(d)
        bytes += d.capturedLength
        cursor++
        if (d.capturedLength > input.batchMaxBytes) break
      }

      const payloads = await hydratePayloads(input.blob, slice)
      if (this.cancelled) throw new Error('cancelled')

      const leases: BufferLease[] = []
      const records: PullBatchRecord[] = []
      for (let i = 0; i < slice.length; i++) {
        const d = slice[i]!
        const data = payloads.get(d.packetNumber) ?? new Uint8Array(0)
        const lease = input.leaseArena.acquire('pull-reader', data)
        leases.push(lease)
        const index = startIndex + i
        records.push({
          index,
          descriptor: d,
          lease,
          envelope: {
            packetNumber: d.packetNumber,
            timestamp: d.timestamp,
            capturedLength: d.capturedLength,
            originalLength: d.originalLength,
            linkType: d.linkType,
            interfaceId: d.interfaceId,
            sectionIndex: d.sectionIndex,
            fileOffset: d.fileOffset,
            data: lease.bytes,
          },
        })
      }

      const last = slice[slice.length - 1]
      if (last) {
        input.reportProgress(Math.min(input.blob.size, last.dataOffset + last.capturedLength))
      }

      return {
        records,
        bytesHydrated: bytes,
        release() {
          for (const lease of leases) lease.release()
        },
      }
    },
  }
}

/**
 * Test/reference helper — materialize all envelopes (not for production session retention).
 */
export async function readAllEnvelopesForTests(
  blob: Blob,
  format: CaptureFormat,
): Promise<readonly PacketEnvelope[]> {
  const reader = await openPullCaptureReader(blob, format)
  const out: PacketEnvelope[] = []
  for (;;) {
    const batch = await reader.pull()
    if (!batch) break
    for (const r of batch.records) {
      out.push({
        ...r.envelope,
        data: r.envelope.data.slice(),
      })
    }
    batch.release()
  }
  return out
}
