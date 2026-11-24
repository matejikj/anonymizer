/**
 * Internal incremental PCAP export port (Stage 11).
 * Production UI uses coordinator streaming path (Stage 12); this port remains for tests/tools.
 */

import type { PacketRecordDescriptor } from '../domain/types'
import type { PcapPlanSnapshot } from './planSnapshot'
import type { ChecksumReport } from '../checksums/types'
import {
  runIncrementalExport,
  type IncrementalExportInput,
  type IncrementalExportProgress,
  type IncrementalExportResult,
} from './incremental'
import { buildIncrementalExportViaWorker } from './incrementalExportWorkerClient'

export interface InternalIncrementalExportRequest {
  readonly plan: PcapPlanSnapshot
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly sourceBlob: Blob
  readonly expectedGenerationId?: string
  readonly expectedProfileHash?: string
  readonly useWorker?: boolean
  readonly onProgress?: (progress: IncrementalExportProgress) => void
  readonly onChunk?: (chunk: ArrayBuffer, index: number) => void
  readonly isCancelled?: () => boolean
}

export interface InternalIncrementalExportResult extends IncrementalExportResult {
  readonly buffer: ArrayBuffer
  readonly checksumReport: ChecksumReport
}

function concatChunks(chunks: readonly ArrayBuffer[]): ArrayBuffer {
  let total = 0
  for (const c of chunks) total += c.byteLength
  const out = new ArrayBuffer(total)
  const view = new Uint8Array(out)
  let off = 0
  for (const c of chunks) {
    view.set(new Uint8Array(c), off)
    off += c.byteLength
  }
  return out
}

/** Stage 11 internal export port — descriptor + blob path, optional worker offload. */
export async function runInternalIncrementalExport(
  input: InternalIncrementalExportRequest,
): Promise<InternalIncrementalExportResult> {
  const base: IncrementalExportInput = {
    plan: input.plan,
    descriptors: input.descriptors,
    sourceBlob: input.sourceBlob,
    expectedGenerationId: input.expectedGenerationId,
    expectedProfileHash: input.expectedProfileHash,
    onProgress: input.onProgress,
    onChunk: input.onChunk,
    isCancelled: input.isCancelled,
  }

  const result =
    input.useWorker !== false && typeof Worker !== 'undefined'
      ? await buildIncrementalExportViaWorker(base)
      : await runIncrementalExport(base)

  return {
    ...result,
    buffer: concatChunks(result.chunks),
  }
}
