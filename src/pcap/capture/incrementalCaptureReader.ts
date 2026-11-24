/**
 * Production incremental capture reader (Stage 6).
 * Uses BlobSliceCursor — never materializes the whole file.
 */

import { CaptureFormat } from '../domain/types'
import { readClassicPcapFromBlob, type ClassicPcapReadResult } from './pcapReader'
import { readPcapngFromBlob, type PcapngReadResult } from './pcapngReader'

export type IncrementalCaptureReadResult =
  | ({ format: typeof CaptureFormat.ClassicPcap } & ClassicPcapReadResult)
  | ({ format: typeof CaptureFormat.Pcapng } & PcapngReadResult)

export interface IncrementalReadOptions {
  signal?: AbortSignal
  onBytes?: (bytesDone: number, bytesTotal: number) => void
}

export async function readCaptureIncremental(
  blob: Blob,
  format: CaptureFormat,
  options: IncrementalReadOptions = {},
): Promise<IncrementalCaptureReadResult> {
  options.signal?.throwIfAborted()
  options.onBytes?.(0, blob.size)

  if (format === CaptureFormat.ClassicPcap) {
    const result = await readClassicPcapFromBlob(blob)
    options.onBytes?.(blob.size, blob.size)
    return { format: CaptureFormat.ClassicPcap, ...result }
  }

  const result = await readPcapngFromBlob(blob)
  options.onBytes?.(blob.size, blob.size)
  return { format: CaptureFormat.Pcapng, ...result }
}
