/**
 * Bounded per-packet payload hydration from Blob.slice (Stage 6).
 */

import type { PacketRecordDescriptor } from '../domain/types'

/**
 * Descriptors are visited in ascending dataOffset order (file order), so a single
 * forward-scanning read-ahead window lets most packets be sliced out of memory instead
 * of costing their own Blob.slice().arrayBuffer() round-trip — each of those is a real
 * async I/O call in the browser, and one-per-packet doesn't scale to real capture sizes.
 */
const HYDRATION_CHUNK_SIZE = 64 * 1024

export async function hydratePayloads(
  blob: Blob,
  descriptors: readonly PacketRecordDescriptor[],
): Promise<Map<number, Uint8Array>> {
  const map = new Map<number, Uint8Array>()
  let buf: Uint8Array | null = null
  let bufOffset = 0

  for (const d of descriptors) {
    if (d.capturedLength === 0) {
      map.set(d.packetNumber, new Uint8Array(0))
      continue
    }
    const start = d.dataOffset
    const end = start + d.capturedLength
    if (!buf || start < bufOffset || end > bufOffset + buf.byteLength) {
      const windowSize = Math.max(end - start, HYDRATION_CHUNK_SIZE)
      const windowEnd = Math.min(start + windowSize, blob.size)
      const ab = await blob.slice(start, windowEnd).arrayBuffer()
      buf = new Uint8Array(ab)
      bufOffset = start
    }
    const localStart = start - bufOffset
    map.set(d.packetNumber, buf.slice(localStart, localStart + d.capturedLength))
  }
  return map
}
