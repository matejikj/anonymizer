/**
 * On-demand packet hydration from Blob + descriptor for export (Stage 11).
 */

import type { PacketEnvelope, PacketRecordDescriptor } from '../../domain/types'
import { PCAP_RECORD_LIMITS } from '../../../domain/capabilityContract'
import { descriptorToEnvelope } from '../../preview/packetAccessor'

export async function hydrateDescriptorForExport(
  blob: Blob,
  descriptor: PacketRecordDescriptor,
): Promise<PacketEnvelope> {
  if (descriptor.capturedLength > PCAP_RECORD_LIMITS.maxRecordSize) {
    throw new Error(`Packet ${descriptor.packetNumber} exceeds export record size limit`)
  }
  let data: Uint8Array
  if (descriptor.capturedLength === 0) {
    data = new Uint8Array(0)
  } else {
    const ab = await blob.slice(descriptor.dataOffset, descriptor.dataOffset + descriptor.capturedLength).arrayBuffer()
    data = new Uint8Array(ab)
  }
  return descriptorToEnvelope(descriptor, data)
}

/**
 * PF-09: read-ahead window size, mirroring src/pcap/capture/packetHydration.ts's proven
 * fix for the same underlying cost — one Blob.slice().arrayBuffer() is a real async I/O
 * round-trip in the browser, and one per packet doesn't scale to real capture sizes.
 */
const EXPORT_HYDRATION_CHUNK_SIZE = 64 * 1024

/**
 * Stateful hydrator for the export loop, which visits descriptors in a single forward pass
 * (packet index order — ordinarily also ascending file/dataOffset order for an unmodified
 * capture). Reuses one read-ahead buffer across calls instead of paying a fresh Blob I/O
 * round-trip per packet. Falls back transparently (same cost as before, never worse) if a
 * descriptor's range isn't covered by the current window, e.g. because export order doesn't
 * match file order for some reason.
 */
export function createSequentialHydrator(blob: Blob): (descriptor: PacketRecordDescriptor) => Promise<PacketEnvelope> {
  let buf: Uint8Array | null = null
  let bufOffset = 0

  return async (descriptor: PacketRecordDescriptor): Promise<PacketEnvelope> => {
    if (descriptor.capturedLength > PCAP_RECORD_LIMITS.maxRecordSize) {
      throw new Error(`Packet ${descriptor.packetNumber} exceeds export record size limit`)
    }
    if (descriptor.capturedLength === 0) {
      return descriptorToEnvelope(descriptor, new Uint8Array(0))
    }
    const start = descriptor.dataOffset
    const end = start + descriptor.capturedLength
    if (!buf || start < bufOffset || end > bufOffset + buf.byteLength) {
      const windowSize = Math.max(end - start, EXPORT_HYDRATION_CHUNK_SIZE)
      const windowEnd = Math.min(start + windowSize, blob.size)
      const ab = await blob.slice(start, windowEnd).arrayBuffer()
      buf = new Uint8Array(ab)
      bufOffset = start
    }
    const localStart = start - bufOffset
    return descriptorToEnvelope(descriptor, buf.slice(localStart, localStart + descriptor.capturedLength))
  }
}

export async function hydrateDescriptorSlice(
  blob: Blob,
  descriptors: readonly PacketRecordDescriptor[],
  indices: readonly number[],
): Promise<PacketEnvelope[]> {
  const out: PacketEnvelope[] = []
  for (const index of indices) {
    out.push(await hydrateDescriptorForExport(blob, descriptors[index]!))
  }
  return out
}
