/**
 * Build anonymized packet bytes from plan — same path for preview and export.
 */

import type { PacketEnvelope, PacketTimestamp } from '../domain/types'
import type { PcapPlanPacket } from './planSnapshot'
import { recomputeChecksums } from '../checksums/engine'
import type { ChecksumReport } from '../checksums/types'
import { TimestampMapping } from '../anonymization/timestampMapping'

export function mapPacketTimestamp(ts: PacketTimestamp, mapping: TimestampMapping): PacketTimestamp {
  return mapping.mapTicks(ts)
}

/** Apply patches + truncation + timestamp; returns bytes only (preview path). */
export function buildAnonymizedBytes(
  original: PacketEnvelope,
  plan: PcapPlanPacket,
  timestampMapping: TimestampMapping,
  applyTimestamps: boolean,
): Uint8Array {
  const out = new Uint8Array(original.data)
  for (const patch of plan.patches) {
    out.set(patch.data, patch.offset)
  }
  let capturedLen = plan.truncatedLength ?? plan.originalCapturedLength
  const bytes = capturedLen < out.length ? out.slice(0, capturedLen) : out

  if (applyTimestamps) {
    // Timestamp is metadata on envelope, not in bytes — handled by caller on envelope
    void mapPacketTimestamp(original.timestamp, timestampMapping)
  }
  return bytes
}

export function buildExportEnvelope(
  original: PacketEnvelope,
  plan: PcapPlanPacket,
  timestampMapping: TimestampMapping,
  applyTimestamps: boolean,
): { envelope: PacketEnvelope; checksumReport: ChecksumReport } {
  const out = new Uint8Array(original.data)
  for (const patch of plan.patches) {
    out.set(patch.data, patch.offset)
  }
  const capturedLen = plan.truncatedLength ?? plan.originalCapturedLength
  const bytes = capturedLen < out.length ? out.subarray(0, capturedLen) : out.subarray(0, capturedLen)

  const checksumReport = recomputeChecksums(bytes, {
    linkType: plan.linkType,
    capturedLen: bytes.length,
    originalLen: plan.originalLength,
    patches: plan.patches,
    originalData: original.data.subarray(0, Math.min(original.data.length, bytes.length)),
  })

  const ts = applyTimestamps
    ? mapPacketTimestamp(original.timestamp, timestampMapping)
    : original.timestamp

  const envelope: PacketEnvelope = {
    packetNumber: original.packetNumber,
    timestamp: ts,
    capturedLength: bytes.length,
    originalLength: plan.originalLength,
    linkType: plan.linkType,
    interfaceId: plan.interfaceId,
    sectionIndex: plan.sectionIndex,
    fileOffset: original.fileOffset,
    data: bytes,
  }
  return { envelope, checksumReport }
}

/** Preview parity helper — must match export bytes for same plan. */
export function previewBytesFromPlan(
  original: PacketEnvelope,
  plan: PcapPlanPacket,
): Uint8Array {
  const out = new Uint8Array(original.data)
  for (const patch of plan.patches) {
    out.set(patch.data, patch.offset)
  }
  if (plan.truncatedLength !== undefined && plan.truncatedLength < out.length) {
    return out.slice(0, plan.truncatedLength)
  }
  return out
}
