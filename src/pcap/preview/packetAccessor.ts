/**
 * On-demand packet hydration from File/Blob + plan application (Stage 9).
 */

import type { PacketEnvelope, PacketRecordDescriptor } from '../domain/types'
import type { PcapPlanPacket } from '../export/planSnapshot'
import { previewBytesFromPlan } from '../export/packetBuilder'
import { PCAP_PREVIEW_LIMITS } from '../../domain/capabilityContract'

export async function hydrateDescriptor(
  blob: Blob,
  descriptor: PacketRecordDescriptor,
): Promise<PacketEnvelope> {
  let data: Uint8Array
  if (descriptor.capturedLength === 0) {
    data = new Uint8Array(0)
  } else if (descriptor.capturedLength > PCAP_PREVIEW_LIMITS.maxPacketBytes) {
    throw new Error(`Packet ${descriptor.packetNumber} exceeds preview size limit`)
  } else {
    const ab = await blob.slice(descriptor.dataOffset, descriptor.dataOffset + descriptor.capturedLength).arrayBuffer()
    data = new Uint8Array(ab)
  }
  return {
    packetNumber: descriptor.packetNumber,
    timestamp: descriptor.timestamp,
    capturedLength: descriptor.capturedLength,
    originalLength: descriptor.originalLength,
    linkType: descriptor.linkType,
    interfaceId: descriptor.interfaceId,
    sectionIndex: descriptor.sectionIndex,
    fileOffset: descriptor.fileOffset,
    data,
  }
}

export function applyPlanPreview(original: PacketEnvelope, plan: PcapPlanPacket): Uint8Array {
  return previewBytesFromPlan(original, plan)
}

export function descriptorToEnvelope(descriptor: PacketRecordDescriptor, data: Uint8Array): PacketEnvelope {
  return {
    packetNumber: descriptor.packetNumber,
    timestamp: descriptor.timestamp,
    capturedLength: descriptor.capturedLength,
    originalLength: descriptor.originalLength,
    linkType: descriptor.linkType,
    interfaceId: descriptor.interfaceId,
    sectionIndex: descriptor.sectionIndex,
    fileOffset: descriptor.fileOffset,
    data,
  }
}
