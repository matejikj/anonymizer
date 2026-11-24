/**
 * PCAP preview controller — generation-scoped LRU + async packet access (Stage 9).
 */

import type { PacketEnvelope, PacketRecordDescriptor } from '../domain/types'
import type { PcapPlanPacket } from '../export/planSnapshot'
import { PCAP_PREVIEW_LIMITS } from '../../domain/capabilityContract'
import { ByteBudgetLru } from './byteBudgetLru'
import { applyPlanPreview, hydrateDescriptor } from './packetAccessor'
import type { PcapSession } from '../ui/pcapSession'

export interface PacketPreview {
  original: PacketEnvelope
  anonymizedBytes: Uint8Array
}

interface PendingEntry {
  generation: number
  promise: Promise<PacketPreview | null>
}

let lru = new ByteBudgetLru<number, PacketPreview>(PCAP_PREVIEW_LIMITS.lruByteBudget)
let activeGeneration = 0
const pending = new Map<number, PendingEntry>()

export function getPreviewLruStats() {
  return lru.stats()
}

export function resetPreviewController(generation: number): void {
  activeGeneration = generation
  lru.clear()
  pending.clear()
}

export function cancelPendingPreviews(): void {
  pending.clear()
}

export async function fetchPacketPreview(
  session: PcapSession,
  packetIndex: number,
): Promise<PacketPreview | null> {
  if (packetIndex < 0 || packetIndex >= session.descriptors.length) return null

  const gen = session.generation
  const cached = lru.get(packetIndex)
  if (cached) return cached

  const existing = pending.get(packetIndex)
  if (existing && existing.generation === gen) return existing.promise

  const promise = loadPreview(session, packetIndex, gen)
  pending.set(packetIndex, { generation: gen, promise })
  try {
    return await promise
  } finally {
    const cur = pending.get(packetIndex)
    if (cur?.promise === promise) pending.delete(packetIndex)
  }
}

async function loadPreview(
  session: PcapSession,
  packetIndex: number,
  generation: number,
): Promise<PacketPreview | null> {
  if (generation !== activeGeneration || session.generation !== generation) return null

  const descriptor = session.descriptors[packetIndex]!
  const planPkt = session.plan.packets[packetIndex]
  if (!planPkt) return null

  const original = await hydrateDescriptor(session.sourceFile, descriptor)
  if (generation !== activeGeneration || session.generation !== generation) return null

  const anonymizedBytes = await counterpartOrPlanPreview(session, descriptor, original, planPkt)
  if (generation !== activeGeneration || session.generation !== generation) return null

  const preview: PacketPreview = { original, anonymizedBytes }
  lru.set(packetIndex, preview, original.data.byteLength + anonymizedBytes.byteLength)
  return preview
}

async function counterpartOrPlanPreview(
  session: PcapSession,
  descriptor: PacketRecordDescriptor,
  original: PacketEnvelope,
  planPkt: PcapPlanPacket,
): Promise<Uint8Array> {
  const counterpart = session.counterpartSource
  if (!counterpart) return applyPlanPreview(original, planPkt)

  const originalPacketNumber = counterpart.anonymizedToOriginal[descriptor.packetNumber]
  const counterpartDescriptor =
    originalPacketNumber != null && originalPacketNumber >= 0
      ? counterpart.byOriginalPacketNumber.get(originalPacketNumber)
      : undefined
  if (!counterpartDescriptor) return original.data

  const hydrated = await hydrateDescriptor(counterpart.blob, counterpartDescriptor)
  return hydrated.data
}

export function getPlanPacketMeta(session: PcapSession, packetIndex: number): {
  plan: PcapPlanPacket | null
  changed: boolean
} {
  const plan = session.plan.packets[packetIndex] ?? null
  const changed = !!plan && (plan.patches.length > 0 || plan.truncatedLength !== undefined || plan.drop)
  return { plan, changed }
}
