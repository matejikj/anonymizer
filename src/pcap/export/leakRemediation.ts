/**
 * T65 — auto-remediate leak hits on an immutable plan (preview === export).
 * Masks surviving originals in place; escalates to app-payload mask / L4 truncate.
 * Never embeds original values in summaries.
 */

import type { PacketEnvelope, PacketRecordDescriptor } from '../domain/types'
import type { BytePatch } from '../sanitize/types'
import { createProtocolNeutralMaskFill } from '../sanitize/maskFill'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import {
  scanBytesForLeaks,
  type LeakCategory,
  type LeakHitPosition,
  type LeakScanOriginal,
} from '../trust/leakScanner'
import type { PcapPlanPacket, PcapPlanSnapshot } from './planSnapshot'
import type { DispositionLedgerAggregate } from './dispositionLedger'
import { emptyDispositionAggregate } from './dispositionLedger'
import { hydrateDescriptorForExport } from './incremental/hydrateSlice'
import type { MappingSnapshot } from '../../mapping/types'
import { propagateIdentitiesOnPlan } from '../plan/identityPropagation'

export const LEAK_REMEDIATION_MAX_PASSES = 3

export interface AutoRemediationSummary {
  readonly occurrences: number
  readonly packets: number
  readonly byCategory: Readonly<Partial<Record<LeakCategory, number>>>
  readonly passes: number
  readonly escalatedPackets: number
}

export interface LeakRemediationResult {
  readonly plan: PcapPlanSnapshot
  readonly autoRemediated: AutoRemediationSummary
  readonly residualLeakHits: number
}

function emptySummary(passes = 0): AutoRemediationSummary {
  return {
    occurrences: 0,
    packets: 0,
    byCategory: {},
    passes,
    escalatedPackets: 0,
  }
}

function applyPatches(original: Uint8Array, patches: readonly BytePatch[], truncatedLength?: number): Uint8Array {
  const out = new Uint8Array(original)
  for (const p of patches) {
    if (p.offset >= 0 && p.offset + p.data.length <= out.length) {
      out.set(p.data, p.offset)
    }
  }
  if (truncatedLength !== undefined && truncatedLength < out.length) {
    return out.subarray(0, truncatedLength)
  }
  return out
}

function mergeMaskPatch(
  patches: readonly BytePatch[],
  packetIndex: number,
  offset: number,
  length: number,
): BytePatch[] {
  if (length <= 0) return [...patches]
  const data = createProtocolNeutralMaskFill({
    length,
    packetIndex,
    offset,
    domain: 'leak-remediation',
  })
  // Drop overlapping patches so the mask wins for this span.
  const end = offset + length
  const kept = patches.filter((p) => p.offset + p.data.length <= offset || p.offset >= end)
  return [...kept, { offset, data }].sort((a, b) => a.offset - b.offset)
}

/** Heuristic L4 header end: Ethernet + IPv4/IPv6 + UDP/TCP/SCTP minimum headers. */
export function estimateL4PayloadOffset(frame: Uint8Array): number {
  if (frame.length < 14) return 0
  const etherType = (frame[12]! << 8) | frame[13]!
  let off = 14
  if (etherType === 0x8100 && frame.length >= 18) {
    off = 18
  }
  if (off + 20 > frame.length) return off
  const ver = frame[off]! >> 4
  if (ver === 4) {
    const ihl = (frame[off]! & 0x0f) * 4
    const proto = frame[off + 9]!
    const ipEnd = off + Math.max(20, ihl)
    if (proto === 6) return Math.min(frame.length, ipEnd + 20) // TCP
    if (proto === 17) return Math.min(frame.length, ipEnd + 8) // UDP
    if (proto === 132) return Math.min(frame.length, ipEnd + 12) // SCTP
    return Math.min(frame.length, ipEnd)
  }
  if (ver === 6) {
    const next = frame[off + 6]!
    const ipEnd = off + 40
    if (next === 6) return Math.min(frame.length, ipEnd + 20)
    if (next === 17) return Math.min(frame.length, ipEnd + 8)
    if (next === 132) return Math.min(frame.length, ipEnd + 12)
    return Math.min(frame.length, ipEnd)
  }
  return off
}

function accumulateHits(
  summary: {
    occurrences: number
    packets: Set<number>
    byCategory: Record<string, number>
  },
  positions: readonly LeakHitPosition[],
): void {
  for (const hit of positions) {
    summary.occurrences += 1
    summary.packets.add(hit.packetNumber)
    summary.byCategory[hit.category] = (summary.byCategory[hit.category] ?? 0) + 1
  }
}

/**
 * Scan plan-applied packet bytes and add mask patches until leaks are gone
 * (max 3 passes), then escalate remaining packets.
 */
export function remediatePlanLeaks(input: {
  readonly plan: PcapPlanSnapshot
  readonly packets: readonly PacketEnvelope[]
  readonly originals: readonly LeakScanOriginal[]
  readonly maxPasses?: number
}): LeakRemediationResult {
  if (!input.originals.length) {
    return {
      plan: input.plan,
      autoRemediated: emptySummary(0),
      residualLeakHits: 0,
    }
  }

  const maxPasses = input.maxPasses ?? LEAK_REMEDIATION_MAX_PASSES
  const level: PcapAnonymizationLevel = input.plan.pcapLevel
  let packets: PcapPlanPacket[] = input.plan.packets.map((p) => ({ ...p, patches: [...p.patches] }))
  const totals = {
    occurrences: 0,
    packets: new Set<number>(),
    byCategory: {} as Record<string, number>,
    escalatedPackets: 0,
  }
  let passes = 0
  let residual = 0

  for (let pass = 0; pass < maxPasses; pass++) {
    passes = pass + 1
    const scanPackets = []
    for (const planPkt of packets) {
      if (planPkt.drop) continue
      const original = input.packets[planPkt.index]
      if (!original?.data?.length) continue
      const bytes = applyPatches(original.data, planPkt.patches, planPkt.truncatedLength)
      scanPackets.push({
        packetIndex: planPkt.index,
        packetNumber: planPkt.packetNumber,
        bytes,
        patches: planPkt.patches,
      })
    }

    const scan = scanBytesForLeaks({
      packets: scanPackets,
      originals: input.originals,
    })
    const positions = scan.positions ?? []
    residual = scan.leakHits
    if (positions.length === 0) {
      residual = 0
      break
    }

    accumulateHits(totals, positions)

    const byPacket = new Map<number, LeakHitPosition[]>()
    for (const hit of positions) {
      const list = byPacket.get(hit.packetIndex) ?? []
      list.push(hit)
      byPacket.set(hit.packetIndex, list)
    }

    packets = packets.map((planPkt) => {
      const hits = byPacket.get(planPkt.index)
      if (!hits?.length || planPkt.drop) return planPkt
      let patches = planPkt.patches
      for (const hit of hits) {
        patches = mergeMaskPatch(patches, planPkt.index, hit.offset, hit.length)
      }
      return { ...planPkt, patches }
    })
  }

  // Escalate packets that still leak after max passes.
  if (residual > 0) {
    const scanPackets = []
    for (const planPkt of packets) {
      if (planPkt.drop) continue
      const original = input.packets[planPkt.index]
      if (!original?.data?.length) continue
      scanPackets.push({
        packetIndex: planPkt.index,
        packetNumber: planPkt.packetNumber,
        bytes: applyPatches(original.data, planPkt.patches, planPkt.truncatedLength),
        patches: planPkt.patches,
      })
    }
    const scan = scanBytesForLeaks({ packets: scanPackets, originals: input.originals })
    const still = new Set((scan.positions ?? []).map((p) => p.packetIndex))
    residual = scan.leakHits

    if (still.size > 0) {
      packets = packets.map((planPkt) => {
        if (!still.has(planPkt.index) || planPkt.drop) return planPkt
        const original = input.packets[planPkt.index]
        if (!original?.data?.length) return planPkt
        totals.escalatedPackets += 1
        const l4 = estimateL4PayloadOffset(original.data)
        if (level === 'high-privacy') {
          // Truncate after L4 header.
          return {
            ...planPkt,
            truncatedLength: Math.min(l4, planPkt.truncatedLength ?? original.data.length),
          }
        }
        // Diagnostic: mask application payload in place (length-preserving).
        const payloadLen = original.data.length - l4
        if (payloadLen <= 0) return planPkt
        const patches = mergeMaskPatch(planPkt.patches, planPkt.index, l4, payloadLen)
        return { ...planPkt, patches }
      })

      // Final verification after escalation.
      const verifyPackets = []
      for (const planPkt of packets) {
        if (planPkt.drop) continue
        const original = input.packets[planPkt.index]
        if (!original?.data?.length) continue
        verifyPackets.push({
          packetIndex: planPkt.index,
          packetNumber: planPkt.packetNumber,
          bytes: applyPatches(original.data, planPkt.patches, planPkt.truncatedLength),
          patches: planPkt.patches,
        })
      }
      residual = scanBytesForLeaks({
        packets: verifyPackets,
        originals: input.originals,
      }).leakHits
    }
  }

  const autoRemediated: AutoRemediationSummary = {
    occurrences: totals.occurrences,
    packets: totals.packets.size,
    byCategory: totals.byCategory,
    passes,
    escalatedPackets: totals.escalatedPackets,
  }

  const remediationGeneration = (input.plan.leakRemediation?.passes ?? 0) + passes
  const plan: PcapPlanSnapshot = {
    ...input.plan,
    packets,
    packetsWithChanges: packets.reduce(
      (n, p) => n + (p.patches.length > 0 || p.truncatedLength !== undefined ? 1 : 0),
      0,
    ),
    leakRemediation: {
      passes: remediationGeneration,
      autoRemediated,
      residualLeakHits: residual,
    },
    dispositionLedger: mergeRemediationIntoLedger(
      input.plan.dispositionLedger ?? emptyDispositionAggregate(),
      autoRemediated,
    ),
  }

  return { plan, autoRemediated, residualLeakHits: residual }
}

function mergeRemediationIntoLedger(
  base: DispositionLedgerAggregate,
  rem: AutoRemediationSummary,
): DispositionLedgerAggregate {
  if (rem.occurrences === 0) return base
  const byDisposition = { ...base.byDisposition }
  byDisposition.mask = (byDisposition.mask ?? 0) + rem.occurrences
  const byReason = { ...base.byReason }
  byReason['leak-remediation'] = (byReason['leak-remediation'] ?? 0) + rem.occurrences
  return {
    ...base,
    byDisposition,
    byReason,
    residualMaskedBytes: base.residualMaskedBytes + rem.occurrences,
  }
}

async function hydratePlanEnvelopes(input: {
  readonly plan: PcapPlanSnapshot
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly sourceBlob: Blob
}): Promise<PacketEnvelope[]> {
  const envelopes: PacketEnvelope[] = new Array(input.plan.packets.length)
  for (const planPkt of input.plan.packets) {
    if (planPkt.drop) continue
    const descriptor = input.descriptors[planPkt.index]
    if (!descriptor) continue
    envelopes[planPkt.index] = await hydrateDescriptorForExport(input.sourceBlob, descriptor)
  }
  for (let i = 0; i < input.plan.packets.length; i++) {
    if (envelopes[i]) continue
    const planPkt = input.plan.packets[i]!
    const descriptor = input.descriptors[i]
    envelopes[i] = {
      packetNumber: planPkt.packetNumber,
      timestamp: planPkt.originalTimestamp,
      capturedLength: 0,
      originalLength: planPkt.originalLength,
      linkType: planPkt.linkType,
      interfaceId: planPkt.interfaceId,
      sectionIndex: planPkt.sectionIndex,
      fileOffset: descriptor?.dataOffset ?? 0,
      data: new Uint8Array(0),
    }
  }
  return envelopes
}

/**
 * Hydrate originals from the source blob, propagate known identities (T66),
 * then remediate residual leaks (T65). Used when plan was built without payloads.
 */
export async function hydrateAndRemediatePlan(input: {
  readonly plan: PcapPlanSnapshot
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly sourceBlob: Blob
  readonly originals: readonly LeakScanOriginal[]
  readonly mappingSnapshot?: MappingSnapshot
  readonly maxPasses?: number
}): Promise<LeakRemediationResult> {
  const needsHydrate =
    (input.originals.length > 0)
    || (input.mappingSnapshot !== undefined && input.plan.identityPropagation === undefined)
  if (!needsHydrate) {
    return {
      plan: input.plan,
      autoRemediated: emptySummary(0),
      residualLeakHits: 0,
    }
  }

  const envelopes = await hydratePlanEnvelopes(input)
  let plan = input.plan
  if (input.mappingSnapshot) {
    plan = propagateIdentitiesOnPlan({
      plan,
      packets: envelopes,
      snapshot: input.mappingSnapshot,
    }).plan
  }

  if (!input.originals.length) {
    return {
      plan,
      autoRemediated: emptySummary(0),
      residualLeakHits: 0,
    }
  }

  return remediatePlanLeaks({
    plan,
    packets: envelopes,
    originals: input.originals,
    maxPasses: input.maxPasses,
  })
}
