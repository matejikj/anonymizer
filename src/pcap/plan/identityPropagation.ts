/**
 * T66 — propagate known mapping identities into free-text PCAP bytes.
 * Runs at plan build (before T65 leak remediation) so preview === export.
 */

import type { PacketEnvelope } from '../domain/types'
import type { BytePatch } from '../sanitize/types'
import type { MappingSnapshot } from '../../mapping/types'
import { IdentityRegistry } from '../../mapping/identityRegistry'
import { formatTextAliasFromWire } from '../anonymization/wireTextFormat'
import { createProtocolNeutralMaskFill } from '../sanitize/maskFill'
import type { PcapPlanPacket, PcapPlanSnapshot } from '../export/planSnapshot'

function overlapsPatch(
  offset: number,
  length: number,
  patches: readonly BytePatch[],
): boolean {
  const end = offset + length
  for (const p of patches) {
    const pEnd = p.offset + p.data.length
    if (offset < pEnd && end > p.offset) return true
  }
  return false
}

function applyPatchesView(original: Uint8Array, patches: readonly BytePatch[]): Uint8Array {
  const out = new Uint8Array(original)
  for (const p of patches) {
    if (p.offset >= 0 && p.offset + p.data.length <= out.length) {
      out.set(p.data, p.offset)
    }
  }
  return out
}

function replacementBytes(
  category: import('../../mapping/identityCategories').IdentityCategory,
  alias: string,
  spelling: string,
  packetIndex: number,
  offset: number,
): Uint8Array {
  try {
    const fixed = formatTextAliasFromWire(category, alias, spelling.length, spelling)
    if (fixed.length === spelling.length) {
      const out = new Uint8Array(spelling.length)
      for (let i = 0; i < fixed.length; i++) out[i] = fixed.charCodeAt(i) & 0xff
      return out
    }
  } catch {
    // fall through to mask
  }
  return createProtocolNeutralMaskFill({
    length: spelling.length,
    packetIndex,
    offset,
    domain: 'identity-propagation',
  })
}

export interface IdentityPropagationSummary {
  readonly hits: number
  readonly packets: number
}

/**
 * Scan plan-applied packet bytes for known identity spellings and add
 * length-preserving map (or mask) patches. Skips spans already patched.
 */
export function propagateIdentitiesOnPlan(input: {
  readonly plan: PcapPlanSnapshot
  readonly packets: readonly PacketEnvelope[]
  readonly snapshot: MappingSnapshot
}): { readonly plan: PcapPlanSnapshot; readonly summary: IdentityPropagationSummary } {
  const registry = IdentityRegistry.fromMappingSnapshot(input.snapshot)
  if (registry.size === 0) {
    return { plan: input.plan, summary: { hits: 0, packets: 0 } }
  }

  let hits = 0
  const touched = new Set<number>()
  const nextPackets: PcapPlanPacket[] = input.plan.packets.map((planPkt) => {
    if (planPkt.drop) return planPkt
    const original = input.packets[planPkt.index]
    if (!original?.data?.length) return planPkt

    const view = applyPatchesView(original.data, planPkt.patches)
    const exportLen = planPkt.truncatedLength ?? view.length
    const slice = exportLen < view.length ? view.subarray(0, exportLen) : view
    const found = registry.findHitsInBytes(slice)
    if (found.length === 0) return planPkt

    let patches = [...planPkt.patches]
    for (const hit of found) {
      if (overlapsPatch(hit.start, hit.end - hit.start, patches)) continue
      const data = replacementBytes(
        hit.identity.category,
        hit.identity.alias,
        hit.spelling,
        planPkt.index,
        hit.start,
      )
      patches.push({ offset: hit.start, data })
      hits += 1
      touched.add(planPkt.packetNumber)
    }
    patches.sort((a, b) => a.offset - b.offset)
    return { ...planPkt, patches }
  })

  if (hits === 0) {
    return { plan: input.plan, summary: { hits: 0, packets: 0 } }
  }

  return {
    plan: {
      ...input.plan,
      packets: nextPackets,
      packetsWithChanges: nextPackets.reduce(
        (n, p) => n + (p.patches.length > 0 || p.truncatedLength !== undefined ? 1 : 0),
        0,
      ),
      identityPropagation: {
        hits,
        packets: touched.size,
      },
    },
    summary: { hits, packets: touched.size },
  }
}
