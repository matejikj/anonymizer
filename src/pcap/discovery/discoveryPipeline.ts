/**
 * Aggregate PCAP discovery from batched packet processing (Stage 8).
 */

import type { PacketEnvelope } from '../domain/types'
import type { SanitizationPolicy } from '../sanitize/types'
import { analyzePackets } from '../protocols/analysis'
import type { PacketInput } from '../sanitize/engine'
import { discoverPacket } from './discoverPacket'
import { CoapBlock2Session } from '../sanitize/industrial/coapBlock2Session.ts'
import { OpcuaChannelSession } from '../sanitize/industrial/opcuaChannelSession.ts'
import { MediaFlowIndex } from './mediaFlowIndex'
import type { CanonicalIdentity } from '../../mapping/types'
import { canonicalizePcapIdentity, defaultWireConstraint } from '../../mapping/pcapCanonical'
import { constraintKey } from '../../mapping/constraintKey'
import type { EntityCategory } from '../anonymization/entityRegistry'
import { mergePortFlowHints, type PortFlowHint } from '../anonymization/portPolicy.ts'
import type { ExactOccurrence, SourceDiscovery, TransformationIntent } from './types'
import {
  buildUnifiedCoverageModel,
  buildOccurrenceIndexFromIntents,
} from '../coverage'

export const DEFAULT_PROCESSING_BATCH_SIZE = 64

export interface DiscoverBatchOptions {
  batchSize?: number
  onProgress?: (packetsDone: number, packetsTotal: number) => void
  isCancelled?: () => boolean
  reassemblyContext?: import('../reassembly/types').ReassemblyContext
}

export function runDiscoveryPipeline(
  packets: readonly PacketEnvelope[],
  policy: SanitizationPolicy,
  generationId: string,
  sourceId: string,
  options: DiscoverBatchOptions = {},
): SourceDiscovery {
  const batchSize = options.batchSize ?? DEFAULT_PROCESSING_BATCH_SIZE
  const analysis = analyzePackets(packets)

  const allIntents: TransformationIntent[] = []
  const packetDiscovery = []
  const portFlowHints = new Map<string, PortFlowHint>()
  const mediaPortPairs = new Map<string, string>()
  const mediaFlowIndex = options.reassemblyContext?.mediaFlowIndex ?? new MediaFlowIndex()
  const coapBlock2 = new CoapBlock2Session()
  const opcuaChannel = new OpcuaChannelSession()

  for (let start = 0; start < packets.length; start += batchSize) {
    if (options.isCancelled?.()) {
      throw new Error('cancelled')
    }

    const end = Math.min(start + batchSize, packets.length)
    for (let i = start; i < end; i++) {
      const pkt = packets[i]!
      const input: PacketInput = {
        index: i,
        data: pkt.data,
        capturedLength: pkt.capturedLength,
        originalLength: pkt.originalLength,
        linkType: pkt.linkType,
      }
      packetDiscovery.push(discoverPacket(
        input,
        pkt.packetNumber,
        policy,
        mediaFlowIndex,
        options.reassemblyContext,
        { generationId, sourceId, coapBlock2, opcuaChannel },
      ))
      const pd = packetDiscovery[packetDiscovery.length - 1]!
      allIntents.push(...pd.intents)
      if (pd.portFlowHints) {
        for (const [canonical, flow] of pd.portFlowHints) {
          const merged = mergePortFlowHints(portFlowHints.get(canonical), flow)
          if (merged) portFlowHints.set(canonical, merged)
        }
      }
      if (pd.mediaPortPairs) {
        for (const [a, b] of pd.mediaPortPairs) {
          mediaPortPairs.set(a, b)
        }
      }
    }

    options.onProgress?.(end, packets.length)
  }

  coapBlock2.finalizeDiscovery(packetDiscovery)

  const exactOccurrences = buildExactOccurrences(
    analysis.entities,
    analysis.entityOccurrenceLists,
    allIntents,
    packets,
  )

  const unifiedCoverage = buildUnifiedCoverageModel({
    packetCount: packets.length,
    analysis,
    packetDiscovery,
    structuralSpans: analysis.structuralSpans,
  })

  const entityOccurrenceIndex = buildOccurrenceIndexFromIntents(
    analysis.entities,
    analysis.entityOccurrenceLists,
    allIntents
      .filter((i) => i.kind === 'entity-replacement')
      .map((i) => ({
        entityKey: `${i.category}:${i.canonical}`,
        packetIndex: i.packetIndex,
      })),
  )

  return {
    generationId,
    sourceId,
    totalPackets: packets.length,
    analysis,
    intents: allIntents,
    packetDiscovery,
    portFlowHints,
    mediaPortPairs,
    exactOccurrences,
    unifiedCoverage,
    entityOccurrenceIndex,
  }
}

export function identitiesFromDiscovery(discovery: SourceDiscovery): CanonicalIdentity[] {
  type ConstraintSlot = {
    constraint: CanonicalIdentity['constraint']
    spellings: Set<string>
    packetIndex: number
  }
  type IdentityAgg = {
    category: CanonicalIdentity['category']
    canonical: string
    byConstraint: Map<string, ConstraintSlot>
    portFlowHint?: PortFlowHint
    mediaMateCanonical?: string
  }

  const byIdentity = new Map<string, IdentityAgg>()

  const touch = (
    category: CanonicalIdentity['category'],
    canonical: string,
    constraint: CanonicalIdentity['constraint'],
    packetIndex: number,
    originalSpelling?: string,
  ) => {
    const idKey = `${category}:${canonical}`
    let agg = byIdentity.get(idKey)
    if (!agg) {
      agg = {
        category,
        canonical,
        byConstraint: new Map(),
        portFlowHint: category === 'port' ? discovery.portFlowHints.get(canonical) : undefined,
        mediaMateCanonical: category === 'port' ? discovery.mediaPortPairs.get(canonical) : undefined,
      }
      byIdentity.set(idKey, agg)
    }
    const ck = constraintKey(constraint)
    let slot = agg.byConstraint.get(ck)
    if (!slot) {
      slot = { constraint, spellings: new Set(), packetIndex }
      agg.byConstraint.set(ck, slot)
    }
    if (originalSpelling !== undefined && originalSpelling.length > 0) {
      slot.spellings.add(originalSpelling)
    }
  }

  for (const intent of discovery.intents) {
    if (intent.kind !== 'entity-replacement') continue
    touch(
      intent.category,
      intent.canonical,
      intent.constraint,
      intent.packetIndex,
      intent.originalSpelling,
    )
  }

  for (const entity of discovery.analysis.entities) {
    const category = entity.category as EntityCategory
    const canonical = canonicalizePcapIdentity(category, entity.value)
    if (canonical === null) continue
    const constraint = defaultWireConstraint(category, canonical)
    if (constraint === null) continue
    const packetIndex = discovery.analysis.entityOccurrenceLists.get(entity.key)?.[0] ?? entity.firstPacket
    touch(category, canonical, constraint, packetIndex)
  }

  const out: CanonicalIdentity[] = []
  for (const agg of byIdentity.values()) {
    for (const slot of agg.byConstraint.values()) {
      if (slot.spellings.size === 0) {
        out.push({
          category: agg.category,
          canonical: agg.canonical,
          constraint: slot.constraint,
          occurrence: { kind: 'packet', sourceId: discovery.sourceId, packetIndex: slot.packetIndex },
          portFlowHint: agg.portFlowHint,
          mediaMateCanonical: agg.mediaMateCanonical,
        })
        continue
      }
      for (const spelling of slot.spellings) {
        out.push({
          category: agg.category,
          canonical: agg.canonical,
          constraint: slot.constraint,
          originalSpelling: spelling,
          occurrence: { kind: 'packet', sourceId: discovery.sourceId, packetIndex: slot.packetIndex },
          portFlowHint: agg.portFlowHint,
          mediaMateCanonical: agg.mediaMateCanonical,
        })
      }
    }
  }
  return out
}

function buildExactOccurrences(
  entities: SourceDiscovery['analysis']['entities'],
  occurrenceLists: ReadonlyMap<string, readonly number[]>,
  intents: readonly TransformationIntent[],
  packets: readonly PacketEnvelope[],
): ExactOccurrence[] {
  const out: ExactOccurrence[] = []
  const seen = new Set<string>()

  for (const entity of entities) {
    const category = entity.category as EntityCategory
    const canonical = canonicalizePcapIdentity(category, entity.value)
    if (canonical === null) continue
    const indices = occurrenceLists.get(entity.key) ?? []
    for (const packetIndex of indices) {
      const sig = `${entity.key}:${packetIndex}`
      if (seen.has(sig)) continue
      seen.add(sig)
      const pkt = packets[packetIndex]
      out.push({
        entityKey: entity.key,
        category,
        canonical,
        packetIndex,
        packetNumber: pkt?.packetNumber ?? entity.firstPacket,
      })
    }
  }

  for (const intent of intents) {
    if (intent.kind !== 'entity-replacement') continue
    const entityKey = `${intent.category}:${intent.canonical}`
    const sig = `${entityKey}:${intent.packetIndex}`
    if (seen.has(sig)) continue
    seen.add(sig)
    const pkt = packets[intent.packetIndex]
    out.push({
      entityKey,
      category: intent.category,
      canonical: intent.canonical,
      packetIndex: intent.packetIndex,
      packetNumber: pkt?.packetNumber ?? intent.packetIndex,
    })
  }

  return out
}

export function summarizeDiscovery(discovery: SourceDiscovery) {
  return {
    generationId: discovery.generationId,
    sourceId: discovery.sourceId,
    totalPackets: discovery.totalPackets,
    decodedPackets: discovery.analysis.decodedPackets,
    entityCount: discovery.analysis.entities.length,
    intentCount: discovery.intents.length,
    entityOverflow: discovery.analysis.entityOverflow,
    coverage: discovery.analysis.coverage,
    entities: discovery.analysis.entities,
    summaries: discovery.analysis.summaries,
  }
}
