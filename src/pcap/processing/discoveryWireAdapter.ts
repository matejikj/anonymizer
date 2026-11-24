/**
 * Rehydrate the slim, payload-free PCAP discovery model from worker DTOs.
 */

import { canonicalizePcapIdentity } from '../../mapping/pcapCanonical'
import { buildSessionCoverage } from '../coverage'
import type { ExactOccurrence, SourceDiscovery, TransformationIntent } from '../discovery/types'
import type { EntityCategory } from '../anonymization/entityRegistry'
import type { AnalysisResult } from '../protocols/analysis'
import type { PacketDiscoveryResult } from '../discovery/types'
import type { PortFlowHint } from '../anonymization/portPolicy.ts'
import type { WireSourceDiscoveryPayload } from './workerProtocol'

export function analysisFromWire(wire: WireSourceDiscoveryPayload): AnalysisResult {
  const summaries = wire.summaries as AnalysisResult['summaries']
  const histogram = new Map<string, number>()
  // Prefer wire.coverage packet counts (authoritative) — per-packet protocol lists on the
  // discover wire are intentionally slim for R10 heap.
  for (const entry of wire.coverage) {
    if (entry.packetCount > 0) histogram.set(entry.protocolId, entry.packetCount)
  }
  if (histogram.size === 0) {
    for (const summary of summaries) {
      for (const protocol of summary.protocols) {
        histogram.set(protocol, (histogram.get(protocol) ?? 0) + 1)
      }
    }
  }
  return {
    histogram: { counts: histogram },
    coverage: wire.coverage as AnalysisResult['coverage'],
    entities: wire.entities as AnalysisResult['entities'],
    summaries,
    totalPackets: wire.totalPackets,
    decodedPackets: wire.decodedPackets,
    unsupportedLinkTypes: new Set(),
    entityOverflow: wire.entityOverflow,
    structuralSpans: [],
    entityOccurrenceLists: new Map(
      (wire.entityOccurrences ?? []).map((entry) => [entry.entityKey, entry.packetIndices]),
    ),
  }
}

export function sourceDiscoveryFromWire(
  wire: WireSourceDiscoveryPayload,
  packetDiscovery: readonly PacketDiscoveryResult[],
): SourceDiscovery {
  const analysis = analysisFromWire(wire)
  const intents: TransformationIntent[] = wire.intents.map((intent) => ({
    kind: 'entity-replacement',
    packetIndex: intent.packetIndex,
    offset: intent.offset,
    byteLength: intent.byteLength,
    category: intent.category as EntityCategory,
    canonical: intent.canonical,
    constraint: intent.constraint,
    originalSpelling: intent.originalSpelling,
  }))
  const coverage = buildSessionCoverage({
    packetCount: wire.totalPackets,
    analysis,
    packetDiscovery,
    entityOccurrences: wire.entityOccurrences,
    entityIntents: wire.intents.map((intent) => ({
      category: intent.category,
      canonical: intent.canonical,
      packetIndex: intent.packetIndex,
    })),
  })

  const exactOccurrences: ExactOccurrence[] = []
  const seen = new Set<string>()
  for (const entity of analysis.entities) {
    const category = entity.category as EntityCategory
    const canonical = canonicalizePcapIdentity(category, entity.value)
    if (canonical === null) continue
    for (const packetIndex of coverage.entityOccurrenceIndex.packetsForEntity(entity.key)) {
      const signature = `${entity.key}:${packetIndex}`
      if (seen.has(signature)) continue
      seen.add(signature)
      exactOccurrences.push({
        entityKey: entity.key,
        category,
        canonical,
        packetIndex,
        packetNumber: analysis.summaries[packetIndex]?.packetNumber ?? entity.firstPacket,
      })
    }
  }
  for (const intent of wire.intents) {
    const entityKey = `${intent.category}:${intent.canonical}`
    const signature = `${entityKey}:${intent.packetIndex}`
    if (seen.has(signature)) continue
    seen.add(signature)
    exactOccurrences.push({
      entityKey,
      category: intent.category as EntityCategory,
      canonical: intent.canonical,
      packetIndex: intent.packetIndex,
      packetNumber: analysis.summaries[intent.packetIndex]?.packetNumber ?? intent.packetIndex,
    })
  }

  const portFlowHints = new Map<string, PortFlowHint>()
  for (const entry of wire.portFlowHints ?? []) {
    portFlowHints.set(entry.canonical, entry.flow as PortFlowHint)
  }

  return {
    generationId: wire.generationId,
    sourceId: wire.sourceId,
    totalPackets: wire.totalPackets,
    analysis,
    intents,
    packetDiscovery,
    portFlowHints,
    // Wire payload omits media mates today; empty map keeps identitiesFromDiscovery safe.
    mediaPortPairs: new Map<string, string>(),
    exactOccurrences,
    unifiedCoverage: coverage.unifiedCoverage,
    entityOccurrenceIndex: coverage.entityOccurrenceIndex,
  }
}
