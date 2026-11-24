/**
 * Build unified coverage from structural decode + sanitizer discovery (Stage 10).
 */

import type { AnalysisResult, PacketSummary } from '../protocols/analysis'
import type { PacketDiscoveryResult } from '../discovery/types'
import type { LayerCoverage } from '../sanitize/types'
import type { DecodedNode } from '../protocols/types'
import type { UnifiedCoverageModel, UnifiedLayerCoverage, UnifiedProtocolSummary } from './types'
import { dominantStatus, mergePacketSpans } from './mergeRules'
import { SANITIZER_PROTOCOL_IDS } from './protocolRegistry'

/** Every sanitizer span gets an empty `issues` array — share one instance instead of
 * allocating millions of identical empty arrays for a large capture. */
const EMPTY_ISSUES: readonly string[] = Object.freeze([])

export interface StructuralSpanInput {
  readonly packetIndex: number
  readonly protocol: string
  readonly offset: number
  readonly length: number
  readonly issues: readonly string[]
}

export function structuralSpansFromNode(packetIndex: number, node: DecodedNode, out: StructuralSpanInput[]): void {
  const length = node.range.end - node.range.start
  if (length > 0) {
    out.push({
      packetIndex,
      protocol: node.protocolId,
      offset: node.range.start,
      length,
      issues: node.issues,
    })
  }
  for (const child of node.children) {
    structuralSpansFromNode(packetIndex, child, out)
  }
}

function structuralStatus(issues: readonly string[]): UnifiedLayerCoverage['status'] {
  if (issues.some((i) => i.includes('malformed'))) return 'malformed'
  if (issues.some((i) => i.startsWith('unsupported'))) return 'unsupported'
  return 'covered'
}

function sanitizerToUnified(packetIndex: number, c: LayerCoverage): UnifiedLayerCoverage {
  return {
    packetIndex,
    protocol: c.protocol,
    source: 'sanitizer',
    offset: c.offset,
    length: c.length,
    status: c.status,
    issues: EMPTY_ISSUES,
  }
}

function structuralToUnified(s: StructuralSpanInput): UnifiedLayerCoverage {
  return {
    packetIndex: s.packetIndex,
    protocol: s.protocol,
    source: 'structural',
    offset: s.offset,
    length: s.length,
    status: structuralStatus(s.issues),
    issues: s.issues,
  }
}

function summaryFromPacket(
  packetIndex: number,
  summary: PacketSummary | undefined,
): UnifiedLayerCoverage[] {
  if (!summary) return []
  const out: UnifiedLayerCoverage[] = []
  if (summary.hasUnsupported) {
    out.push({
      packetIndex,
      protocol: 'link',
      source: 'structural',
      offset: 0,
      length: 0,
      status: 'unsupported',
      issues: summary.issues,
    })
  }
  for (const issue of summary.issues) {
    if (issue.startsWith('unsupported-linktype')) {
      out.push({
        packetIndex,
        protocol: 'link',
        source: 'structural',
        offset: 0,
        length: 0,
        status: 'unsupported',
        issues: [issue],
      })
    }
  }
  return out
}

export function buildUnifiedCoverageModel(input: {
  packetCount: number
  analysis: AnalysisResult
  packetDiscovery: readonly PacketDiscoveryResult[]
  structuralSpans?: readonly (readonly StructuralSpanInput[])[]
}): UnifiedCoverageModel {
  const perPacket: UnifiedLayerCoverage[][] = []
  const histogram = new Map<string, number>()
  let totalUnsupportedSpans = 0
  let totalTruncatedSpans = 0
  let totalHeuristicSpans = 0

  const protocolAcc = new Map<string, {
    // PF-12: a per-protocol Set<number> of every packet index only to report its cardinality
    // via .size below would grow to O(packets) memory per protocol. The outer loop below
    // visits packetIndex in strictly increasing order and processes all of a packet's spans
    // together before moving on, so a packet is "new" for a protocol exactly when its index
    // differs from the last one seen — a counter + last-seen index gives the same distinct
    // count without retaining every index.
    packetCount: number
    lastPacketIndex: number
    spanCount: number
    unsupportedCount: number
    structuralSpanCount: number
    sanitizerSpanCount: number
    dominantStatus: UnifiedLayerCoverage['status']
    issues: Set<string>
  }>()

  for (let packetIndex = 0; packetIndex < input.packetCount; packetIndex++) {
    const raw: UnifiedLayerCoverage[] = []

    const structural = input.structuralSpans?.[packetIndex]
    if (structural) {
      for (const s of structural) raw.push(structuralToUnified(s))
    }

    const summary = input.analysis.summaries[packetIndex]
    raw.push(...summaryFromPacket(packetIndex, summary))

    const discovery = input.packetDiscovery[packetIndex]
    if (discovery) {
      for (const c of discovery.coverage) raw.push(sanitizerToUnified(packetIndex, c))
      if (discovery.truncatedLength !== undefined) {
        raw.push({
          packetIndex,
          protocol: 'payload',
          source: 'sanitizer',
          offset: discovery.truncatedLength,
          length: 0,
          status: 'truncated',
          issues: [`truncated-at-${discovery.truncatedLength}`],
        })
      }
    }

    const merged = mergePacketSpans(raw)
    perPacket.push(merged)

    const protocolsInPacket = new Set<string>()
    for (const span of merged) {
      if (span.status === 'unsupported') totalUnsupportedSpans++
      if (span.status === 'truncated') totalTruncatedSpans++
      if (span.status === 'heuristic') totalHeuristicSpans++

      protocolsInPacket.add(span.protocol)

      let acc = protocolAcc.get(span.protocol)
      if (!acc) {
        acc = {
          packetCount: 0,
          lastPacketIndex: -1,
          spanCount: 0,
          unsupportedCount: 0,
          structuralSpanCount: 0,
          sanitizerSpanCount: 0,
          dominantStatus: 'covered',
          issues: new Set(),
        }
        protocolAcc.set(span.protocol, acc)
      }
      if (acc.lastPacketIndex !== packetIndex) {
        acc.packetCount++
        acc.lastPacketIndex = packetIndex
      }
      acc.spanCount++
      if (span.status === 'unsupported') acc.unsupportedCount++
      if (span.source === 'structural') acc.structuralSpanCount++
      if (span.source === 'sanitizer') acc.sanitizerSpanCount++
      acc.dominantStatus = dominantStatus(acc.dominantStatus, span.status)
      for (const iss of span.issues) acc.issues.add(iss)
    }

    for (const p of protocolsInPacket) {
      histogram.set(p, (histogram.get(p) ?? 0) + 1)
    }
  }

  // Ensure sanitizer registry protocols appear even with zero packets (Stage 10 checklist).
  for (const id of SANITIZER_PROTOCOL_IDS) {
    if (!protocolAcc.has(id)) {
      protocolAcc.set(id, {
        packetCount: 0,
        lastPacketIndex: -1,
        spanCount: 0,
        unsupportedCount: 0,
        structuralSpanCount: 0,
        sanitizerSpanCount: 0,
        dominantStatus: 'covered',
        issues: new Set(),
      })
    }
  }

  const byProtocol: UnifiedProtocolSummary[] = [...protocolAcc.entries()]
    .map(([protocol, acc]) => ({
      protocol,
      packetCount: acc.packetCount,
      spanCount: acc.spanCount,
      unsupportedCount: acc.unsupportedCount,
      structuralSpanCount: acc.structuralSpanCount,
      sanitizerSpanCount: acc.sanitizerSpanCount,
      dominantStatus: acc.dominantStatus,
      issues: [...acc.issues],
    }))
    .sort((a, b) => a.protocol.localeCompare(b.protocol))

  return {
    perPacket,
    byProtocol,
    histogram,
    totalUnsupportedSpans,
    totalTruncatedSpans,
    totalHeuristicSpans,
  }
}

export function unifiedSpansForPacket(model: UnifiedCoverageModel, packetIndex: number): readonly UnifiedLayerCoverage[] {
  return model.perPacket[packetIndex] ?? []
}

export function unifiedProtocols(model: UnifiedCoverageModel): readonly string[] {
  return model.byProtocol.map((p) => p.protocol)
}

export function packetHasProtocol(model: UnifiedCoverageModel, packetIndex: number, protocol: string): boolean {
  return (model.perPacket[packetIndex] ?? []).some((s) => s.protocol === protocol)
}

export function countUnsupportedFromUnified(model: UnifiedCoverageModel): number {
  return model.totalUnsupportedSpans
}
