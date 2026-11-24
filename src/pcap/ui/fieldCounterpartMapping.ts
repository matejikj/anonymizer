/**
 * Resolve Original↔Anonymized field/byte mapping without false matches.
 * Length-preserving patches map 1:1 by path/offset when both dissections share the node.
 */

import type { DissectionNode } from '../dissection/types'
import { nodeByPath } from '../dissection/types'
import type { PcapPlanPacket } from '../export/planSnapshot'

export type FieldCounterpartMapping =
  | {
      readonly kind: 'mapped'
      readonly fieldPath: string
      readonly byteOffset: number | null
      readonly byteLength: number
    }
  | { readonly kind: 'unmapped'; readonly reason: 'missing-path' | 'generated' | 'truncated' | 'dropped' | 'no-selection' }

export function mapFieldCounterpart(input: {
  readonly fieldPath: string | null
  readonly byteOffset: number | null
  readonly counterpartRoots: readonly DissectionNode[]
  readonly planPkt?: PcapPlanPacket | null
  readonly counterpartDropped?: boolean
}): FieldCounterpartMapping {
  if (input.counterpartDropped) {
    return { kind: 'unmapped', reason: 'dropped' }
  }
  if (!input.fieldPath && input.byteOffset === null) {
    return { kind: 'unmapped', reason: 'no-selection' }
  }
  if (input.planPkt?.truncatedLength !== undefined && input.byteOffset !== null) {
    if (input.byteOffset >= input.planPkt.truncatedLength) {
      return { kind: 'unmapped', reason: 'truncated' }
    }
  }
  if (!input.fieldPath) {
    // Offset-only selection: length-preserving patches keep absolute offsets.
    if (input.byteOffset === null) return { kind: 'unmapped', reason: 'no-selection' }
    return {
      kind: 'mapped',
      fieldPath: '',
      byteOffset: input.byteOffset,
      byteLength: 1,
    }
  }
  const node = nodeByPath(input.counterpartRoots, input.fieldPath)
  if (!node) return { kind: 'unmapped', reason: 'missing-path' }
  if (node.generated) return { kind: 'unmapped', reason: 'generated' }
  if (node.changeKind === 'truncated') return { kind: 'unmapped', reason: 'truncated' }
  return {
    kind: 'mapped',
    fieldPath: input.fieldPath,
    byteOffset: input.byteOffset ?? node.offset,
    byteLength: Math.max(1, node.length),
  }
}

/** Highlight range for a pane given shared selection + local dissection. */
export function highlightRangeForPane(input: {
  readonly fieldPath: string | null
  readonly byteOffset: number | null
  readonly roots: readonly DissectionNode[]
  readonly planPkt?: PcapPlanPacket | null
  readonly dropped?: boolean
}): { start: number; end: number } | null | 'unmapped' {
  const mapping = mapFieldCounterpart({
    fieldPath: input.fieldPath,
    byteOffset: input.byteOffset,
    counterpartRoots: input.roots,
    planPkt: input.planPkt,
    counterpartDropped: input.dropped,
  })
  if (mapping.kind === 'unmapped') {
    if (mapping.reason === 'no-selection') return null
    return 'unmapped'
  }
  if (mapping.fieldPath) {
    const node = nodeByPath(input.roots, mapping.fieldPath)
    if (node && node.length > 0) return { start: node.offset, end: node.offset + node.length }
  }
  if (mapping.byteOffset !== null) {
    return { start: mapping.byteOffset, end: mapping.byteOffset + mapping.byteLength }
  }
  return null
}
