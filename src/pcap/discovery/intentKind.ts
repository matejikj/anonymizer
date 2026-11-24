/**
 * Transformation intent kind helpers with compile-time exhaustiveness (Stage 16).
 */

import { assertNever } from '../../domain/assertNever.ts'
import type { TransformationIntent } from './types'

export type TransformationIntentKind = TransformationIntent['kind']

export function transformationIntentKindLabel(kind: TransformationIntentKind): string {
  switch (kind) {
    case 'entity-replacement':
      return 'entity-replacement'
    case 'fixed-redaction':
      return 'fixed-redaction'
    case 'truncation':
      return 'truncation'
    case 'drop-record':
      return 'drop-record'
    case 'mask-range':
      return 'mask-range'
    default:
      return assertNever(kind, 'TransformationIntentKind')
  }
}

export function countIntentsByKind(intents: readonly TransformationIntent[]): Record<TransformationIntentKind, number> {
  const counts: Record<TransformationIntentKind, number> = {
    'entity-replacement': 0,
    'fixed-redaction': 0,
    truncation: 0,
    'drop-record': 0,
    'mask-range': 0,
  }
  for (const intent of intents) {
    counts[intent.kind] += 1
  }
  return counts
}
