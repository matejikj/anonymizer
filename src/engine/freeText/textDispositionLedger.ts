/**
 * T71 — token-level disposition ledger for text mode.
 *
 * Gate is derived from this aggregate (not from “exposed” originals). Disabled
 * category aliases still map via free-token (D4); failed custom rules are gaps.
 */

import type { FreeTextOp } from './types.ts'

export const TEXT_DISPOSITIONS = [
  'preserve-safe',
  'map',
  'map-free-token',
  'mask',
  'gap-failed-rule',
] as const

export type TextDisposition = (typeof TEXT_DISPOSITIONS)[number]

export interface TextDispositionLedgerAggregate {
  readonly byDisposition: Readonly<Record<TextDisposition, number>>
  readonly tokenCount: number
  readonly failedRuleCount: number
  /** Category-alias suppressions that still received a free-token map (D4). */
  readonly aliasSuppressedCount: number
}

export function emptyTextDispositionAggregate(): TextDispositionLedgerAggregate {
  return {
    byDisposition: {
      'preserve-safe': 0,
      map: 0,
      'map-free-token': 0,
      mask: 0,
      'gap-failed-rule': 0,
    },
    tokenCount: 0,
    failedRuleCount: 0,
    aliasSuppressedCount: 0,
  }
}

export function aggregateFreeTextOps(
  ops: readonly FreeTextOp[],
  base: TextDispositionLedgerAggregate = emptyTextDispositionAggregate(),
): TextDispositionLedgerAggregate {
  const by = { ...base.byDisposition }
  let tokenCount = base.tokenCount
  for (const op of ops) {
    tokenCount += 1
    if (op.kind === 'preserve') by['preserve-safe'] += 1
    else if (op.kind === 'mask') by.mask += 1
    else if (op.category === 'free-token') by['map-free-token'] += 1
    else by.map += 1
  }
  return {
    byDisposition: by,
    tokenCount,
    failedRuleCount: base.failedRuleCount,
    aliasSuppressedCount: base.aliasSuppressedCount,
  }
}

export function withFailedRules(
  ledger: TextDispositionLedgerAggregate,
  failedRuleCount: number,
): TextDispositionLedgerAggregate {
  if (failedRuleCount <= 0) return ledger
  return {
    ...ledger,
    failedRuleCount,
    byDisposition: {
      ...ledger.byDisposition,
      'gap-failed-rule': ledger.byDisposition['gap-failed-rule'] + failedRuleCount,
    },
  }
}

export function withAliasSuppressions(
  ledger: TextDispositionLedgerAggregate,
  aliasSuppressedCount: number,
): TextDispositionLedgerAggregate {
  if (aliasSuppressedCount <= 0) return ledger
  return {
    ...ledger,
    aliasSuppressedCount,
    byDisposition: {
      ...ledger.byDisposition,
      'map-free-token': ledger.byDisposition['map-free-token'] + aliasSuppressedCount,
    },
  }
}

/**
 * Text gate from ledger: failed rules → WITH_GAPS; otherwise AI_READY.
 * NOT_AI_READY is never produced for text (I7 / T71).
 */
export function gateFromTextDispositionLedger(
  ledger: TextDispositionLedgerAggregate,
): 'AI_READY' | 'AI_READY_WITH_GAPS' {
  if (ledger.failedRuleCount > 0 || ledger.byDisposition.mask > 0) {
    return 'AI_READY_WITH_GAPS'
  }
  return 'AI_READY'
}
