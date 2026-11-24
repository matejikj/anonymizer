/**
 * T71 — apply T69 free-text allowlist on export so failed-rule gaps and
 * unmatched spans never leave originals (isolateRuleAndRestart remains).
 */

import type { Entity, PackedMatchIndex, ResolvedMatch } from '../../domain/types'
import { MappingAuthority } from '../../mapping/mappingAuthority'
import { applyFreeTextAnalyzePass } from '../../engine/freeText/analyzePass'
import {
  aggregateFreeTextOps,
  withAliasSuppressions,
  withFailedRules,
  type TextDispositionLedgerAggregate,
} from '../../engine/freeText/textDispositionLedger'
import { sanitizeFreeText } from '../../engine/freeText/sanitizeFreeText'
import { defaultFreeTextVocabulary } from '../../engine/freeText/vocabulary'
import { learnTemplateSafeTokens } from '../../engine/freeText/templates'
import { buildLineIndex } from '../../engine/lineIndex'
import type { ExportPlanSnapshot } from './replacementSnapshot'

function resolvedFromPacked(
  packed: PackedMatchIndex,
  entities: readonly Entity[],
): ResolvedMatch[] {
  const out: ResolvedMatch[] = []
  for (let i = 0; i < packed.starts.length; i++) {
    const ent = entities[packed.entityIndexes[i]!]
    if (!ent) continue
    const start = packed.starts[i]!
    const end = start + packed.lengths[i]!
    out.push({
      start,
      end,
      line: packed.lines[i]!,
      category: ent.category,
      original: ent.originalSample,
      normalized: ent.normalized,
      detectorId: 'export.packed',
      priority: 0,
      confidence: 1,
      entityKey: ent.key,
    })
  }
  return out
}

export function buildTextDispositionLedgerForExport(input: {
  readonly original: string
  readonly packed: PackedMatchIndex
  readonly entities: readonly Entity[]
  readonly failedRuleIds: readonly string[]
  readonly aliasSuppressedCount: number
}): TextDispositionLedgerAggregate {
  const matches = resolvedFromPacked(input.packed, input.entities)
  const skipRanges = matches.map((m) => ({ start: m.start, end: m.end }))
  const vocabulary = defaultFreeTextVocabulary()
  const lineIndex = buildLineIndex(input.original)
  const lines: string[] = []
  for (let line = 1; line <= lineIndex.lineCount; line++) lines.push(lineIndex.lineText(line))
  const ops = sanitizeFreeText({
    text: input.original,
    level: 'diagnostic',
    vocabulary,
    templateSafeTokens: learnTemplateSafeTokens(lines, vocabulary),
    skipRanges,
  })
  let ledger = aggregateFreeTextOps(ops)
  ledger = withAliasSuppressions(ledger, input.aliasSuppressedCount)
  ledger = withFailedRules(ledger, input.failedRuleIds.length)
  return ledger
}

/**
 * Rewrite unmatched spans via free-text; detector spans stay original so the
 * replacement plan can overlay category aliases / free-token fallbacks.
 */
export function applyFreeTextToExportSnapshot(
  snapshot: ExportPlanSnapshot,
  options?: { readonly failedRuleIds?: readonly string[] },
): ExportPlanSnapshot {
  const matches = resolvedFromPacked(snapshot.packed, snapshot.entities)
  const authority = new MappingAuthority()
  const withFree = applyFreeTextAnalyzePass({
    original: snapshot.original,
    matches,
    authority,
    level: 'diagnostic',
    sourceId: 'text-export-freetext',
  })
  void options
  if (withFree === snapshot.original) return snapshot
  return {
    ...snapshot,
    original: withFree,
    planRevision: snapshot.planRevision + 1,
  }
}
