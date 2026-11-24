/**
 * T69 — free-text pass for the sync analyze / text pipeline.
 *
 * Detector match spans are skipped (left as original) so a subsequent
 * `transform()` can overlay detector aliases. Remaining tokens use allowlist
 * sanitization; new map ops resolve through MappingAuthority.
 */

import type { ResolvedMatch } from '../../domain/types.ts'
import { MappingAuthority } from '../../mapping/mappingAuthority.ts'
import type { CanonicalIdentity } from '../../mapping/types.ts'
import { buildAliasLookup, mappingKey } from '../../mapping/types.ts'
import { maskAlphanumeric } from '../../mapping/textAliasEngine.ts'
import { buildLineIndex } from '../lineIndex.ts'
import { applyFreeTextOpsToString } from './applyToString.ts'
import { sanitizeFreeText } from './sanitizeFreeText.ts'
import { learnTemplateSafeTokens } from './templates.ts'
import { defaultFreeTextVocabulary } from './vocabulary.ts'
import type { FreeTextLevel, FreeTextOp } from './types.ts'

/**
 * Length-preserving free-text pass. Detector spans stay original so
 * `transform(result, matches, entities)` can still apply detector aliases.
 */
export function applyFreeTextAnalyzePass(input: {
  readonly original: string
  readonly matches: readonly ResolvedMatch[]
  readonly authority: MappingAuthority
  readonly level?: FreeTextLevel
  readonly sourceId?: string
}): string {
  const {
    original,
    matches,
    authority,
    level = 'diagnostic',
    sourceId = 'sync-analyze-freetext',
  } = input

  if (original.length === 0) return original

  const vocabulary = defaultFreeTextVocabulary()
  const lineIndex = buildLineIndex(original)
  const lines: string[] = []
  for (let line = 1; line <= lineIndex.lineCount; line++) {
    lines.push(lineIndex.lineText(line))
  }
  const templateSafeTokens = learnTemplateSafeTokens(lines, vocabulary)
  const skipRanges = matches.map((m) => ({ start: m.start, end: m.end }))

  const ops = sanitizeFreeText({
    text: original,
    level,
    vocabulary,
    templateSafeTokens,
    skipRanges,
  })

  const mapOps = ops.filter((o): o is Extract<FreeTextOp, { kind: 'map' }> => o.kind === 'map')
  if (mapOps.length === 0) {
    return applyFreeTextOpsToString(original, ops, (op) => maskAlphanumeric(op.spelling, 'x'))
  }

  const identities: CanonicalIdentity[] = []
  const seen = new Set<string>()
  for (const op of mapOps) {
    const key = `${op.category}:${op.canonical}`
    if (seen.has(key)) continue
    seen.add(key)
    identities.push({
      category: op.category,
      canonical: op.canonical,
      constraint: { kind: 'text-ascii', byteLength: op.spelling.length },
      originalSpelling: op.spelling,
      source: { detectorId: 'free-text.token' },
      occurrence: {
        kind: 'text',
        sourceId,
        line: lineIndex.lineAt(op.start),
        start: op.start,
        end: op.end,
      },
    })
  }

  const resolved = authority.resolve({
    generationId: sourceId,
    sourceId,
    identities,
  })

  if (!resolved.ok) {
    const masked = ops.map((op) =>
      op.kind === 'map'
        ? {
            kind: 'mask' as const,
            start: op.start,
            end: op.end,
            reason: 'high-privacy-token' as const,
          }
        : op,
    )
    return applyFreeTextOpsToString(original, masked, () => 'x')
  }

  const lookup = buildAliasLookup(resolved.snapshot)
  return applyFreeTextOpsToString(original, ops, (op) => {
    const alias = lookup.get(mappingKey(op.category, op.canonical))
    if (!alias) return maskAlphanumeric(op.spelling, 'x')
    if (alias.length === op.spelling.length) return alias
    return maskAlphanumeric(op.spelling, alias)
  })
}
