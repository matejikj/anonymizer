/**
 * T69 — allowlist-first free-text sanitization.
 *
 * Decision order per span: structure → vocabulary/template → typed → registry →
 * free-token (diagnostic) / mask (high-privacy).
 */

import type { IdentityRegistry } from '../../mapping/identityRegistry.ts'
import { tokenizeFreeText } from './tokenize.ts'
import { classifyDigitToken, findTypedSpans } from './typedValues.ts'
import { templateKey } from './templates.ts'
import type {
  FreeTextLevel,
  FreeTextOp,
  FreeTextVocabulary,
} from './types.ts'
import { defaultFreeTextVocabulary } from './vocabulary.ts'

export interface SanitizeFreeTextInput {
  readonly text: string
  readonly level: FreeTextLevel
  readonly vocabulary?: FreeTextVocabulary
  readonly registry?: IdentityRegistry | null
  /**
   * Keys from {@link learnTemplateSafeTokens} (`${wordIndex}:${lower}`).
   * Only vocabulary words can be template-safe (enforced here too).
   */
  readonly templateSafeTokens?: ReadonlySet<string>
  /** Absolute ranges already handled by a prior pass (auth, SIP display, …). */
  readonly skipRanges?: readonly { start: number; end: number }[]
}

function overlapsSkip(
  start: number,
  end: number,
  skips: readonly { start: number; end: number }[],
): boolean {
  for (const s of skips) {
    if (start < s.end && end > s.start) return true
  }
  return false
}

function normalizeFreeTokenCanonical(spelling: string): string {
  return spelling.toLowerCase()
}

/**
 * Produce ordered, non-overlapping ops covering the whole string (gaps that were
 * skipped are omitted so callers keep prior patches).
 */
export function sanitizeFreeText(input: SanitizeFreeTextInput): FreeTextOp[] {
  const {
    text,
    level,
    vocabulary = defaultFreeTextVocabulary(),
    registry = null,
    templateSafeTokens,
    skipRanges = [],
  } = input

  if (text.length === 0) return []

  const ops: FreeTextOp[] = []
  const typed = findTypedSpans(text)
  const covered = new Uint8Array(text.length)

  const mark = (start: number, end: number) => {
    for (let i = start; i < end; i++) covered[i] = 1
  }
  const isFree = (start: number, end: number) => {
    for (let i = start; i < end; i++) if (covered[i]) return false
    return true
  }

  for (const s of skipRanges) {
    const a = Math.max(0, s.start)
    const b = Math.min(text.length, s.end)
    if (b > a) mark(a, b)
  }

  for (const span of typed) {
    if (!isFree(span.start, span.end)) continue
    if (overlapsSkip(span.start, span.end, skipRanges)) continue
    if (span.forceMask) {
      ops.push({
        kind: 'mask',
        start: span.start,
        end: span.end,
        reason: 'secret',
      })
    } else {
      ops.push({
        kind: 'map',
        start: span.start,
        end: span.end,
        category: span.category,
        canonical: span.canonical,
        spelling: span.spelling,
      })
    }
    mark(span.start, span.end)
  }

  // T66 — known identities win over free-token / vocabulary for the same spelling.
  if (registry) {
    for (const hit of registry.findHitsInText(text)) {
      if (!isFree(hit.start, hit.end)) continue
      ops.push({
        kind: 'map',
        start: hit.start,
        end: hit.end,
        category: hit.identity.category,
        canonical: hit.identity.canonical,
        spelling: hit.spelling,
      })
      mark(hit.start, hit.end)
    }
  }

  const tokens = tokenizeFreeText(text)
  let wordIndex = 0
  for (const token of tokens) {
    if (token.kind === 'structure') {
      if (isFree(token.start, token.end)) {
        ops.push({
          kind: 'preserve',
          start: token.start,
          end: token.end,
          reason: 'structure',
        })
        mark(token.start, token.end)
      }
      continue
    }

    const idx = wordIndex++
    if (!isFree(token.start, token.end)) continue

    const lower = token.text.toLowerCase()
    const tmpl = templateSafeTokens?.has(templateKey(idx, lower)) === true
    if (tmpl && vocabulary.has(lower)) {
      ops.push({
        kind: 'preserve',
        start: token.start,
        end: token.end,
        reason: 'template',
      })
      mark(token.start, token.end)
      continue
    }

    if (vocabulary.has(lower)) {
      ops.push({
        kind: 'preserve',
        start: token.start,
        end: token.end,
        reason: 'vocabulary',
      })
      mark(token.start, token.end)
      continue
    }

    if (/^\d+$/.test(token.text) && classifyDigitToken(token.text) === 'preserve') {
      ops.push({
        kind: 'preserve',
        start: token.start,
        end: token.end,
        reason: 'safe-number',
      })
      mark(token.start, token.end)
      continue
    }

    if (/^\d+$/.test(token.text) || /^[0-9a-fA-F]+$/.test(token.text)) {
      ops.push({
        kind: 'map',
        start: token.start,
        end: token.end,
        category: 'opaque-id',
        canonical: token.text.toLowerCase(),
        spelling: token.text,
      })
      mark(token.start, token.end)
      continue
    }

    if (level === 'high-privacy') {
      ops.push({
        kind: 'mask',
        start: token.start,
        end: token.end,
        reason: 'high-privacy-token',
      })
    } else {
      ops.push({
        kind: 'map',
        start: token.start,
        end: token.end,
        category: 'free-token',
        canonical: normalizeFreeTokenCanonical(token.text),
        spelling: token.text,
      })
    }
    mark(token.start, token.end)
  }

  // Any unmarked gap (should be rare) → preserve structure bytes.
  let i = 0
  while (i < text.length) {
    if (covered[i]) {
      i++
      continue
    }
    let j = i + 1
    while (j < text.length && !covered[j]) j++
    ops.push({ kind: 'preserve', start: i, end: j, reason: 'structure' })
    mark(i, j)
    i = j
  }

  ops.sort((a, b) => a.start - b.start || a.end - b.end)
  return ops
}
