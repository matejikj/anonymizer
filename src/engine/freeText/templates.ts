/**
 * T69 — Drain-like template learning for free-text lines.
 *
 * A token position is template-safe only when the token is in the vocabulary at
 * that position across ≥ minSupport lines that share the same skeleton.
 * Templates NEVER allow a non-vocabulary word.
 */

import { tokenizeFreeText } from './tokenize.ts'
import type { FreeTextVocabulary } from './types.ts'

export interface TemplateLearnOptions {
  readonly minSupport?: number
}

/**
 * Skeleton: vocabulary words kept literally; other words replaced with `*`.
 * Structure is kept as-is so formatting stays discriminative.
 */
function lineSkeleton(line: string, vocabulary: FreeTextVocabulary): string {
  const tokens = tokenizeFreeText(line)
  let out = ''
  for (const t of tokens) {
    if (t.kind === 'structure') {
      out += t.text
      continue
    }
    out += vocabulary.has(t.text) ? t.text.toLowerCase() : '*'
  }
  return out
}

/**
 * Returns keys `"${tokenIndex}:${lower}"` for vocabulary tokens that are stable
 * across enough lines of the same Drain-like skeleton.
 */
export function learnTemplateSafeTokens(
  lines: readonly string[],
  vocabulary: FreeTextVocabulary,
  options: TemplateLearnOptions = {},
): ReadonlySet<string> {
  const minSupport = options.minSupport ?? 3
  type Acc = { count: number; vocabAtPos: Map<number, string> }
  const bySkeleton = new Map<string, Acc>()

  for (const line of lines) {
    if (line.length === 0) continue
    const skeleton = lineSkeleton(line, vocabulary)
    const tokens = tokenizeFreeText(line)
    let acc = bySkeleton.get(skeleton)
    if (!acc) {
      acc = { count: 0, vocabAtPos: new Map() }
      bySkeleton.set(skeleton, acc)
    }
    acc.count++
    let wordIndex = 0
    for (const t of tokens) {
      if (t.kind !== 'word') continue
      const lower = t.text.toLowerCase()
      if (vocabulary.has(lower)) {
        const prev = acc.vocabAtPos.get(wordIndex)
        if (prev === undefined) acc.vocabAtPos.set(wordIndex, lower)
        else if (prev !== lower) acc.vocabAtPos.set(wordIndex, '')
      }
      wordIndex++
    }
  }

  const safe = new Set<string>()
  for (const acc of bySkeleton.values()) {
    if (acc.count < minSupport) continue
    for (const [idx, word] of acc.vocabAtPos) {
      if (word.length > 0) safe.add(`${idx}:${word}`)
    }
  }
  return safe
}

export function templateKey(wordIndex: number, word: string): string {
  return `${wordIndex}:${word.toLowerCase()}`
}
