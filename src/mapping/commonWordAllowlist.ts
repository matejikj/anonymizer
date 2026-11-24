/**
 * T66 / T70 — B2 common-word allowlist backed by the bundled free-text vocabulary.
 *
 * Identities whose spelling is in the vocabulary are NOT propagated across free
 * text (avoids rewriting “user”, “host”, …). Tokens shorter than 4 characters
 * still skip propagation (too ambiguous for cross-protocol hunting).
 *
 * Imports the generated blob only (no engine→mapping cycle via vocabulary.ts).
 */

import { FREE_TEXT_VOCABULARY_BLOB } from '../engine/freeText/vocabulary.generated.ts'

const WORD_SET: ReadonlySet<string> = (() => {
  const set = new Set<string>()
  const blob = FREE_TEXT_VOCABULARY_BLOB
  if (blob.length === 0) return set
  let start = 0
  for (let i = 0; i <= blob.length; i++) {
    if (i === blob.length || blob.charCodeAt(i) === 0) {
      if (i > start) set.add(blob.slice(start, i))
      start = i + 1
    }
  }
  return set
})()

/** True when `spelling` is a common non-identifying word (skip propagation). */
export function isCommonWordAllowlisted(spelling: string): boolean {
  const key = spelling.trim().toLowerCase()
  if (key.length < 4) return true
  return WORD_SET.has(key)
}
