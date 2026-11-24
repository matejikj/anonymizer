/**
 * T69 — free-text tokenizer (word vs structural spans).
 *
 * Complements textproto message framing: this splits a free-text *body* into
 * preservable structure and candidate identity tokens.
 */

import type { FreeTextToken } from './types.ts'

function isWordChar(code: number): boolean {
  // ASCII alnum + underscore + common Latin-1 letters used in CZ logs.
  return (
    (code >= 0x30 && code <= 0x39)
    || (code >= 0x41 && code <= 0x5a)
    || (code >= 0x61 && code <= 0x7a)
    || code === 0x5f
    || (code >= 0xc0 && code <= 0xff && code !== 0xd7 && code !== 0xf7)
  )
}

/**
 * Split `text` into alternating structure / word tokens covering [0, length).
 */
export function tokenizeFreeText(text: string): FreeTextToken[] {
  const out: FreeTextToken[] = []
  let i = 0
  while (i < text.length) {
    const start = i
    const code = text.charCodeAt(i)!
    if (isWordChar(code)) {
      i++
      while (i < text.length && isWordChar(text.charCodeAt(i)!)) i++
      out.push({ start, end: i, text: text.slice(start, i), kind: 'word' })
    } else {
      i++
      while (i < text.length && !isWordChar(text.charCodeAt(i)!)) i++
      out.push({ start, end: i, text: text.slice(start, i), kind: 'structure' })
    }
  }
  return out
}
