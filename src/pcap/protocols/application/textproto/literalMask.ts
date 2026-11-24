/**
 * T15 — length-preserving literal maskers for nested languages (SQL / key=value).
 * JSON bodies continue to use `httpBody.findJsonStringSpans` (avoid import cycle).
 * PostgreSQL dialect includes tagged dollar-quotes (`$$…$$`, `$tag$…$tag$`).
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import { patchFixedLengthAscii } from '../../../sanitize/textPatch'

const MASK_FILLER = 0x78 // 'x'

export type SqlLiteralDialect = 'generic' | 'postgres' | 'mysql' | 'unknown'

export interface FindSqlLiteralOptions {
  readonly dialect?: SqlLiteralDialect
}

export interface LiteralMaskSpan {
  readonly absoluteOffset: number
  readonly byteLength: number
  readonly kind: 'sql-string' | 'sql-number' | 'sql-comment' | 'sql-dollar-string' | 'kv-value'
}

/**
 * True when text may contain a PostgreSQL dollar-quoted literal start (`$$` or `$tag$`).
 */
export function looksLikePostgresDollarQuote(text: string, from = 0): boolean {
  for (let i = from; i < text.length; i++) {
    if (text[i] !== '$') continue
    const tag = readDollarTag(text, i)
    if (tag !== null) return true
  }
  return false
}

/**
 * Find SQL string/number/comment literals.
 * Dialect `postgres` adds dollar-quoting; `unknown` returns no spans (caller must mask).
 * Keywords and bare identifiers are left alone.
 */
export function findSqlLiteralSpans(
  body: Uint8Array,
  bodyAbsOffset: number,
  options?: FindSqlLiteralOptions,
): LiteralMaskSpan[] {
  const dialect: SqlLiteralDialect = options?.dialect ?? 'generic'
  if (dialect === 'unknown') return []

  const text = new TextDecoder('latin1').decode(body)
  if (text.length !== body.length) return []
  const spans: LiteralMaskSpan[] = []
  let i = 0
  while (i < text.length) {
    const ch = text[i]!

    if (dialect === 'postgres' && ch === '$') {
      const tag = readDollarTag(text, i)
      if (tag !== null) {
        const openLen = tag.length
        const contentStart = i + openLen
        const close = text.indexOf(tag, contentStart)
        if (close < 0) {
          // Unclosed dollar quote — treat remainder as literal content (fail-closed for caller)
          const innerLen = text.length - contentStart
          if (innerLen > 0) {
            spans.push({
              absoluteOffset: bodyAbsOffset + contentStart,
              byteLength: innerLen,
              kind: 'sql-dollar-string',
            })
          }
          i = text.length
          continue
        }
        const innerLen = close - contentStart
        if (innerLen > 0) {
          spans.push({
            absoluteOffset: bodyAbsOffset + contentStart,
            byteLength: innerLen,
            kind: 'sql-dollar-string',
          })
        }
        i = close + openLen
        continue
      }
      // Lone `$` — not a dollar quote; fall through
    }

    if (ch === '\'' || ch === '"') {
      const quote = ch
      const start = i
      i++
      while (i < text.length) {
        if (text[i] === '\\' && i + 1 < text.length && dialect !== 'postgres') {
          // MySQL/generic backslash escape; postgres standard_conforming_strings uses ''
          i += 2
          continue
        }
        if (text[i] === quote) {
          // SQL doubled quote escape
          if (i + 1 < text.length && text[i + 1] === quote) {
            i += 2
            continue
          }
          i++
          break
        }
        i++
      }
      const innerStart = start + 1
      const innerLen = Math.max(0, i - 1 - innerStart)
      if (innerLen > 0) {
        spans.push({
          absoluteOffset: bodyAbsOffset + innerStart,
          byteLength: innerLen,
          kind: 'sql-string',
        })
      }
      continue
    }
    if (ch === '-' && text[i + 1] === '-') {
      const start = i
      i += 2
      while (i < text.length && text[i] !== '\n' && text[i] !== '\r') i++
      const len = i - start
      if (len > 2) {
        spans.push({
          absoluteOffset: bodyAbsOffset + start + 2,
          byteLength: len - 2,
          kind: 'sql-comment',
        })
      }
      continue
    }
    if (ch === '/' && text[i + 1] === '*') {
      const start = i
      i += 2
      while (i + 1 < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++
      if (i + 1 < text.length) i += 2
      const contentStart = start + 2
      const contentLen = Math.max(0, i - 2 - contentStart)
      if (contentLen > 0) {
        spans.push({
          absoluteOffset: bodyAbsOffset + contentStart,
          byteLength: contentLen,
          kind: 'sql-comment',
        })
      }
      continue
    }
    if (/\d/.test(ch) && (i === 0 || /[^\w.]/.test(text[i - 1]!))) {
      const start = i
      while (i < text.length && /[\d.]/.test(text[i]!)) i++
      spans.push({
        absoluteOffset: bodyAbsOffset + start,
        byteLength: i - start,
        kind: 'sql-number',
      })
      continue
    }
    i++
  }
  return spans
}

/**
 * Parse `$tag$` or `$$` at `index`. Returns the full delimiter including dollars, or null.
 */
function readDollarTag(text: string, index: number): string | null {
  if (text[index] !== '$') return null
  if (text[index + 1] === '$') return '$$'
  // $[A-Za-z_][A-Za-z0-9_]*$
  if (index + 2 >= text.length) return null
  const first = text[index + 1]!
  if (!/[A-Za-z_]/.test(first)) return null
  let j = index + 2
  while (j < text.length && /[A-Za-z0-9_]/.test(text[j]!)) j++
  if (j >= text.length || text[j] !== '$') return null
  return text.slice(index, j + 1)
}

/**
 * Whether zero found spans still require fail-closed masking for this dialect/body.
 * Postgres with a dollar-quote start but no dollar span → incomplete grammar → mask.
 */
export function sqlDialectRequiresMaskWhenNoLiterals(
  dialect: SqlLiteralDialect,
  body: Uint8Array,
): boolean {
  if (dialect === 'unknown') return true
  if (dialect !== 'postgres') return false
  const text = new TextDecoder('latin1').decode(body)
  return looksLikePostgresDollarQuote(text)
}

/** key=value pairs separated by `&` or `;` or whitespace — mask values only. */
export function findKeyValueValueSpans(body: Uint8Array, bodyAbsOffset: number): LiteralMaskSpan[] {
  const text = new TextDecoder('latin1').decode(body)
  if (text.length !== body.length) return []
  const spans: LiteralMaskSpan[] = []
  const re = /(?:^|[;&\s])([A-Za-z_][\w-]*)=([^\s;&]*)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const value = m[2]!
    if (value.length === 0) continue
    const valueIndex = m.index + m[0]!.lastIndexOf(value)
    spans.push({
      absoluteOffset: bodyAbsOffset + valueIndex,
      byteLength: value.length,
      kind: 'kv-value',
    })
  }
  return spans
}

/** Apply 'x' fill to literal spans (length-preserving). */
export function maskLiteralSpans(collector: PatchCollector, spans: readonly LiteralMaskSpan[]): void {
  for (const span of spans) {
    if (span.byteLength <= 0) continue
    patchFixedLengthAscii(collector, span.absoluteOffset, span.byteLength, '', MASK_FILLER)
  }
}
