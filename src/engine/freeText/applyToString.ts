/**
 * T69 — apply free-text ops to a JS string (text mode / analyze).
 * All ops are length-preserving so line counts stay stable.
 */

import { maskAlphanumeric } from '../../mapping/textAliasEngine.ts'
import type { FreeTextOp } from './types.ts'

function maskFill(spelling: string): string {
  return maskAlphanumeric(spelling, 'x')
}

export type FreeTextMapResolver = (
  op: Extract<FreeTextOp, { kind: 'map' }>,
) => string

/**
 * Build anonymized text from ops. Preserve keeps original; map uses resolver;
 * mask uses length-stable `x` fill.
 */
export function applyFreeTextOpsToString(
  text: string,
  ops: readonly FreeTextOp[],
  resolveMap: FreeTextMapResolver,
): string {
  if (text.length === 0) return text
  const sorted = [...ops].sort((a, b) => a.start - b.start)
  const parts: string[] = []
  let cursor = 0
  for (const op of sorted) {
    if (op.start < cursor) continue
    if (op.start > cursor) parts.push(text.slice(cursor, op.start))
    const spelling = text.slice(op.start, op.end)
    if (op.kind === 'preserve') {
      parts.push(spelling)
    } else if (op.kind === 'mask') {
      parts.push(maskFill(spelling))
    } else {
      try {
        const alias = resolveMap(op)
        parts.push(alias.length === spelling.length ? alias : maskFill(spelling))
      } catch {
        parts.push(maskFill(spelling))
      }
    }
    cursor = op.end
  }
  if (cursor < text.length) parts.push(text.slice(cursor))
  return parts.join('')
}
