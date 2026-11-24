/**
 * Display filter builder helpers — legacy filter chips → expression (step 2).
 */

export function expressionForChangedOnly(): string {
  return 'frame.changed == true'
}

export function expressionForIssueOnly(): string {
  return 'frame.issue == true'
}

export function expressionForProtocol(protocol: string): string {
  return protocol
}

export function expressionForPacketRange(from: number | null, to: number | null): string {
  const parts: string[] = []
  if (from != null) parts.push(`frame.number >= ${from}`)
  if (to != null) parts.push(`frame.number <= ${to}`)
  return parts.join(' and ')
}

export function expressionForEntity(entityKey: string): string {
  return `entity contains "${escapeString(entityKey)}"`
}

export function combineExpressions(parts: readonly string[]): string {
  return parts.filter((p) => p.trim().length > 0).join(' and ')
}

function escapeString(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** Entity pseudo-field handled in filterPacketIndices, not parser. */
export const ENTITY_FILTER_PREFIX = 'entity contains '

export function isEntityFilterExpression(expr: string): boolean {
  return expr.trim().toLowerCase().startsWith(ENTITY_FILTER_PREFIX)
}

export function entityKeyFromExpression(expr: string): string | null {
  const m = expr.trim().match(/^entity\s+contains\s+"((?:\\.|[^"\\])*)"/i)
  if (!m) return null
  return m[1]!.replace(/\\"/g, '"').replace(/\\\\/g, '\\')
}
