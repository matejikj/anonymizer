import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { DEFAULT_DETECTOR_CONFIG, PRIORITY } from '../../domain/types.ts'
import { normalizeInternalId } from '../normalize.ts'

/**
 * Internal identifiers: MP_*, GRP_*, tenant '…'
 */
const TENANT = /tenant\s+'([^']+)'/gi

export function detectContextualIdentifiers(
  text: string,
  lineIndex: LineIndex,
  config: DetectorConfig = DEFAULT_DETECTOR_CONFIG,
): RawMatch[] {
  const out: RawMatch[] = []
  const seen = new Set<string>()

  for (const pattern of config.internalIdPatterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`)
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const original = m[0]
      const start = m.index
      const end = start + original.length
      push(out, seen, text, lineIndex, start, end, original)
    }
  }

  TENANT.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = TENANT.exec(text)) !== null) {
    const name = m[1]!
    const full = m[0]
    const start = m.index + full.indexOf(name)
    const end = start + name.length
    push(out, seen, text, lineIndex, start, end, name)
  }

  return out
}

function push(
  out: RawMatch[],
  seen: Set<string>,
  _text: string,
  lineIndex: LineIndex,
  start: number,
  end: number,
  original: string,
): void {
  const key = `${start}:${end}`
  if (seen.has(key)) return
  if (original.includes('\n') || original.includes('\r')) return
  seen.add(key)
  out.push({
    start,
    end,
    line: lineIndex.lineAt(start),
    category: 'internal-id',
    original,
    normalized: normalizeInternalId(original),
    detectorId: 'builtin.contextualIdentifier',
    priority: PRIORITY.internalId,
    confidence: 0.95,
  })
}
