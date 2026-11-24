import type { LineIndex } from '../lineIndex.ts'
import type { CustomRule, DetectorConfig, RawMatch } from '../../domain/types.ts'
import { DEFAULT_DETECTOR_CONFIG, PRIORITY } from '../../domain/types.ts'
import { normalizeByCategory } from '../normalize.ts'

export function detectCustomRules(
  text: string,
  lineIndex: LineIndex,
  config: DetectorConfig = DEFAULT_DETECTOR_CONFIG,
): RawMatch[] {
  const out: RawMatch[] = []
  for (const rule of config.customRules) {
    if (!rule.enabled) continue
    try {
      const found = runRule(text, lineIndex, rule)
      for (let i = 0; i < found.length; i++) out.push(found[i]!)
    } catch {
      // Invalid regex → skip (ARCHITECTURE: soft-fail with no matches for that rule)
    }
  }
  return out
}

function runRule(text: string, lineIndex: LineIndex, rule: CustomRule): RawMatch[] {
  const priority = Math.max(rule.priority, PRIORITY.customMin)
  const out: RawMatch[] = []

  if (rule.kind === 'literal') {
    const needle = rule.pattern
    if (!needle) return out
    const hay = rule.caseSensitive ? text : text.toLowerCase()
    const needleCmp = rule.caseSensitive ? needle : needle.toLowerCase()
    let from = 0
    while (from < hay.length) {
      const idx = hay.indexOf(needleCmp, from)
      if (idx < 0) break
      const end = idx + needle.length
      if (rule.wholeWord && !isWholeWord(text, idx, end)) {
        from = idx + 1
        continue
      }
      const original = text.slice(idx, end)
      if (!original.includes('\n') && !original.includes('\r')) {
        out.push(makeMatch(lineIndex, rule, priority, idx, end, original))
      }
      from = end
    }
    return out
  }

  // regex
  let flags = 'g'
  if (!rule.caseSensitive) flags += 'i'
  const re = new RegExp(rule.pattern, flags)
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++
      continue
    }
    const start = m.index
    const end = start + m[0].length
    if (rule.wholeWord && !isWholeWord(text, start, end)) continue
    const original = m[0]
    if (original.includes('\n') || original.includes('\r')) continue
    out.push(makeMatch(lineIndex, rule, priority, start, end, original))
  }
  return out
}

function makeMatch(
  lineIndex: LineIndex,
  rule: CustomRule,
  priority: number,
  start: number,
  end: number,
  original: string,
): RawMatch {
  return {
    start,
    end,
    line: lineIndex.lineAt(start),
    category: rule.category,
    original,
    normalized: normalizeByCategory(rule.category, original),
    detectorId: 'custom.rule',
    ruleId: rule.id,
    priority,
    confidence: 1,
  }
}

function isWholeWord(text: string, start: number, end: number): boolean {
  const before = start === 0 ? '' : text[start - 1]!
  const after = end >= text.length ? '' : text[end]!
  const word = /[A-Za-z0-9_]/
  if (before && word.test(before)) return false
  if (after && word.test(after)) return false
  return true
}
