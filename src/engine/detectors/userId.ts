import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { DEFAULT_DETECTOR_CONFIG, PRIORITY } from '../../domain/types.ts'
import { normalizeUserId } from '../normalize.ts'

/**
 * Login / operator IDs: prefix + digits (e.g. disp1…disp24).
 */
export function detectUserIds(
  text: string,
  lineIndex: LineIndex,
  config: DetectorConfig = DEFAULT_DETECTOR_CONFIG,
): RawMatch[] {
  const out: RawMatch[] = []
  const seen = new Set<string>()

  for (const prefix of config.userIdPrefixes) {
    const re = new RegExp(`(?<![A-Za-z0-9_])(${escapeRegExp(prefix)}\\d+)(?![A-Za-z0-9_])`, 'gi')
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const original = m[1]!
      const start = m.index
      const end = start + original.length
      const key = `${start}:${end}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({
        start,
        end,
        line: lineIndex.lineAt(start),
        category: 'user-id',
        original,
        normalized: normalizeUserId(original),
        detectorId: 'builtin.userId',
        priority: PRIORITY.userId,
        confidence: 1,
      })
    }
  }
  return out
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
