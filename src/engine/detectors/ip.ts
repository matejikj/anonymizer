import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { PRIORITY } from '../../domain/types.ts'
import { normalizeIp } from '../normalize.ts'

const IPV4 =
  /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g

export function detectIps(text: string, lineIndex: LineIndex, _config?: DetectorConfig): RawMatch[] {
  const out: RawMatch[] = []
  IPV4.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = IPV4.exec(text)) !== null) {
    const original = m[0]
    const start = m.index
    const end = start + original.length
    out.push({
      start,
      end,
      line: lineIndex.lineAt(start),
      category: 'ip',
      original,
      normalized: normalizeIp(original),
      detectorId: 'builtin.ip',
      priority: PRIORITY.ip,
      confidence: 1,
    })
  }
  return out
}
