import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { PRIORITY } from '../../domain/types.ts'
import { normalizeEmail } from '../normalize.ts'

const EMAIL =
  /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)(?![A-Za-z0-9._%+-])/g

export function detectEmails(
  text: string,
  lineIndex: LineIndex,
  _config?: DetectorConfig,
): RawMatch[] {
  const out: RawMatch[] = []
  EMAIL.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = EMAIL.exec(text)) !== null) {
    const original = m[1] ?? m[0]
    const start = m.index + (m[0].length - original.length)
    const end = start + original.length
    // Skip sip:user@host that looks email-like but is SIP (no TLD with dot after @ domain of only IP)
    if (/^[^@]+@(?:\d{1,3}\.){3}\d{1,3}$/.test(original)) continue
    out.push({
      start,
      end,
      line: lineIndex.lineAt(start),
      category: 'email',
      original,
      normalized: normalizeEmail(original),
      detectorId: 'builtin.email',
      priority: PRIORITY.email,
      confidence: 0.98,
    })
  }
  return out
}
