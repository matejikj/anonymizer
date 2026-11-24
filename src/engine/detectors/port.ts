import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { PRIORITY } from '../../domain/types.ts'

/** IPv4:port, [IPv6]:port, and explicit port= / port keywords in log lines. */
const IPV4_PORT = /(?<=\d\.\d\.\d\.\d)(:\d{1,5})\b/g
const BRACKET_PORT = /(?<=\])(:\d{1,5})\b/g
const KEYWORD_PORT =
  /\b(?:port|srcport|dstport|lport|sport|dport|source[_-]?port|dest(?:ination)?[_-]?port)\s*[=:]?\s*(\d{1,5})\b/gi

function portNumber(original: string): number | null {
  const digits = original.replace(/\D/g, '')
  if (digits.length === 0) return null
  const n = Number.parseInt(digits, 10)
  if (!Number.isInteger(n) || n < 1 || n > 65535) return null
  return n
}

function pushMatch(
  out: RawMatch[],
  seen: Set<string>,
  lineIndex: LineIndex,
  start: number,
  end: number,
  original: string,
): void {
  const key = `${start}:${end}`
  if (seen.has(key)) return
  const n = portNumber(original)
  if (n === null) return
  seen.add(key)
  out.push({
    start,
    end,
    line: lineIndex.lineAt(start),
    category: 'port',
    original,
    normalized: String(n),
    detectorId: 'builtin.port',
    priority: PRIORITY.port,
    confidence: 0.9,
  })
}

export function detectPorts(text: string, lineIndex: LineIndex, _config?: DetectorConfig): RawMatch[] {
  const out: RawMatch[] = []
  const seen = new Set<string>()

  for (const re of [IPV4_PORT, BRACKET_PORT]) {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const original = m[1]!
      pushMatch(out, seen, lineIndex, m.index, m.index + original.length, original)
    }
  }

  KEYWORD_PORT.lastIndex = 0
  let km: RegExpExecArray | null
  while ((km = KEYWORD_PORT.exec(text)) !== null) {
    const original = km[1]!
    pushMatch(out, seen, lineIndex, km.index + km[0].length - original.length, km.index + km[0].length, original)
  }

  return out
}
