import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { DEFAULT_DETECTOR_CONFIG, PRIORITY } from '../../domain/types.ts'
import { normalizeHostname } from '../normalize.ts'

/**
 * Hostname: labels ending with known suffixes (.local, .corp.example, …).
 * Does not match bare IPv4 (handled by IP detector).
 */
export function detectHostnames(
  text: string,
  lineIndex: LineIndex,
  config: DetectorConfig = DEFAULT_DETECTOR_CONFIG,
): RawMatch[] {
  const suffixes = [...config.hostnameSuffixes].sort((a, b) => b.length - a.length)
  const out: RawMatch[] = []
  const seen = new Set<string>()

  for (const suffix of suffixes) {
    const escaped = escapeRegExp(suffix)
    // FQDN-like: label(.label)* + suffix, not preceded by alnum or .
    const re = new RegExp(
      `(?<![A-Za-z0-9_.-])([A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?)*${escaped})(?![A-Za-z0-9_.-])`,
      'gi',
    )
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const original = m[1] ?? m[0]
      const start = m.index + (m[0].length - original.length)
      const end = start + original.length
      const key = `${start}:${end}`
      if (seen.has(key)) continue
      // Skip pure IPv4
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(original)) continue
      seen.add(key)
      out.push({
        start,
        end,
        line: lineIndex.lineAt(start),
        category: 'hostname',
        original,
        normalized: normalizeHostname(original),
        detectorId: 'builtin.hostname',
        priority: PRIORITY.hostname,
        confidence: 0.95,
      })
    }
  }
  return out
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
