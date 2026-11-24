/**
 * Scan AI report for known pseudonyms using Aho-Corasick (Stage 22).
 */

import { RESOLVE_WORKSPACE_LIMITS } from '../../domain/capabilityContract'
import { AhoCorasick } from './ahoCorasick'
import type { AliasLookupIndex } from './aliasIndex'
import type { ReportFinding, ScanReportResult } from './types'

export function scanReportForPseudonyms(
  report: string,
  index: AliasLookupIndex,
): ScanReportResult {
  const scannedBytes = new TextEncoder().encode(report).byteLength
  if (scannedBytes > RESOLVE_WORKSPACE_LIMITS.maxAiReportBytes) {
    throw { code: 'resolve-report-too-large' as const, message: 'AI report exceeds size limit' }
  }

  const aliases = index.allAliases().filter((a) => a.length > 0)
  if (aliases.length === 0) {
    return { findings: [], truncated: false, scannedBytes }
  }

  const ac = new AhoCorasick(aliases)
  const rawMatches = ac.search(report)

  const seen = new Set<string>()
  const findings: ReportFinding[] = []
  let truncated = false

  for (const m of rawMatches) {
    const alias = aliases[m.patternIndex]!
    const key = `${m.start}:${m.end}:${alias}`
    if (seen.has(key)) continue
    seen.add(key)

    const candidates = index.lookupExact(alias)
    if (candidates.length === 0) continue

    const identityIds = new Set(candidates.map((c) => c.identityId))
    findings.push({
      start: m.start,
      end: m.end,
      alias,
      candidates,
      ambiguous: candidates.length > 1 || identityIds.size > 1 || candidates.some((c) => c.disposition === 'ambiguous-fixed'),
    })

    if (findings.length >= RESOLVE_WORKSPACE_LIMITS.maxAiReportFindings) {
      truncated = true
      break
    }
  }

  findings.sort((a, b) => a.start - b.start || a.end - b.end)
  return { findings, truncated, scannedBytes }
}
