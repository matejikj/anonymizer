/**
 * Build locally annotated AI report from scan findings (Stage 22).
 * Caller must explicitly trigger — no automatic clipboard or network.
 */

import type { ReportFinding } from './types'

export interface AnnotatedReportOptions {
  readonly ambiguousLabel: string
  readonly notFoundLabel?: string
}

export function buildAnnotatedReport(
  report: string,
  findings: readonly ReportFinding[],
  options: AnnotatedReportOptions,
): string {
  if (findings.length === 0) return report

  const sorted = [...findings].sort((a, b) => b.start - a.start || b.end - a.end)
  let out = report

  for (const f of sorted) {
    if (f.start < 0 || f.end > out.length || f.start >= f.end) continue
    const replacement = formatReplacement(f, options)
    out = out.slice(0, f.start) + replacement + out.slice(f.end)
  }

  return out
}

function formatReplacement(finding: ReportFinding, options: AnnotatedReportOptions): string {
  if (finding.ambiguous || finding.candidates.length > 1) {
    const labels = finding.candidates.map((c) => `${c.canonical} (${c.category})`)
    return `${finding.alias} → ${options.ambiguousLabel}: ${labels.join('; ')}`
  }
  const c = finding.candidates[0]!
  return `${finding.alias} → ${c.canonical} (${c.category})`
}
