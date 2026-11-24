/**
 * Export validation baseline comparison (Stage 13).
 * New structural errors introduced by export are blocking; pre-existing input issues are preserved in report.
 */

import type { ParseIssue } from '../../domain/types'
import { IssueSeverity } from '../../domain/types'
import type { ValidationResult } from '../../capture/validator'

/** Maps import/parser codes to export validator equivalents for baseline matching. */
const CODE_ALIASES: Readonly<Record<string, readonly string[]>> = {
  'pcap-truncated': ['val-truncated'],
  'pcap-incl-gt-orig': ['val-incl-gt-orig'],
  'pcap-record-too-large': ['val-exceeds-snaplen'],
  'pcapng-truncated': ['val-block-truncated', 'val-epb-data-overflow'],
  'pcapng-block-truncated': ['val-block-truncated'],
  'pcapng-trailing-mismatch': ['val-trailing-mismatch'],
  'pcapng-iface-ref': ['val-iface-ref'],
  'pcapng-cap-gt-orig': ['val-cap-gt-orig'],
  'pcapng-bad-bom': ['val-bad-bom'],
  'pcapng-block-len-min': ['val-block-len-min'],
  'pcapng-block-align': ['val-block-align'],
}

export interface ExportValidationOutcome {
  readonly valid: boolean
  readonly exportValidation: ValidationResult
  readonly exportIssues: readonly ParseIssue[]
  readonly newBlockingIssues: readonly ParseIssue[]
  readonly preservedBaselineIssues: readonly ParseIssue[]
  readonly validationValid: boolean
  readonly validationIssueCount: number
}

function codesMatch(baselineCode: string, exportCode: string): boolean {
  if (baselineCode === exportCode) return true
  const aliases = CODE_ALIASES[baselineCode]
  if (aliases?.includes(exportCode)) return true
  const reverse = CODE_ALIASES[exportCode]
  if (reverse?.includes(baselineCode)) return true
  const normBase = baselineCode.replace(/^(pcap|pcapng|val)-/, '')
  const normExport = exportCode.replace(/^(pcap|pcapng|val)-/, '')
  return normBase === normExport
}

function issueMatchesBaseline(exportIssue: ParseIssue, baseline: readonly ParseIssue[]): boolean {
  return baseline.some((b) => {
    if (!codesMatch(b.code, exportIssue.code)) return false
    if (b.packetNumber !== undefined && exportIssue.packetNumber !== undefined) {
      return b.packetNumber === exportIssue.packetNumber
    }
    return true
  })
}

/** Compare export validation result against input parse baseline. */
export function compareExportValidationToBaseline(
  baselineIssues: readonly ParseIssue[],
  exportValidation: ValidationResult,
): ExportValidationOutcome {
  const exportIssues = exportValidation.issues
  const structuralBaseline = baselineIssues.filter((i) => i.severity >= IssueSeverity.Warning)

  const newBlockingIssues = exportIssues.filter(
    (i) => i.severity >= IssueSeverity.Error && !issueMatchesBaseline(i, structuralBaseline),
  )

  const valid = newBlockingIssues.length === 0

  const issueCount =
    exportIssues.filter((i) => i.severity > IssueSeverity.Warning).length +
    structuralBaseline.filter((i) => i.severity > IssueSeverity.Warning).length

  return {
    valid,
    exportValidation,
    exportIssues,
    newBlockingIssues,
    preservedBaselineIssues: structuralBaseline,
    validationValid: valid,
    validationIssueCount: issueCount,
  }
}
