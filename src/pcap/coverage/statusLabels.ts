import type { CoverageStatus } from '../sanitize/types'
import { cs } from '../../i18n/cs.ts'

const LABELS: Record<CoverageStatus, keyof typeof cs.pcap.coverage.status> = {
  covered: 'covered',
  redacted: 'redacted',
  unsupported: 'unsupported',
  truncated: 'truncated',
  'requires-reassembly': 'requiresReassembly',
  malformed: 'malformed',
  encrypted: 'encrypted',
  heuristic: 'heuristic',
  'preserved-unsafe': 'preservedUnsafe',
  'preserved-for-diagnostics': 'preservedForDiagnostics',
  'processing-failed': 'processingFailed',
}

export function coverageStatusLabel(status: CoverageStatus): string {
  const key = LABELS[status]
  return key ? cs.pcap.coverage.status[key] : status
}
