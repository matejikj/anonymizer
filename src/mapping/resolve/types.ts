/**
 * Resolve workspace domain types (Stage 22).
 */

import type { IdentityCategory } from '../identityCategories'
import type { AliasDisposition } from '../types'

export type ResolveMappingSource = 'active-session' | 'imported-bundle'

export interface ResolveLookupCandidate {
  readonly identityId: number
  readonly category: IdentityCategory
  readonly canonical: string
  readonly alias: string
  readonly disposition: AliasDisposition
  readonly occurrenceCount: number
}

export interface ExactLookupResult {
  readonly alias: string
  readonly candidates: readonly ResolveLookupCandidate[]
  readonly ambiguous: boolean
}

export interface ReportFinding {
  readonly start: number
  readonly end: number
  readonly alias: string
  readonly candidates: readonly ResolveLookupCandidate[]
  readonly ambiguous: boolean
}

export interface ScanReportResult {
  readonly findings: readonly ReportFinding[]
  readonly truncated: boolean
  readonly scannedBytes: number
}

export type ResolveErrorCode =
  | 'resolve-no-mapping'
  | 'resolve-alias-empty'
  | 'resolve-alias-too-long'
  | 'resolve-report-too-large'
  | 'resolve-not-found'

export interface ResolveError {
  readonly code: ResolveErrorCode
  readonly message: string
}
