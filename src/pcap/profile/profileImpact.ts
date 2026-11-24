/**
 * Profile change impact classification (task-1 Stage 26 preview / Stage 16 exhaustiveness).
 */

import { assertNever } from '../../domain/assertNever.ts'

export const ProfileImpactKind = {
  Discovery: 'discovery',
  RepresentationPolicy: 'representation-policy',
  CoverageOnly: 'coverage-only',
  ExportOnly: 'export-only',
} as const

export type ProfileImpactKind = (typeof ProfileImpactKind)[keyof typeof ProfileImpactKind]

export interface ProfileImpact {
  readonly kind: ProfileImpactKind
  /** Human-readable reason key for i18n — not user-facing prose. */
  readonly reasonKey: string
}

export function profileImpactBlocksExport(impact: ProfileImpact): boolean {
  switch (impact.kind) {
    case ProfileImpactKind.Discovery:
    case ProfileImpactKind.RepresentationPolicy:
      return true
    case ProfileImpactKind.CoverageOnly:
    case ProfileImpactKind.ExportOnly:
      return false
    default:
      return assertNever(impact.kind, 'ProfileImpactKind')
  }
}
