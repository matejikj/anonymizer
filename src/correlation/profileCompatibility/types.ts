/**
 * Correlation profile compatibility types (Stage 26).
 * Pure domain — no React or worker imports.
 */

import type { RulesetConfig } from '../../domain/configSchema'
import type { SourceKind } from '../../domain/sourceArtifact'
import type { PcapProfile } from '../../pcap/profile/schema'
import type { CrossFormatCategory } from '../../mapping/crossFormat/types'

export const PROFILE_COMPATIBILITY_OUTCOME = {
  Compatible: 'compatible',
  SessionOverride: 'session-override',
  UncorrelatedCategory: 'uncorrelated-category',
  BlockingConflict: 'blocking-conflict',
} as const

export type ProfileCompatibilityOutcome =
  (typeof PROFILE_COMPATIBILITY_OUTCOME)[keyof typeof PROFILE_COMPATIBILITY_OUTCOME]

export type TextCategoryRepresentation =
  | { readonly kind: 'disabled' }
  | { readonly kind: 'generated'; readonly wireCompatible: boolean }
  | { readonly kind: 'fixed'; readonly value: string; readonly wireCompatible: boolean }

export type PcapCategoryRepresentation =
  | { readonly kind: 'disabled' }
  | { readonly kind: 'wire-valid' }
  | { readonly kind: 'preserved' }

export interface TextEffectivePolicy {
  readonly profileId: string
  readonly profileName: string
  readonly categories: Readonly<Record<CrossFormatCategory, TextCategoryRepresentation>>
  readonly discoveryHash: string
  readonly representationHash: string
}

export interface PcapEffectivePolicy {
  readonly profileId: string
  readonly profileName: string
  readonly categories: Readonly<Record<CrossFormatCategory, PcapCategoryRepresentation>>
  readonly discoveryHash: string
  readonly representationHash: string
}

export interface CorrelationEffectivePolicy {
  readonly text: TextEffectivePolicy | null
  readonly pcap: PcapEffectivePolicy | null
  readonly sourceKinds: readonly SourceKind[]
  readonly representationHash: string
  readonly discoveryHash: string
  readonly policyHash: string
}

export type ProfileConflictResolution =
  | { readonly kind: typeof PROFILE_COMPATIBILITY_OUTCOME.SessionOverride }
  | { readonly kind: typeof PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory }
  | { readonly kind: typeof PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict }

export interface ProfileCompatibilityConflict {
  readonly category: CrossFormatCategory
  readonly reasonKey: string
  readonly textRepresentation: TextCategoryRepresentation | null
  readonly pcapRepresentation: PcapCategoryRepresentation | null
  readonly resolutions: readonly ProfileConflictResolution[]
  readonly recommended: ProfileConflictResolution
}

export interface ProfileCompatibilityReport {
  readonly outcome: ProfileCompatibilityOutcome
  readonly policy: CorrelationEffectivePolicy
  readonly conflicts: readonly ProfileCompatibilityConflict[]
  readonly unresolved: readonly ProfileCompatibilityConflict[]
}

export interface CorrelationProfileInput {
  readonly sourceKinds: readonly SourceKind[]
  readonly textProfile?: RulesetConfig
  readonly pcapProfile?: PcapProfile
}

export interface SessionCategoryResolution {
  readonly category: CrossFormatCategory
  readonly outcome: typeof PROFILE_COMPATIBILITY_OUTCOME.SessionOverride
  | typeof PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory
}

export interface CorrelationSessionPolicy {
  readonly effectivePolicy: CorrelationEffectivePolicy
  readonly categoryResolutions: ReadonlyMap<CrossFormatCategory, SessionCategoryResolution>
  readonly crossFormatLinking: boolean
  readonly uncorrelatedCategories: ReadonlySet<CrossFormatCategory>
  readonly rebuildRequired: boolean
  readonly exportBlocked: boolean
}

export interface CompileCorrelationPolicyOptions {
  readonly sourceKinds: readonly SourceKind[]
  readonly textProfile?: RulesetConfig
  readonly pcapProfile?: PcapProfile
}
