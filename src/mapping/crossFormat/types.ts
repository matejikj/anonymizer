/**
 * Cross-format identity contract types (Stage 25).
 */

import type { WireRepresentationConstraint } from '../types'

/** Monotonic version — unknown versions are rejected, never heuristically migrated. */
export const CROSS_FORMAT_CANONICALIZATION_VERSION = 1

/** Shared categories in the text ∩ PCAP intersection (T45 adds phone/email/user). */
export type CrossFormatCategory =
  | 'ipv4'
  | 'ipv6'
  | 'mac'
  | 'hostname'
  | 'port'
  | 'phone'
  | 'email'
  | 'user'

export type CrossFormatSourceKind = 'text' | 'pcap'

export interface CrossFormatCanonicalResult {
  readonly category: CrossFormatCategory
  readonly canonical: string
}

export interface RepresentationStrategy {
  readonly category: CrossFormatCategory
  readonly version: number
  readonly usesWireEngine: boolean
  readonly requiresTransportContext: boolean
}

export interface CrossFormatCategoryContract {
  readonly category: CrossFormatCategory
  readonly version: number
  readonly canonicalizer: (raw: string, source: CrossFormatSourceKind) => string | null
  readonly representation: RepresentationStrategy
  readonly propertyTestId: string
}

export type RepresentationCompatibility =
  | { readonly compatible: true; readonly sharedAlias: true }
  | { readonly compatible: true; readonly sharedAlias: false; readonly reason: string }
  | { readonly compatible: false; readonly reason: string }

export interface CrossFormatIdentityRef {
  readonly crossFormatKey: string
  readonly category: CrossFormatCategory
  readonly canonical: string
  readonly constraint: WireRepresentationConstraint
}
