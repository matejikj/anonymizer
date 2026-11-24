/**
 * T69 — shared free-text sanitization contracts (text mode + PCAP).
 */

import type { IdentityCategory } from '../../mapping/identityCategories.ts'

export type FreeTextLevel = 'diagnostic' | 'high-privacy'

export type FreeTextPreserveReason =
  | 'structure'
  | 'vocabulary'
  | 'template'
  | 'safe-number'

export type FreeTextMaskReason =
  | 'high-privacy-token'
  | 'secret'
  | 'non-latin1'

export type FreeTextOp =
  | {
      readonly kind: 'preserve'
      readonly start: number
      readonly end: number
      readonly reason: FreeTextPreserveReason
    }
  | {
      readonly kind: 'map'
      readonly start: number
      readonly end: number
      readonly category: IdentityCategory
      readonly canonical: string
      readonly spelling: string
    }
  | {
      readonly kind: 'mask'
      readonly start: number
      readonly end: number
      readonly reason: FreeTextMaskReason
    }

export interface FreeTextVocabulary {
  /** Case-insensitive membership for neutral (non-identifying) words. */
  has(word: string): boolean
  readonly version: string
}

export interface FreeTextToken {
  readonly start: number
  readonly end: number
  readonly text: string
  readonly kind: 'word' | 'structure'
}
