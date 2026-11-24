/**
 * T56 — static schema descriptor types for schema-driven APER.
 * Compiled tables (T57/T58) consume these; no runtime ASN.1 download.
 */

import type { BitSpan } from './bitCursor.ts'

export type AperFieldRole = 'preserve' | 'map' | 'mask' | 'opaque'

export type AperTypeDesc =
  | { readonly kind: 'boolean' }
  | {
      readonly kind: 'integer'
      readonly lower: number
      readonly upper: number
      /** When true, value may use extension (normally-small / semi-constrained path omitted in baseline). */
      readonly extensible?: boolean
    }
  | {
      readonly kind: 'enumerated'
      readonly names: readonly string[]
      readonly extensible?: boolean
    }
  | {
      readonly kind: 'octet-string'
      readonly sizeLower: number
      readonly sizeUpper: number
    }
  | {
      readonly kind: 'bit-string'
      readonly sizeLower: number
      readonly sizeUpper: number
    }
  | {
      readonly kind: 'sequence'
      readonly fields: readonly AperFieldDesc[]
      readonly extensible?: boolean
    }
  | {
      readonly kind: 'choice'
      readonly alts: readonly AperFieldDesc[]
      readonly extensible?: boolean
    }
  | {
      readonly kind: 'sequence-of'
      readonly element: AperTypeDesc
      readonly sizeLower: number
      readonly sizeUpper: number
    }
  | {
      readonly kind: 'open-type'
      /** Nested type when known; else opaque container. */
      readonly contained?: AperTypeDesc
    }

export interface AperFieldDesc {
  readonly name: string
  readonly type: AperTypeDesc
  readonly optional?: boolean
  readonly role?: AperFieldRole
  /** Mapping category hint for identity leaves (opaque-id / …). */
  readonly mappingCategory?: string
}

export interface AperSchemaModule {
  readonly id: string
  readonly revision: string
  readonly root: AperTypeDesc
}

export interface DecodedLeaf {
  readonly path: string
  readonly role: AperFieldRole
  readonly mappingCategory: string | null
  readonly span: BitSpan
  readonly value: number | boolean | Uint8Array | string | null
}

export interface DecodeResult {
  readonly ok: boolean
  readonly leaves: readonly DecodedLeaf[]
  readonly issues: readonly { code: string; bitOffset: number }[]
  /** Total bits consumed from start. */
  readonly bitLength: number
}
