/**
 * T31 — declarative wire-protocol descriptors (compile-time only; no runtime upload/eval).
 */

import type { IdentityCategory } from '../../../mapping/identityCategories.ts'

export const DESCRIPTOR_SCHEMA_VERSION = 1 as const

export type DescriptorEndian = 'be' | 'le'

export type DescriptorWireFormat =
  | 'u8'
  | 'u16'
  | 'u24'
  | 'u32'
  | 'bytes'
  | 'ascii'

export type FieldDisposition =
  | { readonly kind: 'preserve'; readonly reason: string }
  | {
      readonly kind: 'map'
      readonly category: IdentityCategory
      readonly format: DescriptorWireFormat
    }
  | { readonly kind: 'mask' }
  | { readonly kind: 'secret' }
  | {
      readonly kind: 'time'
      /** Absolute epoch seconds on the wire; shifted via PayloadTimeSession when available. */
      readonly format: 'unix-u32'
    }

export interface DescriptorField {
  readonly name: string
  /** Byte offset from start of the framed message (usually datagram payload). */
  readonly offset: number
  readonly length: number
  readonly disposition: FieldDisposition
}

export interface DescriptorMessageVariant {
  /** Discriminator on a header field (offset relative to message start). */
  readonly when: {
    readonly fieldOffset: number
    readonly fieldLength: 1
    readonly equals: number
  }
  readonly fields: readonly DescriptorField[]
  /**
   * Bytes after the last declared field up to message end.
   * Default mask (fail-closed). Opaque voice may use preserve with reason.
   */
  readonly trailing?:
    | { readonly kind: 'mask' }
    | { readonly kind: 'preserve'; readonly reason: string }
}

export interface WireProtocolDescriptor {
  readonly schemaVersion: typeof DESCRIPTOR_SCHEMA_VERSION
  readonly id: string
  readonly title: string
  /** Stable fingerprint of the authored schema (not of capture bytes). */
  readonly profileVersion: string
  readonly specRefs: readonly string[]
  readonly transport: {
    readonly udpPorts?: readonly number[]
    readonly tcpPorts?: readonly number[]
  }
  readonly framing: {
    readonly kind: 'fixed-magic'
    readonly endian: DescriptorEndian
    readonly magic: readonly number[]
    readonly headerLength: number
  }
  /** Union branches; first matching `when` wins. */
  readonly variants: readonly DescriptorMessageVariant[]
  /** Applied when no variant matches (unknown version/type) — always mask body. */
  readonly unknownVariant: {
    readonly headerFields: readonly DescriptorField[]
    readonly trailing: { readonly kind: 'mask' }
  }
}
