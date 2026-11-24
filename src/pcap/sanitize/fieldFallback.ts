/**
 * T04 — length-preserving field fallback fills when deferred mapping/patch fails.
 * Never NUL placeholders, never original bytes.
 */

import { assertNever } from '../../domain/assertNever.ts'
import { createMaskFill } from './maskFill.ts'

export const FIELD_FALLBACK_KINDS = ['digits', 'text-x', 'binary-mask'] as const
export type FieldFallbackKind = (typeof FIELD_FALLBACK_KINDS)[number]

export interface FieldFallbackRequest {
  readonly length: number
  readonly kind: FieldFallbackKind
  readonly packetIndex: number
  readonly offset: number
  /** Domain tag for binary-mask stream separation. */
  readonly domain?: string
}

/**
 * Choose fill kind for a mapped identity category when the sanitizer did not set one.
 * Numeric wire/text fields → digits; other ASCII → `x`; binary → mask stream.
 */
export function defaultFallbackKindForCategory(category: string | undefined): FieldFallbackKind {
  switch (category) {
    case 'port':
    case 'sdp-session-id':
    case 'imsi':
    case 'imei':
    case 'vlan':
    case 'radioId':
    case 'ssrc':
    case 'teid':
    case 'point-code':
      return 'digits'
    case 'opaque-id':
    case 'free-token':
    case 'snmp-engine-id':
      return 'text-x'
    case 'ssid':
      return 'binary-mask'
    case 'ipv4':
    case 'ipv6':
    case 'mac':
      return 'binary-mask'
    default:
      return category ? 'text-x' : 'binary-mask'
  }
}

/** Deterministic field-sized replacement bytes. */
export function createFieldFallbackBytes(request: FieldFallbackRequest): Uint8Array {
  const { length, kind, packetIndex, offset } = request
  if (length <= 0) return new Uint8Array(0)

  switch (kind) {
    case 'digits': {
      const out = new Uint8Array(length)
      let state = seed32(['field-fallback-digits', packetIndex, offset, length])
      for (let i = 0; i < length; i++) {
        state = xorshift32(state)
        out[i] = 0x30 + (state % 10)
      }
      return out
    }
    case 'text-x': {
      const out = new Uint8Array(length)
      out.fill(0x78) // 'x' — SIP-header-safe printable ASCII
      return out
    }
    case 'binary-mask':
      return createMaskFill({
        length,
        packetIndex,
        offset,
        domain: request.domain ?? 'field-fallback',
        mode: 'stream',
      })
    default:
      return assertNever(kind)
  }
}

const FNV_OFFSET = 0x811c9dc5
const FNV_PRIME = 0x01000193

function seed32(parts: readonly (string | number)[]): number {
  let h = FNV_OFFSET
  for (const part of parts) {
    const text = typeof part === 'number' ? `n:${part}` : part
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i) & 0xff
      h = Math.imul(h, FNV_PRIME)
    }
    h ^= 0xff
    h = Math.imul(h, FNV_PRIME)
  }
  return h === 0 ? 0x9e3779b9 : h >>> 0
}

function xorshift32(state: number): number {
  let x = state >>> 0
  x ^= x << 13
  x ^= x >>> 17
  x ^= x << 5
  return x >>> 0
}
