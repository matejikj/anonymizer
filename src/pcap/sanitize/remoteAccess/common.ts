/**
 * T39 — shared helpers for remote-access / out-of-band sanitizers.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'

export function readU16be(buf: Uint8Array, o: number): number {
  return ((buf[o]! << 8) | buf[o + 1]!) >>> 0
}

export function readU32be(buf: Uint8Array, o: number): number {
  return (
    ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!) >>> 0
  )
}

export function readU32le(buf: Uint8Array, o: number): number {
  return (
    (buf[o]! | (buf[o + 1]! << 8) | (buf[o + 2]! << 16) | (buf[o + 3]! << 24)) >>> 0
  )
}

export function maskBytes(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
  protocol: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, protocol)
}

/** Length-preserving ASCII identity map (user-id / hostname). */
export function mapAsciiIdentity(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: 'user-id' | 'hostname',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  if (length <= 0) return
  const raw = new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
  const token = raw.replace(/\0+$/, '')
  if (!token) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-empty-id`, protocol)
    return
  }
  const canon = canonicalizeIdentity(category, token) ?? token
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, length, constraint, token)
  collector.addDeferred(
    offset,
    length,
    ({ mapping: live }) => {
      try {
        return computeFixedLengthAsciiBytes(
          offset,
          length,
          live.aliasFor(category, canon, constraint, token),
        )
      } catch {
        return createProtocolNeutralMaskFill({
          length,
          packetIndex,
          offset,
          domain: `${protocol}-${category}`,
        })
      }
    },
    { fallbackKind: 'text-x', protocol, category, packetIndex },
  )
  void mapping
}

export function asciiIndexOf(
  buffer: Uint8Array,
  offset: number,
  length: number,
  needle: string,
): number {
  const n = needle.length
  if (n === 0 || length < n) return -1
  const end = offset + length - n
  for (let i = offset; i <= end; i++) {
    let ok = true
    for (let j = 0; j < n; j++) {
      if (buffer[i + j]! !== needle.charCodeAt(j)) {
        ok = false
        break
      }
    }
    if (ok) return i
  }
  return -1
}
