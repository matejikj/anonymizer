/**
 * T41 — shared helpers for messaging / telemetry sanitizers.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import { sanitizeHttpBody } from '../httpBody.ts'
import type { LayerCoverage } from '../types.ts'
import { looksLikeUspRecord, sanitizeUspRecord } from '../usp.ts'

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

export function mapAsciiIdentity(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: 'user-id' | 'hostname' | 'opaque-id',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  canonicalOverride?: string,
): void {
  if (length <= 0) return
  const raw = new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
  const token = raw.replace(/\0+$/g, '').replace(/^["']|["']$/g, '')
  if (!token) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-empty`, protocol)
    return
  }
  const canon = canonicalOverride ?? (canonicalizeIdentity(category, token) ?? token)
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

/**
 * Message body: JSON → HTTP JSON structured path; else text detectors; else mask.
 * Never leaves unverified content as passthrough.
 */
export function sanitizeMessageBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  highPrivacy: boolean,
): LayerCoverage[] {
  if (length <= 0) return []
  const coverage: LayerCoverage[] = []
  let i = offset
  const end = offset + length
  while (i < end && (buffer[i] === 0x20 || buffer[i] === 0x09 || buffer[i] === 0x0a || buffer[i] === 0x0d)) {
    i++
  }
  if (i >= end) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-body`, protocol)
    return [{ protocol: `${protocol}-body`, offset, length, status: 'redacted' }]
  }
  // T55 — USP Record over STOMP / messaging MTP
  if (looksLikeUspRecord(buffer, i, end - i)) {
    const usp = sanitizeUspRecord(buffer, i, end - i, collector, mapping, intents, packetIndex)
    if (usp) return [...usp.coverage]
  }
  const first = buffer[i]!
  if (first === 0x7b || first === 0x5b) {
    // `{` or `[` — report the real sanitizeHttpBody disposition (T63).
    const result = sanitizeHttpBody({
      buffer,
      bodyAbsOffset: offset,
      bodyLength: length,
      headers: { contentType: 'application/json', contentEncoding: null, transferEncoding: null },
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy,
    })
    coverage.push({
      protocol: `${protocol}-json`,
      offset,
      length,
      status: result.coverageStatus,
    })
    return coverage
  }
  // zlib/gzip magic → compressed, mask
  if (first === 0x78 || (first === 0x1f && i + 1 < end && buffer[i + 1] === 0x8b)) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-compressed`, protocol)
    coverage.push({
      protocol: `${protocol}-body`,
      offset,
      length,
      status: 'redacted',
    })
    return coverage
  }
  // T63 — until free-text allowlist (T69), mask entire text body in both levels.
  void highPrivacy
  maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-body`, protocol)
  coverage.push({ protocol: `${protocol}-body`, offset, length, status: 'redacted' })
  return coverage
}

export function readU16be(buf: Uint8Array, o: number): number {
  return ((buf[o]! << 8) | buf[o + 1]!) >>> 0
}

export function readU32be(buf: Uint8Array, o: number): number {
  return (
    ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!) >>> 0
  )
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

export function decodeAscii(buffer: Uint8Array, offset: number, length: number): string {
  return new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
}
