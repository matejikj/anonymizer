/**
 * T30 — shared helpers for industrial / IoT sanitizers.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import { sanitizeHttpBody } from '../httpBody.ts'
import { sanitizeTextPayload } from '../../protocols/application/textproto/index.ts'
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
): void {
  if (length <= 0) return
  const raw = new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
  const token = raw.replace(/\0+$/g, '').replace(/^["']|["']$/g, '')
  if (!token) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-empty`, protocol)
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

/** JSON → structured path; else text detectors; else mask. */
export function sanitizePayloadBody(
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
  let i = offset
  const end = offset + length
  while (i < end && (buffer[i] === 0x20 || buffer[i] === 0x09 || buffer[i] === 0x0a || buffer[i] === 0x0d)) {
    i++
  }
  // T55 — USP Record over MQTT (and other industrial payloads)
  if (looksLikeUspRecord(buffer, i, end - i)) {
    const usp = sanitizeUspRecord(buffer, i, end - i, collector, mapping, intents, packetIndex)
    if (usp) return [...usp.coverage]
  }
  if (i < end && (buffer[i] === 0x7b || buffer[i] === 0x5b)) {
    // T63 — report the real sanitizeHttpBody disposition (no status collapse).
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
    return [{
      protocol: `${protocol}-json`,
      offset,
      length,
      status: result.coverageStatus,
    }]
  }
  // T63 — until free-text allowlist (T69), mask entire text body in both levels.
  void highPrivacy
  maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-body`, protocol)
  return [{ protocol: `${protocol}-body`, offset, length, status: 'redacted' }]
}

/**
 * Topic / path with `/` separators: preserve structure; map identity-like segments.
 */
export function sanitizeSlashPath(
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
  // First run detectors across the whole path
  sanitizeTextPayload({
    buffer,
    absoluteOffset: offset,
    byteLength: length,
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy,
    protocolId: protocol,
  })
  let segStart = offset
  const end = offset + length
  for (let i = offset; i <= end; i++) {
    const atEnd = i === end
    const slash = !atEnd && buffer[i] === 0x2f
    if (!slash && !atEnd) continue
    const segLen = i - segStart
    if (segLen > 0) {
      const seg = new TextDecoder('ascii', { fatal: false }).decode(
        buffer.subarray(segStart, segStart + segLen),
      )
      if (seg !== '+' && seg !== '#' && (highPrivacy || looksLikeIdentitySegment(seg))) {
        try {
          mapAsciiIdentity(
            buffer,
            segStart,
            segLen,
            'opaque-id',
            collector,
            mapping,
            intents,
            packetIndex,
            protocol,
          )
        } catch {
          /* overlap with detector patches */
        }
      }
    }
    segStart = i + 1
  }
  return [{ protocol: `${protocol}-topic`, offset, length, status: 'covered' }]
}

function looksLikeIdentitySegment(seg: string): boolean {
  if (seg.length === 0) return false
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(seg)) return true
  if (/^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$/.test(seg)) return true
  if (seg.includes('@')) return true
  if (/^[A-Za-z0-9][A-Za-z0-9._-]{2,}$/.test(seg) && /[A-Za-z]/.test(seg) && /\d/.test(seg)) {
    return true
  }
  return false
}

export function readU16be(buf: Uint8Array, o: number): number {
  return ((buf[o]! << 8) | buf[o + 1]!) >>> 0
}

export function readU16le(buf: Uint8Array, o: number): number {
  return (buf[o]! | (buf[o + 1]! << 8)) >>> 0
}

export function readU32be(buf: Uint8Array, o: number): number {
  return (
    ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!) >>> 0
  )
}

export function decodeAscii(buffer: Uint8Array, offset: number, length: number): string {
  return new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
}

/** MQTT Remaining Length varint (MQTT 3.1.1 / 5). */
export function readMqttRemainingLength(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { value: number; size: number } | null {
  let multiplier = 1
  let value = 0
  let size = 0
  for (let i = 0; i < 4; i++) {
    if (offset + i >= end) return null
    const encoded = buffer[offset + i]!
    value += (encoded & 0x7f) * multiplier
    size++
    if ((encoded & 0x80) === 0) return { value, size }
    multiplier *= 128
  }
  return null
}
