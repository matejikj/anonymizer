/**
 * T41 — Fluent Forward (TCP 24224, MessagePack): tag map; records/time mask without full schema.
 * CompressedPackedForward / unknown ext → fail-closed mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapAsciiIdentity, maskBytes } from './common.ts'

export const FLUENT_FORWARD_PORT = 24224

export function isFluentPortHint(src: number, dst: number): boolean {
  return src === FLUENT_FORWARD_PORT || dst === FLUENT_FORWARD_PORT
}

export function looksLikeFluent(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  const b0 = buffer[offset]!
  // MessagePack array fixarray / array16 / array32
  return (b0 >= 0x90 && b0 <= 0x9f) || b0 === 0xdc || b0 === 0xdd
}

export function sanitizeFluentForward(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isFluentPortHint(srcPort, dstPort) && !looksLikeFluent(buffer, offset, length)) {
    return null
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  const b0 = buffer[pos]!
  let arrayLen = -1
  if (b0 >= 0x90 && b0 <= 0x9f) {
    arrayLen = b0 & 0x0f
    coverage.push({ protocol: 'fluent', offset: pos, length: 1, status: 'covered' })
    pos += 1
  } else if (b0 === 0xdc && pos + 3 <= end) {
    arrayLen = (buffer[pos + 1]! << 8) | buffer[pos + 2]!
    coverage.push({ protocol: 'fluent', offset: pos, length: 3, status: 'covered' })
    pos += 3
  } else if (b0 === 0xdd && pos + 5 <= end) {
    arrayLen =
      ((buffer[pos + 1]! << 24)
        | (buffer[pos + 2]! << 16)
        | (buffer[pos + 3]! << 8)
        | buffer[pos + 4]!)
      >>> 0
    coverage.push({ protocol: 'fluent', offset: pos, length: 5, status: 'covered' })
    pos += 5
  }

  if (arrayLen < 1 || arrayLen > 8 || pos >= end) {
    maskBytes(collector, intents, packetIndex, offset, length, 'fluent-body', 'fluent')
    coverage.push({ protocol: 'fluent-body', offset, length, status: 'redacted' })
    issues.push('fluent-unparsed')
    return { coverage, issues }
  }

  // First element: tag (string)
  const tag = readMsgpackString(buffer, pos, end)
  if (tag) {
    mapAsciiIdentity(
      buffer,
      tag.offset,
      tag.length,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'fluent',
    )
    coverage.push({
      protocol: 'fluent-tag',
      offset: tag.headerOffset,
      length: tag.headerLength + tag.length,
      status: 'covered',
    })
    pos = tag.offset + tag.length
  }

  // Remainder (time + record / entries / option) — fail-closed mask (schema-aware later)
  if (pos < end) {
    // Detect gzip packed
    if (buffer[pos] === 0x1f || buffer[pos] === 0x78) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'fluent-compressed', 'fluent')
      coverage.push({
        protocol: 'fluent-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('fluent-compressed-masked')
    } else {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'fluent-record', 'fluent')
      coverage.push({
        protocol: 'fluent-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('fluent-record-masked')
    }
  }

  return { coverage, issues }
}

function readMsgpackString(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { headerOffset: number; headerLength: number; offset: number; length: number } | null {
  if (offset >= end) return null
  const b = buffer[offset]!
  if (b >= 0xa0 && b <= 0xbf) {
    const len = b & 0x1f
    if (offset + 1 + len > end) return null
    return { headerOffset: offset, headerLength: 1, offset: offset + 1, length: len }
  }
  if (b === 0xd9 && offset + 2 <= end) {
    const len = buffer[offset + 1]!
    if (offset + 2 + len > end) return null
    return { headerOffset: offset, headerLength: 2, offset: offset + 2, length: len }
  }
  if (b === 0xda && offset + 3 <= end) {
    const len = (buffer[offset + 1]! << 8) | buffer[offset + 2]!
    if (offset + 3 + len > end) return null
    return { headerOffset: offset, headerLength: 3, offset: offset + 3, length: len }
  }
  return null
}
