/**
 * T41 — Kafka (TCP 9092): request header preserve; SASL mask; record values JSON/mask.
 * Compressed batches and flexible tagged fields without full schema → mask (honest limit).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  asciiIndexOf,
  mapAsciiIdentity,
  maskBytes,
  readU16be,
  readU32be,
  sanitizeMessageBody,
} from './common.ts'

export const KAFKA_TCP_PORT = 9092

const API_SASL_HANDSHAKE = 17
const API_SASL_AUTHENTICATE = 36
const API_PRODUCE = 0
const API_FETCH = 1

export function isKafkaPortHint(src: number, dst: number): boolean {
  return src === KAFKA_TCP_PORT || dst === KAFKA_TCP_PORT
}

export function looksLikeKafka(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const size = readU32be(buffer, offset)
  // Request size is length of rest; tolerate truncated captures
  return size > 0 && size < 0x10_0000 && size + 4 <= length + 0x10000
}

export function sanitizeKafka(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isKafkaPortHint(srcPort, dstPort) && !looksLikeKafka(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length

  if (length < 12) {
    maskBytes(collector, intents, packetIndex, offset, length, 'kafka-short', 'kafka')
    coverage.push({ protocol: 'kafka', offset, length, status: 'redacted' })
    return { coverage, issues }
  }

  // Request: size(4) + apiKey(2) + apiVersion(2) + correlationId(4) + clientId…
  // Response: size(4) + correlationId(4) …
  const size = readU32be(buffer, offset)
  coverage.push({ protocol: 'kafka', offset, length: 4, status: 'covered' })

  const apiKey = readU16be(buffer, offset + 4)
  // Heuristic: response has no apiKey — high bit of "apiKey" as correlation often large.
  // Prefer request shape when apiKey is a known small key.
  const looksRequest = apiKey < 80 && size + 4 <= length + 64

  if (looksRequest) {
    const apiVersion = readU16be(buffer, offset + 6)
    coverage.push({ protocol: 'kafka', offset: offset + 4, length: 8, status: 'covered' })
    void apiVersion

    let pos = offset + 12
    // clientId STRING: int16 length + bytes
    if (pos + 2 <= end) {
      const cidLen = readU16be(buffer, pos)
      pos += 2
      if (cidLen > 0 && cidLen < 0x1000 && pos + cidLen <= end) {
        mapAsciiIdentity(
          buffer,
          pos,
          cidLen,
          'opaque-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'kafka',
        )
        coverage.push({
          protocol: 'kafka-client-id',
          offset: pos,
          length: cidLen,
          status: 'covered',
        })
        pos += cidLen
      }
    }

    if (apiKey === API_SASL_HANDSHAKE || apiKey === API_SASL_AUTHENTICATE) {
      if (pos < end) {
        // Fail-closed: mask entire SASL payload (avoids PatchCollector overlap with user map)
        maskBytes(collector, intents, packetIndex, pos, end - pos, 'kafka-sasl', 'kafka')
        coverage.push({
          protocol: 'kafka-sasl',
          offset: pos,
          length: end - pos,
          status: 'redacted',
        })
        issues.push('kafka-sasl-masked')
      }
      return { coverage, issues }
    }

    if (apiKey === API_PRODUCE || apiKey === API_FETCH) {
      // Preserve header; mask/sanitize body (topics, batches) — CRC recompute out of scope
      if (pos < end) {
        const bodyCov = sanitizeProduceLikeBody(
          buffer,
          pos,
          end - pos,
          collector,
          mapping,
          intents,
          packetIndex,
          highPrivacy,
        )
        coverage.push(...bodyCov)
        issues.push('kafka-batch-crc-not-recomputed')
      }
      return { coverage, issues }
    }

    // Other APIs: mask free-form trailing (group/member ids may leak)
    if (pos < end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'kafka-body', 'kafka')
      coverage.push({
        protocol: 'kafka-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
    }
    return { coverage, issues }
  }

  // Response / mid-stream: correlation preserve (4), rest mask unless SASL canary visible
  coverage.push({ protocol: 'kafka', offset: offset + 4, length: 4, status: 'covered' })
  const restOff = offset + 8
  if (restOff < end) {
    if (asciiIndexOf(buffer, restOff, end - restOff, 'PLAIN') >= 0) {
      maskBytes(collector, intents, packetIndex, restOff, end - restOff, 'kafka-sasl', 'kafka')
      coverage.push({
        protocol: 'kafka-sasl',
        offset: restOff,
        length: end - restOff,
        status: 'redacted',
      })
    } else {
      maskBytes(collector, intents, packetIndex, restOff, end - restOff, 'kafka-body', 'kafka')
      coverage.push({
        protocol: 'kafka-body',
        offset: restOff,
        length: end - restOff,
        status: 'redacted',
      })
    }
  }
  return { coverage, issues }
}

function sanitizeProduceLikeBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
): AppLayerResult['coverage'] {
  const coverage: AppLayerResult['coverage'] = []
  // Compression magic / snappy/lz4/zstd → whole-body mask
  const first = buffer[offset]
  if (
    first === 0x1f
    || first === 0x78
    || asciiIndexOf(buffer, offset, Math.min(length, 64), 'SNAPPY') >= 0
  ) {
    maskBytes(collector, intents, packetIndex, offset, length, 'kafka-compressed', 'kafka')
    coverage.push({ protocol: 'kafka-body', offset, length, status: 'redacted' })
    return coverage
  }
  // Prefer JSON message body path when payload looks like JSON; else mask
  let i = offset
  const end = offset + length
  while (i < end && (buffer[i] === 0x20 || buffer[i] === 0x09)) i++
  if (i < end && (buffer[i] === 0x7b || buffer[i] === 0x5b)) {
    return sanitizeMessageBody(
      buffer,
      offset,
      length,
      collector,
      mapping,
      intents,
      packetIndex,
      'kafka',
      highPrivacy,
    )
  }
  maskBytes(collector, intents, packetIndex, offset, length, 'kafka-body', 'kafka')
  coverage.push({ protocol: 'kafka-body', offset, length, status: 'redacted' })
  return coverage
}
