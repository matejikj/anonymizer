/**
 * T41 — AMQP 0-9-1 (TCP 5672): frame walk; SASL/Start-Ok secrets mask; content body JSON/mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  mapAsciiIdentity,
  maskBytes,
  readU16be,
  readU32be,
  sanitizeMessageBody,
} from './common.ts'

export const AMQP_TCP_PORT = 5672

const FRAME_METHOD = 1
const FRAME_HEADER = 2
const FRAME_BODY = 3
const FRAME_HEARTBEAT = 8
const FRAME_END = 0xce

export function isAmqpPortHint(src: number, dst: number): boolean {
  return src === AMQP_TCP_PORT || dst === AMQP_TCP_PORT
}

export function looksLikeAmqp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (
    length >= 8
    && buffer[offset] === 0x41
    && buffer[offset + 1] === 0x4d
    && buffer[offset + 2] === 0x51
    && buffer[offset + 3] === 0x50
  ) {
    return true
  }
  if (length >= 8) {
    const t = buffer[offset]!
    const size = readU32be(buffer, offset + 3)
    return (
      (t === FRAME_METHOD || t === FRAME_HEADER || t === FRAME_BODY || t === FRAME_HEARTBEAT)
      && size < 0x10_0000
      && size + 8 <= length + 64
    )
  }
  return false
}

export function sanitizeAmqp(
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
  if (!isAmqpPortHint(srcPort, dstPort) && !looksLikeAmqp(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  if (
    length >= 8
    && buffer[pos] === 0x41
    && buffer[pos + 1] === 0x4d
    && buffer[pos + 2] === 0x51
    && buffer[pos + 3] === 0x50
  ) {
    coverage.push({ protocol: 'amqp', offset: pos, length: 8, status: 'covered' })
    pos += 8
  }

  while (pos + 8 <= end) {
    const type = buffer[pos]!
    const size = readU32be(buffer, pos + 3)
    if (size > 0x10_0000 || pos + 7 + size + 1 > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'amqp-desync', 'amqp')
      coverage.push({
        protocol: 'amqp-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('amqp-frame-desync')
      break
    }
    const payloadOff = pos + 7
    const frameEnd = payloadOff + size
    if (buffer[frameEnd] !== FRAME_END) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'amqp-bad-end', 'amqp')
      coverage.push({
        protocol: 'amqp-body',
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      break
    }

    coverage.push({ protocol: 'amqp', offset: pos, length: 7, status: 'covered' })

    if (type === FRAME_METHOD && size >= 4) {
      const classId = readU16be(buffer, payloadOff)
      const methodId = readU16be(buffer, payloadOff + 2)
      coverage.push({
        protocol: 'amqp-method',
        offset: payloadOff,
        length: 4,
        status: 'covered',
      })
      // Connection.Start-Ok (10,11) / Secure-Ok (10,21) — SASL response
      if (classId === 10 && (methodId === 11 || methodId === 21)) {
        // Secrets: mask entire SASL response (user+password). Mapping individual
        // PLAIN fields would overlap the fail-closed mask in PatchCollector.
        maskBytes(
          collector,
          intents,
          packetIndex,
          payloadOff + 4,
          size - 4,
          'amqp-sasl',
          'amqp',
        )
        coverage.push({
          protocol: 'amqp-sasl',
          offset: payloadOff + 4,
          length: size - 4,
          status: 'redacted',
        })
        issues.push('amqp-sasl-masked')
      } else if (classId === 10 && methodId === 40 && size > 4) {
        sanitizeShortstrIdentity(
          buffer,
          payloadOff + 4,
          size - 4,
          'opaque-id',
          collector,
          mapping,
          intents,
          packetIndex,
        )
        coverage.push({
          protocol: 'amqp-method',
          offset: payloadOff + 4,
          length: size - 4,
          status: 'covered',
        })
      } else if (size > 4) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          payloadOff + 4,
          size - 4,
          'amqp-method-args',
          'amqp',
        )
        coverage.push({
          protocol: 'amqp-body',
          offset: payloadOff + 4,
          length: size - 4,
          status: 'redacted',
        })
      }
    } else if (type === FRAME_HEADER) {
      const keep = Math.min(14, size)
      coverage.push({
        protocol: 'amqp-header',
        offset: payloadOff,
        length: keep,
        status: 'covered',
      })
      if (size > keep) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          payloadOff + keep,
          size - keep,
          'amqp-properties',
          'amqp',
        )
        coverage.push({
          protocol: 'amqp-body',
          offset: payloadOff + keep,
          length: size - keep,
          status: 'redacted',
        })
      }
    } else if (type === FRAME_BODY) {
      coverage.push(
        ...sanitizeMessageBody(
          buffer,
          payloadOff,
          size,
          collector,
          mapping,
          intents,
          packetIndex,
          'amqp',
          highPrivacy,
        ),
      )
    } else if (type === FRAME_HEARTBEAT) {
      coverage.push({ protocol: 'amqp', offset: payloadOff, length: size, status: 'covered' })
    } else {
      maskBytes(collector, intents, packetIndex, payloadOff, size, 'amqp-unknown', 'amqp')
      coverage.push({
        protocol: 'amqp-body',
        offset: payloadOff,
        length: size,
        status: 'redacted',
      })
    }

    pos = frameEnd + 1
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'amqp-session', 'amqp')
    coverage.push({ protocol: 'amqp', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeShortstrIdentity(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: 'opaque-id' | 'hostname',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (length < 1) return
  const slen = buffer[offset]!
  if (slen <= 0 || 1 + slen > length) return
  mapAsciiIdentity(
    buffer,
    offset + 1,
    slen,
    category,
    collector,
    mapping,
    intents,
    packetIndex,
    'amqp',
  )
}
