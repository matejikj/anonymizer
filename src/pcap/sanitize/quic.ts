/**
 * T28 — QUIC v1/v2 long-header sanitizer (mask-first Initial).
 * Initial protected payload is public-derivable → always mask (never encrypted-preserved).
 * DCID/SCID → opaque-id; Retry/NEW_TOKEN masked with payload.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

const QUIC_V1 = 0x00000001
const QUIC_V2 = 0x6b3343cf

export function looksLikeQuicLongHeader(
  data: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 7) return false
  const b0 = data[offset]!
  if ((b0 & 0x80) === 0) return false // short header
  const version =
    ((data[offset + 1]! << 24)
      | (data[offset + 2]! << 16)
      | (data[offset + 3]! << 8)
      | data[offset + 4]!)
    >>> 0
  if (version === 0) {
    // Version Negotiation (RFC 9000 §17.2.1): CIDs then ≥1 supported-version (4-byte aligned).
    // Zeroed RTP (0x80 + PT/seq/ts = 0) also looks like long-header+version-0 — reject those.
    let pos = offset + 5
    const end = offset + length
    if (pos >= end) return false
    const dcidLen = data[pos++]!
    if (pos + dcidLen > end) return false
    pos += dcidLen
    if (pos >= end) return false
    const scidLen = data[pos++]!
    if (pos + scidLen > end) return false
    pos += scidLen
    const rem = end - pos
    return rem >= 4 && rem % 4 === 0
  }
  // QUIC v1/v2 long headers require the Fixed Bit (RTP v2 often starts 0x80 without it).
  if ((b0 & 0x40) === 0) return false
  return version === QUIC_V1 || version === QUIC_V2
}

export function sanitizeQuic(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeQuicLongHeader(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  // Coalesced long headers in one UDP datagram.
  while (pos + 7 <= end && (buffer[pos]! & 0x80) !== 0) {
    const start = pos
    const first = buffer[pos]!
    const version =
      ((buffer[pos + 1]! << 24)
        | (buffer[pos + 2]! << 16)
        | (buffer[pos + 3]! << 8)
        | buffer[pos + 4]!)
      >>> 0
    pos += 5
    if (pos >= end) break
    const dcidLen = buffer[pos]!
    pos += 1
    if (pos + dcidLen > end) {
      maskSpan(collector, intents, packetIndex, start, end - start, 'quic-malformed')
      coverage.push({ protocol: 'quic', offset: start, length: end - start, status: 'malformed' })
      break
    }
    mapCid(buffer, pos, dcidLen, collector, mapping, intents, packetIndex)
    pos += dcidLen
    if (pos >= end) break
    const scidLen = buffer[pos]!
    pos += 1
    if (pos + scidLen > end) {
      maskSpan(collector, intents, packetIndex, start, end - start, 'quic-malformed')
      coverage.push({ protocol: 'quic', offset: start, length: end - start, status: 'malformed' })
      break
    }
    mapCid(buffer, pos, scidLen, collector, mapping, intents, packetIndex)
    pos += scidLen

    if (version === 0) {
      // Version Negotiation — supported versions preserve; CIDs already mapped.
      coverage.push({ protocol: 'quic-vn', offset: start, length: end - start, status: 'covered' })
      pos = end
      break
    }

    const longType = (first >> 4) & 0x03 // v1: 0=Initial,1=0-RTT,2=Handshake,3=Retry
    const isV2 = version === QUIC_V2
    const isInitial = isV2 ? longType === 0x01 : longType === 0x00
    const isRetry = isV2 ? longType === 0x00 : longType === 0x03
    const isHandshake = isV2 ? longType === 0x02 : longType === 0x02

    if (isRetry) {
      // token + integrity tag — mask remainder
      if (pos < end) {
        maskSpan(collector, intents, packetIndex, pos, end - pos, 'quic-retry-token')
      }
      coverage.push({ protocol: 'quic-retry', offset: start, length: end - start, status: 'redacted' })
      pos = end
      break
    }

    // Initial / Handshake / 0-RTT: token (Initial only) + length + protected payload
    if (isInitial) {
      const tokenLen = readVarInt(buffer, pos, end)
      if (!tokenLen) {
        maskSpan(collector, intents, packetIndex, start, end - start, 'quic-malformed')
        coverage.push({ protocol: 'quic', offset: start, length: end - start, status: 'malformed' })
        break
      }
      pos = tokenLen.next
      if (tokenLen.value > 0) {
        if (pos + tokenLen.value > end) {
          maskSpan(collector, intents, packetIndex, start, end - start, 'quic-malformed')
          coverage.push({ protocol: 'quic', offset: start, length: end - start, status: 'malformed' })
          break
        }
        maskSpan(collector, intents, packetIndex, pos, tokenLen.value, 'quic-initial-token')
        pos += tokenLen.value
      }
    }

    const lenField = readVarInt(buffer, pos, end)
    if (!lenField) {
      maskSpan(collector, intents, packetIndex, start, end - start, 'quic-malformed')
      coverage.push({ protocol: 'quic', offset: start, length: end - start, status: 'malformed' })
      break
    }
    pos = lenField.next
    const payloadLen = lenField.value
    if (pos + payloadLen > end) {
      maskSpan(collector, intents, packetIndex, start, end - start, 'quic-malformed')
      coverage.push({ protocol: 'quic', offset: start, length: end - start, status: 'malformed' })
      break
    }

    if (isInitial || isHandshake) {
      // Initial: public key derivation → mask entire protected payload (CRYPTO/SNI).
      // Handshake without proven phase: mask (not encrypted-preserved).
      maskSpan(
        collector,
        intents,
        packetIndex,
        pos,
        payloadLen,
        isInitial ? 'quic-initial-payload' : 'quic-handshake-payload',
      )
      coverage.push({
        protocol: isInitial ? 'quic-initial' : 'quic-handshake',
        offset: start,
        length: pos + payloadLen - start,
        status: 'redacted',
      })
      if (isInitial) issues.push('quic-initial-public-derivable')
    } else {
      // 0-RTT — no confidentiality proof without connection context
      maskSpan(collector, intents, packetIndex, pos, payloadLen, 'quic-0rtt-unproven')
      coverage.push({
        protocol: 'quic-0rtt',
        offset: start,
        length: pos + payloadLen - start,
        status: 'redacted',
      })
      issues.push('quic-confidentiality-unproven')
    }
    pos += payloadLen
  }

  // Trailing short-header bytes without connection proof → mask
  if (pos < end) {
    maskSpan(collector, intents, packetIndex, pos, end - pos, 'quic-short-unproven')
    coverage.push({ protocol: 'quic', offset: pos, length: end - pos, status: 'redacted' })
    issues.push('quic-short-header-unproven')
  }

  return { coverage, issues }
}

function mapCid(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (length <= 0) return
  const hex = bytesToHex(buffer.subarray(offset, offset + length))
  collector.addDeferred(
    offset,
    length,
    (ctx) => {
      const alias = ctx.mapping.map('opaque-id', hex)
      // Same-length binary fill keyed by mapped opaque-id (consistent CID across packets).
      return createProtocolNeutralMaskFill({
        length,
        packetIndex,
        offset,
        domain: `quic-cid:${alias}`,
      })
    },
    { fallbackKind: 'binary-mask', protocol: 'quic', category: 'opaque-id', packetIndex },
  )
  intents?.recordMaskRange(packetIndex, offset, length, 'quic-cid', 'quic')
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'quic')
}

function readVarInt(
  buf: Uint8Array,
  offset: number,
  end: number,
): { value: number; next: number } | null {
  if (offset >= end) return null
  const b0 = buf[offset]!
  const prefix = b0 >> 6
  const len = 1 << prefix
  if (offset + len > end) return null
  let value = b0 & 0x3f
  for (let i = 1; i < len; i++) {
    value = (value << 8) | buf[offset + i]!
  }
  return { value, next: offset + len }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    s += bytes[i]!.toString(16).padStart(2, '0')
  }
  return s
}
