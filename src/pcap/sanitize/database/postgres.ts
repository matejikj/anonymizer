/**
 * T29 — PostgreSQL (TCP 5432): Startup identities; Password/SASL mask; Query SQL literals; DataRow mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  asciiIndexOf,
  decodeAscii,
  mapAsciiIdentity,
  maskBytes,
  readU32be,
  sanitizeSqlText,
} from './common.ts'

export const POSTGRES_TCP_PORT = 5432

const PROTO_30 = 196_608
const SSL_REQUEST = 808_771_03
const CANCEL_REQUEST = 808_771_02

export function isPostgresPortHint(src: number, dst: number): boolean {
  return src === POSTGRES_TCP_PORT || dst === POSTGRES_TCP_PORT
}

export function looksLikePostgres(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const len = readU32be(buffer, offset)
  if (len >= 8 && len <= length + 64 && len < 0x10000) {
    const proto = readU32be(buffer, offset + 4)
    if (proto === PROTO_30 || proto === SSL_REQUEST || proto === CANCEL_REQUEST) return true
  }
  const t = buffer[offset]!
  if (t >= 0x41 && t <= 0x7a && length >= 5) {
    const mlen = readU32be(buffer, offset + 1)
    return mlen >= 4 && mlen < 0x10_0000
  }
  return false
}

export function sanitizePostgres(
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
  if (!isPostgresPortHint(srcPort, dstPort) && !looksLikePostgres(buffer, offset, length)) {
    return null
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  if (length >= 8) {
    const msgLen = readU32be(buffer, pos)
    const proto = readU32be(buffer, pos + 4)
    if (
      msgLen >= 8
      && msgLen <= length
      && (proto === PROTO_30 || proto === SSL_REQUEST || proto === CANCEL_REQUEST)
    ) {
      coverage.push({ protocol: 'postgres', offset: pos, length: 8, status: 'covered' })
      if (proto === PROTO_30 && msgLen > 8) {
        sanitizeStartupParams(
          buffer,
          pos + 8,
          msgLen - 8,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
        )
      }
      pos += msgLen
      if (pos >= end) return { coverage, issues }
    }
  }

  while (pos + 5 <= end) {
    const type = buffer[pos]!
    const mlen = readU32be(buffer, pos + 1)
    if (mlen < 4 || pos + 1 + mlen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'postgres-desync', 'postgres')
      coverage.push({
        protocol: 'postgres-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('postgres-frame-desync')
      break
    }
    const payloadOff = pos + 5
    const payloadLen = mlen - 4
    coverage.push({ protocol: 'postgres', offset: pos, length: 5, status: 'covered' })
    const kind = String.fromCharCode(type)

    if (kind === 'p' || kind === 'R') {
      maskBytes(collector, intents, packetIndex, payloadOff, payloadLen, 'postgres-auth', 'postgres')
      coverage.push({
        protocol: 'postgres-auth',
        offset: payloadOff,
        length: payloadLen,
        status: 'redacted',
      })
      issues.push('postgres-auth-masked')
    } else if (kind === 'Q') {
      let sqlLen = payloadLen
      if (sqlLen > 0 && buffer[payloadOff + sqlLen - 1] === 0) sqlLen -= 1
      coverage.push(
        ...sanitizeSqlText(
          buffer,
          payloadOff,
          sqlLen,
          collector,
          intents,
          packetIndex,
          'postgres',
          highPrivacy,
          'postgres',
        ),
      )
    } else if (kind === 'P') {
      sanitizeParse(
        buffer,
        payloadOff,
        payloadLen,
        collector,
        mapping,
        intents,
        packetIndex,
        highPrivacy,
        coverage,
      )
    } else if (kind === 'B' || kind === 'D' || kind === 'd' || kind === 'T') {
      maskBytes(collector, intents, packetIndex, payloadOff, payloadLen, 'postgres-row', 'postgres')
      coverage.push({
        protocol: 'postgres-row',
        offset: payloadOff,
        length: payloadLen,
        status: 'redacted',
      })
    } else if (kind === 'C') {
      coverage.push({
        protocol: 'postgres',
        offset: payloadOff,
        length: payloadLen,
        status: 'covered',
      })
    } else if (kind === 'E') {
      sanitizeErrorResponse(
        buffer,
        payloadOff,
        payloadLen,
        collector,
        intents,
        packetIndex,
        coverage,
      )
    } else if (payloadLen > 0) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        payloadOff,
        payloadLen,
        'postgres-body',
        'postgres',
      )
      coverage.push({
        protocol: 'postgres-body',
        offset: payloadOff,
        length: payloadLen,
        status: 'redacted',
      })
    }

    pos += 1 + mlen
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'postgres-session', 'postgres')
    coverage.push({ protocol: 'postgres', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeParse(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: AppLayerResult['coverage'],
): void {
  let p = offset
  const end = offset + length
  const nameEnd = asciiIndexOf(buffer, p, end - p, '\0')
  if (nameEnd < 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'postgres-parse', 'postgres')
    coverage.push({ protocol: 'postgres-sql', offset, length, status: 'redacted' })
    return
  }
  const nlen = nameEnd - p
  if (nlen > 0) {
    mapAsciiIdentity(
      buffer,
      p,
      nlen,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'postgres',
    )
  }
  p = nameEnd + 1
  const qEnd = asciiIndexOf(buffer, p, end - p, '\0')
  if (qEnd < 0) {
    maskBytes(collector, intents, packetIndex, p, end - p, 'postgres-parse', 'postgres')
    coverage.push({ protocol: 'postgres-sql', offset: p, length: end - p, status: 'redacted' })
    return
  }
  coverage.push(
    ...sanitizeSqlText(
      buffer,
      p,
      qEnd - p,
      collector,
      intents,
      packetIndex,
      'postgres',
      highPrivacy,
      'postgres',
    ),
  )
  if (qEnd + 1 < end) {
    maskBytes(collector, intents, packetIndex, qEnd + 1, end - (qEnd + 1), 'postgres-parse', 'postgres')
  }
}

function sanitizeStartupParams(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  let pos = offset
  const end = offset + length
  while (pos < end) {
    if (buffer[pos] === 0) break
    let kEnd = pos
    while (kEnd < end && buffer[kEnd] !== 0) kEnd++
    if (kEnd >= end) break
    const key = decodeAscii(buffer, pos, kEnd - pos)
    const vStart = kEnd + 1
    let vEnd = vStart
    while (vEnd < end && buffer[vEnd] !== 0) vEnd++
    if (vEnd > vStart) {
      if (key === 'user') {
        mapAsciiIdentity(
          buffer,
          vStart,
          vEnd - vStart,
          'user-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'postgres',
        )
        coverage.push({
          protocol: 'postgres-user',
          offset: vStart,
          length: vEnd - vStart,
          status: 'covered',
        })
      } else if (key === 'database' || key === 'application_name') {
        mapAsciiIdentity(
          buffer,
          vStart,
          vEnd - vStart,
          'opaque-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'postgres',
        )
        coverage.push({
          protocol: 'postgres-param',
          offset: vStart,
          length: vEnd - vStart,
          status: 'covered',
        })
      } else {
        maskBytes(
          collector,
          intents,
          packetIndex,
          vStart,
          vEnd - vStart,
          'postgres-param',
          'postgres',
        )
      }
    }
    pos = vEnd + 1
  }
}

function sanitizeErrorResponse(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  let pos = offset
  const end = offset + length
  while (pos < end) {
    const field = buffer[pos]!
    if (field === 0) {
      coverage.push({ protocol: 'postgres', offset: pos, length: 1, status: 'covered' })
      break
    }
    pos++
    let vEnd = pos
    while (vEnd < end && buffer[vEnd] !== 0) vEnd++
    const vLen = vEnd - pos
    // C = SQLSTATE, S/V = severity — structural; free text (M/D/H/…) mask
    if (field === 0x43 || field === 0x56 || field === 0x53) {
      coverage.push({
        protocol: 'postgres',
        offset: pos - 1,
        length: 1 + vLen + (vEnd < end ? 1 : 0),
        status: 'covered',
      })
    } else if (vLen > 0) {
      maskBytes(collector, intents, packetIndex, pos, vLen, 'postgres-error', 'postgres')
      coverage.push({
        protocol: 'postgres-error',
        offset: pos,
        length: vLen,
        status: 'redacted',
      })
    }
    pos = vEnd + 1
  }
}
