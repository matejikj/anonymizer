/**
 * T29 — MySQL/MariaDB (TCP 3306): handshake salt/auth mask; user map; COM_QUERY SQL literals.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  mapAsciiIdentity,
  maskBytes,
  sanitizeSqlText,
} from './common.ts'

export const MYSQL_TCP_PORT = 3306

const COM_QUERY = 0x03
const COM_STMT_PREPARE = 0x16
const COM_STMT_EXECUTE = 0x17

export function isMysqlPortHint(src: number, dst: number): boolean {
  return src === MYSQL_TCP_PORT || dst === MYSQL_TCP_PORT
}

export function looksLikeMysql(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 5) return false
  const payloadLen = buffer[offset]! | (buffer[offset + 1]! << 8) | (buffer[offset + 2]! << 16)
  return payloadLen > 0 && payloadLen < 0x10_0000 && payloadLen + 4 <= length + 64
}

export function sanitizeMysql(
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
  if (!isMysqlPortHint(srcPort, dstPort) && !looksLikeMysql(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 4 <= end) {
    const payloadLen = buffer[pos]! | (buffer[pos + 1]! << 8) | (buffer[pos + 2]! << 16)
    const seq = buffer[pos + 3]!
    if (payloadLen === 0 || pos + 4 + payloadLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'mysql-desync', 'mysql')
      coverage.push({
        protocol: 'mysql-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('mysql-frame-desync')
      break
    }
    coverage.push({ protocol: 'mysql', offset: pos, length: 4, status: 'covered' })
    const payloadOff = pos + 4
    const first = buffer[payloadOff]!

    // Handshake from server: protocol version 10
    if (seq === 0 && first === 0x0a) {
      sanitizeHandshake(
        buffer,
        payloadOff,
        payloadLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (seq === 1 && first !== 0xff && first !== 0x00 && first !== COM_QUERY) {
      // HandshakeResponse41 (client)
      sanitizeHandshakeResponse(
        buffer,
        payloadOff,
        payloadLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (first === COM_QUERY || first === COM_STMT_PREPARE) {
      coverage.push({ protocol: 'mysql', offset: payloadOff, length: 1, status: 'covered' })
      coverage.push(
        ...sanitizeSqlText(
          buffer,
          payloadOff + 1,
          payloadLen - 1,
          collector,
          intents,
          packetIndex,
          'mysql',
          highPrivacy,
          'mysql',
        ),
      )
    } else if (first === COM_STMT_EXECUTE) {
      coverage.push({ protocol: 'mysql', offset: payloadOff, length: 1, status: 'covered' })
      if (payloadLen > 1) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          payloadOff + 1,
          payloadLen - 1,
          'mysql-params',
          'mysql',
        )
        coverage.push({
          protocol: 'mysql-row',
          offset: payloadOff + 1,
          length: payloadLen - 1,
          status: 'redacted',
        })
      }
    } else if (first === 0xff) {
      // ERR: 0xff + 2B code + '#' + 5B SQLSTATE + message
      sanitizeErrPacket(
        buffer,
        payloadOff,
        payloadLen,
        collector,
        intents,
        packetIndex,
        coverage,
      )
    } else if (first === 0x00) {
      // OK — preserve status structure, mask info string if present
      const keep = Math.min(7, payloadLen)
      coverage.push({ protocol: 'mysql', offset: payloadOff, length: keep, status: 'covered' })
      if (payloadLen > keep) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          payloadOff + keep,
          payloadLen - keep,
          'mysql-ok',
          'mysql',
        )
      }
    } else {
      // Resultset rows / unknown — fail-closed
      maskBytes(collector, intents, packetIndex, payloadOff, payloadLen, 'mysql-row', 'mysql')
      coverage.push({
        protocol: 'mysql-row',
        offset: payloadOff,
        length: payloadLen,
        status: 'redacted',
      })
    }

    void seq
    pos += 4 + payloadLen
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mysql-session', 'mysql')
    coverage.push({ protocol: 'mysql', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeHandshake(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // version string NUL-terminated after protocol byte
  coverage.push({ protocol: 'mysql', offset, length: 1, status: 'covered' })
  let p = offset + 1
  const end = offset + length
  while (p < end && buffer[p] !== 0) p++
  // server version — fingerprint; leave readable structure, mask if looks like hostname
  coverage.push({ protocol: 'mysql', offset: offset + 1, length: p - (offset + 1), status: 'covered' })
  if (p < end) p++ // NUL
  // connection id 4B
  if (p + 4 <= end) {
    coverage.push({ protocol: 'mysql', offset: p, length: 4, status: 'covered' })
    p += 4
  }
  // auth plugin data part 1 (8) + filler
  if (p + 9 <= end) {
    maskBytes(collector, intents, packetIndex, p, 8, 'mysql-salt', 'mysql')
    coverage.push({ protocol: 'mysql-auth', offset: p, length: 8, status: 'redacted' })
    issues.push('mysql-salt-masked')
    p += 9
  }
  // remainder (capability/charset/status/auth data 2) — mask auth-related tails
  if (p < end) {
    maskBytes(collector, intents, packetIndex, p, end - p, 'mysql-handshake', 'mysql')
    coverage.push({
      protocol: 'mysql-auth',
      offset: p,
      length: end - p,
      status: 'redacted',
    })
  }
  void mapping
}

function sanitizeHandshakeResponse(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // Simplified HandshakeResponse41: caps(4)+max(4)+charset(1)+reserved(23)+username\0+auth_len+auth+db\0
  if (length < 32) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mysql-handshake-resp', 'mysql')
    coverage.push({ protocol: 'mysql-auth', offset, length, status: 'redacted' })
    return
  }
  coverage.push({ protocol: 'mysql', offset, length: 32, status: 'covered' })
  let p = offset + 32
  const end = offset + length
  // username
  let uEnd = p
  while (uEnd < end && buffer[uEnd] !== 0) uEnd++
  if (uEnd > p) {
    mapAsciiIdentity(
      buffer,
      p,
      uEnd - p,
      'user-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'mysql',
    )
    coverage.push({
      protocol: 'mysql-user',
      offset: p,
      length: uEnd - p,
      status: 'covered',
    })
  }
  p = uEnd + 1
  if (p >= end) return
  // auth response: length-encoded or null
  const authLen = buffer[p]!
  p++
  if (authLen > 0 && p + authLen <= end) {
    maskBytes(collector, intents, packetIndex, p, authLen, 'mysql-auth-resp', 'mysql')
    coverage.push({
      protocol: 'mysql-auth',
      offset: p,
      length: authLen,
      status: 'redacted',
    })
    issues.push('mysql-auth-masked')
    p += authLen
  }
  // database
  if (p < end) {
    let dEnd = p
    while (dEnd < end && buffer[dEnd] !== 0) dEnd++
    if (dEnd > p) {
      mapAsciiIdentity(
        buffer,
        p,
        dEnd - p,
        'opaque-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'mysql',
      )
      coverage.push({
        protocol: 'mysql-db',
        offset: p,
        length: dEnd - p,
        status: 'covered',
      })
    }
    p = dEnd + 1
  }
  // plugin name + connect attrs — mask remainder
  if (p < end) {
    maskBytes(collector, intents, packetIndex, p, end - p, 'mysql-attrs', 'mysql')
    coverage.push({
      protocol: 'mysql-body',
      offset: p,
      length: end - p,
      status: 'redacted',
    })
  }
}

function sanitizeErrPacket(
  _buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  // 0xff + code(2) + '#' + SQLSTATE(5) + message
  const keep = Math.min(9, length) // ff + 2 + # + 5
  coverage.push({ protocol: 'mysql', offset, length: keep, status: 'covered' })
  if (length > keep) {
    maskBytes(
      collector,
      intents,
      packetIndex,
      offset + keep,
      length - keep,
      'mysql-error',
      'mysql',
    )
    coverage.push({
      protocol: 'mysql-error',
      offset: offset + keep,
      length: length - keep,
      status: 'redacted',
    })
  }
}
