/**
 * T29 — TDS / MS SQL (TCP 1433): PRELOGIN preserve flags; LOGIN7 UTF-16 IDs + password mask; SQLBatch.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  mapUtf16LeIdentity,
  maskBytes,
  readU16le,
  readU32le,
  sanitizeSqlText,
} from './common.ts'

export const TDS_TCP_PORT = 1433

const TYPE_SQL_BATCH = 0x01
const TYPE_RPC = 0x03
const TYPE_PRELOGIN = 0x12
const TYPE_LOGIN7 = 0x10
const TYPE_SSPI = 0x11

export function isTdsPortHint(src: number, dst: number): boolean {
  return src === TDS_TCP_PORT || dst === TDS_TCP_PORT
}

export function looksLikeTds(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const type = buffer[offset]!
  const status = buffer[offset + 1]!
  const pktLen = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
  return (
    (type === TYPE_PRELOGIN || type === TYPE_LOGIN7 || type === TYPE_SQL_BATCH || type === TYPE_RPC)
    && status <= 0x03
    && pktLen >= 8
    && pktLen <= length + 64
  )
}

export function sanitizeTds(
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
  if (!isTdsPortHint(srcPort, dstPort) && !looksLikeTds(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 8 <= end) {
    const type = buffer[pos]!
    const pktLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    if (pktLen < 8 || pos + pktLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'tds-desync', 'tds')
      coverage.push({ protocol: 'tds-body', offset: pos, length: end - pos, status: 'redacted' })
      issues.push('tds-frame-desync')
      break
    }
    coverage.push({ protocol: 'tds', offset: pos, length: 8, status: 'covered' })
    const bodyOff = pos + 8
    const bodyLen = pktLen - 8

    if (type === TYPE_PRELOGIN) {
      // Keep option directory structurally; mask option values (instance name etc.)
      coverage.push({ protocol: 'tds', offset: bodyOff, length: Math.min(5, bodyLen), status: 'covered' })
      if (bodyLen > 5) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          bodyOff + 5,
          bodyLen - 5,
          'tds-prelogin',
          'tds',
        )
        coverage.push({
          protocol: 'tds-body',
          offset: bodyOff + 5,
          length: bodyLen - 5,
          status: 'redacted',
        })
      }
    } else if (type === TYPE_LOGIN7) {
      sanitizeLogin7(
        buffer,
        bodyOff,
        bodyLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (type === TYPE_SQL_BATCH) {
      coverage.push(
        ...sanitizeSqlText(
          buffer,
          bodyOff,
          bodyLen,
          collector,
          intents,
          packetIndex,
          'tds',
          highPrivacy,
        ),
      )
    } else if (type === TYPE_RPC || type === TYPE_SSPI) {
      maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'tds-rpc', 'tds')
      coverage.push({
        protocol: type === TYPE_SSPI ? 'tds-sspi' : 'tds-row',
        offset: bodyOff,
        length: bodyLen,
        status: 'redacted',
      })
      if (type === TYPE_SSPI) issues.push('tds-sspi-masked')
    } else {
      maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'tds-body', 'tds')
      coverage.push({
        protocol: 'tds-body',
        offset: bodyOff,
        length: bodyLen,
        status: 'redacted',
      })
    }

    pos += pktLen
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'tds-session', 'tds')
    coverage.push({ protocol: 'tds', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeLogin7(
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
  // LOGIN7: Length(4) + … + ibHostName(2)+cchHostName(2) + ibUserName + cchUserName + …
  // Offsets are from start of LOGIN7 packet (body).
  if (length < 36) {
    maskBytes(collector, intents, packetIndex, offset, length, 'tds-login7', 'tds')
    coverage.push({ protocol: 'tds-auth', offset, length, status: 'redacted' })
    return
  }
  coverage.push({ protocol: 'tds', offset, length: 36, status: 'covered' })

  // Fixed header through offset 36 contains length/TDSVersion/… — then ib/cch pairs start at 36
  // MS-TDS: ibHostName at 36, cchHostName at 38, ibUserName 40, cchUserName 42,
  // ibPassword 44, cchPassword 46, ibAppName 48, cchAppName 50, ibServerName 52, cchServerName 54,
  // … ibDatabase 60? Actually: ClientID skip — ibDatabase at 68, cchDatabase 70 (after ibCltIntName etc.)
  // Pragmatic: read common ib/cch at documented offsets for Host/User/Password/App/Server/Database.
  const fields: Array<{ ib: number; cch: number; category: 'hostname' | 'user-id' | 'opaque-id' | 'password' }> = [
    { ib: readU16le(buffer, offset + 36), cch: readU16le(buffer, offset + 38), category: 'hostname' },
    { ib: readU16le(buffer, offset + 40), cch: readU16le(buffer, offset + 42), category: 'user-id' },
    { ib: readU16le(buffer, offset + 44), cch: readU16le(buffer, offset + 46), category: 'password' },
    { ib: readU16le(buffer, offset + 48), cch: readU16le(buffer, offset + 50), category: 'opaque-id' },
    { ib: readU16le(buffer, offset + 52), cch: readU16le(buffer, offset + 54), category: 'hostname' },
  ]
  // Database: ibDatabase/cchDatabase at offset 68/70 in LOGIN7 (after CltIntName/Language)
  if (length >= 72) {
    fields.push({
      ib: readU16le(buffer, offset + 68),
      cch: readU16le(buffer, offset + 70),
      category: 'opaque-id',
    })
  }

  for (const f of fields) {
    const byteLen = f.cch * 2
    if (f.cch <= 0 || f.ib + byteLen > length) continue
    const abs = offset + f.ib
    if (f.category === 'password') {
      maskBytes(collector, intents, packetIndex, abs, byteLen, 'tds-password', 'tds')
      coverage.push({ protocol: 'tds-auth', offset: abs, length: byteLen, status: 'redacted' })
      issues.push('tds-password-masked')
    } else {
      mapUtf16LeIdentity(
        buffer,
        abs,
        byteLen,
        f.category,
        collector,
        mapping,
        intents,
        packetIndex,
        'tds',
      )
      coverage.push({
        protocol: f.category === 'user-id' ? 'tds-user' : 'tds-id',
        offset: abs,
        length: byteLen,
        status: 'covered',
      })
    }
  }

  // Mask any remaining variable data not covered (SSPI blob etc.)
  // Conservative: mask from first variable data region that looks unused — skip if already patched
  void readU32le
}
