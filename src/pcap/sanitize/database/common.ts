/**
 * T29 — shared helpers for database wire-protocol sanitizers.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import {
  findSqlLiteralSpans,
  maskLiteralSpans,
  sqlDialectRequiresMaskWhenNoLiterals,
  type SqlLiteralDialect,
} from '../../protocols/application/textproto/index.ts'
import {
  computeFixedLengthUtf16Bytes,
  decodeUtf16,
} from '../../protocols/application/binproto/utf16.ts'
import type { LayerCoverage } from '../types.ts'

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

export function mapUtf16LeIdentity(
  buffer: Uint8Array,
  offset: number,
  byteLength: number,
  category: 'user-id' | 'hostname' | 'opaque-id',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  if (byteLength <= 0 || byteLength % 2 !== 0) return
  const decoded = decodeUtf16(buffer.subarray(offset, offset + byteLength), 'le')
  const token = (decoded ?? '').replace(/\0+$/g, '')
  if (!token) {
    maskBytes(collector, intents, packetIndex, offset, byteLength, `${protocol}-empty`, protocol)
    return
  }
  const canon = canonicalizeIdentity(category, token) ?? token
  const codeUnits = byteLength / 2
  const constraint = { kind: 'text-ascii' as const, byteLength: codeUnits }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, byteLength, constraint, token)
  collector.addDeferred(
    offset,
    byteLength,
    ({ mapping: live }) => {
      try {
        const alias = live.aliasFor(category, canon, constraint, token)
        return computeFixedLengthUtf16Bytes(byteLength, alias.slice(0, codeUnits), 'le')
      } catch {
        return createProtocolNeutralMaskFill({
          length: byteLength,
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
 * SQL: high-privacy → whole statement mask; diagnostic → dialect literal grammar.
 * Unknown dialect and incomplete postgres dollar-quote parses fail-closed (never "covered" with zero literals).
 */
export function sanitizeSqlText(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  highPrivacy: boolean,
  dialect: SqlLiteralDialect = 'generic',
): LayerCoverage[] {
  if (length <= 0) return []
  if (highPrivacy || dialect === 'unknown') {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-sql`, protocol)
    return [{ protocol: `${protocol}-sql`, offset, length, status: 'redacted' }]
  }
  const body = buffer.subarray(offset, offset + length)
  const spans = findSqlLiteralSpans(body, offset, { dialect })
  const dollarSpans = spans.filter((s) => s.kind === 'sql-dollar-string')
  const needsFailClosed =
    (spans.length === 0 && sqlDialectRequiresMaskWhenNoLiterals(dialect, body))
    || (dialect === 'postgres'
      && sqlDialectRequiresMaskWhenNoLiterals(dialect, body)
      && dollarSpans.length === 0)

  if (needsFailClosed) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-sql`, protocol)
    return [{ protocol: `${protocol}-sql`, offset, length, status: 'redacted' }]
  }

  maskLiteralSpans(collector, spans)
  for (const s of spans) {
    intents?.recordMaskRange(packetIndex, s.absoluteOffset, s.byteLength, `sql-${s.kind}`, protocol)
  }
  return [{ protocol: `${protocol}-sql`, offset, length, status: 'covered' }]
}

export function readU16le(buf: Uint8Array, o: number): number {
  return (buf[o]! | (buf[o + 1]! << 8)) >>> 0
}

export function readU32le(buf: Uint8Array, o: number): number {
  return (
    (buf[o]! | (buf[o + 1]! << 8) | (buf[o + 2]! << 16) | (buf[o + 3]! << 24)) >>> 0
  )
}

export function readU32be(buf: Uint8Array, o: number): number {
  return (
    ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!) >>> 0
  )
}

export function decodeAscii(buffer: Uint8Array, offset: number, length: number): string {
  return new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
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
