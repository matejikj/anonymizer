/**
 * T51 — IUA (RFC 4233) over SCTP PPID 1: TLV walk; Protocol Data → Q.931 (no LAPD required).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from '../types.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import { looksLikeQ931, sanitizeQ931 } from './q931.ts'
import { looksLikeLapd, sanitizeLapd } from './lapd.ts'
import { protocolGraphCaptureGeneration } from '../protocolGraphState.ts'

/** IANA SCTP Payload Protocol Identifier for IUA. */
export const PPID_IUA = 1

/** Common IUA / SCTP port (RFC 4233). */
export const IUA_SCTP_PORT = 9900

const TAG_INTERFACE_ID_INT = 0x0001
const TAG_INTERFACE_ID_TEXT = 0x0003
const TAG_INFO_STRING = 0x0004
const TAG_PROTOCOL_DATA = 0x000e
const TAG_DLCI = 0x0005
const TAG_HEARTBEAT = 0x0009

export function looksLikeIua(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const version = buffer[offset]!
  if (version !== 1) return false
  const msgLen =
    ((buffer[offset + 4]! << 24)
      | (buffer[offset + 5]! << 16)
      | (buffer[offset + 6]! << 8)
      | buffer[offset + 7]!)
    >>> 0
  if (msgLen < 8 || msgLen > length) return false
  const msgClass = buffer[offset + 2]!
  // MGMT=0, ASPSM=3, ASPTM=4, QPTM=5, RKM=9 (common)
  return msgClass <= 9
}

export function sanitizeIua(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeIua(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const msgLen =
    ((buffer[offset + 4]! << 24)
      | (buffer[offset + 5]! << 16)
      | (buffer[offset + 6]! << 8)
      | buffer[offset + 7]!)
    >>> 0
  const end = offset + Math.min(msgLen, length)

  coverage.push({ protocol: 'iua-hdr', offset, length: 8, status: 'covered' })

  // Pass 1 — resolve Interface Identifier before Protocol Data (RFC 4233 TLV order is not
  // guaranteed relative to QPTM payload). Never share a fake `iua:unknown-link` across links.
  let iuaLinkScope = `iua:unscoped:pkt${packetIndex}`
  {
    let scan = offset + 8
    let sn = 0
    while (scan + 4 <= end && sn < 64) {
      sn++
      const tag = (buffer[scan]! << 8) | buffer[scan + 1]!
      const paramLen = (buffer[scan + 2]! << 8) | buffer[scan + 3]!
      if (paramLen < 4 || scan + paramLen > end) break
      const valOff = scan + 4
      const valLen = paramLen - 4
      if (tag === TAG_INTERFACE_ID_INT && valLen >= 4) {
        const ifId =
          ((buffer[valOff]! << 24)
            | (buffer[valOff + 1]! << 16)
            | (buffer[valOff + 2]! << 8)
            | buffer[valOff + 3]!)
          >>> 0
        iuaLinkScope = `iua:if-int:${ifId}`
        break
      }
      if (tag === TAG_INTERFACE_ID_TEXT && valLen > 0) {
        let text = ''
        let ascii = true
        for (let i = 0; i < valLen; i++) {
          const c = buffer[valOff + i]!
          if (c < 0x20 || c > 0x7e) {
            ascii = false
            break
          }
          text += String.fromCharCode(c)
        }
        iuaLinkScope = ascii && text
          ? `iua:if-text:${text}`
          : `iua:if-text-bin:${valLen}:${packetIndex}`
        break
      }
      scan += (paramLen + 3) & ~3
    }
  }

  // Pass 2 — sanitize TLVs with resolved link scope
  let pos = offset + 8
  let n = 0
  while (pos + 4 <= end && n < 64) {
    n++
    const tag = (buffer[pos]! << 8) | buffer[pos + 1]!
    const paramLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    if (paramLen < 4 || pos + paramLen > end) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'iua-tlv-trunc')
      coverage.push({
        protocol: 'iua-tlv',
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      issues.push('iua-tlv-trunc')
      break
    }
    const valOff = pos + 4
    const valLen = paramLen - 4
    const padded = (paramLen + 3) & ~3
    coverage.push({ protocol: 'iua-tlv-hdr', offset: pos, length: 4, status: 'covered' })

    if (tag === TAG_PROTOCOL_DATA && valLen > 0) {
      sanitizeProtocolData(
        buffer,
        valOff,
        valLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        iuaLinkScope,
      )
    } else if (tag === TAG_INTERFACE_ID_TEXT || tag === TAG_INFO_STRING) {
      if (valLen > 0) {
        mapAsciiOpaque(
          buffer,
          valOff,
          valLen,
          collector,
          mapping,
          intents,
          packetIndex,
          tag === TAG_INFO_STRING ? 'iua-info' : 'iua-if',
        )
        coverage.push({
          protocol: 'iua-id',
          offset: valOff,
          length: valLen,
          status: 'covered',
        })
      }
    } else if (tag === TAG_INTERFACE_ID_INT && valLen >= 4) {
      mapUint32Opaque(buffer, valOff, collector, mapping, intents, packetIndex, coverage)
    } else if (tag === TAG_HEARTBEAT || tag === TAG_DLCI) {
      if (valLen > 0) {
        maskRange(collector, intents, packetIndex, valOff, valLen, 'iua-tlv-mask')
        coverage.push({
          protocol: 'iua-body',
          offset: valOff,
          length: valLen,
          status: 'redacted',
        })
      }
    } else if (valLen > 0) {
      // Unknown TLV — preserve tag/len, mask value (fail-closed)
      maskRange(collector, intents, packetIndex, valOff, valLen, `iua-tag-${tag}`)
      coverage.push({
        protocol: 'iua-body',
        offset: valOff,
        length: valLen,
        status: 'redacted',
      })
    }

    // Padding after TLV must stay zero-safe: leave as-is (not identity)
    pos += padded
  }

  if (end < offset + length) {
    // Trailing bytes beyond Message Length
    maskRange(collector, intents, packetIndex, end, offset + length - end, 'iua-trailer')
  }

  coverage.unshift({ protocol: 'iua', offset, length: end - offset, status: 'covered' })
  return { coverage, issues }
}

function sanitizeProtocolData(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  iuaLinkScope: string,
): void {
  // IUA QPTM Protocol Data is commonly bare Q.931 (RFC 4233). Prefer Q.931 before LAPD —
  // looksLikeLapd can false-positive on DSS1 PD/CR octets and steal the IUA linkScope.
  if (looksLikeQ931(buffer, offset, length)) {
    // Generation-wide graph so the same CR on different Interface IDs can flag multi-link.
    const captureScopeKey = `${protocolGraphCaptureGeneration()}/q931`
    const q = sanitizeQ931(
      buffer,
      offset,
      length,
      collector,
      mapping,
      intents,
      packetIndex,
      'q931',
      { linkScope: iuaLinkScope, captureScopeKey },
    )
    if (q) {
      coverage.push(...q.coverage)
      if (q.issues) for (const i of q.issues) issues.push(i)
      return
    }
  }
  if (looksLikeLapd(buffer, offset, length)) {
    const lapd = sanitizeLapd(buffer, offset, length, collector, mapping, intents, packetIndex)
    if (lapd) {
      coverage.push(...lapd.coverage)
      if (lapd.issues) for (const i of lapd.issues) issues.push(i)
      return
    }
  }
  maskRange(collector, intents, packetIndex, offset, length, 'iua-pdata')
  coverage.push({ protocol: 'iua-pdata', offset, length, status: 'redacted' })
  issues.push('iua-pdata-unparsed')
}

function mapAsciiOpaque(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  void mapping
  let text = ''
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c < 0x20 || c > 0x7e) {
      maskRange(collector, intents, packetIndex, offset, length, domain)
      return
    }
    text += String.fromCharCode(c)
  }
  if (!text) return
  const canon = canonicalizeIdentity('opaque-id', `iua:${domain}:${text}`) ?? text
  const constraint = { kind: 'text-ascii' as const, byteLength: text.length }
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, text.length, constraint, text)
  try {
    collector.addDeferred(
      offset,
      text.length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            text.length,
            live.aliasFor('opaque-id', canon, constraint, text),
          )
        } catch {
          return createProtocolNeutralMaskFill({
            length: text.length,
            packetIndex,
            offset,
            domain,
          })
        }
      },
      { fallbackKind: 'text-x', protocol: 'iua', category: 'opaque-id', packetIndex },
    )
  } catch {
    /* overlap */
  }
  void buffer
}

function mapUint32Opaque(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  void mapping
  const v =
    ((buffer[offset]! << 24)
      | (buffer[offset + 1]! << 16)
      | (buffer[offset + 2]! << 8)
      | buffer[offset + 3]!)
    >>> 0
  const token = `if:${v.toString(16)}`
  const canon = canonicalizeIdentity('opaque-id', `iua-ifid:${token}`) ?? token
  const constraint = { kind: 'text-ascii' as const, byteLength: 4 }
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 4, constraint, token)
  try {
    collector.addDeferred(
      offset,
      4,
      ({ mapping: live }) => {
        try {
          const alias = live.aliasFor('opaque-id', canon, { kind: 'text-ascii', byteLength: 8 }, token)
          let h = 2166136261 >>> 0
          for (let i = 0; i < alias.length; i++) {
            h ^= alias.charCodeAt(i)
            h = Math.imul(h, 16777619) >>> 0
          }
          const out = new Uint8Array(4)
          out[0] = (h >>> 24) & 0xff
          out[1] = (h >>> 16) & 0xff
          out[2] = (h >>> 8) & 0xff
          out[3] = h & 0xff
          return out
        } catch {
          return createProtocolNeutralMaskFill({
            length: 4,
            packetIndex,
            offset,
            domain: 'iua-ifid',
          })
        }
      },
      { fallbackKind: 'text-x', protocol: 'iua', category: 'opaque-id', packetIndex },
    )
  } catch {
    /* overlap */
  }
  coverage.push({ protocol: 'iua-id', offset, length: 4, status: 'covered' })
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'iua')
}
