/**
 * T24 — limited H.323: TPKT + Q.931 (TCP 1720). Calling/Called/Display IEs map;
 * H.225/RAS/H.245 PER UUIE → mask-only (no media pairing claim). RAS UDP 1719 identify+mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { IdentityCategory } from '../../mapping/identityCategories'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { maskPayloadSpan } from '../protocols/application/textproto'

const H225_PORTS = new Set([1720])
const RAS_PORTS = new Set([1719])

const Q931_CALLING = 0x6c
const Q931_CALLED = 0x70
const Q931_DISPLAY = 0x28
const Q931_CAUSE = 0x08

export function isH323PortHint(src: number, dst: number): boolean {
  return H225_PORTS.has(src) || H225_PORTS.has(dst)
}

export function isH323RasPortHint(src: number, dst: number): boolean {
  return RAS_PORTS.has(src) || RAS_PORTS.has(dst)
}

export function looksLikeTpktQ931(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 5) return false
  // TPKT: version 3, reserved 0, length BE
  if (data[offset] !== 3 || data[offset + 1] !== 0) return false
  const tpktLen = (data[offset + 2]! << 8) | data[offset + 3]!
  if (tpktLen < 5 || tpktLen > length) return false
  // Q.931: protocol discriminator 0x08
  return data[offset + 4] === 0x08
}

export function sanitizeH323(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeTpktQ931(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  const tpktLen = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
  coverage.push({ protocol: 'h323-tpkt', offset, length: 4, status: 'covered' })

  // Q.931 after TPKT
  const qOff = offset + 4
  const qLen = Math.min(tpktLen - 4, offset + length - qOff)
  if (qLen < 3) {
    maskPayloadSpan(collector, qOff, Math.max(0, offset + length - qOff), intents, packetIndex, 'h323-q931-trunc')
    return {
      coverage: [{ protocol: 'h323', offset, length, status: 'malformed' }],
      issues: ['h323-q931-trunc'],
    }
  }

  // PD (1) + call ref len (1) + call ref + message type
  const crLen = buffer[qOff + 1]! & 0x0f
  const msgTypeOff = qOff + 2 + crLen
  if (msgTypeOff >= qOff + qLen) {
    coverage.push({ protocol: 'h323-q931', offset: qOff, length: qLen, status: 'malformed' })
    issues.push('h323-q931-hdr')
    coverage.unshift({ protocol: 'h323', offset, length, status: 'covered' })
    return { coverage, issues }
  }
  coverage.push({ protocol: 'h323-q931', offset: qOff, length: msgTypeOff - qOff + 1, status: 'covered' })

  let pos = msgTypeOff + 1
  const qEnd = qOff + qLen
  while (pos < qEnd) {
    const iei = buffer[pos]!
    // single-octet IE (shift codes etc.) when bit 7 set for some; Q.931 variable:
    if ((iei & 0x80) !== 0) {
      // single octet IE
      coverage.push({ protocol: 'h323-ie', offset: pos, length: 1, status: 'covered' })
      pos += 1
      continue
    }
    if (pos + 1 >= qEnd) break
    const ieLen = buffer[pos + 1]!
    if (pos + 2 + ieLen > qEnd) {
      maskPayloadSpan(collector, pos, qEnd - pos, intents, packetIndex, 'h323-ie-trunc')
      coverage.push({ protocol: 'h323-ie', offset: pos, length: qEnd - pos, status: 'malformed' })
      issues.push('h323-ie-trunc')
      break
    }
    const dataOff = pos + 2
    switch (iei) {
      case Q931_CALLING:
      case Q931_CALLED:
        sanitizeNumberIe(buffer, dataOff, ieLen, collector, mapping, intents, packetIndex, coverage)
        break
      case Q931_DISPLAY:
        mapAscii(buffer, dataOff, ieLen, 'person', collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'h323-display', offset: dataOff, length: ieLen, status: 'covered' })
        break
      case Q931_CAUSE:
        coverage.push({ protocol: 'h323-cause', offset: pos, length: 2 + ieLen, status: 'covered' })
        break
      default:
        // Unknown IE — preserve type/len, mask content (incl. possible H.225 UUIE)
        if (ieLen > 0) {
          maskPayloadSpan(collector, dataOff, ieLen, intents, packetIndex, `h323-ie-${iei}`)
          coverage.push({ protocol: 'h323-ie', offset: dataOff, length: ieLen, status: 'redacted' })
        }
        coverage.push({ protocol: 'h323-ie-hdr', offset: pos, length: 2, status: 'covered' })
    }
    pos += 2 + ieLen
  }

  // Trailing bytes after Q.931 inside TPKT (often H.225 UUIE PER) → mask
  const afterQ = qOff + qLen
  const frameEnd = offset + Math.min(tpktLen, length)
  if (afterQ < frameEnd) {
    maskPayloadSpan(collector, afterQ, frameEnd - afterQ, intents, packetIndex, 'h323-h225-per')
    coverage.push({
      protocol: 'h323-h225',
      offset: afterQ,
      length: frameEnd - afterQ,
      status: 'redacted',
    })
    issues.push('h323-h225-per-mask')
  }

  // Do not claim full-frame "covered" when UUIE/H.225 (or other IEs) were only masked.
  const parentStatus = coverage.some(
    (c) => c.status === 'redacted' || c.status === 'unsupported' || c.status === 'malformed',
  )
    ? 'redacted'
    : 'covered'
  coverage.unshift({ protocol: 'h323', offset, length, status: parentStatus })
  return { coverage, issues }
}

/** RAS (UDP 1719) — PER identify+mask, no structured claim. */
export function sanitizeH323Ras(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  void mapping
  void buffer
  if (length < 2) return null
  maskPayloadSpan(collector, offset, length, intents, packetIndex, 'h323-ras')
  return {
    coverage: [{ protocol: 'h323-ras', offset, length, status: 'redacted' }],
    issues: ['h323-ras-per-mask'],
  }
}

function sanitizeNumberIe(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (length < 1) return
  // First octet: type/plan — preserve; digits follow as IA5 or BCD
  coverage.push({ protocol: 'h323-number-hdr', offset, length: 1, status: 'covered' })
  if (length === 1) return
  const digitOff = offset + 1
  const digitLen = length - 1
  // Prefer IA5 digit string
  let ascii = true
  for (let i = 0; i < digitLen; i++) {
    const c = buffer[digitOff + i]!
    if (c === 0) break
    if (c < 0x30 || c > 0x39) {
      if (c !== 0x23 && c !== 0x2a) { ascii = false; break }
    }
  }
  if (ascii) {
    mapAscii(buffer, digitOff, digitLen, 'sip-phone', collector, mapping, intents, packetIndex)
  } else {
    // BCD / unknown — mask digits, keep type octet
    maskPayloadSpan(collector, digitOff, digitLen, intents, packetIndex, 'h323-number-bcd')
  }
  coverage.push({ protocol: 'h323-number', offset: digitOff, length: digitLen, status: 'redacted' })
}

function mapAscii(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  let text = ''
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) break
    if (c < 0x20 || c > 0x7e) {
      maskPayloadSpan(collector, offset, length, intents, packetIndex, `h323-${category}`)
      return
    }
    text += String.fromCharCode(c)
  }
  if (!text) return
  const canon = canonicalizeIdentity(category, text) ?? text
  const constraint = { kind: 'text-ascii' as const, byteLength: text.length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, text.length, constraint, text)
  collector.addDeferred(offset, text.length, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(
        offset, text.length, live.aliasFor(category, canon, constraint, text),
      )
    } catch {
      return createProtocolNeutralMaskFill({
        length: text.length, packetIndex, offset, domain: `h323-${category}`,
      })
    }
  }, {
    fallbackKind: category === 'sip-phone' ? 'digits' : 'text-x',
    protocol: 'h323',
    category,
    packetIndex,
  })
  if (text.length < length) {
    maskPayloadSpan(collector, offset + text.length, length - text.length, intents, packetIndex, 'h323-pad')
  }
}
