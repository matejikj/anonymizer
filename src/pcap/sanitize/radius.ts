/**
 * T22 — RADIUS (UDP 1812/1813/1645/1646/3799): map identities; mask authenticators and passwords.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { maskPayloadSpan } from '../protocols/application/textproto'
import { sanitizeEapPacket } from './eapol'
import { mapSsidBytes } from './wireless/common.ts'
import { deferredBinaryMapMeta, deferredTextMapMeta } from './deferredMapMeta.ts'

const RADIUS_PORTS = new Set([1812, 1813, 1645, 1646, 3799])

const ATTR_USER_NAME = 1
const ATTR_USER_PASSWORD = 2
const ATTR_CHAP_PASSWORD = 3
const ATTR_NAS_IP = 4
const ATTR_FRAMED_IP = 8
const ATTR_REPLY_MESSAGE = 18
const ATTR_STATE = 24
const ATTR_CLASS = 25
const ATTR_VENDOR = 26
const ATTR_CALLED_STATION = 30
const ATTR_CALLING_STATION = 31
const ATTR_NAS_ID = 32
const ATTR_ACCT_SESSION = 44
const ATTR_ACCT_MULTI = 50
const ATTR_EVENT_TS = 55
const ATTR_CHAP_CHALLENGE = 60
const ATTR_TUNNEL_PASSWORD = 69
const ATTR_EAP_MESSAGE = 79
const ATTR_MSG_AUTH = 80
const ATTR_TUNNEL_PRIVATE_GROUP = 81
const ATTR_NAS_IPV6 = 95
const ATTR_FRAMED_IPV6_PREFIX = 97

/** Structural / accounting counters — preserve value bytes. */
const PRESERVE_ATTR = new Set([
  5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 27, 28, 29, 40, 41, 42, 43, 45, 46, 47, 48, 49, 51, 52, 53,
  61, 62, 63, 64, 65, 66, 67, 68, 85, 87,
])

export function isRadiusPortHint(src: number, dst: number): boolean {
  return RADIUS_PORTS.has(src) || RADIUS_PORTS.has(dst)
}

export function looksLikeRadius(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 20) return false
  const code = data[offset]!
  const pktLen = (data[offset + 2]! << 8) | data[offset + 3]!
  return code >= 1 && code <= 45 && pktLen === length && pktLen >= 20
}

export function sanitizeRadius(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
): AppLayerResult | null {
  if (!looksLikeRadius(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  // Code + Identifier + Length preserved; Authenticator (16) always masked
  coverage.push({ protocol: 'radius', offset, length: 4, status: 'covered' })
  maskPayloadSpan(collector, offset + 4, 16, intents, packetIndex, 'radius-authenticator')
  coverage.push({ protocol: 'radius', offset: offset + 4, length: 16, status: 'redacted' })

  const eapChunks: { abs: number; len: number }[] = []
  let pos = offset + 20
  const end = offset + length
  while (pos + 2 <= end) {
    const type = buffer[pos]!
    const attrLen = buffer[pos + 1]!
    if (attrLen < 2 || pos + attrLen > end) {
      coverage.push({ protocol: 'radius', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('radius-attr-truncated')
      break
    }
    const valOff = pos + 2
    const valLen = attrLen - 2
    sanitizeAttr(
      buffer,
      type,
      valOff,
      valLen,
      collector,
      mapping,
      intents,
      packetIndex,
      payloadTime,
      eapChunks,
      coverage,
      issues,
    )
    pos += attrLen
  }
  if (pos < end) {
    // Trailing bytes — not trusted padding
    maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'radius-trailer')
    coverage.push({ protocol: 'radius', offset: pos, length: end - pos, status: 'redacted' })
  }

  if (eapChunks.length > 0) {
    applyEapMessages(buffer, eapChunks, collector, mapping, intents, packetIndex, coverage, issues)
  }

  return { coverage, issues }
}

function sanitizeAttr(
  buffer: Uint8Array,
  type: number,
  valOff: number,
  valLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  eapChunks: { abs: number; len: number }[],
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (valLen <= 0) {
    coverage.push({ protocol: 'radius', offset: valOff - 2, length: 2, status: 'covered' })
    return
  }

  switch (type) {
    case ATTR_USER_PASSWORD:
    case ATTR_CHAP_PASSWORD:
    case ATTR_CHAP_CHALLENGE:
    case ATTR_TUNNEL_PASSWORD:
    case ATTR_MSG_AUTH:
      maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, `radius-secret-${type}`)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'redacted' })
      return
    case ATTR_USER_NAME:
      mapUserName(buffer, valOff, valLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_NAS_IP:
    case ATTR_FRAMED_IP:
      if (valLen === 4) mapIpv4(buffer, valOff, collector, mapping, intents, packetIndex)
      else maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, 'radius-ip')
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_NAS_IPV6:
      if (valLen === 16) mapIpv6(buffer, valOff, collector, mapping, intents, packetIndex)
      else maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, 'radius-ipv6')
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_FRAMED_IPV6_PREFIX:
      // reserved(1) + prefix-len(1) + prefix bytes
      if (valLen >= 2) {
        const prefLen = Math.min(valLen - 2, 16)
        if (prefLen > 0) maskPayloadSpan(collector, valOff + 2, prefLen, intents, packetIndex, 'radius-ipv6-prefix')
      }
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'redacted' })
      return
    case ATTR_NAS_ID:
      mapHostnameAscii(buffer, valOff, valLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_CALLED_STATION:
    case ATTR_CALLING_STATION:
      // Cover type+length so residual payload masking cannot swallow the value (T40 SSID).
      coverage.push({ protocol: 'radius', offset: valOff - 2, length: 2, status: 'covered' })
      mapStationId(buffer, valOff, valLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_STATE:
    case ATTR_CLASS:
    case ATTR_ACCT_SESSION:
    case ATTR_ACCT_MULTI:
      mapOpaque(buffer, valOff, valLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_REPLY_MESSAGE:
      // Unknown free text — mask (not detector-only)
      maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, 'radius-reply-message')
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'redacted' })
      return
    case ATTR_EVENT_TS:
      if (valLen === 4) rewriteEventTimestamp(buffer, valOff, collector, intents, packetIndex, payloadTime)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
      return
    case ATTR_EAP_MESSAGE:
      eapChunks.push({ abs: valOff, len: valLen })
      coverage.push({ protocol: 'radius', offset: valOff - 2, length: 2, status: 'covered' })
      return
    case ATTR_VENDOR:
      sanitizeVendor(buffer, valOff, valLen, collector, mapping, intents, packetIndex, coverage)
      return
    case ATTR_TUNNEL_PRIVATE_GROUP:
      // May be VLAN id as string or binary
      if (valLen === 4) {
        const tag = buffer[valOff]! // tag byte often present
        void tag
        const vlan = (buffer[valOff + 2]! << 8) | buffer[valOff + 3]!
        if (vlan > 0 && vlan < 4095) {
          mapVlan(buffer, valOff + 2, vlan, collector, mapping, intents, packetIndex)
          coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
          return
        }
      }
      maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, 'radius-tunnel-group')
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'redacted' })
      return
    default:
      if (PRESERVE_ATTR.has(type)) {
        coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'covered' })
        return
      }
      maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, `radius-attr-${type}`)
      coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'redacted' })
  }
  void issues
}

function applyEapMessages(
  buffer: Uint8Array,
  chunks: { abs: number; len: number }[],
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // Concatenate for parse; patches apply to original attribute spans via relative offsets.
  const total = chunks.reduce((s, c) => s + c.len, 0)
  if (total <= 0 || total > 4096) {
    for (const c of chunks) {
      maskPayloadSpan(collector, c.abs, c.len, intents, packetIndex, 'radius-eap-oversize')
      coverage.push({ protocol: 'radius', offset: c.abs, length: c.len, status: 'redacted' })
    }
    return
  }
  const assembled = new Uint8Array(total)
  let o = 0
  for (const c of chunks) {
    assembled.set(buffer.subarray(c.abs, c.abs + c.len), o)
    o += c.len
  }
  // Sanitize against a scratch buffer then project masks/maps onto wire chunks by absolute remap.
  // Simpler fail-closed: mask all EAP attribute values, then if Identity-only map first chunk text.
  const scratchCollector = collector
  // Map assembled offsets → wire: walk EAP on assembled using absolute offsets of first chunk only
  // when single chunk; multi-chunk → mask all (fragmented EAP identity rare in baseline).
  if (chunks.length === 1) {
    const c = chunks[0]!
    sanitizeEapPacket(buffer, c.abs, c.len, scratchCollector, mapping, intents, packetIndex, coverage, issues)
    return
  }
  for (const c of chunks) {
    maskPayloadSpan(collector, c.abs, c.len, intents, packetIndex, 'radius-eap-fragment')
    coverage.push({ protocol: 'eap', offset: c.abs, length: c.len, status: 'redacted' })
  }
  issues.push('radius-eap-multi-attr')
}

function sanitizeVendor(
  buffer: Uint8Array,
  valOff: number,
  valLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (valLen < 6) {
    maskPayloadSpan(collector, valOff, valLen, intents, packetIndex, 'radius-vsa-short')
    coverage.push({ protocol: 'radius', offset: valOff, length: valLen, status: 'redacted' })
    return
  }
  const vendorId =
    (buffer[valOff]! << 24)
    | (buffer[valOff + 1]! << 16)
    | (buffer[valOff + 2]! << 8)
    | buffer[valOff + 3]!
  // Vendor-Id preserved; walk vendor attrs (type,len,value)
  coverage.push({ protocol: 'radius', offset: valOff, length: 4, status: 'covered' })
  let pos = valOff + 4
  const end = valOff + valLen
  // Microsoft vendor 311 — MS-CHAP / MPPE keys always mask
  const microsoft = vendorId === 311
  const cisco = vendorId === 9
  while (pos + 2 <= end) {
    const vType = buffer[pos]!
    const vLen = buffer[pos + 1]!
    if (vLen < 2 || pos + vLen > end) {
      maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'radius-vsa-trunc')
      break
    }
    const vVal = pos + 2
    const vValLen = vLen - 2
    if (microsoft || (cisco && vType === 1)) {
      // Cisco AVPair: try detectors on key=value; unknown mask
      if (cisco && vType === 1 && vValLen > 0) {
        const text = latin1(buffer, vVal, vValLen)
        if (/password|secret|key=/i.test(text)) {
          maskPayloadSpan(collector, vVal, vValLen, intents, packetIndex, 'radius-cisco-secret')
        } else {
          mapHostnameAscii(buffer, vVal, vValLen, collector, mapping, intents, packetIndex)
        }
      } else {
        maskPayloadSpan(collector, vVal, vValLen, intents, packetIndex, 'radius-ms-chap')
      }
      coverage.push({ protocol: 'radius', offset: vVal, length: vValLen, status: 'redacted' })
    } else {
      // 3GPP vendor 10415 — IMSI/IMEI/MSISDN style: digit map when looks numeric
      if (vendorId === 10415 && vValLen > 0) {
        const text = latin1(buffer, vVal, vValLen).replace(/\D/g, '')
        if (text.length >= 14 && text.length <= 16) {
          mapDigits(buffer, vVal, vValLen, 'imei', collector, mapping, intents, packetIndex)
        } else if (text.length >= 6 && text.length <= 15) {
          mapDigits(buffer, vVal, vValLen, 'imsi', collector, mapping, intents, packetIndex)
        } else {
          maskPayloadSpan(collector, vVal, vValLen, intents, packetIndex, 'radius-3gpp')
        }
      } else {
        maskPayloadSpan(collector, vVal, vValLen, intents, packetIndex, 'radius-vsa-unknown')
      }
      coverage.push({ protocol: 'radius', offset: vVal, length: Math.max(0, vValLen), status: 'redacted' })
    }
    pos += vLen
  }
}

function rewriteEventTimestamp(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
): void {
  const sec =
    ((buffer[abs]! << 24) | (buffer[abs + 1]! << 16) | (buffer[abs + 2]! << 8) | buffer[abs + 3]!) >>> 0
  if (!payloadTime?.isBound) {
    maskPayloadSpan(collector, abs, 4, intents, packetIndex, 'radius-event-ts')
    return
  }
  const shiftedMs = payloadTime.shiftAbsoluteEpochMs(sec * 1000)
  if (shiftedMs === null) {
    maskPayloadSpan(collector, abs, 4, intents, packetIndex, 'radius-event-ts')
    return
  }
  const shiftedSec = Math.floor(shiftedMs / 1000) >>> 0
  intents?.recordEntityReplacement(packetIndex, abs, 'timestamp', String(sec), 4)
  collector.addDeferred(abs, 4, () => new Uint8Array([
    (shiftedSec >>> 24) & 0xff,
    (shiftedSec >>> 16) & 0xff,
    (shiftedSec >>> 8) & 0xff,
    shiftedSec & 0xff,
  ]), { fallbackKind: 'binary-mask', protocol: 'radius', category: 'timestamp', packetIndex })
}

function mapUserName(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  const trimmed = raw.trim()
  // IMSI-only NAI
  if (/^\d{6,15}$/.test(trimmed)) {
    mapDigits(buffer, abs, len, 'imsi', collector, mapping, intents, packetIndex)
    return
  }
  const at = raw.indexOf('@')
  if (at > 0) {
    const user = raw.slice(0, at)
    const realm = raw.slice(at + 1)
    mapAsciiCategory(buffer, abs, at, 'sip-user', user.trim().toLowerCase(), collector, mapping, intents, packetIndex)
    if (realm.length > 0 && realm.includes('.')) {
      mapHostnameAscii(buffer, abs + at + 1, realm.length, collector, mapping, intents, packetIndex)
    }
    return
  }
  mapAsciiCategory(buffer, abs, len, 'sip-user', trimmed.toLowerCase(), collector, mapping, intents, packetIndex)
}

function mapStationId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  // MAC forms: AA-BB-CC-DD-EE-FF or AA:BB:… optionally :SSID
  const macMatch = raw.match(/^([0-9a-fA-F]{2}([-:])){5}[0-9a-fA-F]{2}/)
  if (macMatch) {
    const macLen = macMatch[0]!.length
    const macText = macMatch[0]!.replace(/-/g, ':').toLowerCase()
    const canon = canonicalizeIdentity('mac', macText)
    if (canon) {
      const constraint = { kind: 'text-ascii' as const, byteLength: macLen }
      intents?.recordEntityReplacement(packetIndex, abs, 'mac', canon, macLen, constraint, macMatch[0])
      collector.addDeferred(abs, macLen, ({ mapping: live }) => {
        try {
          const alias = live.aliasFor('mac', canon, constraint, macMatch[0])
          return computeFixedLengthAsciiBytes(abs, macLen, alias)
        } catch {
          return createProtocolNeutralMaskFill({ length: macLen, packetIndex, offset: abs, domain: 'radius-mac' })
        }
      }, deferredTextMapMeta('radius', packetIndex, 'mac', macMatch[0], macLen, { canonical: canon }))
    }
    if (macLen < len) {
      let ssidOff = abs + macLen
      let ssidLen = len - macLen
      while (ssidLen > 0 && (buffer[ssidOff] === 0x3a || buffer[ssidOff] === 0x2d)) {
        ssidOff++
        ssidLen--
      }
      if (ssidLen > 0 && ssidLen <= 32) {
        mapSsidBytes(buffer, ssidOff, ssidLen, collector, mapping, intents, packetIndex, 'radius')
      } else if (ssidLen > 0) {
        maskPayloadSpan(collector, ssidOff, ssidLen, intents, packetIndex, 'radius-ssid')
      }
    }
    void mapping
    return
  }
  if (/^\+?\d{6,15}$/.test(raw.trim())) {
    mapAsciiCategory(buffer, abs, len, 'sip-phone', raw.trim(), collector, mapping, intents, packetIndex)
    return
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw.trim())) {
    mapHostnameAscii(buffer, abs, len, collector, mapping, intents, packetIndex)
    return
  }
  maskPayloadSpan(collector, abs, len, intents, packetIndex, 'radius-station')
}

function mapDigits(
  buffer: Uint8Array,
  abs: number,
  len: number,
  category: 'imsi' | 'imei',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  const digits = raw.replace(/\D/g, '')
  const canon = canonicalizeIdentity(category, digits)
  if (!canon) {
    maskPayloadSpan(collector, abs, len, intents, packetIndex, `radius-${category}`)
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor(category, canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `radius-${category}` })
    }
  }, deferredTextMapMeta('radius', packetIndex, category, raw, len, { fallbackKind: 'digits', canonical: canon }))
  void mapping
  void buffer
}

function mapAsciiCategory(
  buffer: Uint8Array,
  abs: number,
  len: number,
  category: 'sip-user' | 'sip-phone' | 'opaque-id',
  canonRaw: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity(category, canonRaw) ?? canonRaw
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor(category, canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `radius-${category}` })
    }
  }, deferredTextMapMeta('radius', packetIndex, category, raw, len, { canonical: canon }))
  void mapping
}

function mapHostnameAscii(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity('hostname', raw.trim().toLowerCase())
  if (!canon) {
    maskPayloadSpan(collector, abs, len, intents, packetIndex, 'radius-hostname')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'hostname', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('hostname', canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'radius-hostname' })
    }
  }, deferredTextMapMeta('radius', packetIndex, 'hostname', raw, len, { canonical: canon }))
  void mapping
}

function mapOpaque(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  const hex = Array.from(buffer.subarray(abs, abs + len)).map((b) => b.toString(16).padStart(2, '0')).join('')
  const canon = canonicalizeIdentity('opaque-id', hex.length >= 4 ? hex : raw) ?? hex
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  // Binary opaque: use binary mask keyed by alias when not printable
  const printable = /^[\x20-\x7e]+$/.test(raw)
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len, printable ? constraint : { kind: 'text-ascii', byteLength: len }, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      if (printable) {
        return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('opaque-id', canon, constraint, raw))
      }
      const alias = live.map('opaque-id', canon)
      return createProtocolNeutralMaskFill({
        length: len,
        packetIndex,
        offset: abs,
        domain: `radius-opaque:${alias.slice(0, 16)}`,
      })
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'radius-opaque' })
    }
  }, printable
    ? deferredTextMapMeta('radius', packetIndex, 'opaque-id', raw, len, { canonical: canon })
    : { fallbackKind: 'binary-mask', protocol: 'radius', category: 'opaque-id', packetIndex })
  void mapping
}

function mapIpv4(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = `${buffer[abs]!}.${buffer[abs + 1]!}.${buffer[abs + 2]!}.${buffer[abs + 3]!}`
  if (text === '0.0.0.0' || text === '255.255.255.255') return
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', text, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', text)
    return new Uint8Array(mapped.split('.').map(Number))
  }, deferredBinaryMapMeta('radius', packetIndex, 'ipv4', text))
  void mapping
}

function mapIpv6(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buffer[abs + i]! << 8) | buffer[abs + i + 1]!).toString(16))
  }
  const text = parts.join(':')
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv6', text, 16)
  collector.addDeferred(abs, 16, ({ mapping: live }) => {
    const mapped = live.map('ipv6', text)
    const fill = createProtocolNeutralMaskFill({ length: 16, packetIndex, offset: abs, domain: 'radius-ipv6' })
    const hextets = mapped.split(':')
    if (hextets.length !== 8) return fill
    const out = new Uint8Array(16)
    for (let i = 0; i < 8; i++) {
      const v = Number.parseInt(hextets[i]!, 16)
      if (!Number.isInteger(v) || v < 0 || v > 0xffff) return fill
      out[i * 2] = (v >> 8) & 0xff
      out[i * 2 + 1] = v & 0xff
    }
    return out
  }, deferredBinaryMapMeta('radius', packetIndex, 'ipv6', text))
  void mapping
}

function mapVlan(
  buffer: Uint8Array,
  abs: number,
  vlan: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const canonical = `${vlan}`
  intents?.recordEntityReplacement(packetIndex, abs, 'vlan', canonical, 2)
  collector.addDeferred(abs, 2, ({ mapping: live }) => {
    const mapped = Number.parseInt(live.map('vlan', canonical), 10)
    if (!Number.isInteger(mapped) || mapped < 1 || mapped > 4094) return null
    return new Uint8Array([(mapped >> 8) & 0xff, mapped & 0xff])
  }, deferredBinaryMapMeta('radius', packetIndex, 'vlan', canonical, { fallbackKind: 'digits', canonical }))
  void mapping
  void buffer
}

function latin1(buffer: Uint8Array, abs: number, len: number): string {
  return new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
}
