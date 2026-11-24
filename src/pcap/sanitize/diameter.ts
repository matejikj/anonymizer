/**
 * T22 — Diameter (TCP 3868): AVP walker — map hosts/IDs; mask auth vectors and unknown AVPs.
 * SCTP transport: complete DATA chunks with PPID 46/47 dispatch via T17 sanitizeSctp.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { deferredBinaryMapMeta } from './deferredMapMeta.ts'
import { maskPayloadSpan } from '../protocols/application/textproto'

const DIAMETER_PORTS = new Set([3868])
const MAX_AVP_DEPTH = 6

const AVP_USER_NAME = 1
const AVP_HOST_IP = 257
const AVP_SESSION_ID = 263
const AVP_ORIGIN_HOST = 264
const AVP_DEST_HOST = 293
const AVP_ROUTE_RECORD = 282
const AVP_DEST_REALM = 283
const AVP_ORIGIN_REALM = 296
const AVP_RESULT_CODE = 268
const AVP_AUTH_APP_ID = 258
const AVP_VENDOR_ID = 266
const AVP_SUBSCRIPTION_ID = 443
const AVP_SUBSCRIPTION_ID_DATA = 444
const AVP_SUBSCRIPTION_ID_TYPE = 450
const AVP_UE_INFO = 458
const AVP_EAP_PAYLOAD = 462
const AVP_AUTH_INFO = 1413 // S6a Authentication-Info (3GPP)

const PRESERVE_CODES = new Set([
  AVP_RESULT_CODE,
  AVP_AUTH_APP_ID,
  AVP_VENDOR_ID,
  416, // CC-Request-Type
  415, // CC-Request-Number
  258,
  266,
  268,
  278, // Origin-State-Id
  55, // Accounting-Record-Type
  485, // Accounting-Record-Number
])

const ALWAYS_MASK = new Set([
  AVP_EAP_PAYLOAD,
  AVP_AUTH_INFO,
  1447, // SIP-Auth-Data-Item
  1448, // SIP-Authentication-Scheme
  1414, // E-UTRAN-Vector
])

export function isDiameterPortHint(src: number, dst: number): boolean {
  return DIAMETER_PORTS.has(src) || DIAMETER_PORTS.has(dst)
}

export function looksLikeDiameter(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 20) return false
  const version = data[offset]!
  const msgLen =
    ((data[offset + 1]! & 0xff) << 16)
    | (data[offset + 2]! << 8)
    | data[offset + 3]!
  return version === 1 && msgLen === length
}

export function sanitizeDiameter(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeDiameter(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  // Header 20B: version/length/flags/cmd/app-id/hop-by-hop/end-to-end — preserve correlation nonces
  coverage.push({ protocol: 'diameter', offset, length: 20, status: 'covered' })

  walkAvps(
    buffer,
    offset + 20,
    length - 20,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
    0,
  )
  return { coverage, issues }
}

function walkAvps(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
): void {
  if (depth > MAX_AVP_DEPTH) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'diameter-depth')
    coverage.push({ protocol: 'diameter', offset, length, status: 'redacted' })
    issues.push('diameter-avp-depth')
    return
  }
  let pos = offset
  const end = offset + length
  while (pos + 8 <= end) {
    const code =
      (buffer[pos]! << 24)
      | (buffer[pos + 1]! << 16)
      | (buffer[pos + 2]! << 8)
      | buffer[pos + 3]!
    const flags = buffer[pos + 4]!
    const avpLen =
      ((buffer[pos + 5]! & 0xff) << 16)
      | (buffer[pos + 6]! << 8)
      | buffer[pos + 7]!
    if (avpLen < 8 || pos + avpLen > end) {
      maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'diameter-avp-trunc')
      coverage.push({ protocol: 'diameter', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('diameter-avp-length')
      break
    }
    const vendor = (flags & 0x80) !== 0
    const headerLen = vendor ? 12 : 8
    if (avpLen < headerLen) {
      maskPayloadSpan(collector, pos, avpLen, intents, packetIndex, 'diameter-avp-hdr')
      break
    }
    const dataOff = pos + headerLen
    const dataLen = avpLen - headerLen
    const pad = (4 - (avpLen % 4)) % 4
    coverage.push({ protocol: 'diameter', offset: pos, length: headerLen, status: 'covered' })

    sanitizeAvpData(
      buffer,
      code,
      dataOff,
      dataLen,
      flags,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      depth,
    )
    // Padding may contain canaries — mask
    if (pad > 0 && pos + avpLen + pad <= end) {
      maskPayloadSpan(collector, pos + avpLen, pad, intents, packetIndex, 'diameter-avp-pad')
    }
    pos += avpLen + pad
  }
  if (pos < end) {
    maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'diameter-trailer')
    coverage.push({ protocol: 'diameter', offset: pos, length: end - pos, status: 'redacted' })
  }
}

function sanitizeAvpData(
  buffer: Uint8Array,
  code: number,
  dataOff: number,
  dataLen: number,
  flags: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
): void {
  if (dataLen <= 0) return
  const grouped = (flags & 0x20) !== 0 || code === AVP_SUBSCRIPTION_ID || code === AVP_UE_INFO || code === AVP_AUTH_INFO

  if (ALWAYS_MASK.has(code)) {
    maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, `diameter-secret-${code}`)
    coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'redacted' })
    return
  }
  if (PRESERVE_CODES.has(code)) {
    coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
    return
  }

  switch (code) {
    case AVP_SESSION_ID:
      mapSessionId(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case AVP_ORIGIN_HOST:
    case AVP_DEST_HOST:
    case AVP_ROUTE_RECORD:
      mapHostname(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case AVP_ORIGIN_REALM:
    case AVP_DEST_REALM:
      mapRealm(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case AVP_HOST_IP:
      if (dataLen === 6 && buffer[dataOff] === 0 && buffer[dataOff + 1] === 1) {
        mapIpv4(buffer, dataOff + 2, collector, mapping, intents, packetIndex)
      } else if (dataLen === 18 && buffer[dataOff] === 0 && buffer[dataOff + 1] === 2) {
        mapIpv6(buffer, dataOff + 2, collector, mapping, intents, packetIndex)
      } else {
        maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, 'diameter-host-ip')
      }
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case AVP_USER_NAME:
      mapUserName(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case AVP_SUBSCRIPTION_ID_DATA:
      mapSubscriptionData(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case AVP_SUBSCRIPTION_ID_TYPE:
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'covered' })
      return
    default:
      if (grouped && dataLen >= 8) {
        walkAvps(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex, coverage, issues, depth + 1)
        return
      }
      // Unknown AVP — fail-closed mask (ignore M-bit)
      maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, `diameter-avp-${code}`)
      coverage.push({ protocol: 'diameter', offset: dataOff, length: dataLen, status: 'redacted' })
  }
}

function mapSessionId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  // host;high;low[;opt]
  const parts = raw.split(';')
  if (parts.length >= 3 && parts[0]!.length > 0) {
    const hostLen = parts[0]!.length
    mapHostname(buffer, abs, hostLen, collector, mapping, intents, packetIndex)
    const restOff = abs + hostLen
    const restLen = len - hostLen
    if (restLen > 0) {
      // keep leading ';' then opaque-map remainder
      mapOpaqueAscii(buffer, restOff, restLen, collector, mapping, intents, packetIndex)
    }
    return
  }
  mapOpaqueAscii(buffer, abs, len, collector, mapping, intents, packetIndex)
}

function mapRealm(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len)
  // Preserve 3GPP PLMN shape epc.mncXXX.mccYYY.3gppnetwork.org — map only non-PLMN host labels
  if (/mnc\d{3}\.mcc\d{3}\.3gppnetwork\.org$/i.test(raw)) {
    coveragePreserve(collector, abs, len)
    return
  }
  mapHostname(buffer, abs, len, collector, mapping, intents, packetIndex)
}

function coveragePreserve(_c: PatchCollector, _a: number, _l: number): void {
  // structural preserve — no patch
}

function mapHostname(
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
    maskPayloadSpan(collector, abs, len, intents, packetIndex, 'diameter-hostname')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'hostname', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('hostname', canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'diameter-host' })
    }
  }, { fallbackKind: 'text-x', protocol: 'diameter', category: 'hostname', packetIndex })
  void mapping
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
  const raw = latin1(buffer, abs, len).trim()
  if (/^\d{6,15}$/.test(raw)) {
    mapDigits(buffer, abs, len, 'imsi', collector, mapping, intents, packetIndex)
    return
  }
  mapOpaqueAscii(buffer, abs, len, collector, mapping, intents, packetIndex, 'sip-user', raw.toLowerCase())
}

function mapSubscriptionData(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = latin1(buffer, abs, len).trim()
  if (/^\+?\d{6,15}$/.test(raw)) {
    mapOpaqueAscii(buffer, abs, len, collector, mapping, intents, packetIndex, 'sip-phone', raw)
    return
  }
  if (/^\d{6,15}$/.test(raw)) {
    mapDigits(buffer, abs, len, 'imsi', collector, mapping, intents, packetIndex)
    return
  }
  maskPayloadSpan(collector, abs, len, intents, packetIndex, 'diameter-subscription')
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
    maskPayloadSpan(collector, abs, len, intents, packetIndex, `diameter-${category}`)
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor(category, canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `diameter-${category}` })
    }
  }, { fallbackKind: 'digits', protocol: 'diameter', category, packetIndex })
  void mapping
}

function mapOpaqueAscii(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  category: 'opaque-id' | 'sip-user' | 'sip-phone' = 'opaque-id',
  canonOverride?: string,
): void {
  const raw = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity(category, canonOverride ?? raw) ?? (canonOverride ?? raw)
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor(category, canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `diameter-${category}` })
    }
  }, { fallbackKind: 'text-x', protocol: 'diameter', category, packetIndex })
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
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', text, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', text)
    return new Uint8Array(mapped.split('.').map(Number))
  }, deferredBinaryMapMeta('diameter', packetIndex, 'ipv4', text))
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
    const fill = createProtocolNeutralMaskFill({ length: 16, packetIndex, offset: abs, domain: 'diameter-ipv6' })
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
  }, deferredBinaryMapMeta('diameter', packetIndex, 'ipv6', text))
  void mapping
}

function latin1(buffer: Uint8Array, abs: number, len: number): string {
  return new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
}
