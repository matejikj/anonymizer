/**
 * T26 — GTPv1/v2-C (UDP 2123) and GTP-U (UDP 2152) sanitizers.
 * Separate IE walkers for v1 TV/TLV vs v2 type/length/instance; GTP-U T-PDU via tunnel child port.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import {
  decodeTbcd,
  encodeTbcd,
  remapTbcdBytes,
  TBCD_GSM,
  normalizeImsiDigits,
  normalizeImeiDigits,
  scopeImsiWithPlmn,
} from '../protocols/application/binproto/tbcd'
import type { PatchCollector } from './PatchCollector'
import { deferredBinaryMapMeta, deferredTextMapMeta } from './deferredMapMeta.ts'
import type { AppLayerResult, LayerCoverage } from './types'

export type GtpSanitizeResult = AppLayerResult & { readonly drop?: boolean }
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import {
  sanitizeTunnel,
  sanitizeLinkedEthernet,
  type InnerTransportHandler,
} from './tunnel'

export const GTP_C_UDP_PORT = 2123
export const GTP_U_UDP_PORT = 2152

const MAX_IE_DEPTH = 8

/** GTPv2 IE types (TS 29.274 baseline). */
const V2 = {
  IMSI: 1,
  CAUSE: 2,
  RECOVERY: 3,
  APN: 71,
  AMBR: 72,
  EBI: 73,
  IP_ADDRESS: 74,
  MEI: 75,
  MSISDN: 76,
  INDICATION: 77,
  PCO: 78,
  PAA: 79,
  BEARER_QOS: 80,
  FLOW_QOS: 81,
  RAT_TYPE: 82,
  SERVING_NETWORK: 83,
  BEARER_TFT: 84,
  ULI: 86,
  F_TEID: 87,
  BEARER_CONTEXT: 93,
  CHARGING_ID: 94,
  CHARGING_CHARACTERISTICS: 95,
  PDN_TYPE: 99,
  APCO: 163,
} as const

/** GTPv1 TV fixed lengths (TS 29.060); unknown TV stops traversal. */
const V1_TV_LEN: ReadonlyMap<number, number> = new Map([
  [1, 1], // Cause
  [2, 8], // IMSI
  [3, 6], // RAI
  [4, 4], // TLLI
  [5, 4], // P-TMSI
  [8, 1], // Reordering Required
  [9, 28], // Authentication Triplet
  [11, 1], // MAP Cause
  [12, 3], // P-TMSI Signature
  [13, 1], // MS Validated
  [14, 1], // Recovery
  [15, 1], // Selection Mode
  [16, 4], // TEID Data I
  [17, 4], // TEID Control Plane
  [18, 5], // TEID Data II
  [19, 1], // Teardown Ind
  [20, 1], // NSAPI
  [21, 1], // RANAP Cause
  [22, 9], // RAB Context
  [23, 1], // Radio Priority SMS
  [24, 1], // Radio Priority
  [25, 2], // Packet Flow Id
  [26, 2], // Charging Characteristics
  [27, 2], // Trace Reference
  [28, 2], // Trace Type
  [29, 1], // MS Not Reachable Reason
  [127, 4], // Charging ID
])

const V1_TLV = {
  END_USER_ADDRESS: 128,
  APN: 131,
  PCO: 132,
  GSN_ADDRESS: 133,
  MSISDN: 134,
  IMEI: 154,
} as const

const GTP_U_G_PDU = 0xff
const GTP_U_ERROR_INDICATION = 26

export function isGtpCPort(src: number, dst: number): boolean {
  return src === GTP_C_UDP_PORT || dst === GTP_C_UDP_PORT
}

export function isGtpUPort(src: number, dst: number): boolean {
  return src === GTP_U_UDP_PORT || dst === GTP_U_UDP_PORT
}

export function isGtpPortHint(src: number, dst: number): boolean {
  return isGtpCPort(src, dst) || isGtpUPort(src, dst)
}

export function looksLikeGtp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const ver = (data[offset]! >> 5) & 0x7
  return ver === 1 || ver === 2
}

export type GtpTeidScope = {
  readonly receiveEndpoint?: string
  readonly plane?: string
  readonly generation?: number
}

export function sanitizeGtp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number,
  onInnerTransport?: InnerTransportHandler,
  /** Prefer user-plane when UDP 2152; control-plane when 2123. */
  plane: 'c' | 'u' | 'auto' = 'auto',
  teidScope?: GtpTeidScope,
): GtpSanitizeResult | null {
  if (!looksLikeGtp(buffer, offset, length)) return null
  const ver = (buffer[offset]! >> 5) & 0x7
  const msgType = buffer[offset + 1]!
  const treatAsU = plane === 'u'
    || (plane === 'auto' && (
      msgType === GTP_U_G_PDU
      || msgType === GTP_U_ERROR_INDICATION
      || msgType === 254
      || msgType === 31
    ))
  const scope: GtpTeidScope = {
    receiveEndpoint: teidScope?.receiveEndpoint,
    generation: teidScope?.generation,
    plane: teidScope?.plane ?? (plane === 'auto' ? (treatAsU ? 'u' : 'c') : plane),
  }
  if (ver === 2) {
    return sanitizeGtpv2C(buffer, offset, length, collector, mapping, intents, packetIndex, scope)
  }
  if (treatAsU) {
    return sanitizeGtpU(
      buffer, offset, length, collector, mapping, intents, packetIndex, depth, onInnerTransport, scope,
    )
  }
  return sanitizeGtpv1C(buffer, offset, length, collector, mapping, intents, packetIndex, scope)
}

function sanitizeGtpv2C(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  teidScope?: GtpTeidScope,
): GtpSanitizeResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = offset
  const end = offset + length
  let piggyIndex = 0
  while (pos < end) {
    const remain = end - pos
    if (remain < 4) {
      coverage.push({ protocol: 'gtpv2-c', offset: pos, length: remain, status: 'malformed' })
      issues.push('gtpv2-trunc')
      break
    }
    const flags = buffer[pos]!
    const msgLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const total = 4 + msgLen
    if (total < 8 || pos + total > end) {
      coverage.push({ protocol: 'gtpv2-c', offset: pos, length: remain, status: 'malformed' })
      issues.push('gtpv2-length-bad')
      maskSpan(collector, intents, packetIndex, pos, remain, 'gtpv2-trunc')
      break
    }
    if (piggyIndex > 0) {
      issues.push('gtpv2-piggyback')
      coverage.push({ protocol: 'gtpv2-piggyback', offset: pos, length: total, status: 'covered' })
    }
    sanitizeOneGtpv2Message(
      buffer,
      pos,
      total,
      collector,
      mapping,
      intents,
      packetIndex,
      teidScope,
      coverage,
      issues,
    )
    piggyIndex++
    const pFlag = (flags >> 4) & 0x1
    pos += total
    if (!pFlag) {
      if (pos < end) {
        maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv2-udp-trailer')
        coverage.push({ protocol: 'gtpv2-udp-trailer', offset: pos, length: end - pos, status: 'redacted' })
        issues.push('gtpv2-udp-trailer')
      }
      break
    }
  }
  coverage.unshift({ protocol: 'gtpv2-c', offset, length: pos - offset, status: 'covered' })
  return { coverage, issues }
}

function sanitizeOneGtpv2Message(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  teidScope: GtpTeidScope | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const flags = buffer[offset]!
  const tFlag = (flags >> 3) & 0x1
  let hdrLen = 4
  if (tFlag) hdrLen += 4
  hdrLen += 4 // seq (3) + spare (1)
  if (length < hdrLen) {
    coverage.push({ protocol: 'gtpv2-c-hdr', offset, length, status: 'malformed' })
    issues.push('gtpv2-hdr-trunc')
    return
  }
  coverage.push({ protocol: 'gtpv2-c-hdr', offset, length: hdrLen, status: 'covered' })
  if (tFlag) {
    patchTeid(buffer, offset + 4, collector, mapping, intents, packetIndex, teidScope)
  }
  walkGtpv2Ies(
    buffer,
    offset + hdrLen,
    length - hdrLen,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
    0,
  )
}

function sanitizeGtpv1C(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  teidScope?: GtpTeidScope,
): GtpSanitizeResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const hdr = parseGtpv1Header(buffer, offset, length)
  if (!hdr) {
    coverage.push({ protocol: 'gtpv1-c', offset, length, status: 'malformed' })
    return { coverage, issues: ['gtpv1-c-trunc'] }
  }
  coverage.push({ protocol: 'gtpv1-c', offset, length: hdr.headerLength, status: 'covered' })
  patchTeid(buffer, offset + 4, collector, mapping, intents, packetIndex, teidScope)
  if (hdr.extMasked) {
    maskSpan(collector, intents, packetIndex, hdr.extOff, hdr.extLen, 'gtpv1-ext')
    coverage.push({ protocol: 'gtpv1-ext', offset: hdr.extOff, length: hdr.extLen, status: 'redacted' })
  }
  walkGtpv1Ies(
    buffer,
    hdr.payloadOff,
    offset + length - hdr.payloadOff,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
    teidScope,
  )
  return { coverage, issues }
}

function sanitizeGtpU(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number,
  onInnerTransport?: InnerTransportHandler,
  teidScope?: GtpTeidScope,
): GtpSanitizeResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const hdr = parseGtpv1Header(buffer, offset, length)
  if (!hdr) {
    coverage.push({ protocol: 'gtp-u', offset, length, status: 'malformed' })
    return { coverage, issues: ['gtp-u-trunc'] }
  }
  coverage.push({ protocol: 'gtp-u', offset, length: hdr.headerLength, status: 'covered' })
  patchTeid(buffer, offset + 4, collector, mapping, intents, packetIndex, teidScope)
  if (hdr.extMasked) {
    maskSpan(collector, intents, packetIndex, hdr.extOff, hdr.extLen, 'gtp-u-ext')
    coverage.push({ protocol: 'gtp-u-ext', offset: hdr.extOff, length: hdr.extLen, status: 'redacted' })
  }
  const msgType = buffer[offset + 1]!
  if (msgType !== GTP_U_G_PDU) {
    // Echo / Error Indication / End Marker — no nested T-PDU; Error Indication may carry IE IP
    if (msgType === GTP_U_ERROR_INDICATION && hdr.payloadOff < offset + length) {
      walkGtpv1Ies(
        buffer,
        hdr.payloadOff,
        offset + length - hdr.payloadOff,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        teidScope,
      )
    }
    return { coverage, issues }
  }
  const tpduOff = hdr.payloadOff
  const tpduLen = offset + length - tpduOff
  if (tpduLen <= 0) return { coverage, issues }
  const version = (buffer[tpduOff]! >> 4) & 0xf
  if (version === 4 || version === 6) {
    const proto = version === 4 ? 4 : 41
    const inner = sanitizeTunnel(
      buffer,
      tpduOff,
      tpduLen,
      proto,
      collector,
      mapping,
      depth,
      onInnerTransport,
      { packetIndex, intents },
    )
    coverage.push(...inner.coverage)
    if (inner.depthExceeded) issues.push('gtp-u-tunnel-depth')
    return { coverage, issues, drop: inner.drop }
  }
  if (tpduLen >= 14) {
    const eth = sanitizeLinkedEthernet(
      buffer,
      tpduOff,
      tpduLen,
      collector,
      mapping,
      depth,
      onInnerTransport,
      { packetIndex, intents },
      'gtp-u-ethernet',
      'gtp-u-payload',
    )
    coverage.push(...eth.coverage)
    if (eth.depthExceeded) issues.push('gtp-u-tunnel-depth')
    return { coverage, issues, drop: eth.drop }
  }
  maskSpan(collector, intents, packetIndex, tpduOff, tpduLen, 'gtp-u-unstructured')
  coverage.push({ protocol: 'gtp-u-unstructured', offset: tpduOff, length: tpduLen, status: 'redacted' })
  issues.push('gtp-u-unstructured-pdu')
  return { coverage, issues }
}

interface Gtpv1Header {
  readonly headerLength: number
  readonly payloadOff: number
  readonly extMasked: boolean
  readonly extOff: number
  readonly extLen: number
}

function parseGtpv1Header(
  buffer: Uint8Array,
  offset: number,
  length: number,
): Gtpv1Header | null {
  if (length < 8) return null
  const flags = buffer[offset]!
  const e = (flags >> 2) & 0x1
  const s = (flags >> 1) & 0x1
  const pn = flags & 0x1
  let headerLength = 8
  let extMasked = false
  let extOff = offset + 8
  let extLen = 0
  if (e || s || pn) {
    if (length < 12) return null
    headerLength = 12
    if (e) {
      // Extension header chain — mask unknown bodies; length unit = 4 octets
      let pos = offset + 12
      const end = offset + length
      while (pos + 1 <= end) {
        const extType = buffer[pos - 1]! // next ext type at end of previous
        void extType
        const lenUnits = buffer[pos]!
        if (lenUnits === 0) break
        const extBytes = lenUnits * 4
        if (pos + extBytes > end) {
          extMasked = true
          extOff = offset + 12
          extLen = end - (offset + 12)
          headerLength = length
          return { headerLength, payloadOff: end, extMasked, extOff, extLen }
        }
        // Preserve type/length; mask content after first 2 bytes of each ext
        if (extBytes > 2) {
          extMasked = true
          if (extLen === 0) {
            extOff = pos + 1
            extLen = extBytes - 2
          } else {
            // accumulate via single mask of remaining — simplify: mask whole chain body
            extOff = offset + 12
            extLen = pos + extBytes - (offset + 12)
          }
        }
        const nextType = buffer[pos + extBytes - 1]!
        pos += extBytes
        headerLength = pos - offset
        if (nextType === 0) break
      }
    }
  }
  return {
    headerLength,
    payloadOff: offset + headerLength,
    extMasked,
    extOff,
    extLen,
  }
}

/** T16 — MNC digit count from GTPv2 Serving Network (3GPP TS 29.274), when present. */
function servingNetworkMncLength(buffer: Uint8Array, abs: number, len: number): 2 | 3 | null {
  if (len < 3) return null
  // Octet 6 high nibble = MNC digit 3; 0xF ⇒ two-digit MNC.
  const mncDigit3 = (buffer[abs + 1]! >> 4) & 0x0f
  return mncDigit3 === 0x0f ? 2 : 3
}

function scanGtpv2ServingNetworkMnc(
  buffer: Uint8Array,
  offset: number,
  length: number,
  depth: number,
): 2 | 3 | null {
  if (depth >= MAX_IE_DEPTH) return null
  let pos = offset
  const end = offset + length
  let found: 2 | 3 | null = null
  while (pos + 4 <= end) {
    const type = buffer[pos]!
    const ieLen = (buffer[pos + 1]! << 8) | buffer[pos + 2]!
    const valueOff = pos + 4
    if (valueOff + ieLen > end) break
    if (type === V2.SERVING_NETWORK) {
      found = servingNetworkMncLength(buffer, valueOff, ieLen) ?? found
    } else if (type === V2.BEARER_CONTEXT) {
      found = scanGtpv2ServingNetworkMnc(buffer, valueOff, ieLen, depth + 1) ?? found
    }
    pos = valueOff + ieLen
  }
  return found
}

function walkGtpv2Ies(
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
  mncLength: 2 | 3 | null = null,
): void {
  if (depth >= MAX_IE_DEPTH) {
    maskSpan(collector, intents, packetIndex, offset, length, 'gtpv2-ie-depth')
    coverage.push({ protocol: 'gtpv2-ie', offset, length, status: 'redacted' })
    issues.push('gtpv2-ie-depth')
    return
  }
  const plmnMnc = mncLength ?? scanGtpv2ServingNetworkMnc(buffer, offset, length, depth)
  let pos = offset
  const end = offset + length
  while (pos + 4 <= end) {
    const type = buffer[pos]!
    const ieLen = (buffer[pos + 1]! << 8) | buffer[pos + 2]!
    const valueOff = pos + 4
    if (valueOff + ieLen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv2-ie-trunc')
      coverage.push({ protocol: 'gtpv2-ie', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('gtpv2-ie-trunc')
      return
    }
    sanitizeGtpv2Ie(
      buffer,
      type,
      valueOff,
      ieLen,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      depth,
      plmnMnc,
    )
    pos = valueOff + ieLen
  }
  if (pos < end) {
    maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv2-ie-tail')
    coverage.push({ protocol: 'gtpv2-ie-tail', offset: pos, length: end - pos, status: 'redacted' })
  }
}

function sanitizeGtpv2Ie(
  buffer: Uint8Array,
  type: number,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
  mncLength: 2 | 3 | null,
): void {
  switch (type) {
    case V2.IMSI:
      mapTbcdCategory(buffer, abs, len, 'imsi', collector, mapping, intents, packetIndex, mncLength)
      coverage.push({ protocol: 'gtpv2-imsi', offset: abs, length: len, status: 'covered' })
      return
    case V2.MEI:
      mapTbcdCategory(buffer, abs, len, 'imei', collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-mei', offset: abs, length: len, status: 'covered' })
      return
    case V2.MSISDN:
      mapMsisdn(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-msisdn', offset: abs, length: len, status: 'covered' })
      return
    case V2.APN:
      mapApn(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-apn', offset: abs, length: len, status: 'covered' })
      return
    case V2.F_TEID:
      mapFteid(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-f-teid', offset: abs, length: len, status: 'covered' })
      return
    case V2.PAA:
      mapPaa(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-paa', offset: abs, length: len, status: 'covered' })
      return
    case V2.IP_ADDRESS:
      mapIpAddressIe(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-ip', offset: abs, length: len, status: 'covered' })
      return
    case V2.BEARER_CONTEXT:
      walkGtpv2Ies(
        buffer, abs, len, collector, mapping, intents, packetIndex, coverage, issues, depth + 1,
        mncLength,
      )
      return
    case V2.PCO:
    case V2.APCO:
      sanitizePco(buffer, abs, len, collector, mapping, intents, packetIndex, coverage)
      return
    case V2.ULI:
      maskSpan(collector, intents, packetIndex, abs, len, 'gtpv2-uli')
      coverage.push({ protocol: 'gtpv2-uli', offset: abs, length: len, status: 'redacted' })
      return
    case V2.CHARGING_ID:
      mapOpaqueU32(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtpv2-charging-id', offset: abs, length: len, status: 'covered' })
      return
    case V2.CAUSE:
    case V2.RECOVERY:
    case V2.EBI:
    case V2.RAT_TYPE:
    case V2.BEARER_QOS:
    case V2.FLOW_QOS:
    case V2.AMBR:
    case V2.INDICATION:
    case V2.SERVING_NETWORK:
    case V2.BEARER_TFT:
    case V2.CHARGING_CHARACTERISTICS:
    case V2.PDN_TYPE:
      coverage.push({ protocol: 'gtpv2-ie', offset: abs, length: len, status: 'covered' })
      return
    default:
      maskSpan(collector, intents, packetIndex, abs, len, `gtpv2-ie-${type}`)
      coverage.push({ protocol: 'gtpv2-ie', offset: abs, length: len, status: 'redacted' })
  }
}

function walkGtpv1Ies(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  teidScope?: GtpTeidScope,
): void {
  let pos = offset
  const end = offset + length
  while (pos < end) {
    const type = buffer[pos]!
    if (type < 128) {
      const tvLen = V1_TV_LEN.get(type)
      if (tvLen === undefined) {
        // Unknown TV — stop traversal (implicit length unknown)
        maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv1-tv-unknown')
        coverage.push({ protocol: 'gtpv1-ie', offset: pos, length: end - pos, status: 'redacted' })
        issues.push(`gtpv1-tv-unknown:${type}`)
        return
      }
      if (pos + 1 + tvLen > end) {
        maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv1-tv-trunc')
        coverage.push({ protocol: 'gtpv1-ie', offset: pos, length: end - pos, status: 'malformed' })
        return
      }
      const valOff = pos + 1
      if (type === 2) {
        mapTbcdCategory(buffer, valOff, tvLen, 'imsi', collector, mapping, intents, packetIndex)
      } else if (type === 16 || type === 17) {
        patchTeid(buffer, valOff, collector, mapping, intents, packetIndex, teidScope)
      } else if (type === 127) {
        mapOpaqueU32(buffer, valOff, tvLen, collector, mapping, intents, packetIndex)
      } else if (type === 9) {
        // Auth triplet — always mask
        maskSpan(collector, intents, packetIndex, valOff, tvLen, 'gtpv1-auth')
      }
      // else preserve (Cause, Recovery, NSAPI, …)
      coverage.push({ protocol: 'gtpv1-ie', offset: pos, length: 1 + tvLen, status: 'covered' })
      pos += 1 + tvLen
      continue
    }
    // TLV
    if (pos + 3 > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv1-tlv-trunc')
      coverage.push({ protocol: 'gtpv1-ie', offset: pos, length: end - pos, status: 'malformed' })
      return
    }
    const ieLen = (buffer[pos + 1]! << 8) | buffer[pos + 2]!
    const valOff = pos + 3
    if (valOff + ieLen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtpv1-tlv-trunc')
      coverage.push({ protocol: 'gtpv1-ie', offset: pos, length: end - pos, status: 'malformed' })
      return
    }
    switch (type) {
      case V1_TLV.END_USER_ADDRESS:
        mapGtpv1EndUserAddress(buffer, valOff, ieLen, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtpv1-eua', offset: pos, length: 3 + ieLen, status: 'covered' })
        break
      case V1_TLV.APN:
        mapApn(buffer, valOff, ieLen, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtpv1-apn', offset: pos, length: 3 + ieLen, status: 'covered' })
        break
      case V1_TLV.PCO:
        sanitizePco(buffer, valOff, ieLen, collector, mapping, intents, packetIndex, coverage)
        break
      case V1_TLV.GSN_ADDRESS:
        mapIpAddressIe(buffer, valOff, ieLen, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtpv1-gsn', offset: pos, length: 3 + ieLen, status: 'covered' })
        break
      case V1_TLV.MSISDN:
        mapMsisdn(buffer, valOff, ieLen, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtpv1-msisdn', offset: pos, length: 3 + ieLen, status: 'covered' })
        break
      case V1_TLV.IMEI:
        mapTbcdCategory(buffer, valOff, ieLen, 'imei', collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtpv1-imei', offset: pos, length: 3 + ieLen, status: 'covered' })
        break
      default:
        maskSpan(collector, intents, packetIndex, valOff, ieLen, `gtpv1-tlv-${type}`)
        coverage.push({ protocol: 'gtpv1-ie', offset: pos, length: 3 + ieLen, status: 'redacted' })
    }
    pos = valOff + ieLen
  }
}

function mapTbcdCategory(
  buffer: Uint8Array,
  abs: number,
  len: number,
  category: 'imsi' | 'imei',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  mncLength: 2 | 3 | null = null,
): void {
  if (len <= 0) return
  const slice = buffer.subarray(abs, abs + len)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits) {
    maskSpan(collector, intents, packetIndex, abs, len, `gtp-${category}-bad`)
    return
  }
  let identityRaw: string | null =
    category === 'imsi' ? normalizeImsiDigits(digits) : normalizeImeiDigits(digits)
  if (category === 'imsi' && identityRaw && mncLength !== null) {
    identityRaw = scopeImsiWithPlmn(identityRaw, mncLength) ?? identityRaw
  }
  const canon = identityRaw ? canonicalizeIdentity(category, identityRaw) : null
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, `gtp-${category}-bad`)
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.map(category, canon)
      const remapped = remapTbcdBytes(slice, alias, TBCD_GSM)
      if (remapped) return remapped
      const encoded = encodeTbcd(alias, len, TBCD_GSM)
      if (encoded) return encoded
    } catch { /* fall through */ }
    return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `gtp-${category}` })
  }, deferredTextMapMeta('gtp', packetIndex, category, digits, len, {
    fallbackKind: 'binary-mask',
    canonical: canon,
  }))
  void mapping
}

function mapMsisdn(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len < 2) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-msisdn-short')
    return
  }
  // First byte: number digits / TON / NPI — preserve; TBCD follows
  const tbcdOff = abs + 1
  const tbcdLen = len - 1
  const slice = buffer.subarray(tbcdOff, tbcdOff + tbcdLen)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits || digits.length < 6) {
    maskSpan(collector, intents, packetIndex, tbcdOff, tbcdLen, 'gtp-msisdn-bad')
    return
  }
  const phone = `+${digits}`
  const canon = canonicalizeIdentity('sip-phone', phone) ?? phone
  const constraint = { kind: 'text-ascii' as const, byteLength: digits.length }
  intents?.recordEntityReplacement(packetIndex, tbcdOff, 'sip-phone', canon, tbcdLen, constraint, digits)
  collector.addDeferred(tbcdOff, tbcdLen, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor('sip-phone', canon, constraint, digits)
      const digitAlias = alias.replace(/\D/g, '')
      const use = digitAlias.length === digits.length ? digitAlias : digits.replace(/\d/g, '0')
      const remapped = remapTbcdBytes(slice, use, TBCD_GSM)
      if (remapped) return remapped
    } catch { /* fall through */ }
    return createProtocolNeutralMaskFill({
      length: tbcdLen, packetIndex, offset: tbcdOff, domain: 'gtp-msisdn',
    })
  }, deferredTextMapMeta('gtp', packetIndex, 'sip-phone', digits, tbcdLen, {
    fallbackKind: 'digits',
    canonical: canon,
  }))
  void mapping
}

function mapApn(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len <= 0) return
  const labels: { offset: number; length: number; text: string }[] = []
  let cur = 0
  while (cur < len) {
    const labelLen = buffer[abs + cur]!
    if (labelLen === 0) break
    if (cur + 1 + labelLen > len) {
      maskSpan(collector, intents, packetIndex, abs, len, 'gtp-apn-trunc')
      return
    }
    let text = ''
    for (let i = 0; i < labelLen; i++) {
      text += String.fromCharCode(buffer[abs + cur + 1 + i]!)
    }
    labels.push({ offset: cur + 1, length: labelLen, text: text.toLowerCase() })
    cur += 1 + labelLen
  }
  if (labels.length === 0) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-apn-empty')
    return
  }
  const fullName = labels.map((l) => l.text).join('.')
  const canon = canonicalizeIdentity('hostname', fullName)
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-apn-bad')
    return
  }
  const firstAbs = abs + labels[0]!.offset
  intents?.recordEntityReplacement(packetIndex, firstAbs, 'hostname', canon, labels[0]!.length)
  // Preserve trailing PLMN / gprs / 3gppnetwork.org labels (T16 policy).
  const preserve = new Array<boolean>(labels.length).fill(false)
  for (let i = labels.length - 1; i >= 0; i--) {
    const t = labels[i]!.text
    if (/^mnc\d{2,3}$/.test(t) || /^mcc\d{3}$/.test(t) || t === 'gprs'
      || t === '3gppnetwork.org' || t === 'epc' || t === 'apn' || t === 'org') {
      preserve[i] = true
      continue
    }
    break
  }
  for (let i = 0; i < labels.length; i++) {
    if (preserve[i]) continue
    const label = labels[i]!
    const labelAbs = abs + label.offset
    collector.addDeferred(labelAbs, label.length, ({ mapping: live }) => {
      try {
        const mappedLabels = live.map('hostname', canon).split('.')
        const mapped = mappedLabels[i] ?? 'x'.repeat(label.length)
        return computeFixedLengthAsciiBytes(labelAbs, label.length, mapped)
      } catch {
        return createProtocolNeutralMaskFill({
          length: label.length, packetIndex, offset: labelAbs, domain: 'gtp-apn',
        })
      }
    }, deferredTextMapMeta('gtp', packetIndex, 'hostname', label.text, label.length, {
      canonical: canon,
    }))
  }
  void mapping
}

function mapFteid(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len < 5) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-f-teid-short')
    return
  }
  const flags = buffer[abs]!
  const v4 = (flags >> 7) & 0x1
  const v6 = (flags >> 6) & 0x1
  // F-TEID receive endpoint is the address carried in the IE (not outer packet dst).
  let receiveEndpoint = 'fteid'
  let peek = abs + 5
  if (v4 && peek + 4 <= abs + len) {
    receiveEndpoint = `${buffer[peek]}.${buffer[peek + 1]}.${buffer[peek + 2]}.${buffer[peek + 3]}`
  } else if (v6 && peek + 16 <= abs + len) {
    const parts: string[] = []
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buffer[peek + i]! << 8) | buffer[peek + i + 1]!).toString(16))
    }
    receiveEndpoint = parts.join(':')
  }
  // Same TEID namespace as GTP-U header at this receive endpoint (T26 consistency).
  patchTeid(buffer, abs + 1, collector, mapping, intents, packetIndex, {
    receiveEndpoint,
    plane: 'u',
  })
  let pos = abs + 5
  if (v4) {
    if (pos + 4 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'gtp-f-teid-v4')
      return
    }
    patchIpv4Bytes(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  }
  if (v6) {
    if (pos + 16 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'gtp-f-teid-v6')
      return
    }
    patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
  }
}

function mapPaa(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len < 1) return
  const pdnType = buffer[abs]! & 0x7
  let pos = abs + 1
  // 1 = IPv4, 2 = IPv6, 3 = IPv4v6, 4 = Non-IP, 5 = Ethernet
  if (pdnType === 1 || pdnType === 3) {
    if (pos + 4 <= abs + len) {
      patchIpv4Bytes(buffer, pos, collector, mapping, intents, packetIndex)
      pos += 4
    }
  }
  if (pdnType === 2 || pdnType === 3) {
    // IPv6: 1 byte prefix length + 16 bytes interface id / address (baseline: map 16B if present)
    if (pdnType === 2 && pos < abs + len) pos += 1 // prefix length
    if (pos + 16 <= abs + len) {
      patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
      pos += 16
    }
  }
  if (pdnType === 3 && pos + 16 <= abs + len) {
    // IPv4v6: after IPv4 comes prefix-len + IPv6
    if (pos < abs + len) pos += 1
    if (pos + 16 <= abs + len) {
      patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
    }
  }
  if (pdnType === 4 || pdnType === 5) {
    maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'gtp-paa-non-ip')
  }
}

function mapGtpv1EndUserAddress(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // PDP type org (1) + PDP type number (1) + address
  if (len < 2) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtpv1-eua-short')
    return
  }
  const addrOff = abs + 2
  const addrLen = len - 2
  if (addrLen === 4) {
    patchIpv4Bytes(buffer, addrOff, collector, mapping, intents, packetIndex)
  } else if (addrLen === 16) {
    patchIpv6Bytes(buffer, addrOff, collector, mapping, intents, packetIndex)
  } else if (addrLen === 20) {
    patchIpv4Bytes(buffer, addrOff, collector, mapping, intents, packetIndex)
    patchIpv6Bytes(buffer, addrOff + 4, collector, mapping, intents, packetIndex)
  } else if (addrLen > 0) {
    maskSpan(collector, intents, packetIndex, addrOff, addrLen, 'gtpv1-eua-addr')
  }
}

function mapIpAddressIe(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len === 4) {
    patchIpv4Bytes(buffer, abs, collector, mapping, intents, packetIndex)
  } else if (len === 16) {
    patchIpv6Bytes(buffer, abs, collector, mapping, intents, packetIndex)
  } else if (len > 0) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-ip-ie')
  }
}

function mapOpaqueU32(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len !== 4) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-opaque')
    return
  }
  const v =
    ((buffer[abs]! << 24) >>> 0)
    + (buffer[abs + 1]! << 16)
    + (buffer[abs + 2]! << 8)
    + buffer[abs + 3]!
  const canon = `gtp-charging/${v >>> 0}`
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: 4, packetIndex, offset: abs, domain: `gtp-charging:${alias}`,
    })
  })
  void mapping
}

/** PCO/APCO — map known IP options; PAP/CHAP secrets always mask. */
function sanitizePco(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (len < 1) return
  coverage.push({ protocol: 'gtp-pco', offset: abs, length: 1, status: 'covered' })
  let pos = abs + 1
  const end = abs + len
  while (pos + 3 <= end) {
    const protoId = (buffer[pos]! << 8) | buffer[pos + 1]!
    const contLen = buffer[pos + 2]!
    const contOff = pos + 3
    if (contOff + contLen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtp-pco-trunc')
      coverage.push({ protocol: 'gtp-pco', offset: pos, length: end - pos, status: 'malformed' })
      return
    }
    // PAP 0xC023 / CHAP 0xC223 — mask contents (auth secrets)
    if (protoId === 0xc023 || protoId === 0xc223) {
      maskSpan(collector, intents, packetIndex, contOff, contLen, 'gtp-pco-auth')
      coverage.push({ protocol: 'gtp-pco-auth', offset: pos, length: 3 + contLen, status: 'redacted' })
    } else if (
      protoId === 0x000d // DNS Server IPv4
      || protoId === 0x000c // P-CSCF IPv4
      || protoId === 0x0010 // IPv4 Link MTU (preserve length, no IP)
    ) {
      if ((protoId === 0x000d || protoId === 0x000c) && contLen === 4) {
        patchIpv4Bytes(buffer, contOff, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtp-pco-ip', offset: pos, length: 3 + contLen, status: 'covered' })
      } else if (protoId === 0x0010) {
        coverage.push({ protocol: 'gtp-pco', offset: pos, length: 3 + contLen, status: 'covered' })
      } else {
        maskSpan(collector, intents, packetIndex, contOff, contLen, 'gtp-pco-opt')
        coverage.push({ protocol: 'gtp-pco', offset: pos, length: 3 + contLen, status: 'redacted' })
      }
    } else if (protoId === 0x0003 || protoId === 0x0001) {
      // DNS / P-CSCF IPv6
      if (contLen === 16) {
        patchIpv6Bytes(buffer, contOff, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'gtp-pco-ip', offset: pos, length: 3 + contLen, status: 'covered' })
      } else {
        maskSpan(collector, intents, packetIndex, contOff, contLen, 'gtp-pco-opt')
        coverage.push({ protocol: 'gtp-pco', offset: pos, length: 3 + contLen, status: 'redacted' })
      }
    } else if (protoId === 0x8021) {
      // IPCP — walk options for IP addresses
      sanitizeIpcp(buffer, contOff, contLen, collector, mapping, intents, packetIndex, coverage)
    } else {
      maskSpan(collector, intents, packetIndex, contOff, contLen, 'gtp-pco-unknown')
      coverage.push({ protocol: 'gtp-pco', offset: pos, length: 3 + contLen, status: 'redacted' })
    }
    pos = contOff + contLen
  }
}

function sanitizeIpcp(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // IPCP: code(1) id(1) length(2) options…
  if (len < 4) {
    maskSpan(collector, intents, packetIndex, abs, len, 'gtp-ipcp-short')
    return
  }
  coverage.push({ protocol: 'gtp-ipcp', offset: abs, length: 4, status: 'covered' })
  let pos = abs + 4
  const end = abs + len
  while (pos + 2 <= end) {
    const optType = buffer[pos]!
    const optLen = buffer[pos + 1]!
    if (optLen < 2 || pos + optLen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'gtp-ipcp-opt')
      return
    }
    // IP-Address (3), Primary DNS (129), Secondary DNS (131)
    if ((optType === 3 || optType === 129 || optType === 131) && optLen === 6) {
      patchIpv4Bytes(buffer, pos + 2, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'gtp-ipcp-ip', offset: pos, length: optLen, status: 'covered' })
    } else {
      maskSpan(collector, intents, packetIndex, pos + 2, optLen - 2, 'gtp-ipcp-opt')
      coverage.push({ protocol: 'gtp-ipcp', offset: pos, length: optLen, status: 'redacted' })
    }
    pos += optLen
  }
}

/**
 * V17 / T26 — TEID namespace = receive endpoint + plane + generation + value.
 * Same numeric TEID on two receivers must not collapse to one alias.
 */
export function teidCanonicalKey(
  teid: number,
  scope?: { readonly receiveEndpoint?: string; readonly plane?: string; readonly generation?: number },
): string {
  const n = teid >>> 0
  if (!scope?.receiveEndpoint) return String(n)
  const plane = scope.plane ?? '?'
  const gen = scope.generation ?? 0
  return `${scope.receiveEndpoint}|${plane}|g${gen}|${n}`
}

export function patchTeid(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  scope?: { readonly receiveEndpoint?: string; readonly plane?: string; readonly generation?: number },
): void {
  const teid =
    ((buffer[offset]! << 24) >>> 0)
    + (buffer[offset + 1]! << 16)
    + (buffer[offset + 2]! << 8)
    + buffer[offset + 3]!
  // Zero is absent/sentinel — not a session TEID alias.
  if (teid === 0) return
  const canonical = teidCanonicalKey(teid, scope)
  intents?.recordEntityReplacement(packetIndex, offset, 'teid', canonical, 4)
  collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
    const mapped = Number(liveMapping.map('teid', canonical)) >>> 0
    return new Uint8Array([
      (mapped >>> 24) & 0xff,
      (mapped >>> 16) & 0xff,
      (mapped >>> 8) & 0xff,
      mapped & 0xff,
    ])
  }, deferredBinaryMapMeta('gtp', packetIndex, 'teid', canonical, {
    fallbackKind: 'digits',
    canonical,
  }))
}

function patchIpv4Bytes(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const ip = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`
  if (ip === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4)
  collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('ipv4', ip)
    return new Uint8Array(mapped.split('.').map(Number))
  }, deferredBinaryMapMeta('gtp', packetIndex, 'ipv4', ip))
}

function patchIpv6Bytes(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buffer[offset + i]! << 8) | buffer[offset + i + 1]!).toString(16))
  }
  const ip = parts.join(':')
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16)
  collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('ipv6', ip)
    const out = new Uint8Array(16)
    // Expand compressed form via canonical re-map: SessionMapping returns full form
    const hex = mapped.replace(/:/g, '')
    if (hex.length === 32) {
      for (let i = 0; i < 16; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
      }
      return out
    }
    const groups = mapped.split(':')
    let idx = 0
    for (const g of groups) {
      if (g === '' || idx >= 16) continue
      const val = parseInt(g, 16)
      out[idx++] = (val >> 8) & 0xff
      out[idx++] = val & 0xff
    }
    return out
  }, deferredBinaryMapMeta('gtp', packetIndex, 'ipv6', ip))
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'gtp')
  collector.addDeferred(offset, length, () => createProtocolNeutralMaskFill({
    length, packetIndex, offset, domain,
  }))
}
