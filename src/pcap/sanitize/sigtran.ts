/**
 * T25 — SIGTRAN/SS7 over M3UA (SCTP PPID 3): map OPC/DPC as point-code;
 * SCCP GT/PC; ISUP numbers → sip-phone; TCAP/MAP BER IMSI/MSISDN/IMEI map;
 * auth vectors / SMS UD / USSD / location → mask (fail-closed).
 *
 * M2PA (SCTP PPID 5) → {@link sanitizeM2pa}; M2UA/SUA stay identify+mask in sanitizeSctp.
 * Network dialect default: ITU 14-bit PC in SCCP; M3UA Protocol Data OPC/DPC as 24-bit.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import {
  decodeTbcd,
  encodeTbcd,
  normalizeImeiDigits,
  normalizeImsiDigits,
  remapTbcdBytes,
  TBCD_GSM,
} from '../protocols/application/binproto/tbcd'
import { walkBer, type BerNode } from '../protocols/application/binproto/ber'
import { sanitizeIsupPdu } from './isup/pdu.ts'
import { mapTbcdSipPhoneField, maskWireSpan } from './isup/tbcdPhoneMap.ts'

export { sanitizeIsupPdu } from './isup/pdu.ts'

const M3UA_VERSION = 1
/** RFC 4666 Protocol Data parameter. */
const M3UA_PARAM_PROTOCOL_DATA = 0x0210
const M3UA_PARAM_ROUTING_CONTEXT = 0x0006
const M3UA_PARAM_NETWORK_APPEARANCE = 0x0200
const M3UA_PARAM_INFO_STRING = 0x0004
const M3UA_PARAM_ASP_IDENTIFIER = 0x0011

const SI_SCCP = 3
const SI_ISUP = 5

const SCCP_UDT = 0x09
const SCCP_XUDT = 0x11
const SCCP_LUDT = 0x13

const MAX_TLV = 64
const MAX_BER_DEPTH = 12

export function looksLikeM3ua(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  if (data[offset] !== M3UA_VERSION) return false
  const msgLen =
    ((data[offset + 4]! << 24)
      | (data[offset + 5]! << 16)
      | (data[offset + 6]! << 8)
      | data[offset + 7]!)
    >>> 0
  return msgLen === length
}

export function sanitizeM3ua(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeM3ua(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  coverage.push({ protocol: 'm3ua', offset, length: 8, status: 'covered' })

  const msgClass = buffer[offset + 2]!
  const msgType = buffer[offset + 3]!
  let pos = offset + 8
  const end = offset + length
  let tlvCount = 0

  while (pos + 4 <= end && tlvCount < MAX_TLV) {
    tlvCount++
    const tag = (buffer[pos]! << 8) | buffer[pos + 1]!
    const paramLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    if (paramLen < 4 || pos + paramLen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'm3ua-tlv-bad')
      coverage.push({ protocol: 'm3ua-tlv', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('m3ua-tlv-malformed')
      break
    }
    const valueOff = pos + 4
    const valueLen = paramLen - 4
    const padded = (paramLen + 3) & ~3

    if (tag === M3UA_PARAM_PROTOCOL_DATA && valueLen >= 12) {
      sanitizeProtocolData(
        buffer, valueOff, valueLen, collector, mapping, intents, packetIndex, coverage, issues,
      )
      coverage.push({ protocol: 'm3ua-protocol-data', offset: pos, length: paramLen, status: 'covered' })
    } else if (tag === M3UA_PARAM_ROUTING_CONTEXT || tag === M3UA_PARAM_NETWORK_APPEARANCE) {
      mapOpaqueScoped(buffer, valueOff, valueLen, collector, mapping, intents, packetIndex, 'm3ua-rc-na')
      coverage.push({ protocol: 'm3ua-scoped', offset: pos, length: paramLen, status: 'covered' })
    } else if (tag === M3UA_PARAM_INFO_STRING || tag === M3UA_PARAM_ASP_IDENTIFIER) {
      mapOpaqueScoped(buffer, valueOff, valueLen, collector, mapping, intents, packetIndex, 'm3ua-info')
      coverage.push({ protocol: 'm3ua-opaque', offset: pos, length: paramLen, status: 'covered' })
    } else if (valueLen > 0) {
      // Unknown TLV — fail-closed mask of value (header preserved for class/type diagnostics).
      maskSpan(collector, intents, packetIndex, valueOff, valueLen, `m3ua-tlv-0x${tag.toString(16)}`)
      coverage.push({ protocol: 'm3ua-tlv', offset: pos, length: paramLen, status: 'redacted' })
    } else {
      coverage.push({ protocol: 'm3ua-tlv', offset: pos, length: paramLen, status: 'covered' })
    }

    pos += padded
  }

  if (pos < end) {
    maskSpan(collector, intents, packetIndex, pos, end - pos, 'm3ua-trailer')
    coverage.push({ protocol: 'm3ua-trailer', offset: pos, length: end - pos, status: 'redacted' })
  }

  void msgClass
  void msgType
  return { coverage, issues: issues.length > 0 ? issues : undefined }
}

function sanitizeProtocolData(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // OPC (4) DPC (4) SI NI MP SLS (1 each) + user data
  mapPointCodeBe32(buffer, abs, 24, collector, mapping, intents, packetIndex)
  mapPointCodeBe32(buffer, abs + 4, 24, collector, mapping, intents, packetIndex)
  coverage.push({ protocol: 'm3ua-opc-dpc', offset: abs, length: 8, status: 'covered' })
  coverage.push({ protocol: 'm3ua-si-ni', offset: abs + 8, length: 4, status: 'covered' })

  const si = buffer[abs + 8]!
  const userOff = abs + 12
  const userLen = len - 12
  if (userLen <= 0) return

  if (si === SI_SCCP) {
    sanitizeSccp(buffer, userOff, userLen, collector, mapping, intents, packetIndex, coverage, issues)
  } else if (si === SI_ISUP) {
    sanitizeIsupPdu(buffer, userOff, userLen, collector, mapping, intents, packetIndex, coverage, issues)
  } else {
    maskSpan(collector, intents, packetIndex, userOff, userLen, `m3ua-si-${si}`)
    coverage.push({ protocol: `m3ua-si-${si}`, offset: userOff, length: userLen, status: 'redacted' })
    issues.push(`m3ua-si-unsupported:${si}`)
  }
}

function sanitizeSccp(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (len < 2) {
    maskSpan(collector, intents, packetIndex, abs, len, 'sccp-short')
    coverage.push({ protocol: 'sccp', offset: abs, length: len, status: 'malformed' })
    return
  }
  const msgType = buffer[abs]!
  coverage.push({ protocol: 'sccp', offset: abs, length: 1, status: 'covered' })

  if (msgType === SCCP_LUDT) {
    maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'sccp-ludt')
    coverage.push({
      protocol: 'sccp-segmented',
      offset: abs + 1,
      length: len - 1,
      status: 'requires-reassembly',
    })
    issues.push('sccp-requires-reassembly')
    return
  }

  if (msgType === SCCP_XUDT) {
    if (len < 6) {
      maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'sccp-xudt-short')
      coverage.push({ protocol: 'sccp-xudt', offset: abs, length: len, status: 'malformed' })
      return
    }
    const optPtr = buffer[abs + 5]!
    if (optPtr !== 0) {
      const optOff = abs + 5 + optPtr
      if (optOff < abs + 6 || optOff >= abs + len) {
        maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'sccp-xudt-opt-bad')
        coverage.push({ protocol: 'sccp-xudt', offset: abs, length: len, status: 'malformed' })
        issues.push('sccp-pointer-overflow')
        return
      }
      if (sccpOptionalNeedsReassembly(buffer, optOff, abs + len)) {
        maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'sccp-xudt-segmented')
        coverage.push({
          protocol: 'sccp-segmented',
          offset: abs + 1,
          length: len - 1,
          status: 'requires-reassembly',
        })
        issues.push('sccp-requires-reassembly')
        return
      }
    }
    sanitizeSccpUdtBody(
      buffer, abs, len, 6, collector, mapping, intents, packetIndex, coverage, issues,
    )
    return
  }

  if (msgType !== SCCP_UDT) {
    maskSpan(collector, intents, packetIndex, abs + 1, len - 1, `sccp-type-0x${msgType.toString(16)}`)
    coverage.push({ protocol: 'sccp-msg', offset: abs, length: len, status: 'redacted' })
    issues.push(`sccp-unsupported-type:${msgType}`)
    return
  }

  if (len < 5) {
    maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'sccp-udt-short')
    coverage.push({ protocol: 'sccp-udt', offset: abs, length: len, status: 'malformed' })
    return
  }
  sanitizeSccpUdtBody(
    buffer, abs, len, 5, collector, mapping, intents, packetIndex, coverage, issues,
  )
}

/** Q.714 optional-part segmentation (0x10): remaining>0 or segment>1 needs reassembly. */
function sccpOptionalNeedsReassembly(buffer: Uint8Array, optOff: number, limit: number): boolean {
  let pos = optOff
  while (pos + 2 <= limit) {
    const name = buffer[pos]!
    const plen = buffer[pos + 1]!
    if (pos + 2 + plen > limit) return true
    if (name === 0x10 && plen >= 2) {
      const remaining = buffer[pos + 2]!
      const segment = plen >= 3 ? buffer[pos + 3]! : 1
      if (remaining > 0 || segment > 1) return true
    }
    pos += 2 + plen
  }
  return false
}

function sanitizeSccpUdtBody(
  buffer: Uint8Array,
  abs: number,
  len: number,
  minHeader: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  coverage.push({ protocol: 'sccp-udt-class', offset: abs + 1, length: 1, status: 'covered' })

  const ptrCalled = buffer[abs + 2]!
  const ptrCalling = buffer[abs + 3]!
  const ptrData = buffer[abs + 4]!

  const calledOff = abs + 2 + ptrCalled
  const callingOff = abs + 3 + ptrCalling
  const dataOff = abs + 4 + ptrData

  if (calledOff < abs + minHeader || calledOff >= abs + len) {
    maskSpan(collector, intents, packetIndex, abs + 1, len - 1, 'sccp-ptr-bad')
    coverage.push({ protocol: 'sccp-udt', offset: abs, length: len, status: 'malformed' })
    issues.push('sccp-pointer-overflow')
    return
  }

  sanitizeSccpAddress(buffer, calledOff, abs + len, collector, mapping, intents, packetIndex, coverage)
  if (callingOff >= abs + minHeader && callingOff < abs + len) {
    sanitizeSccpAddress(buffer, callingOff, abs + len, collector, mapping, intents, packetIndex, coverage)
  }

  if (dataOff >= abs + minHeader && dataOff < abs + len) {
    const dataLenField = buffer[dataOff]!
    const payloadOff = dataOff + 1
    const payloadLen = Math.min(dataLenField, abs + len - payloadOff)
    if (payloadLen > 0) {
      sanitizeTcapMap(buffer, payloadOff, payloadLen, collector, mapping, intents, packetIndex, coverage, issues)
    }
  }
}

function sanitizeSccpAddress(
  buffer: Uint8Array,
  abs: number,
  limit: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (abs >= limit) return
  const addrLen = buffer[abs]!
  if (addrLen === 0 || abs + 1 + addrLen > limit) {
    maskSpan(collector, intents, packetIndex, abs, Math.min(1, limit - abs), 'sccp-addr-bad')
    return
  }
  const aiOff = abs + 1
  const ai = buffer[aiOff]!
  const pcPresent = (ai & 0x01) !== 0
  const ssnPresent = (ai & 0x02) !== 0
  const gti = (ai >> 2) & 0x0f
  let pos = aiOff + 1
  const addrEnd = abs + 1 + addrLen

  coverage.push({ protocol: 'sccp-address', offset: abs, length: 1 + addrLen, status: 'covered' })

  if (pcPresent) {
    // ITU 14-bit PC in 2 octets (little-endian packing of 14 bits).
    if (pos + 2 > addrEnd) {
      maskSpan(collector, intents, packetIndex, pos, addrEnd - pos, 'sccp-pc-short')
      return
    }
    const raw = buffer[pos]! | (buffer[pos + 1]! << 8)
    const pc = raw & 0x3fff
    mapPointCodeValue(pc, 14, buffer, pos, 2, 'sccp-pc-itu14', collector, mapping, intents, packetIndex)
    pos += 2
  }

  if (ssnPresent) {
    // SSN preserved
    if (pos < addrEnd) pos += 1
  }

  if (gti !== 0 && pos < addrEnd) {
    sanitizeSccpGt(buffer, pos, addrEnd, gti, collector, mapping, intents, packetIndex, coverage)
  } else if (pos < addrEnd) {
    maskSpan(collector, intents, packetIndex, pos, addrEnd - pos, 'sccp-addr-tail')
  }
}

function sanitizeSccpGt(
  buffer: Uint8Array,
  abs: number,
  end: number,
  gti: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  let pos = abs
  // GTI 0100 (4): NAI (1) then digits; GTI 0001 (1): digits only;
  // GTI 0010 (2): TT (1) + digits; GTI 0011 (3): TT+NP+ES (1) + digits;
  // GTI 0100 already; common ITU GTI=4.
  let numberingPlan = 0 // unknown
  if (gti === 1) {
    numberingPlan = 1 // digits only, treat as E.164
  } else if (gti === 2) {
    if (pos >= end) return
    pos += 1 // translation type
    numberingPlan = 1
  } else if (gti === 3) {
    if (pos >= end) return
    const npEs = buffer[pos]!
    numberingPlan = (npEs >> 4) & 0x0f
    pos += 1
  } else if (gti === 4) {
    if (pos >= end) return
    // Nature of address — preserve; ITU GTI=4 digits are telephone numbers
    pos += 1
    numberingPlan = 1
  } else {
    maskSpan(collector, intents, packetIndex, abs, end - abs, `sccp-gti-${gti}`)
    coverage.push({ protocol: 'sccp-gt', offset: abs, length: end - abs, status: 'redacted' })
    return
  }

  const digiLen = end - pos
  if (digiLen <= 0) return
  const slice = buffer.subarray(pos, end)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits || digits.length < 3) {
    maskSpan(collector, intents, packetIndex, pos, digiLen, 'sccp-gt-bad')
    return
  }

  // E.164 (NP=1) → sip-phone; E.214 (NP=6) → opaque-id GT namespace (not IMSI).
  if (numberingPlan === 6) {
    const token = `gt214:${digits}`
    const canon = canonicalizeIdentity('opaque-id', token) ?? token
    intents?.recordEntityReplacement(packetIndex, pos, 'opaque-id', canon, digiLen)
    collector.addDeferred(pos, digiLen, ({ mapping: live }) => {
      try {
        const alias = live.map('opaque-id', canon)
        const digiAlias = alias.replace(/\D/g, '')
        const use = digiAlias.length === digits.length ? digiAlias : digits.replace(/\d/g, '0')
        return remapTbcdBytes(slice, use, TBCD_GSM)
          ?? encodeTbcd(use, digiLen, TBCD_GSM)
          ?? createProtocolNeutralMaskFill({ length: digiLen, packetIndex, offset: pos, domain: 'sccp-gt214' })
      } catch {
        return createProtocolNeutralMaskFill({ length: digiLen, packetIndex, offset: pos, domain: 'sccp-gt214' })
      }
    }, { fallbackKind: 'binary-mask', protocol: 'sccp', category: 'opaque-id', packetIndex })
    coverage.push({ protocol: 'sccp-gt-e214', offset: pos, length: digiLen, status: 'covered' })
    void mapping
    return
  }

  // Default / E.164 telephone
  mapTbcdPhone(buffer, pos, digiLen, collector, mapping, intents, packetIndex, 'sccp-gt')
  coverage.push({ protocol: 'sccp-gt-e164', offset: pos, length: digiLen, status: 'covered' })
}

function sanitizeTcapMap(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (len < 2) {
    maskSpan(collector, intents, packetIndex, abs, len, 'tcap-short')
    return
  }
  const walked = walkBer(buffer, abs, len, { maxDepth: MAX_BER_DEPTH, maxNodes: 256 })
  if (walked.roots.length === 0) {
    maskSpan(collector, intents, packetIndex, abs, len, 'tcap-ber-bad')
    coverage.push({ protocol: 'tcap', offset: abs, length: len, status: 'malformed' })
    issues.push('tcap-ber-malformed')
    return
  }
  coverage.push({ protocol: 'tcap', offset: abs, length: len, status: 'covered' })
  for (const root of walked.roots) {
    visitTcapNode(buffer, root, collector, mapping, intents, packetIndex, coverage, issues, 0)
  }
}

function visitTcapNode(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
): void {
  if (depth > MAX_BER_DEPTH) {
    maskSpan(collector, intents, packetIndex, node.contentOffset, node.contentLength, 'tcap-depth')
    return
  }

  if (node.tag.constructed && node.children.length > 0) {
    for (const child of node.children) {
      visitTcapNode(buffer, child, collector, mapping, intents, packetIndex, coverage, issues, depth + 1)
    }
    return
  }

  const off = node.contentOffset
  const clen = node.contentLength
  if (clen <= 0) return

  // Universal OCTET STRING (4) or APPLICATION / CONTEXT primitives carrying identities.
  const isOctet = node.tag.tagClass === 'universal' && node.tag.number === 4
  const isPrimitiveApp = !node.tag.constructed
    && (node.tag.tagClass === 'application' || node.tag.tagClass === 'context')

  if (!isOctet && !isPrimitiveApp) {
    if (!node.tag.constructed && clen >= 4) {
      maskSpan(collector, intents, packetIndex, off, clen, 'tcap-primitive')
      coverage.push({ protocol: 'tcap-primitive', offset: off, length: clen, status: 'redacted' })
    }
    return
  }

  // Auth vector sizes (RAND=16, AUTN=16, Kc=8, CK/IK=16, KASME=32, XRES 4–16)
  if (clen === 16 || clen === 32 || clen === 8) {
    maskSpan(collector, intents, packetIndex, off, clen, 'map-auth-or-secret')
    coverage.push({ protocol: 'map-secret', offset: off, length: clen, status: 'redacted' })
    return
  }

  // ISDN-AddressString: TOA (1) + TBCD
  if (clen >= 3 && clen <= 12) {
    const toa = buffer[off]!
    // High bit often 1 for extension; numbering plan in low nibble of second form
    if ((toa & 0x80) !== 0 || (toa & 0x70) !== 0) {
      const digiOff = off + 1
      const digiLen = clen - 1
      const slice = buffer.subarray(digiOff, digiOff + digiLen)
      const digits = decodeTbcd(slice, TBCD_GSM)
      if (digits && digits.length >= 6 && digits.length <= 15 && /^\d+$/.test(digits)) {
        mapTbcdPhone(buffer, digiOff, digiLen, collector, mapping, intents, packetIndex, 'map-msisdn')
        coverage.push({ protocol: 'map-msisdn', offset: digiOff, length: digiLen, status: 'covered' })
        return
      }
    }
  }

  // IMSI / IMEI as bare TBCD
  if (clen >= 3 && clen <= 9) {
    const slice = buffer.subarray(off, off + clen)
    const digits = decodeTbcd(slice, TBCD_GSM)
    if (digits && /^\d+$/.test(digits)) {
      const imsi = normalizeImsiDigits(digits)
      if (imsi && digits.length >= 5 && digits.length <= 15) {
        mapTbcdCategory(buffer, off, clen, 'imsi', collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'map-imsi', offset: off, length: clen, status: 'covered' })
        return
      }
      const imei = normalizeImeiDigits(digits)
      if (imei) {
        mapTbcdCategory(buffer, off, clen, 'imei', collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'map-imei', offset: off, length: clen, status: 'covered' })
        return
      }
    }
  }

  // Location / USSD / SMS UD / unknown — mask
  if (clen >= 2) {
    maskSpan(collector, intents, packetIndex, off, clen, 'map-unknown')
    coverage.push({ protocol: 'map-unknown', offset: off, length: clen, status: 'redacted' })
  }
}

function mapPointCodeBe32(
  buffer: Uint8Array,
  abs: number,
  width: 14 | 24,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw =
    ((buffer[abs]! << 24)
      | (buffer[abs + 1]! << 16)
      | (buffer[abs + 2]! << 8)
      | buffer[abs + 3]!)
    >>> 0
  const mask = width === 14 ? 0x3fff : 0xffffff
  const pc = raw & mask
  if (pc === 0) return
  mapPointCodeValue(pc, width, buffer, abs, 4, 'm3ua-pc', collector, mapping, intents, packetIndex)
}

/** ANSI 24-bit point code in 3 octets (M2PA routing label baseline). */
export function mapPointCodeAnsi24(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  if (abs + 3 > buffer.length) return
  const pc =
    ((buffer[abs]! << 16) | (buffer[abs + 1]! << 8) | buffer[abs + 2]!) & 0xffffff
  if (pc === 0) return
  mapPointCodeValue(pc, 24, buffer, abs, 3, domain, collector, mapping, intents, packetIndex)
}

function mapPointCodeValue(
  pc: number,
  width: 14 | 24,
  buffer: Uint8Array,
  abs: number,
  byteLen: number,
  domain: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (pc === 0) return
  const canonical = `pc/${width}/${pc}`
  intents?.recordEntityReplacement(packetIndex, abs, 'point-code', canonical, byteLen)
  collector.addDeferred(abs, byteLen, ({ mapping: live }) => {
    try {
      const mapped = live.map('point-code', canonical)
      const m = /^pc\/(?:14|24)\/(\d+)$/.exec(mapped)
      const n = m ? Number(m[1]) >>> 0 : 0
      if (byteLen === 4) {
        return new Uint8Array([
          (n >>> 24) & 0xff,
          (n >>> 16) & 0xff,
          (n >>> 8) & 0xff,
          n & 0xff,
        ])
      }
      if (byteLen === 3) {
        const masked = n & 0xffffff
        return new Uint8Array([
          (masked >>> 16) & 0xff,
          (masked >>> 8) & 0xff,
          masked & 0xff,
        ])
      }
      // ITU 14-bit LE in 2 octets
      return new Uint8Array([n & 0xff, (n >>> 8) & 0xff])
    } catch {
      return createProtocolNeutralMaskFill({ length: byteLen, packetIndex, offset: abs, domain })
    }
  }, { fallbackKind: 'digits', protocol: 'm3ua', category: 'point-code', packetIndex })
  void mapping
  void buffer
}

function mapOpaqueScoped(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  // Hex token of wire octets as opaque-id (length-stable).
  let hex = ''
  for (let i = 0; i < len; i++) hex += buffer[abs + i]!.toString(16).padStart(2, '0')
  const canon = canonicalizeIdentity('opaque-id', hex) ?? hex
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.map('opaque-id', canon)
      const out = new Uint8Array(len)
      for (let i = 0; i < len; i++) {
        const pair = alias.slice(i * 2, i * 2 + 2)
        const v = Number.parseInt(pair, 16)
        out[i] = Number.isFinite(v) ? v & 0xff : 0xaa
      }
      return out
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'm3ua', category: 'opaque-id', packetIndex })
  void mapping
}

function mapTbcdPhone(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  mapTbcdSipPhoneField(
    buffer,
    abs,
    len,
    collector,
    mapping,
    intents,
    packetIndex,
    domain,
    'sigtran',
  )
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
): void {
  const slice = buffer.subarray(abs, abs + len)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits) {
    maskSpan(collector, intents, packetIndex, abs, len, `map-${category}-bad`)
    return
  }
  const normalized = category === 'imsi' ? normalizeImsiDigits(digits) : normalizeImeiDigits(digits)
  const canon = normalized ? canonicalizeIdentity(category, normalized) : null
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, `map-${category}-bad`)
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.map(category, canon)
      return remapTbcdBytes(slice, alias, TBCD_GSM)
        ?? encodeTbcd(alias, len, TBCD_GSM)
        ?? createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `map-${category}` })
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `map-${category}` })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'map', category, packetIndex })
  void mapping
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  maskSigtranSpan(collector, intents, packetIndex, offset, length, domain)
}

/** Shared mask helper for SIGTRAN family modules (M2PA). */
export function maskSigtranSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  maskWireSpan(collector, intents, packetIndex, offset, length, domain, 'sigtran')
}
