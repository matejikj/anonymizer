/**
 * T34 — Link encapsulations: NULL/LOOP, PPP/PPPoE, MPLS, NFLOG, MACsec/PBB baselines.
 * Helpers return next-layer offset + synthetic etherType (or done/mask).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { sanitizeEapol } from './eapol'

export const LINKTYPE_NULL = 0
export const LINKTYPE_PPP = 9
export const LINKTYPE_PPP_HDLC = 50
export const LINKTYPE_LOOP = 108
export const LINKTYPE_C_HDLC = 104
export const LINKTYPE_NFLOG = 239

export const ETHERTYPE_PPPOE_DISC = 0x8863
export const ETHERTYPE_PPPOE_SES = 0x8864
export const ETHERTYPE_MPLS_UC = 0x8847
export const ETHERTYPE_MPLS_MC = 0x8848
export const ETHERTYPE_MACSEC = 0x88e5
export const ETHERTYPE_PBB = 0x88e7

const PPP_IPV4 = 0x0021
const PPP_IPV6 = 0x0057
const PPP_LCP = 0xc021
const PPP_IPCP = 0x8021
const PPP_IPV6CP = 0x8057
const PPP_PAP = 0xc023
const PPP_CHAP = 0xc223
const PPP_EAP = 0xc227

const MAX_MPLS_LABELS = 16

export interface LinkContinue {
  readonly offset: number
  readonly etherType: number
  readonly coverage: readonly LayerCoverage[]
  readonly issues: readonly string[]
  /** When true, caller must not continue into IP — body already handled. */
  readonly done?: boolean
  readonly lastCoveredOffset?: number
}

/** DLT_NULL (0) / DLT_LOOP (108): 4-byte AF → IPv4/IPv6. */
export function continueNullLoop(
  data: Uint8Array,
  linkType: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (data.length < 5) {
    coverage.push({ protocol: 'null-loop', offset: 0, length: data.length, status: 'malformed' })
    return { offset: 0, etherType: 0, coverage, issues: ['null-loop-trunc'], done: true, lastCoveredOffset: data.length }
  }
  const le = data[0]! | (data[1]! << 8) | (data[2]! << 16) | (data[3]! << 24)
  const be = (data[0]! << 24) | (data[1]! << 16) | (data[2]! << 8) | data[3]!
  // LOOP prefers network order; NULL (macOS) prefers host/LE
  const order = linkType === LINKTYPE_LOOP ? [be, le] : [le, be]
  for (const af of order) {
    const ver = data[4]! >> 4
    if (af === 2 && ver === 4) {
      coverage.push({ protocol: 'null-loop', offset: 0, length: 4, status: 'covered' })
      return { offset: 4, etherType: 0x0800, coverage, issues }
    }
    if ((af === 24 || af === 28 || af === 30) && ver === 6) {
      coverage.push({ protocol: 'null-loop', offset: 0, length: 4, status: 'covered' })
      return { offset: 4, etherType: 0x86dd, coverage, issues }
    }
  }
  // Unknown AF — fail-closed mask payload, preserve AF field
  coverage.push({ protocol: 'null-loop', offset: 0, length: 4, status: 'covered' })
  if (data.length > 4) {
    mask(collector, intents, packetIndex, 4, data.length - 4, 'null-loop-unknown-af')
    coverage.push({
      protocol: 'null-loop-payload',
      offset: 4,
      length: data.length - 4,
      status: 'redacted',
    })
    issues.push('null-loop-unknown-af')
  }
  return { offset: 4, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
}

/** PPP / PPP-HDLC / Cisco HDLC linktypes → IPv4/IPv6 or auth mask. */
export function continuePppLink(
  data: Uint8Array,
  linkType: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = 0
  // HDLC address/control FF 03 (optional)
  if (
    (linkType === LINKTYPE_PPP_HDLC || linkType === LINKTYPE_C_HDLC || linkType === LINKTYPE_PPP)
    && data.length >= 2
    && data[0] === 0xff
    && data[1] === 0x03
  ) {
    coverage.push({ protocol: 'ppp-hdlc', offset: 0, length: 2, status: 'covered' })
    pos = 2
  }
  return continuePppAtOffset(data, pos, collector, mapping, packetIndex, intents, coverage, issues)
}

/** Offset-aware PPP payload (PPPoE session / L2TP data). */
export function continuePppAtOffset(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
  coverage: LayerCoverage[] = [],
  issues: string[] = [],
): LinkContinue {
  return sanitizePppPayload(data, offset, collector, mapping, packetIndex, intents, coverage, issues)
}

/** PPPoE discovery/session after Ethernet. */
export function continuePppoe(
  data: Uint8Array,
  offset: number,
  discovery: boolean,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (offset + 6 > data.length) {
    coverage.push({ protocol: 'pppoe', offset, length: data.length - offset, status: 'malformed' })
    return { offset, etherType: 0, coverage, issues: ['pppoe-trunc'], done: true, lastCoveredOffset: data.length }
  }
  const verType = data[offset]!
  if ((verType >> 4) !== 1) {
    mask(collector, intents, packetIndex, offset, data.length - offset, 'pppoe-ver')
    coverage.push({ protocol: 'pppoe', offset, length: data.length - offset, status: 'malformed' })
    return { offset, etherType: 0, coverage, issues: ['pppoe-version'], done: true, lastCoveredOffset: data.length }
  }
  const code = data[offset + 1]!
  const sessionId = (data[offset + 2]! << 8) | data[offset + 3]!
  const payloadLen = (data[offset + 4]! << 8) | data[offset + 5]!
  coverage.push({ protocol: 'pppoe', offset, length: 6, status: 'covered' })
  // Session ID → opaque scoped alias (2 bytes)
  if (sessionId !== 0) {
    const canon = `pppoe-session/${sessionId}`
    intents?.recordEntityReplacement(packetIndex, offset + 2, 'opaque-id', canon, 2)
    collector.addDeferred(offset + 2, 2, ({ mapping: live }) => {
      const alias = live.map('opaque-id', canon)
      // Keep numeric 16-bit from alias hash-ish: use first 2 bytes of masked fill keyed by alias
      const fill = createProtocolNeutralMaskFill({
        length: 2,
        packetIndex,
        offset: offset + 2,
        domain: `pppoe-sid:${alias}`,
      })
      return fill
    })
  }
  const bodyOff = offset + 6
  const bodyEnd = Math.min(data.length, bodyOff + payloadLen)
  if (discovery || code !== 0) {
    sanitizePppoeTags(data, bodyOff, bodyEnd - bodyOff, collector, mapping, packetIndex, intents, coverage, issues)
    return { offset: bodyEnd, etherType: 0, coverage, issues, done: true, lastCoveredOffset: bodyEnd }
  }
  // Session (code 0): PPP payload
  return sanitizePppPayload(data, bodyOff, collector, mapping, packetIndex, intents, coverage, issues)
}

/** MPLS label stack → inner IPv4/IPv6 by first nibble (no CW guess). */
export function continueMpls(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = offset
  let labels = 0
  let bottom = false
  while (pos + 4 <= data.length && labels < MAX_MPLS_LABELS && !bottom) {
    const entry =
      ((data[pos]! << 24) | (data[pos + 1]! << 16) | (data[pos + 2]! << 8) | data[pos + 3]!) >>> 0
    const label = entry >>> 12
    const tc = (entry >>> 9) & 0x7
    const s = (entry >>> 8) & 0x1
    const ttl = entry & 0xff
    void tc
    void ttl
    // Reserved labels 0–15 preserve; others map as opaque topology id (keep TC/S/TTL)
    if (label > 15) {
      const canon = `mpls-label/${label}`
      const labelPos = pos
      const keepTc = tc
      const keepS = s
      const keepTtl = ttl
      intents?.recordEntityReplacement(packetIndex, labelPos, 'opaque-id', canon, 4)
      collector.addDeferred(labelPos, 4, ({ mapping: live }) => {
        const alias = live.map('opaque-id', canon)
        const fill = createProtocolNeutralMaskFill({
          length: 3,
          packetIndex,
          offset: labelPos,
          domain: `mpls:${alias}`,
        })
        const newLabel =
          ((fill[0]! << 12) | (fill[1]! << 4) | (fill[2]! >> 4)) & 0xfffff
        const entry = ((newLabel << 12) | (keepTc << 9) | (keepS << 8) | keepTtl) >>> 0
        return new Uint8Array([
          (entry >>> 24) & 0xff,
          (entry >>> 16) & 0xff,
          (entry >>> 8) & 0xff,
          entry & 0xff,
        ])
      })
    }
    coverage.push({ protocol: 'mpls', offset: pos, length: 4, status: 'covered' })
    bottom = s === 1
    pos += 4
    labels++
  }
  if (!bottom) {
    if (pos < data.length) {
      mask(collector, intents, packetIndex, pos, data.length - pos, 'mpls-no-bottom')
      coverage.push({
        protocol: 'mpls-payload',
        offset: pos,
        length: data.length - pos,
        status: 'redacted',
      })
      issues.push('mpls-no-bottom')
    }
    return { offset: pos, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
  }
  if (pos >= data.length) {
    return { offset: pos, etherType: 0, coverage, issues, done: true, lastCoveredOffset: pos }
  }
  const nibble = data[pos]! >> 4
  if (nibble === 4) return { offset: pos, etherType: 0x0800, coverage, issues }
  if (nibble === 6) return { offset: pos, etherType: 0x86dd, coverage, issues }
  // Ambiguous / pseudowire — fail-closed
  mask(collector, intents, packetIndex, pos, data.length - pos, 'mpls-unknown-payload')
  coverage.push({
    protocol: 'mpls-payload',
    offset: pos,
    length: data.length - pos,
    status: 'redacted',
  })
  issues.push('mpls-unknown-inner')
  return { offset: pos, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
}

/** NFLOG (239): TLV walk; map hwaddr; mask prefix/uid; continue IP payload. */
export function continueNflog(
  data: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (data.length < 4) {
    coverage.push({ protocol: 'nflog', offset: 0, length: data.length, status: 'malformed' })
    return { offset: 0, etherType: 0, coverage, issues: ['nflog-trunc'], done: true, lastCoveredOffset: data.length }
  }
  // nflog_hdr: family(1) version(1) res(2)
  const family = data[0]!
  coverage.push({ protocol: 'nflog', offset: 0, length: 4, status: 'covered' })
  let pos = 4
  let payloadOff = -1
  let payloadLen = 0
  while (pos + 4 <= data.length) {
    const tlvLen = data[pos]! | (data[pos + 1]! << 8)
    const tlvType = data[pos + 2]! | (data[pos + 3]! << 8)
    if (tlvLen < 4 || pos + tlvLen > data.length) {
      mask(collector, intents, packetIndex, pos, data.length - pos, 'nflog-tlv-trunc')
      issues.push('nflog-tlv-trunc')
      break
    }
    const valOff = pos + 4
    const valLen = tlvLen - 4
    // NFULA_PAYLOAD = 9, NFULA_PREFIX = 10, NFULA_UID = 11, NFULA_GID = 12, NFULA_HWADDR = 4
    if (tlvType === 9 && valLen > 0) {
      payloadOff = valOff
      payloadLen = valLen
      coverage.push({ protocol: 'nflog-payload', offset: pos, length: 4, status: 'covered' })
    } else if (tlvType === 10 && valLen > 0) {
      mask(collector, intents, packetIndex, valOff, valLen, 'nflog-prefix')
      coverage.push({ protocol: 'nflog-prefix', offset: pos, length: tlvLen, status: 'redacted' })
    } else if ((tlvType === 11 || tlvType === 12) && valLen >= 4) {
      const canon = `nflog-id/${tlvType}/${data[valOff]!}`
      intents?.recordEntityReplacement(packetIndex, valOff, 'opaque-id', canon, valLen)
      collector.addDeferred(valOff, valLen, ({ mapping: live }) => {
        const alias = live.map('opaque-id', canon)
        return createProtocolNeutralMaskFill({
          length: valLen,
          packetIndex,
          offset: valOff,
          domain: `nflog:${alias}`,
        })
      })
      coverage.push({ protocol: 'nflog-id', offset: pos, length: tlvLen, status: 'covered' })
    } else if (tlvType === 4 && valLen >= 8) {
      // hwaddr struct: len, pad, addr…
      const hwLen = data[valOff]!
      if (hwLen === 6 && valOff + 4 + 6 <= valOff + valLen) {
        patchMacLocal(data, valOff + 4, collector, mapping, packetIndex, intents)
      }
      coverage.push({ protocol: 'nflog-hwaddr', offset: pos, length: tlvLen, status: 'covered' })
    } else if (valLen > 0 && tlvType !== 1 && tlvType !== 3) {
      // unknown / timestamp / ifindex — mask free text-ish, preserve structure types lightly
      if (tlvType === 5 || tlvType === 6) {
        coverage.push({ protocol: 'nflog-tlv', offset: pos, length: tlvLen, status: 'covered' })
      } else {
        mask(collector, intents, packetIndex, valOff, valLen, `nflog-tlv-${tlvType}`)
        coverage.push({ protocol: 'nflog-tlv', offset: pos, length: tlvLen, status: 'redacted' })
      }
    } else {
      coverage.push({ protocol: 'nflog-tlv', offset: pos, length: tlvLen, status: 'covered' })
    }
    pos += (tlvLen + 3) & ~3
  }
  if (payloadOff >= 0 && payloadLen > 0) {
    const ver = data[payloadOff]! >> 4
    if (family === 2 && ver === 4) {
      return { offset: payloadOff, etherType: 0x0800, coverage, issues }
    }
    if (family === 10 && ver === 6) {
      return { offset: payloadOff, etherType: 0x86dd, coverage, issues }
    }
    if (ver === 4) return { offset: payloadOff, etherType: 0x0800, coverage, issues }
    if (ver === 6) return { offset: payloadOff, etherType: 0x86dd, coverage, issues }
    mask(collector, intents, packetIndex, payloadOff, payloadLen, 'nflog-payload-unknown')
    coverage.push({
      protocol: 'nflog-payload',
      offset: payloadOff,
      length: payloadLen,
      status: 'redacted',
    })
    issues.push('nflog-payload-unknown')
  }
  return { offset: pos, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
}

/** MACsec SecTAG: map SCI MAC; integrity-only → continue ethertype; else mask. */
export function continueMacsec(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  // SecTAG: TCI/AN(1) SL(1) PN(4) SCI(8 optional)
  if (offset + 6 > data.length) {
    coverage.push({ protocol: 'macsec', offset, length: data.length - offset, status: 'malformed' })
    return { offset, etherType: 0, coverage, issues: ['macsec-trunc'], done: true, lastCoveredOffset: data.length }
  }
  const tci = data[offset]!
  const sc = (tci & 0x20) !== 0 // SC bit — SCI present
  const e = (tci & 0x08) !== 0 // E bit — encryption
  const c = (tci & 0x04) !== 0 // C bit
  let pos = offset + 6
  coverage.push({ protocol: 'macsec', offset, length: 6, status: 'covered' })
  if (sc) {
    if (pos + 8 > data.length) {
      issues.push('macsec-sci-trunc')
      mask(collector, intents, packetIndex, offset, data.length - offset, 'macsec-sci-trunc')
      return { offset, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
    }
    // SCI: 6B MAC + 2B port
    patchMacLocal(data, pos, collector, mapping, packetIndex, intents)
    coverage.push({ protocol: 'macsec-sci', offset: pos, length: 8, status: 'covered' })
    pos += 8
  }
  if (e || c) {
    // Encrypted / confidentiality — mask remainder (no SA proof)
    if (pos < data.length) {
      mask(collector, intents, packetIndex, pos, data.length - pos, 'macsec-ciphertext')
      coverage.push({
        protocol: 'macsec-payload',
        offset: pos,
        length: data.length - pos,
        status: 'encrypted',
      })
      issues.push('macsec-encrypted-unproven')
    }
    return { offset: pos, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
  }
  // Integrity-only: ethertype follows
  if (pos + 2 > data.length) {
    return { offset: pos, etherType: 0, coverage, issues, done: true, lastCoveredOffset: pos }
  }
  const next = (data[pos]! << 8) | data[pos + 1]!
  coverage.push({ protocol: 'macsec-ethertype', offset: pos, length: 2, status: 'covered' })
  return { offset: pos + 2, etherType: next, coverage, issues }
}

/** PBB / 802.1ah: outer B-MAC already patched as Ethernet; I-TAG + inner C-MAC. */
export function continuePbb(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): LinkContinue {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  // I-TAG: 4 bytes (PCP/DEI/UCA/Res/I-SID) then inner C-DA/C-SA + ethertype
  if (offset + 4 + 14 > data.length) {
    coverage.push({ protocol: 'pbb', offset, length: data.length - offset, status: 'malformed' })
    return { offset, etherType: 0, coverage, issues: ['pbb-trunc'], done: true, lastCoveredOffset: data.length }
  }
  coverage.push({ protocol: 'pbb-itag', offset, length: 4, status: 'covered' })
  const inner = offset + 4
  patchMacLocal(data, inner, collector, mapping, packetIndex, intents)
  patchMacLocal(data, inner + 6, collector, mapping, packetIndex, intents)
  let pos = inner + 12
  let etherType = (data[pos]! << 8) | data[pos + 1]!
  pos += 2
  while ((etherType === 0x8100 || etherType === 0x88a8) && pos + 2 <= data.length) {
    pos += 2 // skip TCI
    if (pos + 2 > data.length) break
    etherType = (data[pos]! << 8) | data[pos + 1]!
    pos += 2
  }
  coverage.push({ protocol: 'pbb', offset, length: pos - offset, status: 'covered' })
  return { offset: pos, etherType, coverage, issues }
}

function sanitizePppPayload(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): LinkContinue {
  if (offset >= data.length) {
    return { offset, etherType: 0, coverage, issues, done: true, lastCoveredOffset: offset }
  }
  // Protocol field: 1 or 2 bytes (PFC)
  let proto: number
  let protoLen: number
  if ((data[offset]! & 0x01) !== 0) {
    proto = data[offset]!
    protoLen = 1
  } else if (offset + 2 <= data.length) {
    proto = (data[offset]! << 8) | data[offset + 1]!
    protoLen = 2
  } else {
    coverage.push({ protocol: 'ppp', offset, length: data.length - offset, status: 'malformed' })
    return { offset, etherType: 0, coverage, issues: ['ppp-trunc'], done: true, lastCoveredOffset: data.length }
  }
  coverage.push({ protocol: 'ppp', offset, length: protoLen, status: 'covered' })
  const body = offset + protoLen
  if (proto === PPP_IPV4) return { offset: body, etherType: 0x0800, coverage, issues }
  if (proto === PPP_IPV6) return { offset: body, etherType: 0x86dd, coverage, issues }
  if (proto === PPP_PAP) {
    sanitizePap(data, body, collector, mapping, packetIndex, intents, coverage, issues)
    return { offset: body, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
  }
  if (proto === PPP_CHAP) {
    sanitizeChap(data, body, collector, mapping, packetIndex, intents, coverage, issues)
    return { offset: body, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
  }
  if (proto === PPP_EAP) {
    const r = sanitizeEapol(data, body, data.length - body, collector, mapping, intents, packetIndex)
    coverage.push(...r.coverage)
    if (r.issues) for (const i of r.issues) issues.push(i)
    return { offset: body, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
  }
  if (proto === PPP_LCP || proto === PPP_IPCP || proto === PPP_IPV6CP) {
    sanitizePppCp(data, body, proto, collector, mapping, packetIndex, intents, coverage, issues)
    return { offset: body, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
  }
  mask(collector, intents, packetIndex, body, data.length - body, `ppp-proto-0x${proto.toString(16)}`)
  coverage.push({
    protocol: `ppp-0x${proto.toString(16)}`,
    offset: body,
    length: data.length - body,
    status: 'redacted',
  })
  issues.push(`ppp-unsupported-proto:0x${proto.toString(16)}`)
  return { offset: body, etherType: 0, coverage, issues, done: true, lastCoveredOffset: data.length }
}

function sanitizePap(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // Code(1) Id(1) Len(2) Peer-Id-Len(1) Peer-Id Password-Len(1) Password
  if (offset + 4 > data.length) {
    coverage.push({ protocol: 'ppp-pap', offset, length: data.length - offset, status: 'malformed' })
    return
  }
  const code = data[offset]!
  coverage.push({ protocol: 'ppp-pap', offset, length: 4, status: 'covered' })
  if (code !== 1 && code !== 2) {
    mask(collector, intents, packetIndex, offset + 4, data.length - offset - 4, 'ppp-pap-other')
    return
  }
  let pos = offset + 4
  if (pos >= data.length) return
  const idLen = data[pos]!
  pos += 1
  if (pos + idLen > data.length) {
    mask(collector, intents, packetIndex, pos - 1, data.length - (pos - 1), 'ppp-pap-id')
    return
  }
  if (idLen > 0) {
    const raw = new TextDecoder('latin1').decode(data.subarray(pos, pos + idLen))
    intents?.recordEntityReplacement(packetIndex, pos, 'user-id', raw, idLen)
    collector.addDeferred(pos, idLen, ({ mapping: live }) => {
      const alias = live.aliasFor('user-id', raw, { kind: 'text-ascii', byteLength: idLen }, raw)
      return computeFixedLengthAsciiBytes(pos, idLen, alias)
    })
  }
  pos += idLen
  if (code === 1 && pos < data.length) {
    const pwLen = data[pos]!
    pos += 1
    const n = Math.min(pwLen, data.length - pos)
    if (n > 0) {
      mask(collector, intents, packetIndex, pos, n, 'ppp-pap-password')
      coverage.push({ protocol: 'ppp-pap-password', offset: pos, length: n, status: 'redacted' })
      issues.push('ppp-pap-password-masked')
    }
  }
  void mapping
}

function sanitizeChap(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // Code Id Len Value-Size Value Name
  if (offset + 5 > data.length) {
    coverage.push({ protocol: 'ppp-chap', offset, length: data.length - offset, status: 'malformed' })
    return
  }
  const code = data[offset]!
  coverage.push({ protocol: 'ppp-chap', offset, length: 4, status: 'covered' })
  const valSize = data[offset + 4]!
  let pos = offset + 5
  if (pos + valSize > data.length) {
    mask(collector, intents, packetIndex, offset + 4, data.length - offset - 4, 'ppp-chap-trunc')
    return
  }
  if (valSize > 0) {
    mask(collector, intents, packetIndex, pos, valSize, 'ppp-chap-value')
    coverage.push({ protocol: 'ppp-chap-value', offset: pos, length: valSize, status: 'redacted' })
    issues.push('ppp-chap-challenge-masked')
  }
  pos += valSize
  const nameLen = data.length - pos
  if (nameLen > 0 && (code === 1 || code === 2)) {
    const raw = new TextDecoder('latin1').decode(data.subarray(pos, pos + nameLen))
    intents?.recordEntityReplacement(packetIndex, pos, 'user-id', raw, nameLen)
    collector.addDeferred(pos, nameLen, ({ mapping: live }) => {
      const alias = live.aliasFor('user-id', raw, { kind: 'text-ascii', byteLength: nameLen }, raw)
      return computeFixedLengthAsciiBytes(pos, nameLen, alias)
    })
    coverage.push({ protocol: 'ppp-chap-name', offset: pos, length: nameLen, status: 'covered' })
  }
  void mapping
}

function sanitizePppCp(
  data: Uint8Array,
  offset: number,
  proto: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // Code Id Len options…
  if (offset + 4 > data.length) {
    coverage.push({ protocol: 'ppp-cp', offset, length: data.length - offset, status: 'malformed' })
    return
  }
  coverage.push({ protocol: 'ppp-cp', offset, length: 4, status: 'covered' })
  let pos = offset + 4
  const end = data.length
  while (pos + 2 <= end) {
    const type = data[pos]!
    const len = data[pos + 1]!
    if (len < 2 || pos + len > end) {
      mask(collector, intents, packetIndex, pos, end - pos, 'ppp-cp-opt')
      issues.push('ppp-cp-opt-trunc')
      break
    }
    const valOff = pos + 2
    const valLen = len - 2
    // IPCP: IP-Address=3, DNS=129/131; IPV6CP: Interface-Identifier=1
    if (proto === PPP_IPCP && type === 3 && valLen >= 4) {
      patchIpv4Local(data, valOff, collector, mapping, packetIndex, intents)
      coverage.push({ protocol: 'ppp-ipcp-ip', offset: pos, length: len, status: 'covered' })
    } else if (proto === PPP_IPCP && (type === 129 || type === 131) && valLen >= 4) {
      patchIpv4Local(data, valOff, collector, mapping, packetIndex, intents)
      coverage.push({ protocol: 'ppp-ipcp-dns', offset: pos, length: len, status: 'covered' })
    } else if (proto === PPP_IPV6CP && type === 1 && valLen >= 8) {
      mask(collector, intents, packetIndex, valOff, valLen, 'ppp-ipv6cp-iid')
      coverage.push({ protocol: 'ppp-ipv6cp-iid', offset: pos, length: len, status: 'redacted' })
    } else if (proto === PPP_LCP && type === 5 && valLen >= 4) {
      // Magic-Number — preserve
      coverage.push({ protocol: 'ppp-lcp-magic', offset: pos, length: len, status: 'covered' })
    } else if (valLen > 0) {
      mask(collector, intents, packetIndex, valOff, valLen, `ppp-cp-${type}`)
      coverage.push({ protocol: 'ppp-cp-opt', offset: pos, length: len, status: 'redacted' })
    } else {
      coverage.push({ protocol: 'ppp-cp-opt', offset: pos, length: len, status: 'covered' })
    }
    pos += len
  }
}

function sanitizePppoeTags(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  let pos = offset
  const end = offset + length
  while (pos + 4 <= end) {
    const type = (data[pos]! << 8) | data[pos + 1]!
    const tlen = (data[pos + 2]! << 8) | data[pos + 3]!
    if (pos + 4 + tlen > end) {
      mask(collector, intents, packetIndex, pos, end - pos, 'pppoe-tag-trunc')
      issues.push('pppoe-tag-trunc')
      break
    }
    const valOff = pos + 4
    // 0x0101 Service-Name, 0x0102 AC-Name → hostname-ish; 0x0103 Host-Uniq, 0x0104 AC-Cookie, 0x0110 Relay → mask
    if ((type === 0x0101 || type === 0x0102) && tlen > 0) {
      const raw = new TextDecoder('latin1').decode(data.subarray(valOff, valOff + tlen))
      if (/[A-Za-z]/.test(raw)) {
        intents?.recordEntityReplacement(packetIndex, valOff, 'hostname', raw, tlen)
        collector.addDeferred(valOff, tlen, ({ mapping: live }) => {
          const alias = live.aliasFor('hostname', raw, { kind: 'text-ascii', byteLength: tlen }, raw)
          return computeFixedLengthAsciiBytes(valOff, tlen, alias)
        })
      } else {
        mask(collector, intents, packetIndex, valOff, tlen, 'pppoe-tag-name')
      }
      coverage.push({ protocol: 'pppoe-tag', offset: pos, length: 4 + tlen, status: 'covered' })
    } else if (tlen > 0 && (type === 0x0103 || type === 0x0104 || type === 0x0110 || type === 0x0105)) {
      mask(collector, intents, packetIndex, valOff, tlen, `pppoe-tag-0x${type.toString(16)}`)
      coverage.push({ protocol: 'pppoe-tag', offset: pos, length: 4 + tlen, status: 'redacted' })
    } else {
      coverage.push({ protocol: 'pppoe-tag', offset: pos, length: 4 + tlen, status: 'covered' })
    }
    pos += 4 + tlen
  }
  void mapping
}

function mask(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'link-encaps')
}

function patchMacLocal(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const mac = Array.from(data.subarray(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
  intents?.recordEntityReplacement(packetIndex, offset, 'mac', mac, 6)
  try {
    collector.addDeferred(offset, 6, ({ mapping: live }) => {
      const mapped = live.map('mac', mac)
      return new Uint8Array(mapped.split(':').map((s) => Number.parseInt(s, 16)))
    })
  } catch {
    /* overlap */
  }
}

function patchIpv4Local(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`
  if (ip === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4)
  collector.addDeferred(offset, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', ip)
    return new Uint8Array(mapped.split('.').map(Number))
  })
}
