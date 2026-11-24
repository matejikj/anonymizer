/**
 * T34 — Geneve (UDP 6081) and L2TPv2 (UDP 1701) encapsulations.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { sanitizeLinkedEthernet } from './tunnel'
import type { InnerTransportHandler } from './tunnel'

export const GENEVE_UDP_PORT = 6081
export const L2TP_UDP_PORT = 1701

export function isGenevePort(src: number, dst: number): boolean {
  return src === GENEVE_UDP_PORT || dst === GENEVE_UDP_PORT
}

export function isL2tpPort(src: number, dst: number): boolean {
  return src === L2TP_UDP_PORT || dst === L2TP_UDP_PORT
}

export function looksLikeGeneve(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const ver = data[offset]! >> 6
  return ver === 0
}

/** Geneve → map VNI; mask options; recurse Ethernet. */
export function sanitizeGeneve(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  depth: number,
  onInnerTransport?: InnerTransportHandler,
): { coverage: LayerCoverage[]; lastCoveredOffset: number; issues: string[]; drop?: boolean } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (length < 8) {
    coverage.push({ protocol: 'geneve', offset, length, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset, issues: ['geneve-trunc'] }
  }
  const optLen = (data[offset]! & 0x3f) * 4
  const protocol = (data[offset + 2]! << 8) | data[offset + 3]!
  const vni =
    ((data[offset + 4]! << 16) | (data[offset + 5]! << 8) | data[offset + 6]!) >>> 0
  coverage.push({ protocol: 'geneve', offset, length: 8, status: 'covered' })
  // VNI → opaque (24-bit) — rewrite 3 bytes, preserve reserved byte
  const vniCanon = `geneve-vni/${vni}`
  intents?.recordEntityReplacement(packetIndex, offset + 4, 'opaque-id', vniCanon, 3)
  collector.addDeferred(offset + 4, 3, ({ mapping: live }) => {
    const alias = live.map('opaque-id', vniCanon)
    return createProtocolNeutralMaskFill({
      length: 3,
      packetIndex,
      offset: offset + 4,
      domain: `geneve-vni:${alias}`,
    })
  })
  const optOff = offset + 8
  if (optLen > 0) {
    if (optOff + optLen > offset + length) {
      mask(collector, intents, packetIndex, optOff, offset + length - optOff, 'geneve-opt-trunc')
      issues.push('geneve-opt-trunc')
      return { coverage, lastCoveredOffset: offset + length, issues }
    }
    mask(collector, intents, packetIndex, optOff, optLen, 'geneve-options')
    coverage.push({ protocol: 'geneve-opt', offset: optOff, length: optLen, status: 'redacted' })
  }
  const innerOff = optOff + optLen
  const innerLen = offset + length - innerOff
  if (innerLen <= 0) return { coverage, lastCoveredOffset: innerOff, issues }
  // Protocol 0x6558 = Transparent Ethernet bridging
  if (protocol === 0x6558 && innerLen >= 14) {
    const eth = sanitizeLinkedEthernet(
      data,
      innerOff,
      innerLen,
      collector,
      mapping,
      depth,
      onInnerTransport,
      { packetIndex, intents },
    )
    coverage.push(...eth.coverage)
    return {
      coverage,
      lastCoveredOffset: eth.coverage.reduce((m, c) => Math.max(m, c.offset + c.length), innerOff),
      issues,
      drop: eth.drop,
    }
  }
  if (protocol === 0x0800 || protocol === 0x86dd) {
    // Handled by caller if we expose — for now mask unless ethernet
    mask(collector, intents, packetIndex, innerOff, innerLen, 'geneve-inner')
    coverage.push({ protocol: 'geneve-inner', offset: innerOff, length: innerLen, status: 'redacted' })
    issues.push(`geneve-proto-0x${protocol.toString(16)}`)
    return { coverage, lastCoveredOffset: offset + length, issues }
  }
  mask(collector, intents, packetIndex, innerOff, innerLen, 'geneve-inner')
  coverage.push({ protocol: 'geneve-inner', offset: innerOff, length: innerLen, status: 'redacted' })
  issues.push(`geneve-unknown-proto:0x${protocol.toString(16)}`)
  return { coverage, lastCoveredOffset: offset + length, issues }
}

/** L2TPv2 control/data: map tunnel/session; mask challenge/hidden; PPP data via callback. */
export function sanitizeL2tp(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  onPpp?: (pppOff: number, pppLen: number) => {
    coverage: LayerCoverage[]
    issues: string[]
    lastCoveredOffset: number
  },
): { coverage: LayerCoverage[]; lastCoveredOffset: number; issues: string[] } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (length < 6) {
    coverage.push({ protocol: 'l2tp', offset, length, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset, issues: ['l2tp-trunc'] }
  }
  const flags = (data[offset]! << 8) | data[offset + 1]!
  const typeBit = (flags & 0x8000) !== 0 // 1=control
  const lenBit = (flags & 0x4000) !== 0
  const seqBit = (flags & 0x0800) !== 0
  const offsetBit = (flags & 0x0200) !== 0
  let pos = offset + 2
  if (lenBit) {
    if (pos + 2 > offset + length) {
      coverage.push({ protocol: 'l2tp', offset, length, status: 'malformed' })
      return { coverage, lastCoveredOffset: offset, issues: ['l2tp-len'] }
    }
    pos += 2
  }
  if (pos + 4 > offset + length) {
    coverage.push({ protocol: 'l2tp', offset, length, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset, issues: ['l2tp-ids'] }
  }
  const tunnelId = (data[pos]! << 8) | data[pos + 1]!
  const sessionId = (data[pos + 2]! << 8) | data[pos + 3]!
  mapU16Opaque(collector, intents, packetIndex, pos, `l2tp-tunnel/${tunnelId}`)
  mapU16Opaque(collector, intents, packetIndex, pos + 2, `l2tp-session/${sessionId}`)
  coverage.push({ protocol: 'l2tp', offset, length: pos + 4 - offset, status: 'covered' })
  pos += 4
  if (seqBit) {
    if (pos + 4 > offset + length) {
      issues.push('l2tp-seq-trunc')
      mask(collector, intents, packetIndex, pos, offset + length - pos, 'l2tp-seq')
      return { coverage, lastCoveredOffset: offset + length, issues }
    }
    pos += 4 // Ns Nr preserve
  }
  if (offsetBit) {
    if (pos + 2 > offset + length) {
      issues.push('l2tp-off-trunc')
      return { coverage, lastCoveredOffset: offset + length, issues }
    }
    const offSize = (data[pos]! << 8) | data[pos + 1]!
    pos += 2 + offSize
  }
  if (typeBit) {
    // Control AVPs
    sanitizeL2tpAvps(data, pos, offset + length - pos, collector, mapping, packetIndex, intents, coverage, issues)
    return { coverage, lastCoveredOffset: offset + length, issues }
  }
  // Data → PPP
  if (onPpp && pos < offset + length) {
    const r = onPpp(pos, offset + length - pos)
    coverage.push(...r.coverage)
    for (const i of r.issues) issues.push(i)
    return { coverage, lastCoveredOffset: r.lastCoveredOffset, issues }
  }
  if (pos < offset + length) {
    mask(collector, intents, packetIndex, pos, offset + length - pos, 'l2tp-data')
    coverage.push({
      protocol: 'l2tp-data',
      offset: pos,
      length: offset + length - pos,
      status: 'redacted',
    })
  }
  return { coverage, lastCoveredOffset: offset + length, issues }
}

function sanitizeL2tpAvps(
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
  while (pos + 6 <= end) {
    const bits = (data[pos]! << 8) | data[pos + 1]!
    const mBit = (bits & 0x8000) !== 0
    const hBit = (bits & 0x4000) !== 0
    const avpLen = bits & 0x3ff
    if (avpLen < 6 || pos + avpLen > end) {
      mask(collector, intents, packetIndex, pos, end - pos, 'l2tp-avp-trunc')
      issues.push('l2tp-avp-trunc')
      break
    }
    const vendor = (data[pos + 2]! << 8) | data[pos + 3]!
    const attr = (data[pos + 4]! << 8) | data[pos + 5]!
    const valOff = pos + 6
    const valLen = avpLen - 6
    void mBit
    void vendor
    // IETF: Host Name=7, Challenge=11, Challenge Response=13, Random Vector=36
    if (hBit || attr === 11 || attr === 13 || attr === 36) {
      if (valLen > 0) {
        mask(collector, intents, packetIndex, valOff, valLen, `l2tp-avp-${attr}`)
        coverage.push({ protocol: 'l2tp-avp', offset: pos, length: avpLen, status: 'redacted' })
        issues.push(`l2tp-secret-avp:${attr}`)
      }
    } else if (attr === 7 && valLen > 0) {
      const raw = new TextDecoder('latin1').decode(data.subarray(valOff, valOff + valLen))
      intents?.recordEntityReplacement(packetIndex, valOff, 'hostname', raw, valLen)
      collector.addDeferred(valOff, valLen, ({ mapping: live }) => {
        const alias = live.aliasFor('hostname', raw, { kind: 'text-ascii', byteLength: valLen }, raw)
        return computeFixedLengthAsciiBytes(valOff, valLen, alias)
      })
      coverage.push({ protocol: 'l2tp-avp-hostname', offset: pos, length: avpLen, status: 'covered' })
    } else if (attr === 8 && valLen > 0) {
      // Vendor Name — preserve fingerprint? Task says preserve Vendor Name
      coverage.push({ protocol: 'l2tp-avp', offset: pos, length: avpLen, status: 'covered' })
    } else if (valLen > 0 && attr !== 0 && attr !== 1 && attr !== 2) {
      // Unknown AVP value mask
      mask(collector, intents, packetIndex, valOff, valLen, `l2tp-avp-${attr}`)
      coverage.push({ protocol: 'l2tp-avp', offset: pos, length: avpLen, status: 'redacted' })
    } else {
      coverage.push({ protocol: 'l2tp-avp', offset: pos, length: avpLen, status: 'covered' })
    }
    pos += avpLen
  }
  void mapping
}

function mapU16Opaque(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  canon: string,
): void {
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 2)
  collector.addDeferred(offset, 2, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: 2,
      packetIndex,
      offset,
      domain: `l2tp:${alias}`,
    })
  })
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'geneve-l2tp')
}
