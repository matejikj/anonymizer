/**
 * T20 — SNMP v1/v2c/v3 sanitizer (BER via T16 toolkit).
 * Community / auth / priv always masked; known OID values mapped.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { walkBer, readBerTag, readBerLength, type BerNode } from '../protocols/application/binproto'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { deferredBinaryMapMeta, deferredTextMapMeta } from './deferredMapMeta.ts'

const SNMP_PORTS = new Set([161, 162])

/** sysName.0 / sysContact.0 / sysLocation.0 / sysDescr.0 */
const OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'
const OID_SYS_CONTACT = '1.3.6.1.2.1.1.4.0'
const OID_SYS_NAME = '1.3.6.1.2.1.1.5.0'
const OID_SYS_LOCATION = '1.3.6.1.2.1.1.6.0'

const ASN1_OCTET_STRING = 0x04
const ASN1_INTEGER = 0x02

export function isSnmpPortHint(src: number, dst: number): boolean {
  return SNMP_PORTS.has(src) || SNMP_PORTS.has(dst)
}

export function looksLikeSnmp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 4 || data[offset] !== 0x30) return false
  const len = readBerLength(data, offset + 1, offset + length, false)
  return len !== null && !len.indefinite
}

export function sanitizeSnmp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeSnmp(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const { roots, issues: berIssues } = walkBer(buffer, offset, length, { maxDepth: 24, maxNodes: 512 })
  for (const i of berIssues) issues.push(`snmp-${i.code}`)

  if (roots.length === 0) {
    mask(collector, intents, packetIndex, offset, length, 'snmp-malformed')
    coverage.push({ protocol: 'snmp', offset, length, status: 'malformed' })
    return { coverage, issues }
  }

  const msg = roots[0]!
  const children = msg.children
  if (children.length < 2) {
    mask(collector, intents, packetIndex, offset, length, 'snmp-malformed')
    coverage.push({ protocol: 'snmp', offset, length, status: 'malformed' })
    return { coverage, issues }
  }

  const versionNode = children[0]!
  const version = readInteger(buffer, versionNode)
  if (version === null) {
    mask(collector, intents, packetIndex, offset, length, 'snmp-version')
    coverage.push({ protocol: 'snmp', offset, length, status: 'malformed' })
    return { coverage, issues }
  }

  if (version === 0 || version === 1) {
    // community OCTET STRING
    const community = children[1]!
    maskNodeContent(buffer, community, collector, intents, packetIndex, 'snmp-community')
    const pdu = children[2]
    if (pdu) sanitizePdu(buffer, pdu, collector, mapping, intents, packetIndex, issues)
    coverage.push({ protocol: 'snmp', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  if (version === 3) {
    // msgGlobalData, msgSecurityParameters, msgData
    const secParams = children[2]
    if (secParams) sanitizeV3Security(buffer, secParams, collector, mapping, intents, packetIndex, issues)
    const msgData = children[3]
    if (msgData) {
      // scopedPDU plaintext (authNoPriv) or encrypted OCTET STRING
      if (!msgData.tag.constructed && msgData.tag.number === ASN1_OCTET_STRING) {
        // encrypted / opaque — mask content, preserve framing
        maskNodeContent(buffer, msgData, collector, intents, packetIndex, 'snmp-v3-scoped-encrypted')
        issues.push('snmp-v3-encrypted-scoped')
      } else {
        sanitizeScopedOrPdu(buffer, msgData, collector, mapping, intents, packetIndex, issues)
      }
    }
    coverage.push({ protocol: 'snmp', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  mask(collector, intents, packetIndex, offset, length, 'snmp-unsupported-version')
  coverage.push({ protocol: 'snmp', offset, length, status: 'unsupported' })
  return { coverage, issues }
}

function sanitizeV3Security(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // msgSecurityParameters is OCTET STRING wrapping a SEQUENCE
  if (node.tag.number !== ASN1_OCTET_STRING) return
  const inner = walkBer(buffer, node.contentOffset, node.contentLength, { maxDepth: 8 })
  const seq = inner.roots[0]
  if (!seq || seq.children.length < 6) {
    maskNodeContent(buffer, node, collector, intents, packetIndex, 'snmp-v3-secparams')
    return
  }
  // engineID, engineBoots, engineTime, userName, authParams, privParams
  const engineId = seq.children[0]!
  mapOctetAsHexCategory(buffer, engineId, collector, mapping, intents, packetIndex, 'snmp-engine-id')
  const userName = seq.children[3]!
  // Wire path uses SessionMapping; user-id is TextAliasEngine — length-stable opaque token.
  mapOctetAsText(buffer, userName, collector, mapping, intents, packetIndex, 'opaque-id')
  maskNodeContent(buffer, seq.children[4]!, collector, intents, packetIndex, 'snmp-v3-auth')
  maskNodeContent(buffer, seq.children[5]!, collector, intents, packetIndex, 'snmp-v3-priv')
  void issues
}

function sanitizeScopedOrPdu(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // scopedPDU: contextEngineID, contextName, data
  if (node.tag.constructed && node.children.length >= 3) {
    mapOctetAsHexCategory(buffer, node.children[0]!, collector, mapping, intents, packetIndex, 'snmp-engine-id')
    mapOctetAsText(buffer, node.children[1]!, collector, mapping, intents, packetIndex, 'opaque-id')
    sanitizePdu(buffer, node.children[2]!, collector, mapping, intents, packetIndex, issues)
    return
  }
  sanitizePdu(buffer, node, collector, mapping, intents, packetIndex, issues)
}

function sanitizePdu(
  buffer: Uint8Array,
  pdu: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // PDU: request-id, error-status, error-index, varbind-list  OR trap fields
  const kids = pdu.children
  if (kids.length === 0) return

  // SNMPv1 Trap-PDU has enterprise, agent-addr, …
  // Heuristic: if second child is IpAddress, treat as trap.
  if (kids.length >= 6 && kids[1]!.tag.number === 0 && kids[1]!.tag.tagClass === 'application') {
    // agent-addr
    mapIpAddressNode(buffer, kids[1]!, collector, mapping, intents, packetIndex)
  }

  const varbinds = kids[kids.length - 1]!
  if (!varbinds.tag.constructed) return
  for (const vb of varbinds.children) {
    sanitizeVarbind(buffer, vb, collector, mapping, intents, packetIndex, issues)
  }
}

function sanitizeVarbind(
  buffer: Uint8Array,
  vb: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  if (vb.children.length < 2) return
  const oidNode = vb.children[0]!
  const valNode = vb.children[1]!
  const oid = decodeOid(buffer, oidNode)
  if (!oid) {
    if (valNode.tag.number === ASN1_OCTET_STRING) {
      maskNodeContent(buffer, valNode, collector, intents, packetIndex, 'snmp-unknown-octet')
    }
    return
  }

  if (oid === OID_SYS_NAME) {
    mapOctetAsText(buffer, valNode, collector, mapping, intents, packetIndex, 'hostname')
    return
  }
  if (oid === OID_SYS_CONTACT) {
    mapOctetAsText(buffer, valNode, collector, mapping, intents, packetIndex, 'opaque-id')
    return
  }
  if (oid === OID_SYS_LOCATION || oid === OID_SYS_DESCR) {
    maskNodeContent(buffer, valNode, collector, intents, packetIndex, 'snmp-sys-text')
    return
  }

  // IpAddress value
  if (valNode.tag.tagClass === 'application' && valNode.tag.number === 0) {
    mapIpAddressNode(buffer, valNode, collector, mapping, intents, packetIndex)
    return
  }

  // Counters / gauges / timeticks / integers → preserve
  if (
    valNode.tag.number === ASN1_INTEGER
    || (valNode.tag.tagClass === 'application' && (valNode.tag.number === 1 || valNode.tag.number === 2 || valNode.tag.number === 3))
  ) {
    return
  }

  // Unknown OCTET STRING → mask both levels
  if (valNode.tag.number === ASN1_OCTET_STRING) {
    maskNodeContent(buffer, valNode, collector, intents, packetIndex, 'snmp-unknown-octet')
    issues.push('snmp-unknown-octet-masked')
  }
}

function mapIpAddressNode(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (node.contentLength !== 4) {
    maskNodeContent(buffer, node, collector, intents, packetIndex, 'snmp-ip-bad')
    return
  }
  const b = buffer.subarray(node.contentOffset, node.contentOffset + 4)
  const text = `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
  const canon = canonicalizeIdentity('ipv4', text)
  if (!canon) {
    maskNodeContent(buffer, node, collector, intents, packetIndex, 'snmp-ip-bad')
    return
  }
  const abs = node.contentOffset
  const constraint = { kind: 'ipv4-wire' as const }
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', canon, 4, constraint, text)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const alias = live.map('ipv4', canon)
    const parts = alias.split('.').map((x) => Number(x))
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset: abs, domain: 'snmp-ip-fallback' })
    }
    return new Uint8Array(parts as number[])
  }, deferredBinaryMapMeta('snmp', packetIndex, 'ipv4', text, { canonical: canon }))
  void mapping
}

function mapOctetAsText(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  category: 'hostname' | 'opaque-id',
): void {
  if (node.contentLength <= 0) return
  const abs = node.contentOffset
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + node.contentLength))
  const canon = canonicalizeIdentity(category, raw)
  if (!canon) {
    maskNodeContent(buffer, node, collector, intents, packetIndex, 'snmp-text-opaque')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: raw.length }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, raw.length, constraint, raw)
  collector.addDeferred(abs, raw.length, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, raw.length, live.aliasFor(category, canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: raw.length, packetIndex, offset: abs, domain: 'snmp-text-fallback' })
    }
  }, deferredTextMapMeta('snmp', packetIndex, category, raw, raw.length, { canonical: canon }))
  void mapping
}

function mapOctetAsHexCategory(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  category: 'snmp-engine-id',
): void {
  if (node.contentLength < 5 || node.contentLength > 32) {
    maskNodeContent(buffer, node, collector, intents, packetIndex, 'snmp-engine-id-bad')
    return
  }
  const abs = node.contentOffset
  const bytes = buffer.subarray(abs, abs + node.contentLength)
  let hex = ''
  for (let i = 0; i < bytes.length; i++) hex += bytes[i]!.toString(16).padStart(2, '0')
  const canon = canonicalizeIdentity(category, hex)
  if (!canon) {
    maskNodeContent(buffer, node, collector, intents, packetIndex, 'snmp-engine-id-bad')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: hex.length }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, bytes.length, constraint, hex)
  collector.addDeferred(abs, bytes.length, ({ mapping: live }) => {
    const aliasHex = live.map(category, canon)
    if (aliasHex.length !== hex.length || !/^[0-9a-f]+$/.test(aliasHex)) {
      return createProtocolNeutralMaskFill({ length: bytes.length, packetIndex, offset: abs, domain: 'snmp-engine-fallback' })
    }
    const out = new Uint8Array(bytes.length)
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(aliasHex.slice(i * 2, i * 2 + 2), 16)
    }
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'snmp', category, packetIndex })
  void mapping
}

function maskNodeContent(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  if (node.contentLength <= 0) return
  mask(collector, intents, packetIndex, node.contentOffset, node.contentLength, domain)
  void buffer
}

function mask(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  domain: string,
): void {
  const fill = createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
  collector.maskRange(abs, fill)
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'snmp')
}

function readInteger(buffer: Uint8Array, node: BerNode): number | null {
  if (node.tag.number !== ASN1_INTEGER || node.contentLength === 0 || node.contentLength > 4) return null
  let v = 0
  for (let i = 0; i < node.contentLength; i++) {
    v = (v << 8) | buffer[node.contentOffset + i]!
  }
  // signed
  const bits = node.contentLength * 8
  if (node.contentLength > 0 && (buffer[node.contentOffset]! & 0x80) !== 0) {
    v -= 1 << bits
  }
  return v
}

function decodeOid(buffer: Uint8Array, node: BerNode): string | null {
  const tag = readBerTag(buffer, node.tag.headerOffset, node.contentOffset + node.contentLength)
  if (!tag || tag.number !== 6) return null // OBJECT IDENTIFIER
  const bytes = buffer.subarray(node.contentOffset, node.contentOffset + node.contentLength)
  if (bytes.length === 0) return null
  const first = bytes[0]!
  const out: number[] = [Math.floor(first / 40), first % 40]
  let i = 1
  while (i < bytes.length) {
    let v = 0
    for (;;) {
      if (i >= bytes.length) return null
      const b = bytes[i++]!
      v = (v << 7) | (b & 0x7f)
      if ((b & 0x80) === 0) break
    }
    out.push(v)
  }
  return out.join('.')
}
