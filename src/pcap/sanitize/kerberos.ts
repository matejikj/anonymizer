/**
 * T23 — Kerberos (RFC 4120) sanitizer: map principals/realms, mask EncryptedData cipher.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec'
import { walkBer, type BerNode } from '../protocols/application/binproto'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'

const KERBEROS_PORTS = new Set([88, 464])
const ASN1_INTEGER = 0x02
const ASN1_OCTET_STRING = 0x04
const ASN1_GENERAL_STRING = 0x1b
const ASN1_GENERALIZED_TIME = 0x18
const ASN1_SEQUENCE = 0x10

export function isKerberosPortHint(src: number, dst: number): boolean {
  return KERBEROS_PORTS.has(src) || KERBEROS_PORTS.has(dst)
}

export function looksLikeKerberos(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  // TCP record mark: 4-byte length prefix then APPLICATION tag
  let off = offset
  let len = length
  if (len >= 5 && data[off]! === 0x00) {
    const marked =
      ((data[off]! << 24) | (data[off + 1]! << 16) | (data[off + 2]! << 8) | data[off + 3]!) >>> 0
    if (marked > 0 && marked + 4 <= len && (data[off + 4]! & 0xe0) === 0x60) {
      return true
    }
  }
  // UDP / bare: APPLICATION tag 0x6a–0x6f (AS/TGS/AP) or 0x7e (ERROR).
  // Exclude 5GMM NAS EPD 0x7E (TS 24.501) — claimed by T59 looksLikeNas.
  const tag = data[off]!
  if (tag === 0x7e && length >= 3) {
    const sec = data[off + 1]! & 0x0f
    // 5GMM plain/protected uses low-nibble security header; KRB-ERROR is constructed ASN.1
    if (sec <= 4 && length >= 3) return false
  }
  return (tag & 0xe0) === 0x60
}

export function sanitizeKerberos(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
): AppLayerResult | null {
  if (!looksLikeKerberos(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  let bodyOff = offset
  let bodyLen = length
  // TCP length prefix
  if (
    length >= 5
    && buffer[offset]! === 0x00
    && (buffer[offset + 4]! & 0xe0) === 0x60
  ) {
    const marked =
      ((buffer[offset]! << 24)
        | (buffer[offset + 1]! << 16)
        | (buffer[offset + 2]! << 8)
        | buffer[offset + 3]!) >>> 0
    if (marked + 4 <= length) {
      bodyOff = offset + 4
      bodyLen = marked
      coverage.push({ protocol: 'kerberos-tcp', offset, length: 4, status: 'covered' })
    }
  }

  const { roots, issues: berIssues } = walkBer(buffer, bodyOff, bodyLen, {
    maxDepth: 28,
    maxNodes: 2048,
  })
  for (const i of berIssues) issues.push(`kerberos-${i.code}`)

  if (roots.length === 0) {
    mask(collector, intents, packetIndex, bodyOff, bodyLen, 'kerberos-malformed')
    coverage.push({ protocol: 'kerberos', offset: bodyOff, length: bodyLen, status: 'malformed' })
    return { coverage, issues }
  }

  for (const root of roots) {
    visit(buffer, root, collector, mapping, intents, packetIndex, payloadTime, issues, null)
  }
  coverage.push({ protocol: 'kerberos', offset: bodyOff, length: bodyLen, status: 'covered' })
  return { coverage, issues }
}

function visit(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
  parentHint: string | null,
): void {
  // EncryptedData ::= SEQUENCE { etype[0] Int32, kvno[1] UInt32 OPTIONAL, cipher[2] OCTET STRING }
  if (node.tag.constructed && looksLikeEncryptedData(node)) {
    sanitizeEncryptedData(buffer, node, collector, intents, packetIndex, issues)
    return
  }

  if (!node.tag.constructed) {
    if (node.tag.number === ASN1_GENERAL_STRING || node.tag.number === ASN1_OCTET_STRING) {
      const text = latin1(buffer, node.contentOffset, node.contentLength)
      if (node.contentLength === 0) return
      // Realm / principal component heuristics
      if (parentHint === 'realm' || looksLikeRealm(text)) {
        mapString(buffer, node, 'hostname', collector, mapping, intents, packetIndex)
        return
      }
      if (parentHint === 'cname' || parentHint === 'sname') {
        // service/host form HTTP/host → map host part only when slash present
        if (text.includes('/')) {
          mapServicePrincipal(buffer, node, collector, mapping, intents, packetIndex)
        } else {
          mapString(buffer, node, 'user-id', collector, mapping, intents, packetIndex)
        }
        return
      }
      // PA-ENC-TIMESTAMP and unknown octet blobs that aren't short principals → mask if long
      if (node.tag.number === ASN1_OCTET_STRING && node.contentLength >= 16) {
        maskContent(buffer, node, collector, intents, packetIndex, 'kerberos-octet')
        return
      }
    }
    if (node.tag.number === ASN1_GENERALIZED_TIME && node.contentLength >= 15) {
      shiftGeneralizedTime(buffer, node, collector, intents, packetIndex, payloadTime, issues)
      return
    }
    // INTEGER preserve (pvno, msg-type, error-code, etype, nonce, flags)
    return
  }

  // Context tags hint PrincipalName / Realm
  let hint = parentHint
  if (node.tag.tagClass === 'context') {
    if (node.tag.number === 1 || node.tag.number === 2) hint = 'cname' // crealm/cname vary by msg
    if (node.tag.number === 3) hint = 'sname'
    // Many messages: [1] pvno [2] msg-type [3] padata [4] req-body
    // Inside req-body: [1] kdc-options [2] cname [3] realm [4] sname ...
    if (parentHint === 'req-body' && node.tag.number === 2) hint = 'cname'
    if (parentHint === 'req-body' && node.tag.number === 3) hint = 'realm'
    if (parentHint === 'req-body' && node.tag.number === 4) hint = 'sname'
    if (node.tag.number === 4 && node.children.some((c) => c.tag.constructed)) hint = hint ?? 'req-body'
  }

  for (const c of node.children) {
    visit(buffer, c, collector, mapping, intents, packetIndex, payloadTime, issues, hint)
  }
}

function looksLikeEncryptedData(node: BerNode): boolean {
  if (node.children.length < 2) return false
  // Look for OCTET STRING cipher among children (possibly context-wrapped)
  let hasEtype = false
  let hasCipher = false
  for (const c of node.children) {
    const leaf = unwrapContext(c)
    if (leaf.tag.number === ASN1_INTEGER) hasEtype = true
    if (leaf.tag.number === ASN1_OCTET_STRING && leaf.contentLength >= 8) hasCipher = true
  }
  return hasEtype && hasCipher
}

function sanitizeEncryptedData(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  for (const c of node.children) {
    const leaf = unwrapContext(c)
    if (leaf.tag.number === ASN1_OCTET_STRING && leaf.contentLength > 0) {
      maskContent(buffer, leaf, collector, intents, packetIndex, 'kerberos-enc-part')
      issues.push('kerberos-enc-masked')
    }
    // etype / kvno INTEGER preserved
  }
}

function unwrapContext(node: BerNode): BerNode {
  if (node.tag.tagClass === 'context' && node.tag.constructed && node.children.length === 1) {
    return node.children[0]!
  }
  if (node.tag.tagClass === 'context' && !node.tag.constructed) return node
  return node
}

function mapServicePrincipal(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const abs = node.contentOffset
  const len = node.contentLength
  const text = latin1(buffer, abs, len)
  const slash = text.indexOf('/')
  if (slash <= 0 || slash >= text.length - 1) {
    mapString(buffer, node, 'user-id', collector, mapping, intents, packetIndex)
    return
  }
  // Preserve service class; map host
  const hostAbs = abs + slash + 1
  const hostLen = len - slash - 1
  const host = text.slice(slash + 1)
  const canon = canonicalizeIdentity('hostname', host)
  if (!canon) {
    mask(collector, intents, packetIndex, hostAbs, hostLen, 'kerberos-spn-host')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: hostLen }
  intents?.recordEntityReplacement(packetIndex, hostAbs, 'hostname', canon, hostLen, constraint, host)
  collector.addDeferred(hostAbs, hostLen, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor('hostname', canon, constraint, host)
      return computeFixedLengthAsciiBytes(hostAbs, hostLen, alias)
    } catch {
      return createProtocolNeutralMaskFill({ length: hostLen, packetIndex, offset: hostAbs, domain: 'kerberos-spn' })
    }
  }, { fallbackKind: 'text-x', protocol: 'kerberos', category: 'hostname', packetIndex })
  void mapping
}

function mapString(
  buffer: Uint8Array,
  node: BerNode,
  category: 'hostname' | 'user-id',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const abs = node.contentOffset
  const len = node.contentLength
  if (len <= 0) return
  const text = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity(category, text)
  if (!canon) {
    mask(collector, intents, packetIndex, abs, len, `kerberos-${category}-bad`)
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, text)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      let alias = live.aliasFor(category, canon, constraint, text)
      // Realms conventionally uppercase
      if (category === 'hostname' && text === text.toUpperCase()) alias = alias.toUpperCase()
      return computeFixedLengthAsciiBytes(abs, len, alias)
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `kerberos-${category}` })
    }
  }, { fallbackKind: 'text-x', protocol: 'kerberos', category, packetIndex })
  void mapping
  void buffer
}

function shiftGeneralizedTime(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): void {
  // YYYYMMDDHHmmssZ
  const abs = node.contentOffset
  const len = node.contentLength
  const text = latin1(buffer, abs, len)
  if (!payloadTime?.isBound || !/^\d{14}Z$/.test(text)) {
    // leave relative/ambiguous clocks; do not leak by failing open on unknown format
    if (!/^\d{14}Z$/.test(text)) {
      mask(collector, intents, packetIndex, abs, len, 'kerberos-time-opaque')
    }
    return
  }
  const y = Number(text.slice(0, 4))
  const mo = Number(text.slice(4, 6))
  const d = Number(text.slice(6, 8))
  const h = Number(text.slice(8, 10))
  const mi = Number(text.slice(10, 12))
  const s = Number(text.slice(12, 14))
  const epochMs = Date.UTC(y, mo - 1, d, h, mi, s)
  const shifted = payloadTime.shiftAbsoluteEpochMs(epochMs)
  if (shifted === null) {
    issues.push('kerberos-time-unbound')
    return
  }
  const dt = new Date(shifted)
  const out =
    dt.getUTCFullYear().toString().padStart(4, '0')
    + (dt.getUTCMonth() + 1).toString().padStart(2, '0')
    + dt.getUTCDate().toString().padStart(2, '0')
    + dt.getUTCHours().toString().padStart(2, '0')
    + dt.getUTCMinutes().toString().padStart(2, '0')
    + dt.getUTCSeconds().toString().padStart(2, '0')
    + 'Z'
  intents?.recordMaskRange(packetIndex, abs, len, 'kerberos-time', 'timestamp')
  collector.addDeferred(abs, len, () => computeFixedLengthAsciiBytes(abs, len, out), {
    fallbackKind: 'text-x',
    protocol: 'kerberos',
    category: 'timestamp',
    packetIndex,
  })
  void buffer
}

function looksLikeRealm(text: string): boolean {
  return text.length >= 2 && text === text.toUpperCase() && /[A-Z]/.test(text) && !text.includes(' ')
}

function maskContent(
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
  collector.maskRange(abs, createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }))
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'kerberos')
}

function latin1(buffer: Uint8Array, abs: number, len: number): string {
  return new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
}

void ASN1_SEQUENCE
