/**
 * T22 — TACACS+ (TCP 49): preserve header; obfuscated body always mask (MD5 pad ≠ ciphertext).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { maskPayloadSpan } from '../protocols/application/textproto'
import { deferredTextMapMeta } from './deferredMapMeta.ts'

const TACACS_PORTS = new Set([49])
const FLAG_UNENCRYPTED = 0x01

export function isTacacsPortHint(src: number, dst: number): boolean {
  return TACACS_PORTS.has(src) || TACACS_PORTS.has(dst)
}

export function looksLikeTacacs(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 12) return false
  const major = (data[offset]! >> 4) & 0x0f
  const type = data[offset + 1]!
  const bodyLen =
    (data[offset + 8]! << 24)
    | (data[offset + 9]! << 16)
    | (data[offset + 10]! << 8)
    | data[offset + 11]!
  return major === 0xc && type >= 1 && type <= 3 && bodyLen === length - 12 && bodyLen >= 0 && bodyLen < 0x10000
}

export function sanitizeTacacs(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeTacacs(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const flags = buffer[offset + 3]!
  const sessionIdOff = offset + 4
  // version, type, seq, flags preserved
  coverage.push({ protocol: 'tacacs', offset, length: 4, status: 'covered' })

  // session_id → opaque-id (4 bytes binary)
  const sidHex = Array.from(buffer.subarray(sessionIdOff, sessionIdOff + 4))
    .map((b) => b.toString(16).padStart(2, '0')).join('')
  const sidCanon = canonicalizeIdentity('opaque-id', sidHex) ?? sidHex
  intents?.recordEntityReplacement(packetIndex, sessionIdOff, 'opaque-id', sidCanon, 4)
  collector.addDeferred(sessionIdOff, 4, ({ mapping: live }) => {
    const alias = live.map('opaque-id', sidCanon)
    return createProtocolNeutralMaskFill({
      length: 4,
      packetIndex,
      offset: sessionIdOff,
      domain: `tacacs-sid:${alias.slice(0, 12)}`,
    })
  }, { fallbackKind: 'binary-mask', protocol: 'tacacs', category: 'opaque-id', packetIndex })
  coverage.push({ protocol: 'tacacs', offset: sessionIdOff, length: 4, status: 'covered' })
  coverage.push({ protocol: 'tacacs', offset: offset + 8, length: 4, status: 'covered' }) // length field

  const bodyOff = offset + 12
  const bodyLen = length - 12
  if (bodyLen <= 0) return { coverage, issues }

  if ((flags & FLAG_UNENCRYPTED) === 0) {
    // Obfuscated with shared secret — not safe ciphertext
    maskPayloadSpan(collector, bodyOff, bodyLen, intents, packetIndex, 'tacacs-obfuscated')
    coverage.push({
      protocol: 'tacacs',
      offset: bodyOff,
      length: bodyLen,
      status: 'redacted',
    })
    issues.push('tacacs-obfuscated-redacted')
    return { coverage, issues }
  }

  // Cleartext authen start: priv_lvl(1) authen_type(1) service(1) user_len(1) port_len(1) rem_len(1) data_len(1) + fields
  if (bodyLen < 8) {
    maskPayloadSpan(collector, bodyOff, bodyLen, intents, packetIndex, 'tacacs-body-short')
    coverage.push({ protocol: 'tacacs', offset: bodyOff, length: bodyLen, status: 'malformed' })
    return { coverage, issues }
  }
  const userLen = buffer[bodyOff + 3]!
  const portLen = buffer[bodyOff + 4]!
  const remLen = buffer[bodyOff + 5]!
  const dataLen = buffer[bodyOff + 6]!
  // byte 7 often unused/flags in some layouts — treat as reserved
  let pos = bodyOff + 8
  const end = bodyOff + bodyLen
  coverage.push({ protocol: 'tacacs', offset: bodyOff, length: 8, status: 'covered' })

  if (pos + userLen + portLen + remLen + dataLen > end) {
    maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'tacacs-fields-trunc')
    coverage.push({ protocol: 'tacacs', offset: pos, length: end - pos, status: 'malformed' })
    issues.push('tacacs-length-mismatch')
    return { coverage, issues }
  }

  if (userLen > 0) {
    mapUser(buffer, pos, userLen, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'tacacs', offset: pos, length: userLen, status: 'covered' })
    pos += userLen
  }
  if (portLen > 0) {
    // port string — not auto-public
    maskPayloadSpan(collector, pos, portLen, intents, packetIndex, 'tacacs-port-str')
    coverage.push({ protocol: 'tacacs', offset: pos, length: portLen, status: 'redacted' })
    pos += portLen
  }
  if (remLen > 0) {
    mapRemAddr(buffer, pos, remLen, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'tacacs', offset: pos, length: remLen, status: 'covered' })
    pos += remLen
  }
  if (dataLen > 0) {
    // password / authen data
    maskPayloadSpan(collector, pos, dataLen, intents, packetIndex, 'tacacs-authen-data')
    coverage.push({ protocol: 'tacacs', offset: pos, length: dataLen, status: 'redacted' })
    pos += dataLen
  }
  if (pos < end) {
    maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'tacacs-trailer')
    coverage.push({ protocol: 'tacacs', offset: pos, length: end - pos, status: 'redacted' })
  }
  return { coverage, issues }
}

function mapUser(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
  const canon = canonicalizeIdentity('sip-user', raw.trim().toLowerCase())
  if (!canon) {
    maskPayloadSpan(collector, abs, len, intents, packetIndex, 'tacacs-user')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'sip-user', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('sip-user', canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'tacacs-user' })
    }
  }, deferredTextMapMeta('tacacs', packetIndex, 'sip-user', raw, len, { canonical: canon }))
  void mapping
}

function mapRemAddr(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len)).trim()
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) {
    // ASCII IPv4 — map via hostname-style text alias of ipv4 is awkward; use opaque hostname path
    const canon = canonicalizeIdentity('hostname', raw)
    if (canon) {
      const constraint = { kind: 'text-ascii' as const, byteLength: len }
      intents?.recordEntityReplacement(packetIndex, abs, 'hostname', canon, len, constraint, raw)
      collector.addDeferred(abs, len, ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('hostname', canon, constraint, raw))
        } catch {
          return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'tacacs-rem' })
        }
      }, deferredTextMapMeta('tacacs', packetIndex, 'hostname', raw, len, { canonical: canon }))
      void mapping
      return
    }
  }
  const hCanon = canonicalizeIdentity('hostname', raw.toLowerCase())
  if (hCanon) {
    const constraint = { kind: 'text-ascii' as const, byteLength: len }
    intents?.recordEntityReplacement(packetIndex, abs, 'hostname', hCanon, len, constraint, raw)
    collector.addDeferred(abs, len, ({ mapping: live }) => {
      try {
        return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('hostname', hCanon, constraint, raw))
      } catch {
        return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'tacacs-rem' })
      }
    }, deferredTextMapMeta('tacacs', packetIndex, 'hostname', raw, len, { canonical: hCanon }))
    void mapping
    return
  }
  maskPayloadSpan(collector, abs, len, intents, packetIndex, 'tacacs-rem')
}
