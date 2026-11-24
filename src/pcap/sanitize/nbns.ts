/**
 * T18 — NBNS (UDP 137) + NetBIOS datagram (UDP 138) sanitizer.
 * First-level A–P names → hostname map; NB address / unit ID → IP/MAC.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import {
  decodeNetbiosFirstLevel,
  encodeNetbiosFirstLevel,
  joinNetbiosName,
  splitNetbiosName,
} from './netbiosNameCodec'

const NBNS_PORT = 137
const NBDG_PORT = 138
const TYPE_NB = 0x20
const TYPE_NBSTAT = 0x21

export function isNbnsPortHint(src: number, dst: number): boolean {
  return src === NBNS_PORT || dst === NBNS_PORT || src === NBDG_PORT || dst === NBDG_PORT
}

export function looksLikeNbns(_data: Uint8Array, _offset: number, length: number): boolean {
  return length >= 12
}

export function sanitizeNbns(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  srcPort: number,
  dstPort: number,
): AppLayerResult | null {
  if (!looksLikeNbns(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (srcPort === NBDG_PORT || dstPort === NBDG_PORT) {
    sanitizeDatagram(buffer, offset, length, collector, mapping, intents, packetIndex, issues)
    coverage.push({ protocol: 'netbios-datagram', offset, length, status: 'redacted' })
    return { coverage, issues }
  }

  const ok = sanitizeNbnsMessage(buffer, offset, length, collector, mapping, intents, packetIndex, issues)
  coverage.push({
    protocol: 'nbns',
    offset,
    length,
    status: ok ? 'covered' : 'malformed',
  })
  return { coverage, issues }
}

function sanitizeNbnsMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): boolean {
  if (length < 12) return false
  const view = new DataView(buffer.buffer, buffer.byteOffset + offset, length)
  const qd = view.getUint16(4)
  const an = view.getUint16(6)
  const ns = view.getUint16(8)
  const ar = view.getUint16(10)
  let pos = 12

  for (let i = 0; i < qd && pos < length; i++) {
    const next = sanitizeNbName(buffer, offset, pos, length, collector, mapping, intents, packetIndex)
    if (next < 0) return false
    pos = next + 4 // type + class
  }

  const rrCount = an + ns + ar
  for (let i = 0; i < rrCount && pos < length; i++) {
    const nameEnd = sanitizeNbName(buffer, offset, pos, length, collector, mapping, intents, packetIndex)
    if (nameEnd < 0) return false
    pos = nameEnd
    if (pos + 10 > length) return false
    const rrType = (buffer[offset + pos]! << 8) | buffer[offset + pos + 1]!
    const rdlen = (buffer[offset + pos + 8]! << 8) | buffer[offset + pos + 9]!
    pos += 10
    if (pos + rdlen > length) return false
    sanitizeNbRdata(
      buffer,
      offset + pos,
      rdlen,
      rrType,
      collector,
      mapping,
      intents,
      packetIndex,
      issues,
    )
    pos += rdlen
  }
  return true
}

function sanitizeNbName(
  buffer: Uint8Array,
  base: number,
  pos: number,
  maxLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): number {
  if (pos >= maxLen) return -1
  const labelLen = buffer[base + pos]!
  // Pointer
  if ((labelLen & 0xc0) === 0xc0) {
    if (pos + 1 >= maxLen) return -1
    return pos + 2
  }
  if (labelLen === 0) return pos + 1
  if (labelLen === 32 && pos + 1 + 32 <= maxLen) {
    const encAbs = base + pos + 1
    const enc = buffer.subarray(encAbs, encAbs + 32)
    const raw = decodeNetbiosFirstLevel(enc)
    if (raw) {
      const split = splitNetbiosName(raw)
      if (split) {
        const canon = canonicalizeIdentity('hostname', split.host)
        if (canon) {
          const constraint = { kind: 'text-ascii' as const, byteLength: Math.min(15, split.host.length) }
          intents?.recordEntityReplacement(
            packetIndex,
            encAbs,
            'hostname',
            canon,
            32,
            { kind: 'text-ascii', byteLength: 32 },
            split.host,
          )
          collector.addDeferred(encAbs, 32, ({ mapping: live }) => {
            try {
              const alias = live.aliasFor('hostname', canon, constraint, split.host)
              const host15 = alias.length <= 15 ? alias : alias.slice(0, 15)
              const joined = joinNetbiosName(host15.toUpperCase(), split.suffix)
                ?? joinNetbiosName(host15, split.suffix)
              if (!joined) {
                return createProtocolNeutralMaskFill({
                  length: 32,
                  packetIndex,
                  offset: encAbs,
                  domain: 'nbns-name-fallback',
                })
              }
              return encodeNetbiosFirstLevel(joined)
                ?? createProtocolNeutralMaskFill({
                  length: 32,
                  packetIndex,
                  offset: encAbs,
                  domain: 'nbns-encode-fallback',
                })
            } catch {
              return createProtocolNeutralMaskFill({
                length: 32,
                packetIndex,
                offset: encAbs,
                domain: 'nbns-name-fallback',
              })
            }
          }, { fallbackKind: 'text-x', protocol: 'nbns', category: 'hostname', packetIndex })
          void mapping
        }
      }
    }
    // skip label + root null
    let next = pos + 1 + labelLen
    if (next < maxLen && buffer[base + next] === 0) next++
    return next
  }
  // Generic DNS-style name — mask labels (scope)
  let cur = pos
  while (cur < maxLen) {
    const len = buffer[base + cur]!
    if (len === 0) return cur + 1
    if ((len & 0xc0) === 0xc0) return cur + 2
    if (cur + 1 + len > maxLen) return -1
    mask(collector, intents, packetIndex, base + cur + 1, len, 'nbns-scope')
    cur += 1 + len
  }
  return -1
}

function sanitizeNbRdata(
  buffer: Uint8Array,
  abs: number,
  rdlen: number,
  rrType: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  if (rrType === TYPE_NB && rdlen >= 6) {
    // flags(2) + IPv4(4)
    mapIpv4(buffer, abs + 2, collector, mapping, intents, packetIndex)
    return
  }
  if (rrType === TYPE_NBSTAT && rdlen >= 1) {
    const nameCount = buffer[abs]!
    let off = abs + 1
    for (let i = 0; i < nameCount && off + 18 <= abs + rdlen; i++) {
      // 15 name + 1 type + 2 flags
      const nameBytes = buffer.subarray(off, off + 16)
      const split = splitNetbiosName(nameBytes)
      if (split) {
        const canon = canonicalizeIdentity('hostname', split.host)
        if (canon) {
          const constraint = { kind: 'text-ascii' as const, byteLength: 15 }
          intents?.recordEntityReplacement(packetIndex, off, 'hostname', canon, 15, constraint, split.host)
          collector.addDeferred(off, 15, ({ mapping: live }) => {
            try {
              const alias = live.aliasFor('hostname', canon, constraint, split.host)
              const host15 = (alias.length <= 15 ? alias : alias.slice(0, 15)).toUpperCase()
              return computeFixedLengthAsciiBytes(off, 15, host15.padEnd(15, ' '))
            } catch {
              return createProtocolNeutralMaskFill({
                length: 15,
                packetIndex,
                offset: off,
                domain: 'nbstat-name',
              })
            }
          }, { fallbackKind: 'text-x', protocol: 'nbns', category: 'hostname', packetIndex })
        }
      }
      off += 18
    }
    // Unit ID = MAC (6 bytes) after names; remainder stats preserved when present
    if (off + 6 <= abs + rdlen) {
      mapMac(buffer, off, collector, mapping, intents, packetIndex)
    } else if (rdlen > 0) {
      issues.push('nbstat-truncated')
    }
    return
  }
  if (rdlen > 0) {
    mask(collector, intents, packetIndex, abs, rdlen, 'nbns-rdata-unknown')
  }
}

function sanitizeDatagram(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // RFC 1002 datagram: header + source/dest names (first-level) + source IP
  if (length < 14) {
    mask(collector, intents, packetIndex, offset, length, 'nbdg-trunc')
    return
  }
  // Source IP at offset 8 (4 bytes) in common datagram header layout
  mapIpv4(buffer, offset + 8, collector, mapping, intents, packetIndex)
  // Remainder after header often carries browser/SMB — mask fail-closed
  if (length > 14) {
    mask(collector, intents, packetIndex, offset + 14, length - 14, 'nbdg-payload')
    issues.push('nbdg-payload-masked')
  }
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
  const text = `${buffer[abs]}.${buffer[abs + 1]}.${buffer[abs + 2]}.${buffer[abs + 3]}`
  const canon = canonicalizeIdentity('ipv4', text)
  if (!canon) {
    mask(collector, intents, packetIndex, abs, 4, 'nbns-ip-bad')
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', canon, 4, { kind: 'ipv4-wire' }, text)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const alias = live.map('ipv4', canon)
    const parts = alias.split('.').map((x) => Number(x))
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset: abs, domain: 'nbns-ip' })
    }
    return new Uint8Array(parts as number[])
  }, { fallbackKind: 'binary-mask', protocol: 'nbns', category: 'ipv4', packetIndex })
  void mapping
}

function mapMac(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 6; i++) parts.push(buffer[abs + i]!.toString(16).padStart(2, '0'))
  const text = parts.join(':')
  const canon = canonicalizeIdentity('mac', text)
  if (!canon) {
    mask(collector, intents, packetIndex, abs, 6, 'nbstat-mac')
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, 'mac', canon, 6, { kind: 'mac-wire' }, text)
  collector.addDeferred(abs, 6, ({ mapping: live }) => {
    const alias = live.map('mac', canon)
    const hex = alias.replace(/[^0-9a-f]/gi, '')
    if (hex.length < 12) {
      return createProtocolNeutralMaskFill({ length: 6, packetIndex, offset: abs, domain: 'nbstat-mac' })
    }
    const out = new Uint8Array(6)
    for (let i = 0; i < 6; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'nbns', category: 'mac', packetIndex })
  void mapping
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
  if (len <= 0) return
  collector.maskRange(
    abs,
    createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }),
  )
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'nbns')
}
