/**
 * T38 — shared helpers for routing / first-hop sanitizers.
 *
 * Router-ID is a protocol 32-bit identifier (opaque-id `rid/<scope>/<u32>`), not
 * automatically the same alias as a routable IPv4. Prefixes: map the network address
 * via `ipv4` (topology-preserving session already correlates hosts in the same /16
 * target space); prefix length bytes are preserved. ASN: opaque-id `asn/<n>` (same as T21).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'

export function readU16(buf: Uint8Array, o: number): number {
  return ((buf[o]! << 8) | buf[o + 1]!) >>> 0
}

export function readU32(buf: Uint8Array, o: number): number {
  return (
    ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!) >>> 0
  )
}

export function writeU32(n: number): Uint8Array {
  const v = n >>> 0
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff])
}

export function writeU16(n: number): Uint8Array {
  const v = n & 0xffff
  return new Uint8Array([(v >>> 8) & 0xff, v & 0xff])
}

export function ipv4Text(buf: Uint8Array, o: number): string {
  return `${buf[o]!}.${buf[o + 1]!}.${buf[o + 2]!}.${buf[o + 3]!}`
}

export function maskBytes(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
  protocol: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, protocol)
}

/** Map 32-bit router-id / LSR-id style identifiers (not a routable IPv4 claim). */
export function mapRouterId(
  buf: Uint8Array,
  offset: number,
  scope: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  const value = readU32(buf, offset)
  if (value === 0) return
  const canon = `rid/${scope}/${value}`
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 4)
  collector.addDeferred(
    offset,
    4,
    ({ mapping: live }) => {
      const alias = live.map('opaque-id', canon)
      // Stable 32-bit from alias bytes (length-preserving opaque-id is ASCII; hash to u32).
      let h = 2166136261
      for (let i = 0; i < alias.length; i++) {
        h ^= alias.charCodeAt(i)
        h = Math.imul(h, 16777619)
      }
      const out = (h >>> 0) || 1
      return writeU32(out)
    },
    { fallbackKind: 'binary-mask', protocol, category: 'opaque-id', packetIndex },
  )
  void mapping
}

export function mapIpv4At(
  buf: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  const text = ipv4Text(buf, offset)
  if (text === '0.0.0.0' || text === '255.255.255.255') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', text, 4)
  collector.addDeferred(
    offset,
    4,
    ({ mapping: live }) => {
      const mapped = live.map('ipv4', text)
      return new Uint8Array(mapped.split('.').map(Number))
    },
    { fallbackKind: 'binary-mask', protocol, category: 'ipv4', packetIndex },
  )
  void mapping
}

/**
 * Map an IPv4 prefix network address; `prefixLen` (0–32) selects host bits to zero
 * before mapping so topology-preserving ipv4 aliases stay coherent with hosts.
 */
export function mapIpv4Prefix(
  buf: Uint8Array,
  offset: number,
  prefixLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  const plen = Math.max(0, Math.min(32, prefixLen))
  const raw = readU32(buf, offset)
  const mask = plen === 0 ? 0 : (~0 << (32 - plen)) >>> 0
  const network = raw & mask
  const text = `${(network >>> 24) & 0xff}.${(network >>> 16) & 0xff}.${(network >>> 8) & 0xff}.${network & 0xff}`
  if (text === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', text, 4)
  collector.addDeferred(
    offset,
    4,
    ({ mapping: live }) => {
      const mapped = live.map('ipv4', text)
      const parts = mapped.split('.').map(Number)
      const mappedU =
        (((parts[0]! & 0xff) << 24)
          | ((parts[1]! & 0xff) << 16)
          | ((parts[2]! & 0xff) << 8)
          | (parts[3]! & 0xff))
        >>> 0
      return writeU32(mappedU & mask)
    },
    { fallbackKind: 'binary-mask', protocol, category: 'ipv4', packetIndex },
  )
  void mapping
}

export function mapAsnAt(
  buf: Uint8Array,
  offset: number,
  wireLen: 2 | 4,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  const value = wireLen === 4 ? readU32(buf, offset) : readU16(buf, offset)
  if (value === 0) return
  const canon = `asn/${value}`
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, wireLen)
  collector.addDeferred(
    offset,
    wireLen,
    ({ mapping: live }) => {
      const alias = live.map('opaque-id', canon)
      let h = 2166136261
      for (let i = 0; i < alias.length; i++) {
        h ^= alias.charCodeAt(i)
        h = Math.imul(h, 16777619)
      }
      const out = (h >>> 0) || 1
      return wireLen === 4 ? writeU32(out) : writeU16(out & 0xffff)
    },
    { fallbackKind: 'binary-mask', protocol, category: 'opaque-id', packetIndex },
  )
  void mapping
}
