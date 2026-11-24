/**
 * T40 — shared helpers for wireless link / GSMTAP sanitizers.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'

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

export function mapMacAt(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  if (offset + 6 > buffer.length) return
  const mac = Array.from(buffer.subarray(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
  // Broadcast / multicast: still map via SessionMapping (preserves group bit policy inside map).
  intents?.recordEntityReplacement(packetIndex, offset, 'mac', mac, 6)
  collector.addDeferred(
    offset,
    6,
    ({ mapping: live }) => {
      const mapped = live.map('mac', mac)
      return new Uint8Array(mapped.split(':').map((s) => Number.parseInt(s, 16)))
    },
    { fallbackKind: 'binary-mask', protocol, category: 'mac', packetIndex },
  )
  void mapping
}

/** Canonical identity for raw SSID octets (`ssid/<lowercase-hex>`). */
export function ssidCanonicalFromBytes(buffer: Uint8Array, offset: number, length: number): string {
  let hex = ''
  for (let i = 0; i < length; i++) hex += buffer[offset + i]!.toString(16).padStart(2, '0')
  return `ssid/${hex}`
}

/** Derive length-preserving binary alias bytes from a mapped SSID alias string. */
export function ssidWireBytesFromAlias(alias: string, length: number): Uint8Array {
  const out = new Uint8Array(length)
  let h = 2166136261
  for (let i = 0; i < alias.length; i++) {
    h ^= alias.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  for (let i = 0; i < length; i++) {
    h ^= i + 1
    h = Math.imul(h, 16777619)
    out[i] = (h >>> 0) & 0xff
  }
  if (out.every((b) => b === 0)) out[0] = 0x61
  return out
}

/**
 * Binary-safe SSID via `ssid` category (`ssid/<hex>` canonical); length-preserving wire bytes.
 */
export function mapSsidBytes(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
): void {
  if (length <= 0) return // hidden SSID sentinel — preserve empty
  if (length > 32) {
    maskBytes(collector, intents, packetIndex, offset, length, 'ssid-overlong', protocol)
    return
  }
  const canon = ssidCanonicalFromBytes(buffer, offset, length)
  intents?.recordEntityReplacement(packetIndex, offset, 'ssid', canon, length)
  collector.addDeferred(
    offset,
    length,
    ({ mapping: live }) => {
      const alias = live.map('ssid', canon)
      return ssidWireBytesFromAlias(alias, length)
    },
    { fallbackKind: 'binary-mask', protocol, category: 'ssid', packetIndex },
  )
  void mapping
}

export function readU16le(buf: Uint8Array, o: number): number {
  return (buf[o]! | (buf[o + 1]! << 8)) >>> 0
}

export function readU32le(buf: Uint8Array, o: number): number {
  return (
    (buf[o]! | (buf[o + 1]! << 8) | (buf[o + 2]! << 16) | (buf[o + 3]! << 24)) >>> 0
  )
}
