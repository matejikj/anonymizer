/**
 * T35 — TZSP (TaZmen Sniffer Protocol) UDP encapsulation.
 * Tagged fields then inner link frame (Ethernet / 802.11) via shared Ethernet walker.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { computeFixedLengthAsciiBytes } from './textPatch'
import {
  sanitizeLinkedEthernet,
  type InnerTransportHandler,
  type TunnelIdentityContext,
  MAX_TUNNEL_DEPTH,
} from './tunnel'
import type { AppLayerResult, LayerCoverage } from './types'

const TZSP_PORTS = new Set([37008])

/** TZSP encapsulation types (Wireshark / Aerohive). */
const ENCAP_ETHERNET = 1
const ENCAP_802_11 = 0x12

const TAG_PADDING = 0x00
const TAG_END = 0x01
const TAG_RSSI = 0x0a
const TAG_SNR = 0x0b
const TAG_DATA_RATE = 0x0c
const TAG_TIMESTAMP = 0x0d
const TAG_CONTENTION_FREE = 0x0f
const TAG_DECRYPTED = 0x10
const TAG_FCS_ERROR = 0x11
const TAG_RX_CHANNEL = 0x12
const TAG_PACKET_COUNT = 0x13
const TAG_SENSOR_MAC = 0x1f // common vendor extension length 6

export function isTzspPortHint(src: number, dst: number): boolean {
  return TZSP_PORTS.has(src) || TZSP_PORTS.has(dst)
}

export function looksLikeTzsp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  const ver = data[offset]!
  const typ = data[offset + 1]!
  if (ver !== 1) return false
  // type: 0=RX, 1=TX, 2=reserved, 3=config
  if (typ > 3) return false
  const encap = ((data[offset + 2]! << 8) | data[offset + 3]!) >>> 0
  return encap === ENCAP_ETHERNET || encap === ENCAP_802_11 || encap === 0
}

export function sanitizeTzsp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number = 0,
  onInnerTransport?: InnerTransportHandler,
): AppLayerResult | null {
  if (!looksLikeTzsp(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (depth >= MAX_TUNNEL_DEPTH) {
    coverage.push({ protocol: 'tzsp', offset, length, status: 'unsupported' })
    return { coverage, issues: ['tzsp-depth'] }
  }

  const encap = ((buffer[offset + 2]! << 8) | buffer[offset + 3]!) >>> 0
  coverage.push({ protocol: 'tzsp', offset, length: 4, status: 'covered' })

  let cursor = offset + 4
  const end = offset + length
  let sawEnd = false

  while (cursor < end && !sawEnd) {
    const tag = buffer[cursor]!
    if (tag === TAG_END) {
      coverage.push({ protocol: 'tzsp-tag', offset: cursor, length: 1, status: 'covered' })
      cursor += 1
      sawEnd = true
      break
    }
    if (tag === TAG_PADDING) {
      coverage.push({ protocol: 'tzsp-tag', offset: cursor, length: 1, status: 'covered' })
      cursor += 1
      continue
    }
    if (cursor + 2 > end) {
      maskSpan(buffer, cursor, end - cursor, collector, packetIndex, 'tzsp-tag-tail')
      coverage.push({
        protocol: 'tzsp-tag',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      })
      issues.push('tzsp-tag-bounds')
      return { coverage, issues }
    }
    const tagLen = buffer[cursor + 1]!
    if (cursor + 2 + tagLen > end) {
      maskSpan(buffer, cursor, end - cursor, collector, packetIndex, 'tzsp-tag-oob')
      coverage.push({
        protocol: 'tzsp-tag',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      })
      issues.push('tzsp-tag-length')
      return { coverage, issues }
    }
    const valOff = cursor + 2
    applyTzspTag(buffer, tag, valOff, tagLen, collector, mapping, intents, packetIndex, coverage)
    cursor += 2 + tagLen
  }

  if (!sawEnd) {
    // No END tag — remaining bytes may be frame; still try if Ethernet-sized
    issues.push('tzsp-missing-end')
  }

  const innerOff = cursor
  const innerLen = end - cursor
  if (innerLen <= 0) {
    return { coverage, issues: issues.length ? issues : undefined }
  }

  const identity: TunnelIdentityContext = { packetIndex, intents }

  if (encap === ENCAP_ETHERNET || encap === 0) {
    const eth = sanitizeLinkedEthernet(
      buffer,
      innerOff,
      innerLen,
      collector,
      mapping,
      depth,
      onInnerTransport,
      identity,
      'tzsp-ethernet',
      'tzsp-payload',
    )
    coverage.push(...eth.coverage)
    return { coverage, issues: issues.length ? issues : undefined }
  }

  if (encap === ENCAP_802_11) {
    // 802.11 radiotap-less frame — map addresses when header present; no full 802.11 stack yet
    if (innerLen >= 24) {
      // addr1/addr2/addr3 at typical offsets 4, 10, 16 for data frames
      mapMac(buffer, innerOff + 4, collector, mapping, intents, packetIndex)
      mapMac(buffer, innerOff + 10, collector, mapping, intents, packetIndex)
      mapMac(buffer, innerOff + 16, collector, mapping, intents, packetIndex)
      // Remainder (LLC/payload) mask — T40 owns full 802.11
      coverage.push({ protocol: 'tzsp-80211', offset: innerOff, length: 24, status: 'covered' })
      if (innerLen > 24) {
        maskSpan(buffer, innerOff + 24, innerLen - 24, collector, packetIndex, 'tzsp-80211-body')
        // T63 — masked body reports redacted (not heuristic).
        coverage.push({
          protocol: 'tzsp-80211-body',
          offset: innerOff + 24,
          length: innerLen - 24,
          status: 'redacted',
        })
      }
      issues.push('tzsp-80211-partial')
    } else {
      maskSpan(buffer, innerOff, innerLen, collector, packetIndex, 'tzsp-80211-short')
      coverage.push({ protocol: 'tzsp-80211', offset: innerOff, length: innerLen, status: 'malformed' })
    }
    return { coverage, issues: issues.length ? issues : undefined }
  }

  maskSpan(buffer, innerOff, innerLen, collector, packetIndex, 'tzsp-encap')
  coverage.push({ protocol: 'tzsp-payload', offset: innerOff, length: innerLen, status: 'unsupported' })
  return { coverage, issues: issues.length ? issues : undefined }
}

function applyTzspTag(
  buffer: Uint8Array,
  tag: number,
  valOff: number,
  tagLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const chunkLen = 2 + tagLen
  const tagOff = valOff - 2

  switch (tag) {
    case TAG_RSSI:
    case TAG_SNR:
    case TAG_DATA_RATE:
    case TAG_CONTENTION_FREE:
    case TAG_DECRYPTED:
    case TAG_FCS_ERROR:
    case TAG_RX_CHANNEL:
    case TAG_PACKET_COUNT:
      // RF / counters — preserve (fingerprint policy may redact later)
      coverage.push({ protocol: 'tzsp-tag', offset: tagOff, length: chunkLen, status: 'covered' })
      break
    case TAG_TIMESTAMP:
      // Opaque sensor clock — not capture Δ without units; mask
      if (tagLen > 0) maskSpan(buffer, valOff, tagLen, collector, packetIndex, 'tzsp-ts')
      coverage.push({ protocol: 'tzsp-tag', offset: tagOff, length: chunkLen, status: 'covered' })
      break
    case TAG_SENSOR_MAC:
      if (tagLen === 6) mapMac(buffer, valOff, collector, mapping, intents, packetIndex)
      else if (tagLen > 0) mapOpaque(buffer, valOff, tagLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'tzsp-tag', offset: tagOff, length: chunkLen, status: 'covered' })
      break
    default:
      if (tagLen === 6) {
        // Likely MAC-shaped unknown tag
        mapMac(buffer, valOff, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'tzsp-tag', offset: tagOff, length: chunkLen, status: 'covered' })
      } else if (tagLen > 0) {
        maskSpan(buffer, valOff, tagLen, collector, packetIndex, `tzsp-tag-${tag}`)
        // T63 — masked value reports redacted (not heuristic).
        coverage.push({ protocol: 'tzsp-tag', offset: tagOff, length: 2, status: 'covered' })
        coverage.push({
          protocol: 'tzsp-tag',
          offset: valOff,
          length: tagLen,
          status: 'redacted',
        })
      } else {
        coverage.push({ protocol: 'tzsp-tag', offset: tagOff, length: chunkLen, status: 'covered' })
      }
      break
  }
}

function mapMac(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const mac = Array.from(buffer.subarray(abs, abs + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
  intents?.recordEntityReplacement(packetIndex, abs, 'mac', mac, 6)
  collector.addDeferred(abs, 6, ({ mapping: live }) => {
    const mapped = live.map('mac', mac)
    return new Uint8Array(mapped.split(':').map((s) => Number.parseInt(s, 16)))
  }, { fallbackKind: 'binary-mask', protocol: 'tzsp', category: 'mac', packetIndex })
  void mapping
}

function mapOpaque(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
  const hex = Array.from(buffer.subarray(abs, abs + len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const canon = canonicalizeIdentity('opaque-id', hex.length >= 4 ? hex : raw) ?? hex
  const printable = /^[\x20-\x7e]+$/.test(raw)
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      if (printable) {
        return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('opaque-id', canon, constraint, raw))
      }
      const alias = live.map('opaque-id', canon)
      return createProtocolNeutralMaskFill({
        length: len,
        packetIndex,
        offset: abs,
        domain: `tzsp-opaque:${alias.slice(0, 16)}`,
      })
    } catch {
      return createProtocolNeutralMaskFill({
        length: len,
        packetIndex,
        offset: abs,
        domain: 'tzsp-opaque',
      })
    }
  }, {
    fallbackKind: printable ? 'text-x' : 'binary-mask',
    protocol: 'tzsp',
    category: 'opaque-id',
    packetIndex,
  })
  void mapping
}

function maskSpan(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  try {
    collector.maskRangeDeferred(abs, len, () =>
      createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }),
    )
  } catch {
    /* overlap */
  }
  void buffer
}
