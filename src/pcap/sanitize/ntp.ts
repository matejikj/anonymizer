/**
 * T20 — NTP (RFC 5905) sanitizer: refid map/opaque, timestamp Δ, MAC digest mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'

const NTP_PORTS = new Set([123])
/** Seconds between NTP era 0 (1900) and Unix epoch (1970). */
const NTP_UNIX_DELTA = 2_208_988_800n

const REFCLOCK_ASCII = new Set([
  'GOES', 'GPS\0', 'PPS\0', 'IRIG', 'WWVB', 'DCF\0', 'HBG\0', 'MSF\0',
  'JJY\0', 'LORC', 'TDF\0', 'CHU\0', 'WWV\0', 'WWVH', 'NIST', 'ACTS',
  'USNO', 'PTB\0', 'RATE', 'DEV\0', 'ATOM',
])

const KOD_ASCII = new Set([
  'DENY', 'RSTR', 'RATE', 'DROP', 'CRYP', 'AUTH', 'NKEY', 'NTSN',
])

export function isNtpPortHint(src: number, dst: number): boolean {
  return NTP_PORTS.has(src) || NTP_PORTS.has(dst)
}

export function looksLikeNtp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 48) return false
  const liVnMode = data[offset]!
  const vn = (liVnMode >> 3) & 0x07
  const mode = liVnMode & 0x07
  return vn >= 1 && vn <= 4 && mode >= 1 && mode <= 7
}

export function sanitizeNtp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
): AppLayerResult | null {
  if (!looksLikeNtp(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const mode = buffer[offset]! & 0x07
  const stratum = buffer[offset + 1]!

  // Mode 6/7 control — mask body after minimal header (fail-closed for address lists).
  if (mode === 6 || mode === 7) {
    if (length > 12) {
      mask(collector, intents, packetIndex, offset + 12, length - 12, 'ntp-control-body')
    }
    coverage.push({ protocol: 'ntp', offset, length, status: 'redacted' })
    issues.push('ntp-control-masked')
    return { coverage, issues }
  }

  sanitizeRefId(buffer, offset, stratum, mode, collector, mapping, intents, packetIndex)

  // Timestamps at 16, 24, 32, 40 — 8 bytes each (NTP short fixed-point).
  for (const rel of [16, 24, 32, 40]) {
    shiftNtpTimestamp(buffer, offset + rel, collector, intents, packetIndex, payloadTime, issues)
  }

  // Extension fields + MAC: last 4+ bytes if length > 48 — key ID preserve, digest mask.
  if (length > 48) {
    sanitizeAuthTail(buffer, offset, length, collector, intents, packetIndex)
  }

  coverage.push({ protocol: 'ntp', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeRefId(
  buffer: Uint8Array,
  offset: number,
  stratum: number,
  mode: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const abs = offset + 12
  const b0 = buffer[abs]!
  const b1 = buffer[abs + 1]!
  const b2 = buffer[abs + 2]!
  const b3 = buffer[abs + 3]!
  const ascii = String.fromCharCode(b0, b1, b2, b3)
  const asciiKey = ascii.replace(/\0+$/, '') + '\0'.repeat(Math.max(0, 4 - ascii.replace(/\0+$/, '').length))

  if (stratum === 0 || stratum === 1) {
    if (REFCLOCK_ASCII.has(ascii) || REFCLOCK_ASCII.has(asciiKey) || KOD_ASCII.has(ascii.replace(/\0/g, '')) || KOD_ASCII.has(ascii.slice(0, 4))) {
      return // preserve
    }
    // Unknown kiss / refclock → opaque fingerprint rewrite (not raw preserve).
    mask(collector, intents, packetIndex, abs, 4, 'ntp-refid-opaque')
    return
  }

  // stratum ≥ 2: may be IPv4 or IPv6-hash — only map when looks like unicast IPv4.
  if (b0 !== 0 && b0 < 224) {
    const text = `${b0}.${b1}.${b2}.${b3}`
    const canon = canonicalizeIdentity('ipv4', text)
    if (canon) {
      const constraint = { kind: 'ipv4-wire' as const }
      intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', canon, 4, constraint, text)
      collector.addDeferred(abs, 4, ({ mapping: live }) => {
        const alias = live.map('ipv4', canon)
        const parts = alias.split('.').map((x) => Number(x))
        if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
          return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset: abs, domain: 'ntp-refid-fallback' })
        }
        return new Uint8Array(parts as number[])
      }, { fallbackKind: 'binary-mask', protocol: 'ntp', category: 'ipv4', packetIndex })
      void mapping
      void mode
      return
    }
  }

  // IPv6-derived / unknown — rewrite as opaque (never keep original hash).
  mask(collector, intents, packetIndex, abs, 4, 'ntp-refid-opaque')
}

function shiftNtpTimestamp(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): void {
  const sec =
    (BigInt(buffer[abs]!) << 24n)
    | (BigInt(buffer[abs + 1]!) << 16n)
    | (BigInt(buffer[abs + 2]!) << 8n)
    | BigInt(buffer[abs + 3]!)
  const frac =
    (BigInt(buffer[abs + 4]!) << 24n)
    | (BigInt(buffer[abs + 5]!) << 16n)
    | (BigInt(buffer[abs + 6]!) << 8n)
    | BigInt(buffer[abs + 7]!)

  // Zero / unset sentinel
  if (sec === 0n && frac === 0n) return

  if (!payloadTime?.isBound) {
    mask(collector, intents, packetIndex, abs, 8, 'ntp-time-unbound')
    issues.push('ntp-time-unbound')
    return
  }

  // Convert NTP seconds to Unix ms (ignore era wrap for baseline; frac preserved).
  if (sec < NTP_UNIX_DELTA) {
    // Pre-1970 / era ambiguity → mask
    mask(collector, intents, packetIndex, abs, 8, 'ntp-time-era')
    issues.push('ntp-time-era')
    return
  }
  const unixSec = sec - NTP_UNIX_DELTA
  if (unixSec > BigInt(Number.MAX_SAFE_INTEGER)) {
    mask(collector, intents, packetIndex, abs, 8, 'ntp-time-overflow')
    return
  }
  const epochMs = Number(unixSec) * 1000
  const shiftedMs = payloadTime.shiftAbsoluteEpochMs(epochMs)
  if (shiftedMs === null) {
    mask(collector, intents, packetIndex, abs, 8, 'ntp-time-unwritable')
    return
  }
  const shiftedUnix = BigInt(Math.trunc(shiftedMs / 1000))
  const shiftedNtp = shiftedUnix + NTP_UNIX_DELTA
  if (shiftedNtp < 0n || shiftedNtp > 0xffffffffn) {
    mask(collector, intents, packetIndex, abs, 8, 'ntp-time-range')
    return
  }
  const out = new Uint8Array(8)
  const s = Number(shiftedNtp & 0xffffffffn)
  out[0] = (s >>> 24) & 0xff
  out[1] = (s >>> 16) & 0xff
  out[2] = (s >>> 8) & 0xff
  out[3] = s & 0xff
  // Preserve fractional part (relative offsets between stamps stay meaningful).
  out[4] = buffer[abs + 4]!
  out[5] = buffer[abs + 5]!
  out[6] = buffer[abs + 6]!
  out[7] = buffer[abs + 7]!
  collector.add(abs, out)
}

function sanitizeAuthTail(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const tail = length - 48
  if (tail < 4) {
    mask(collector, intents, packetIndex, offset + 48, tail, 'ntp-ext-opaque')
    return
  }
  // Common crypto-NAK / MAC: 4-byte key ID + digest
  // If last 20 bytes look like keyid+16 digest, or last 24 = keyid+20
  if (tail === 20 || tail === 24 || tail === 4) {
    const digestLen = Math.max(0, tail - 4)
    if (digestLen > 0) {
      mask(collector, intents, packetIndex, offset + length - digestLen, digestLen, 'ntp-mac-digest')
    }
    return
  }
  // Unknown extensions — mask body, keep nothing identity-bearing
  mask(collector, intents, packetIndex, offset + 48, tail, 'ntp-extension')
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
  const fill = createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
  collector.maskRange(abs, fill)
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'ntp')
}
