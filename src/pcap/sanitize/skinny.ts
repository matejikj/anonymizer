/**
 * T24 — Cisco Skinny / SCCP (TCP 2000): length/reserved/messageId LE header;
 * Register SEP MAC + IP; CallInfo phones/names; keypad digits mask; media IP/port map.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { IdentityCategory } from '../../mapping/identityCategories'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { maskPayloadSpan } from '../protocols/application/textproto'

const SKINNY_PORTS = new Set([2000])

// Common Skinny message IDs (Cisco SCCP)
const MSG_REGISTER = 0x0001
const MSG_REGISTER_ACK = 0x0081
const MSG_KEYPAD_BUTTON = 0x0003
const MSG_CALL_INFO = 0x008f // CallInfoMessage (station→callmanager variants differ)
const MSG_CALL_INFO_ALT = 0x004a
const MSG_OPEN_RECEIVE_CHANNEL = 0x0105
const MSG_OPEN_RECEIVE_CHANNEL_ACK = 0x0022
const MSG_START_MEDIA_TRANSMISSION = 0x008a
const MSG_DISPLAY_PROMPT = 0x0011
const MSG_LINE_STAT = 0x0092
const MSG_SPEED_DIAL_STAT = 0x0093

export function isSkinnyPortHint(src: number, dst: number): boolean {
  return SKINNY_PORTS.has(src) || SKINNY_PORTS.has(dst)
}

export function looksLikeSkinny(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 12) return false
  const msgLen = readU32LE(data, offset)
  if (msgLen < 4 || msgLen > 0x10000) return false
  const reserved = readU32LE(data, offset + 4)
  if (reserved !== 0 && msgLen + 8 !== length && msgLen + 12 !== length) return false
  return true
}

export function sanitizeSkinny(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeSkinny(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  let pos = offset
  const end = offset + length
  while (pos + 12 <= end) {
    const msgLen = readU32LE(buffer, pos)
    const msgId = readU32LE(buffer, pos + 8)
    const total = 8 + msgLen // length field = bytes after length+reserved (common shape)
    const msgEnd = Math.min(pos + Math.max(total, 12), end)
    coverage.push({ protocol: 'skinny', offset: pos, length: 12, status: 'covered' })
    const bodyOff = pos + 12
    const bodyLen = Math.max(0, msgEnd - bodyOff)
    sanitizeMessage(msgId, buffer, bodyOff, bodyLen, collector, mapping, intents, packetIndex, coverage, issues)
    if (msgLen < 4 || msgEnd <= pos) break
    pos = msgEnd
  }
  if (pos < end && coverage.length === 1) {
    // only header claimed
  }
  coverage.unshift({ protocol: 'skinny', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeMessage(
  msgId: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  switch (msgId) {
    case MSG_REGISTER:
      sanitizeRegister(buffer, offset, length, collector, mapping, intents, packetIndex, coverage)
      return
    case MSG_KEYPAD_BUTTON:
      if (length >= 4) {
        maskPayloadSpan(collector, offset, 4, intents, packetIndex, 'skinny-keypad')
        coverage.push({ protocol: 'skinny-digit', offset, length: 4, status: 'redacted' })
      }
      return
    case MSG_CALL_INFO:
    case MSG_CALL_INFO_ALT:
    case MSG_DISPLAY_PROMPT:
    case MSG_LINE_STAT:
    case MSG_SPEED_DIAL_STAT:
      sanitizeTextHeavy(buffer, offset, length, collector, mapping, intents, packetIndex, coverage)
      return
    case MSG_OPEN_RECEIVE_CHANNEL:
    case MSG_OPEN_RECEIVE_CHANNEL_ACK:
    case MSG_START_MEDIA_TRANSMISSION:
      sanitizeMediaIpPort(buffer, offset, length, collector, mapping, intents, packetIndex, coverage)
      return
    case MSG_REGISTER_ACK:
      coverage.push({ protocol: 'skinny-msg', offset, length, status: 'covered' })
      return
    default:
      maskPayloadSpan(collector, offset, length, intents, packetIndex, `skinny-msg-${msgId}`)
      coverage.push({ protocol: `skinny-msg`, offset, length, status: 'redacted' })
      issues.push(`skinny-unknown-msgid`)
  }
}

function sanitizeRegister(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // Device name typically 16 bytes ASCII at start: SEP + 12 hex MAC
  if (length >= 16) {
    const name = asciiZ(buffer, offset, 16)
    const sep = /^SEP([0-9A-Fa-f]{12})$/.exec(name)
    if (sep) {
      const macRaw = sep[1]!
      const mac = macRaw.match(/.{2}/g)!.join(':').toLowerCase()
      const canon = canonicalizeIdentity('mac', mac)
      if (canon) {
        // Map only the 12 hex digits (bytes 3..15), keep SEP prefix
        const hexOff = offset + 3
        const constraint = { kind: 'text-ascii' as const, byteLength: 12 }
        intents?.recordEntityReplacement(packetIndex, hexOff, 'mac', canon, 12, constraint, macRaw)
        collector.addDeferred(hexOff, 12, ({ mapping: live }) => {
          try {
            const mapped = live.map('mac', canon).replace(/:/g, '').toUpperCase()
            const out = mapped.length >= 12 ? mapped.slice(0, 12) : mapped.padEnd(12, '0')
            return computeFixedLengthAsciiBytes(hexOff, 12, out)
          } catch {
            return createProtocolNeutralMaskFill({ length: 12, packetIndex, offset: hexOff, domain: 'skinny-sep' })
          }
        }, { fallbackKind: 'text-x', protocol: 'skinny', category: 'mac', packetIndex })
      }
    } else if (name) {
      mapFixedAscii(buffer, offset, 16, 'hostname', collector, mapping, intents, packetIndex)
    }
    coverage.push({ protocol: 'skinny-register', offset, length: 16, status: 'covered' })
  }
  // Station IP often at +36 (4 bytes) in common RegisterMessage layout — best-effort
  if (length >= 40) {
    mapIpv4(buffer, offset + 36, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'skinny-register-ip', offset: offset + 36, length: 4, status: 'covered' })
  }
  if (length > 40) {
    // Remainder may hold station identifier strings
    sanitizeTextHeavy(buffer, offset + 40, length - 40, collector, mapping, intents, packetIndex, coverage)
  }
}

function sanitizeTextHeavy(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // Walk fixed 40-byte C-string slots common in CallInfo
  let pos = 0
  while (pos + 4 <= length) {
    const slot = Math.min(40, length - pos)
    const text = asciiZ(buffer, offset + pos, slot)
    if (/^\+?\d{3,15}$/.test(text)) {
      mapFixedAscii(buffer, offset + pos, text.length, 'sip-phone', collector, mapping, intents, packetIndex)
      if (text.length < slot) {
        maskPayloadSpan(collector, offset + pos + text.length, slot - text.length, intents, packetIndex, 'skinny-pad')
      }
    } else if (text.length >= 2 && /[A-Za-z]/.test(text)) {
      mapFixedAscii(buffer, offset + pos, text.length, 'person', collector, mapping, intents, packetIndex)
      if (text.length < slot) {
        maskPayloadSpan(collector, offset + pos + text.length, slot - text.length, intents, packetIndex, 'skinny-pad')
      }
    } else if (text.length === 0) {
      // empty slot preserve zeros
    } else {
      maskPayloadSpan(collector, offset + pos, slot, intents, packetIndex, 'skinny-text')
    }
    pos += slot
  }
  coverage.push({ protocol: 'skinny-text', offset, length, status: 'covered' })
}

function sanitizeMediaIpPort(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // Best-effort: scan for plausible IPv4 + port16 pairs in LE/BE
  for (let i = 0; i + 6 <= length; i++) {
    const b0 = buffer[offset + i]!
    // skip zeros / broadcast-ish
    if (b0 === 0 || b0 === 255) continue
    const b3 = buffer[offset + i + 3]!
    if (b3 === 0 || b3 === 255) continue
    const portLe = buffer[offset + i + 4]! | (buffer[offset + i + 5]! << 8)
    const portBe = (buffer[offset + i + 4]! << 8) | buffer[offset + i + 5]!
    const port = portLe >= 1024 && portLe < 65535 ? portLe : (portBe >= 1024 && portBe < 65535 ? portBe : 0)
    if (port === 0) continue
    mapIpv4(buffer, offset + i, collector, mapping, intents, packetIndex)
    const portOff = offset + i + 4
    const useBe = port === portBe
    mapPortU16(portOff, port, useBe, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'skinny-media', offset: offset + i, length: 6, status: 'covered' })
    i += 5
  }
  // Unknown remainder mask
  coverage.push({ protocol: 'skinny-media-body', offset, length, status: 'covered' })
}

function mapFixedAscii(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  const text = asciiZ(buffer, offset, length)
  if (!text) return
  const canon = canonicalizeIdentity(category, text) ?? text
  const constraint = { kind: 'text-ascii' as const, byteLength: text.length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, text.length, constraint, text)
  collector.addDeferred(offset, text.length, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(
        offset, text.length, live.aliasFor(category, canon, constraint, text),
      )
    } catch {
      return createProtocolNeutralMaskFill({
        length: text.length, packetIndex, offset, domain: `skinny-${category}`,
      })
    }
  }, {
    fallbackKind: category === 'sip-phone' ? 'digits' : 'text-x',
    protocol: 'skinny',
    category,
    packetIndex,
  })
}

function mapIpv4(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  const ip = `${buffer[offset]!}.${buffer[offset + 1]!}.${buffer[offset + 2]!}.${buffer[offset + 3]!}`
  const canon = canonicalizeIdentity('ipv4', ip)
  if (!canon) {
    maskPayloadSpan(collector, offset, 4, intents, packetIndex, 'skinny-ipv4')
    return
  }
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', canon, 4)
  collector.addDeferred(offset, 4, ({ mapping: live }) => {
    try {
      const mapped = live.map('ipv4', canon)
      const parts = mapped.split('.').map((x) => Number(x))
      if (parts.length !== 4) {
        return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset, domain: 'skinny-ipv4' })
      }
      return new Uint8Array([parts[0]!, parts[1]!, parts[2]!, parts[3]!])
    } catch {
      return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset, domain: 'skinny-ipv4' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'skinny', category: 'ipv4', packetIndex })
}

function mapPortU16(
  offset: number,
  port: number,
  bigEndian: boolean,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  const canon = canonicalizeIdentity('port', `udp/${port}`)
  if (!canon) {
    maskPayloadSpan(collector, offset, 2, intents, packetIndex, 'skinny-port')
    return
  }
  intents?.recordEntityReplacement(packetIndex, offset, 'port', canon, 2)
  collector.addDeferred(offset, 2, ({ mapping: live }) => {
    try {
      const mapped = live.map('port', canon)
      const slash = mapped.indexOf('/')
      const n = Number.parseInt(mapped.slice(slash + 1), 10) & 0xffff
      return bigEndian
        ? new Uint8Array([(n >> 8) & 0xff, n & 0xff])
        : new Uint8Array([n & 0xff, (n >> 8) & 0xff])
    } catch {
      return createProtocolNeutralMaskFill({ length: 2, packetIndex, offset, domain: 'skinny-port' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'skinny', category: 'port', packetIndex })
}

function asciiZ(buf: Uint8Array, off: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) {
    const c = buf[off + i]!
    if (c === 0) break
    if (c < 0x20 || c > 0x7e) break
    s += String.fromCharCode(c)
  }
  return s
}

function readU32LE(buf: Uint8Array, off: number): number {
  return (
    buf[off]!
    | (buf[off + 1]! << 8)
    | (buf[off + 2]! << 16)
    | (buf[off + 3]! << 24)
  ) >>> 0
}
