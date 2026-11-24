/**
 * T24 — IAX2 (UDP 4569): full-frame IE walk; phones/names map; PASSWORD/MD5/RSA/CHALLENGE mask;
 * mini/meta voice → media mask. Relative timestamps preserved.
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

const IAX2_PORTS = new Set([4569])

// RFC 5456 IE types
const IE_CALLED_NUMBER = 1
const IE_CALLING_NUMBER = 2
const IE_CALLING_ANI = 3
const IE_CALLING_NAME = 4
const IE_CALLED_CONTEXT = 5
const IE_USERNAME = 6
const IE_PASSWORD = 7
const IE_CAPABILITY = 8
const IE_FORMAT = 9
const IE_LANGUAGE = 10
const IE_VERSION = 11
const IE_DNID = 13
const IE_AUTHMETHODS = 14
const IE_CHALLENGE = 15
const IE_MD5_RESULT = 16
const IE_RSA_RESULT = 17
const IE_APPARENT_ADDR = 18
const IE_DEVICETYPE = 20
const IE_SERVICEIDENT = 30
const IE_CAUSE = 22
const IE_DATETIME = 31
const IE_RDNIS = 27
const IE_CAUSECODE = 42

export function isIax2PortHint(src: number, dst: number): boolean {
  return IAX2_PORTS.has(src) || IAX2_PORTS.has(dst)
}

export function looksLikeIax2(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  // Full frame: F bit set
  if ((data[offset]! & 0x80) !== 0 && length >= 12) return true
  // Mini frame: F bit clear, common on media
  if ((data[offset]! & 0x80) === 0 && length >= 4) return true
  return false
}

export function sanitizeIax2(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeIax2(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  const full = (buffer[offset]! & 0x80) !== 0
  if (!full) {
    // Mini / meta — preserve 4-byte header, mask voice
    const hdr = Math.min(4, length)
    coverage.push({ protocol: 'iax2-mini', offset, length: hdr, status: 'covered' })
    if (length > hdr) {
      maskPayloadSpan(collector, offset + hdr, length - hdr, intents, packetIndex, 'iax2-voice')
      coverage.push({ protocol: 'iax2-media', offset: offset + hdr, length: length - hdr, status: 'redacted' })
    }
    coverage.unshift({ protocol: 'iax2', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  // Full frame header 12 bytes: scallno(2) dcallno(2) ts(4) oseq/iseq(2) type(1) subclass(1)
  if (length < 12) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'iax2-trunc')
    return {
      coverage: [{ protocol: 'iax2', offset, length, status: 'malformed' }],
      issues: ['iax2-header-trunc'],
    }
  }
  coverage.push({ protocol: 'iax2', offset, length: 12, status: 'covered' })

  let pos = offset + 12
  const end = offset + length
  while (pos + 2 <= end) {
    const ieType = buffer[pos]!
    const ieLen = buffer[pos + 1]!
    if (pos + 2 + ieLen > end) {
      maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'iax2-ie-trunc')
      coverage.push({ protocol: 'iax2-ie', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('iax2-ie-trunc')
      break
    }
    const dataOff = pos + 2
    sanitizeIe(ieType, buffer, dataOff, ieLen, collector, mapping, intents, packetIndex, coverage)
    coverage.push({ protocol: 'iax2-ie', offset: pos, length: 2, status: 'covered' })
    pos += 2 + ieLen
  }

  coverage.unshift({ protocol: 'iax2', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeIe(
  ieType: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (length <= 0) return
  switch (ieType) {
    case IE_CALLED_NUMBER:
    case IE_CALLING_NUMBER:
    case IE_CALLING_ANI:
    case IE_DNID:
    case IE_RDNIS:
      mapAscii(buffer, offset, length, 'sip-phone', collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'iax2-phone', offset, length, status: 'covered' })
      return
    case IE_CALLING_NAME:
      mapAscii(buffer, offset, length, 'person', collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'iax2-name', offset, length, status: 'covered' })
      return
    case IE_USERNAME:
      mapAscii(buffer, offset, length, 'user-id', collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'iax2-user', offset, length, status: 'covered' })
      return
    case IE_PASSWORD:
    case IE_CHALLENGE:
    case IE_MD5_RESULT:
    case IE_RSA_RESULT:
      maskPayloadSpan(collector, offset, length, intents, packetIndex, `iax2-ie-${ieType}`)
      coverage.push({ protocol: 'iax2-auth', offset, length, status: 'redacted' })
      return
    case IE_APPARENT_ADDR:
      // sockaddr — map IPv4 at typical offset 4 (family 2) length 4, port at 2
      if (length >= 8) {
        const family = buffer[offset]! | (buffer[offset + 1]! << 8)
        if (family === 2 && length >= 8) {
          // port network order at +2
          const port = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
          mapPortBytes(buffer, offset + 2, port, collector, mapping, intents, packetIndex)
          mapIpv4Bytes(buffer, offset + 4, collector, mapping, intents, packetIndex)
        } else {
          maskPayloadSpan(collector, offset, length, intents, packetIndex, 'iax2-addr')
        }
      } else {
        maskPayloadSpan(collector, offset, length, intents, packetIndex, 'iax2-addr')
      }
      coverage.push({ protocol: 'iax2-addr', offset, length, status: 'covered' })
      return
    case IE_CAPABILITY:
    case IE_FORMAT:
    case IE_VERSION:
    case IE_LANGUAGE:
    case IE_CAUSE:
    case IE_CAUSECODE:
    case IE_DATETIME:
    case IE_DEVICETYPE:
    case IE_SERVICEIDENT:
    case IE_CALLED_CONTEXT:
    case IE_AUTHMETHODS:
      coverage.push({ protocol: 'iax2-ie', offset, length, status: 'covered' })
      return
    default:
      maskPayloadSpan(collector, offset, length, intents, packetIndex, `iax2-ie-unk-${ieType}`)
      coverage.push({ protocol: 'iax2-ie', offset, length, status: 'redacted' })
  }
}

function mapAscii(
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
  let text = ''
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) break
    text += String.fromCharCode(c)
  }
  if (!text) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, `iax2-${category}`)
    return
  }
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
        length: text.length, packetIndex, offset, domain: `iax2-${category}`,
      })
    }
  }, { fallbackKind: category === 'sip-phone' ? 'digits' : 'text-x', protocol: 'iax2', category, packetIndex })
  // Pad remainder after NUL with mask if any
  if (text.length < length) {
    maskPayloadSpan(collector, offset + text.length, length - text.length, intents, packetIndex, 'iax2-pad')
  }
}

function mapIpv4Bytes(
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
    maskPayloadSpan(collector, offset, 4, intents, packetIndex, 'iax2-ipv4')
    return
  }
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', canon, 4)
  collector.addDeferred(offset, 4, ({ mapping: live }) => {
    try {
      const mapped = live.map('ipv4', canon)
      const parts = mapped.split('.').map((x) => Number(x))
      if (parts.length !== 4) {
        return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset, domain: 'iax2-ipv4' })
      }
      return new Uint8Array([parts[0]!, parts[1]!, parts[2]!, parts[3]!])
    } catch {
      return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset, domain: 'iax2-ipv4' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'iax2', category: 'ipv4', packetIndex })
  void buffer
}

function mapPortBytes(
  buffer: Uint8Array,
  offset: number,
  port: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  void buffer
  const canon = canonicalizeIdentity('port', `udp/${port}`)
  if (!canon) {
    maskPayloadSpan(collector, offset, 2, intents, packetIndex, 'iax2-port')
    return
  }
  intents?.recordEntityReplacement(packetIndex, offset, 'port', canon, 2)
  collector.addDeferred(offset, 2, ({ mapping: live }) => {
    try {
      const mapped = live.map('port', canon)
      const slash = mapped.indexOf('/')
      const n = Number.parseInt(mapped.slice(slash + 1), 10)
      return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
    } catch {
      return createProtocolNeutralMaskFill({ length: 2, packetIndex, offset, domain: 'iax2-port' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'iax2', category: 'port', packetIndex })
}
