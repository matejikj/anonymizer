/**
 * T19 — LACP (Slow Protocols EtherType 0x8809, subtype 0x01): map Actor/Partner System MAC.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { maskPayloadSpan } from '../protocols/application/textproto'

export const ETHERTYPE_SLOW = 0x8809
const SUBTYPE_LACP = 0x01
const SUBTYPE_MARKER = 0x02
const TLV_ACTOR = 1
const TLV_PARTNER = 2
const TLV_COLLECTOR = 3
const TLV_TERMINATOR = 0
const ACTOR_PARTNER_LEN = 20

export function sanitizeLacp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (length < 2) {
    return {
      coverage: [{ protocol: 'lacp', offset, length, status: 'malformed' }],
      issues: ['lacp-short'],
    }
  }
  const subtype = buffer[offset]!
  const version = buffer[offset + 1]!

  if (subtype === SUBTYPE_MARKER) {
    // Marker/Response — not LACP; fail-closed mask body after subtype/version
    if (length > 2) {
      maskPayloadSpan(collector, offset + 2, length - 2, intents, packetIndex, 'slow-marker')
    }
    coverage.push({ protocol: 'slow-protocols', offset, length, status: 'redacted' })
    return { coverage, issues: ['slow-marker-not-lacp'] }
  }
  if (subtype !== SUBTYPE_LACP) {
    if (length > 2) {
      maskPayloadSpan(collector, offset + 2, length - 2, intents, packetIndex, 'slow-unknown')
    }
    coverage.push({ protocol: 'slow-protocols', offset, length, status: 'redacted' })
    return { coverage, issues: ['slow-unknown-subtype'] }
  }
  if (version !== 1) {
    issues.push('lacp-version')
  }

  coverage.push({ protocol: 'lacp', offset, length: 2, status: 'covered' })
  let pos = offset + 2
  const end = offset + length
  while (pos + 2 <= end) {
    const tlvType = buffer[pos]!
    const tlvLen = buffer[pos + 1]!
    if (tlvType === TLV_TERMINATOR) {
      coverage.push({ protocol: 'lacp', offset: pos, length: Math.min(2, end - pos), status: 'covered' })
      break
    }
    if (tlvLen < 2 || pos + tlvLen > end) {
      coverage.push({ protocol: 'lacp', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('lacp-tlv-truncated')
      break
    }
    const valueOff = pos + 2
    const valueLen = tlvLen - 2
    if ((tlvType === TLV_ACTOR || tlvType === TLV_PARTNER) && tlvLen === ACTOR_PARTNER_LEN) {
      // priority(2) + system MAC(6) + key(2) + portPri(2) + port(2) + state(1) + reserved(3)
      if (valueLen >= 8) {
        mapMac(buffer, valueOff + 2, collector, mapping, intents, packetIndex)
      }
      // reserved padding at end — mask to kill canaries
      if (valueLen >= 18) {
        const reservedOff = valueOff + 15
        maskPayloadSpan(collector, reservedOff, 3, intents, packetIndex, 'lacp-reserved')
      }
      coverage.push({ protocol: 'lacp', offset: pos, length: tlvLen, status: 'covered' })
    } else if (tlvType === TLV_COLLECTOR) {
      coverage.push({ protocol: 'lacp', offset: pos, length: tlvLen, status: 'covered' })
    } else {
      maskPayloadSpan(collector, valueOff, valueLen, intents, packetIndex, 'lacp-unknown-tlv')
      coverage.push({ protocol: 'lacp', offset: pos, length: tlvLen, status: 'redacted' })
    }
    pos += tlvLen
  }
  return { coverage, issues }
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
    maskPayloadSpan(collector, abs, 6, intents, packetIndex, 'lacp-mac')
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, 'mac', canon, 6, { kind: 'mac-wire' }, text)
  collector.addDeferred(abs, 6, ({ mapping: live }) => {
    const alias = live.map('mac', canon)
    const hex = alias.replace(/[^0-9a-f]/gi, '')
    if (hex.length < 12) {
      return createProtocolNeutralMaskFill({ length: 6, packetIndex, offset: abs, domain: 'lacp-mac' })
    }
    const out = new Uint8Array(6)
    for (let i = 0; i < 6; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'lacp', category: 'mac', packetIndex })
  void mapping
}
