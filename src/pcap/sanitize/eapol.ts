/**
 * T19 — EAPOL / 802.1X (EtherType 0x888E): map EAP Identity; mask MD5/MSCHAP/EAPOL-Key material.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { maskPayloadSpan } from '../protocols/application/textproto'

export const ETHERTYPE_EAPOL = 0x888e

const EAPOL_EAP = 0
const EAPOL_START = 1
const EAPOL_LOGOFF = 2
const EAPOL_KEY = 3

const EAP_REQUEST = 1
const EAP_RESPONSE = 2
const EAP_SUCCESS = 3
const EAP_FAILURE = 4

const EAP_IDENTITY = 1
const EAP_NOTIFICATION = 2
const EAP_MD5 = 4
const EAP_TLS = 13
const EAP_LEAP = 17
const EAP_TTLS = 21
const EAP_PEAP = 25
const EAP_MSCHAPV2 = 26
const EAP_EXPANDED = 254

export function sanitizeEapol(
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
  if (length < 4) {
    return {
      coverage: [{ protocol: 'eapol', offset, length, status: 'malformed' }],
      issues: ['eapol-short'],
    }
  }
  const packetType = buffer[offset + 1]!
  const bodyLen = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
  coverage.push({ protocol: 'eapol', offset, length: 4, status: 'covered' })

  const bodyOff = offset + 4
  const bodyAvail = Math.min(bodyLen, length - 4)
  if (bodyAvail < 0) {
    return { coverage, issues: ['eapol-length'] }
  }
  if (bodyLen > length - 4) {
    issues.push('eapol-body-truncated')
  }

  if (packetType === EAPOL_START || packetType === EAPOL_LOGOFF) {
    if (bodyAvail > 0) {
      maskPayloadSpan(collector, bodyOff, bodyAvail, intents, packetIndex, 'eapol-tlv-body')
    }
    return { coverage, issues }
  }

  if (packetType === EAPOL_KEY) {
    sanitizeEapolKey(buffer, bodyOff, bodyAvail, collector, intents, packetIndex, coverage)
    return { coverage, issues }
  }

  if (packetType === EAPOL_EAP) {
    sanitizeEapPacket(buffer, bodyOff, bodyAvail, collector, mapping, intents, packetIndex, coverage, issues)
    return { coverage, issues }
  }

  if (bodyAvail > 0) {
    maskPayloadSpan(collector, bodyOff, bodyAvail, intents, packetIndex, 'eapol-unknown-type')
    coverage.push({ protocol: 'eapol', offset: bodyOff, length: bodyAvail, status: 'redacted' })
  }
  return { coverage, issues }
}

/** Shared EAP method sanitizer (EAPOL + RADIUS EAP-Message, T19/T22). */
export function sanitizeEapPacket(
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
  if (length < 4) {
    coverage.push({ protocol: 'eap', offset, length, status: 'malformed' })
    issues.push('eap-short')
    return
  }
  const code = buffer[offset]!
  const eapLen = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
  const take = Math.min(eapLen, length)
  // Code + Identifier + Length preserved
  coverage.push({ protocol: 'eap', offset, length: Math.min(4, take), status: 'covered' })

  if (code === EAP_SUCCESS || code === EAP_FAILURE) {
    return
  }
  if (code !== EAP_REQUEST && code !== EAP_RESPONSE) {
    if (take > 4) {
      maskPayloadSpan(collector, offset + 4, take - 4, intents, packetIndex, 'eap-unknown-code')
      coverage.push({ protocol: 'eap', offset: offset + 4, length: take - 4, status: 'redacted' })
    }
    return
  }
  if (take < 5) {
    coverage.push({ protocol: 'eap', offset, length: take, status: 'malformed' })
    return
  }
  const method = buffer[offset + 4]!
  const dataOff = offset + 5
  const dataLen = take - 5

  if (method === EAP_IDENTITY) {
    if (dataLen > 0) {
      mapIdentity(buffer, dataOff, dataLen, collector, mapping, intents, packetIndex)
    }
    coverage.push({ protocol: 'eap', offset: dataOff, length: Math.max(0, dataLen), status: 'covered' })
    return
  }
  if (method === EAP_NOTIFICATION) {
    if (dataLen > 0) {
      maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, 'eap-notification')
    }
    coverage.push({ protocol: 'eap', offset: dataOff, length: Math.max(0, dataLen), status: 'redacted' })
    return
  }
  if (
    method === EAP_MD5
    || method === EAP_LEAP
    || method === EAP_MSCHAPV2
    || method === EAP_EXPANDED
  ) {
    // Offline crack material — mask both levels
    if (dataLen > 0) {
      maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, 'eap-auth-material')
    }
    coverage.push({ protocol: 'eap', offset: offset + 4, length: take - 4, status: 'redacted' })
    return
  }
  if (method === EAP_TLS || method === EAP_PEAP || method === EAP_TTLS) {
    // Flags/length header may be present; mask TLS records (no full TLS reassembly in T19 baseline)
    if (dataLen > 0) {
      maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, 'eap-tls-payload')
    }
    coverage.push({ protocol: 'eap', offset: offset + 4, length: take - 4, status: 'redacted' })
    issues.push('eap-tls-fragment-baseline')
    return
  }
  // Unknown method body — fail-closed
  if (dataLen > 0) {
    maskPayloadSpan(collector, dataOff, dataLen, intents, packetIndex, 'eap-unknown-method')
  }
  coverage.push({ protocol: 'eap', offset: offset + 4, length: take - 4, status: 'redacted' })
}

/**
 * EAPOL-Key (WPA/WPA2): mask Nonce / MIC / Key Data; preserve Key Info / replay / lengths shape.
 * Descriptor layouts vary; we use the common 802.11 RSN key descriptor offsets after descriptor type.
 */
function sanitizeEapolKey(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (length < 1) {
    coverage.push({ protocol: 'eapol-key', offset, length, status: 'malformed' })
    return
  }
  // Descriptor type preserved
  coverage.push({ protocol: 'eapol-key', offset, length: 1, status: 'covered' })
  if (length < 95) {
    // Too short for full RSN key — mask remainder
    if (length > 1) {
      maskPayloadSpan(collector, offset + 1, length - 1, intents, packetIndex, 'eapol-key-short')
    }
    coverage.push({ protocol: 'eapol-key', offset: offset + 1, length: Math.max(0, length - 1), status: 'redacted' })
    return
  }
  // Common RSN layout after descriptor type (1):
  // key info(2) key len(2) replay(8) nonce(32) iv(16) rsc(8) key-id(8) mic(16) key-data-len(2) key-data
  const nonceOff = offset + 1 + 2 + 2 + 8
  const ivOff = nonceOff + 32
  const rscOff = ivOff + 16
  const keyIdOff = rscOff + 8
  const micOff = keyIdOff + 8
  const kdLenOff = micOff + 16
  const kdOff = kdLenOff + 2

  // Preserve key info, key length, replay counter
  coverage.push({ protocol: 'eapol-key', offset: offset + 1, length: 12, status: 'covered' })
  maskPayloadSpan(collector, nonceOff, 32, intents, packetIndex, 'eapol-key-nonce')
  maskPayloadSpan(collector, ivOff, 16, intents, packetIndex, 'eapol-key-iv')
  // RSC / key-id often zero — still mask identifying material
  maskPayloadSpan(collector, rscOff, 16, intents, packetIndex, 'eapol-key-rsc-id')
  maskPayloadSpan(collector, micOff, 16, intents, packetIndex, 'eapol-key-mic')
  coverage.push({ protocol: 'eapol-key', offset: nonceOff, length: micOff + 16 - nonceOff, status: 'redacted' })

  if (kdLenOff + 2 <= offset + length) {
    const kdLen = (buffer[kdLenOff]! << 8) | buffer[kdLenOff + 1]!
    coverage.push({ protocol: 'eapol-key', offset: kdLenOff, length: 2, status: 'covered' })
    const kdAvail = Math.min(kdLen, offset + length - kdOff)
    if (kdAvail > 0) {
      maskPayloadSpan(collector, kdOff, kdAvail, intents, packetIndex, 'eapol-key-data')
      coverage.push({ protocol: 'eapol-key', offset: kdOff, length: kdAvail, status: 'redacted' })
    }
  }
}

function mapIdentity(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
  const trimmed = raw.trim()
  // PCAP SessionMapping: sip-user for usernames; opaque-id for email-shaped (user-id/email text cats → T22)
  const looksEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)
  const category = looksEmail ? 'opaque-id' : 'sip-user'
  const canon = canonicalizeIdentity(category, trimmed.toLowerCase())
  if (!canon) {
    maskPayloadSpan(collector, abs, len, intents, packetIndex, 'eap-identity')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor(category, canon, constraint, raw)
      return computeFixedLengthAsciiBytes(abs, len, alias)
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'eap-identity' })
    }
  }, { fallbackKind: 'text-x', protocol: 'eap', category, packetIndex })
  void mapping
}
