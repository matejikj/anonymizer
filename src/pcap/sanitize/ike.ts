/**
 * T28 — IKEv1/IKEv2 sanitizer (UDP 500/4500).
 * Preserve SPI/exchange/flags; mask ID, CERT, AUTH, HASH, KE, Nonce, NAT_DETECTION notifies.
 * SK (encrypted) payloads → encrypted only with proven IKEv2 confidentiality variant.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import {
  assertEncryptedClassification,
} from '../kernel/encryptedClassification.ts'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

/** IKEv2 payload types (RFC 7296) — overlapping v1 names where relevant. */
const PL_SA = 33
const PL_KE = 34
const PL_IDI = 35
const PL_IDR = 36
const PL_CERT = 37
const PL_CERTREQ = 38
const PL_AUTH = 39
const PL_NONCE = 40
const PL_NOTIFY = 41
const PL_DELETE = 42
const PL_VENDOR = 43
const PL_TS_I = 44
const PL_TS_R = 45
const PL_SK = 46
const PL_SKF = 53

/** IKEv1 legacy types still seen. */
const V1_ID = 5
const V1_CERT = 6
const V1_HASH = 8
const V1_SIG = 9
const V1_NONCE = 10
const V1_NOTIFY = 11
const V1_KE = 4

const NOTIFY_NAT_DETECTION_SOURCE = 16388
const NOTIFY_NAT_DETECTION_DESTINATION = 16389

const IKE_HEADER = 28

export function looksLikeIke(
  data: Uint8Array,
  offset: number,
  length: number,
  opts?: { readonly nattUdp4500?: boolean },
): boolean {
  if (length < IKE_HEADER) return false
  // NAT-T non-ESP marker only on UDP 4500 — SPI may be all-zero on UDP 500.
  let off = offset
  if (
    opts?.nattUdp4500
    && length >= IKE_HEADER + 4
    && data[offset] === 0
    && data[offset + 1] === 0
    && data[offset + 2] === 0
    && data[offset + 3] === 0
  ) {
    off = offset + 4
  }
  if (off + IKE_HEADER > offset + length) return false
  const nextPayload = data[off + 16]!
  const version = data[off + 17]!
  const major = version >> 4
  if (major !== 1 && major !== 2) return false
  if (nextPayload === 0) return false
  return true
}

export function isIkePort(src: number, dst: number): boolean {
  return src === 500 || dst === 500 || src === 4500 || dst === 4500
}

export function sanitizeIke(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  opts?: { readonly nattUdp4500?: boolean },
): AppLayerResult | null {
  if (!looksLikeIke(buffer, offset, length, opts)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let hdr = offset
  if (
    opts?.nattUdp4500
    && length >= IKE_HEADER + 4
    && buffer[offset] === 0
    && buffer[offset + 1] === 0
    && buffer[offset + 2] === 0
    && buffer[offset + 3] === 0
  ) {
    coverage.push({ protocol: 'ike-natt-marker', offset, length: 4, status: 'covered' })
    hdr = offset + 4
  }

  const end = offset + length
  if (hdr + IKE_HEADER > end) {
    maskSpan(collector, intents, packetIndex, offset, length, 'ike-malformed')
    return {
      coverage: [{ protocol: 'ike', offset, length, status: 'malformed' }],
      issues: ['ike-header-trunc'],
    }
  }

  // SPI (16) preserve; next payload / version / exchange / flags / message id preserve.
  coverage.push({ protocol: 'ike-header', offset: hdr, length: IKE_HEADER, status: 'covered' })

  let next = buffer[hdr + 16]!
  let pos = hdr + IKE_HEADER
  let sawSk = false

  while (next !== 0 && pos + 4 <= end) {
    const payloadType = next
    const np = buffer[pos]!
    const plen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    if (plen < 4 || pos + plen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'ike-malformed')
      coverage.push({ protocol: 'ike', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('ike-payload-trunc')
      break
    }

    const bodyOff = pos + 4
    const bodyLen = plen - 4

    if (payloadType === PL_SK || payloadType === PL_SKF) {
      sawSk = true
      assertEncryptedClassification({
        protocolId: 'ike',
        variant: 'ikev2-sk',
        phase: 'application-data',
        confidentialityProven: true,
      })
      coverage.push({ protocol: 'ike-sk', offset: pos, length: plen, status: 'encrypted' })
    } else if (shouldMaskPayload(payloadType)) {
      if (bodyLen > 0) {
        maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, `ike-pl-${payloadType}`)
      }
      coverage.push({ protocol: 'ike', offset: pos, length: plen, status: 'redacted' })
      if (isNatDetectionNotify(buffer, bodyOff, bodyLen, payloadType)) {
        issues.push('ike-nat-detection-masked')
      }
    } else if (payloadType === PL_NOTIFY || payloadType === V1_NOTIFY) {
      if (isNatDetectionNotify(buffer, bodyOff, bodyLen, payloadType) && bodyLen > 0) {
        maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'ike-nat-detection')
        coverage.push({ protocol: 'ike-notify', offset: pos, length: plen, status: 'redacted' })
        issues.push('ike-nat-detection-masked')
      } else {
        coverage.push({ protocol: 'ike-notify', offset: pos, length: plen, status: 'covered' })
      }
    } else if (payloadType === PL_VENDOR || payloadType === PL_SA || payloadType === PL_DELETE
      || payloadType === PL_TS_I || payloadType === PL_TS_R || payloadType === PL_CERTREQ) {
      coverage.push({ protocol: 'ike', offset: pos, length: plen, status: 'covered' })
    } else {
      // Unknown payload — fail closed mask body
      if (bodyLen > 0) {
        maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'ike-unknown')
      }
      coverage.push({ protocol: 'ike', offset: pos, length: plen, status: 'redacted' })
    }

    next = np
    pos += plen
    if (sawSk) break // encrypted payload is last
  }

  return { coverage, issues }
}

function shouldMaskPayload(type: number): boolean {
  return (
    type === PL_KE
    || type === PL_IDI
    || type === PL_IDR
    || type === PL_CERT
    || type === PL_AUTH
    || type === PL_NONCE
    || type === V1_ID
    || type === V1_CERT
    || type === V1_HASH
    || type === V1_SIG
    || type === V1_NONCE
    || type === V1_KE
  )
}

function isNatDetectionNotify(
  buf: Uint8Array,
  bodyOff: number,
  bodyLen: number,
  payloadType: number,
): boolean {
  if (payloadType !== PL_NOTIFY && payloadType !== V1_NOTIFY) return false
  // IKEv2 Notify: Protocol ID(1) + SPI Size(1) + Notify Message Type(2) + …
  if (bodyLen < 4) return false
  const ntype = (buf[bodyOff + 2]! << 8) | buf[bodyOff + 3]!
  return ntype === NOTIFY_NAT_DETECTION_SOURCE || ntype === NOTIFY_NAT_DETECTION_DESTINATION
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'ike')
}
