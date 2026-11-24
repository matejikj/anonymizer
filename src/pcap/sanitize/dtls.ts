/**
 * T28 — DTLS 1.0/1.2 record framing over UDP; reuse TLS handshake sanitizer on plaintext fragments.
 * Incomplete datagrams and unknown epochs → mask-only (no false encrypted-preserved).
 */

import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { maskRangeDeferredProtocolNeutral } from './deferredMaskMeta.ts'
import { sanitizeDtlsHandshakeRecord } from './dtlsHandshake.ts'

const DTLS_HEADER_LEN = 13
const CONTENT_HANDSHAKE = 0x16
const CONTENT_APP = 0x17
const CONTENT_ALERT = 0x15
const CONTENT_CCS = 0x14

export function looksLikeDtls(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < DTLS_HEADER_LEN) return false
  const ct = buffer[offset]!
  if (ct !== CONTENT_HANDSHAKE && ct !== CONTENT_APP && ct !== CONTENT_ALERT && ct !== CONTENT_CCS) {
    return false
  }
  const major = buffer[offset + 1]!
  const minor = buffer[offset + 2]!
  if (major === 0xfe && (minor === 0xff || minor === 0xfd)) return true
  // Some stacks label DTLS 1.3 records with TLS version bytes on the wire.
  if (major === 0x03 && minor === 0x03 && ct === CONTENT_HANDSHAKE) return true
  return false
}

export function sanitizeDtls(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeDtls(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = offset
  const end = offset + length
  let records = 0

  while (pos + DTLS_HEADER_LEN <= end && records < 32) {
    records++
    const contentType = buffer[pos]!
    const recordLen = (buffer[pos + 11]! << 8) | buffer[pos + 12]!
    const bodyStart = pos + DTLS_HEADER_LEN
    const recordEnd = bodyStart + recordLen
    const totalLen = DTLS_HEADER_LEN + recordLen

    if (recordEnd > end) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'dtls-incomplete')
      coverage.push({
        protocol: 'dtls',
        offset: pos,
        length: end - pos,
        status: 'requires-reassembly',
      })
      issues.push('dtls-record-incomplete')
      break
    }

    coverage.push({
      protocol: 'dtls',
      offset: pos,
      length: DTLS_HEADER_LEN,
      status: 'covered',
    })

    switch (contentType) {
      case CONTENT_HANDSHAKE: {
        const hs = sanitizeDtlsHandshakeRecord(
          buffer,
          pos,
          bodyStart,
          recordEnd,
          collector,
          mapping,
          intents,
          packetIndex,
        )
        coverage.push(...hs.coverage)
        if (hs.issues?.length) issues.push(...hs.issues)
        break
      }
      case CONTENT_APP:
      case CONTENT_CCS: {
        // R02 — record type alone is not proof of negotiated confidentiality.
        // Without epoch/cipher/session context, mask body (never claim encrypted-preserved).
        maskRange(
          collector,
          intents,
          packetIndex,
          bodyStart,
          recordLen,
          contentType === CONTENT_APP ? 'dtls-app-unproven' : 'dtls-ccs-unproven',
        )
        // T08: fail-closed mask must surface as gaps (unsupported → mask-in-place), not `redacted`→keep.
        coverage.push({
          protocol: contentType === CONTENT_APP ? 'dtls-app' : 'dtls-ccs',
          offset: pos,
          length: totalLen,
          status: 'unsupported',
        })
        issues.push(
          contentType === CONTENT_APP
            ? 'dtls-app-unproven-confidentiality'
            : 'dtls-ccs-unproven-confidentiality',
        )
        break
      }
      case CONTENT_ALERT:
        // Alert may carry plaintext reason — mask body; keep header covered.
        maskRange(collector, intents, packetIndex, bodyStart, recordLen, 'dtls-alert')
        coverage.push({
          protocol: 'dtls-alert',
          offset: pos,
          length: totalLen,
          status: 'redacted',
        })
        break
      default:
        maskRange(collector, intents, packetIndex, bodyStart, recordLen, 'dtls-unknown-type')
        coverage.push({
          protocol: 'dtls',
          offset: bodyStart,
          length: recordLen,
          status: 'redacted',
        })
    }

    pos = recordEnd
  }

  if (pos < end) {
    maskRange(collector, intents, packetIndex, pos, end - pos, 'dtls-trailer')
    coverage.push({ protocol: 'dtls-trailer', offset: pos, length: end - pos, status: 'redacted' })
  }

  return { coverage, issues: issues.length > 0 ? issues : undefined }
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  domain: string,
): void {
  if (len <= 0) return
  try {
    maskRangeDeferredProtocolNeutral(
      collector,
      abs,
      len,
      packetIndex,
      domain,
      'dtls',
      domain,
    )
    intents?.recordMaskRange(packetIndex, abs, len, domain, 'dtls')
  } catch {
    /* overlap */
  }
}
