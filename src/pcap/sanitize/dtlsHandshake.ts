/**
 * DTLS handshake fragment framing (RFC 6347) — 12-byte message headers, not TLS 4-byte.
 * Cross-UDP datagram flight reassembly is unsupported (requires-reassembly + mask).
 */

import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { LayerCoverage } from './types.ts'
import { maskRangeDeferredProtocolNeutral } from './deferredMaskMeta.ts'
import { sanitizeCoalescedTlsHandshakes, sanitizeOneTlsHandshakeMessage } from './tls.ts'

const DTLS_HANDSHAKE_HEADER_LEN = 12
const MAX_DTLS_HANDSHAKE_BODY = 64 * 1024

function readUint24(buffer: Uint8Array, offset: number): number {
  return (buffer[offset]! << 16) | (buffer[offset + 1]! << 8) | buffer[offset + 2]!
}

function isPlausibleDtlsHandshakeHeader(buffer: Uint8Array, pos: number, recordEnd: number): boolean {
  if (pos + DTLS_HANDSHAKE_HEADER_LEN > recordEnd) return false
  const messageLength = readUint24(buffer, pos + 1)
  const fragmentOffset = readUint24(buffer, pos + 6)
  const fragmentLength = readUint24(buffer, pos + 9)
  if (messageLength > MAX_DTLS_HANDSHAKE_BODY) return false
  if (fragmentLength > MAX_DTLS_HANDSHAKE_BODY) return false
  if (fragmentOffset > messageLength) return false
  if (fragmentOffset + fragmentLength > messageLength) return false
  if (pos + DTLS_HANDSHAKE_HEADER_LEN + fragmentLength > recordEnd) return false
  return true
}

export function sanitizeDtlsHandshakeRecord(
  buffer: Uint8Array,
  recordOffset: number,
  bodyStart: number,
  recordEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): { coverage: LayerCoverage[]; issues?: string[] } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (bodyStart >= recordEnd) {
    return { coverage, issues }
  }

  if (!isPlausibleDtlsHandshakeHeader(buffer, bodyStart, recordEnd)) {
    const legacy = sanitizeCoalescedTlsHandshakes(
      buffer,
      recordOffset,
      bodyStart,
      recordEnd,
      collector,
      mapping,
      intents,
      packetIndex,
      'dtls',
    )
    const remapped = legacy.coverage.map((c) => ({
      ...c,
      status: c.status === 'covered' ? ('heuristic' as const) : c.status,
    }))
    issues.push(...legacy.issues, 'dtls-heuristic-tls-handshake-framing')
    return { coverage: remapped, issues }
  }

  let pos = bodyStart

  while (pos + DTLS_HANDSHAKE_HEADER_LEN <= recordEnd) {
    if (!isPlausibleDtlsHandshakeHeader(buffer, pos, recordEnd)) {
      const tailLen = recordEnd - pos
      maskDtlsRange(collector, intents, packetIndex, pos, tailLen, 'dtls-handshake-trailer')
      coverage.push({
        protocol: 'dtls-handshake-trailer',
        offset: pos,
        length: tailLen,
        status: 'malformed',
      })
      issues.push('dtls-handshake-trailer-bytes')
      break
    }

    const messageType = buffer[pos]!
    const messageLength = readUint24(buffer, pos + 1)
    const fragmentOffset = readUint24(buffer, pos + 6)
    const fragmentLength = readUint24(buffer, pos + 9)
    const fragmentBodyStart = pos + DTLS_HANDSHAKE_HEADER_LEN
    const fragmentBodyEnd = fragmentBodyStart + fragmentLength

    coverage.push({
      protocol: 'dtls-handshake-fragment',
      offset: pos,
      length: DTLS_HANDSHAKE_HEADER_LEN,
      status: 'covered',
    })

    if (fragmentBodyEnd > recordEnd) {
      maskDtlsRange(
        collector,
        intents,
        packetIndex,
        pos,
        recordEnd - pos,
        'dtls-handshake-fragment-incomplete',
      )
      coverage.push({
        protocol: 'dtls-handshake-fragment',
        offset: pos,
        length: recordEnd - pos,
        status: 'requires-reassembly',
      })
      issues.push('dtls-handshake-fragment-incomplete')
      break
    }

    const singleCompleteFragment =
      fragmentOffset === 0 && fragmentLength === messageLength && messageLength > 0

    if (singleCompleteFragment) {
      const messageCoverageOffset = pos
      const messageCoverageLength = DTLS_HANDSHAKE_HEADER_LEN + messageLength
      const hs = sanitizeOneTlsHandshakeMessage(
        buffer,
        messageCoverageOffset,
        messageCoverageLength,
        messageType,
        fragmentBodyStart,
        fragmentBodyStart + messageLength,
        collector,
        mapping,
        intents,
        packetIndex,
        'dtls',
      )
      coverage.push(...hs.coverage)
      if (hs.issues.length) issues.push(...hs.issues)
      pos = fragmentBodyEnd
      continue
    }

    maskDtlsRange(
      collector,
      intents,
      packetIndex,
      fragmentBodyStart,
      fragmentLength,
      'dtls-handshake-fragment-payload',
    )
    coverage.push({
      protocol: 'dtls-handshake-fragment',
      offset: fragmentBodyStart,
      length: fragmentLength,
      status: 'requires-reassembly',
    })
    issues.push(
      fragmentOffset > 0
        ? 'dtls-cross-datagram-reassembly-unsupported'
        : 'dtls-handshake-fragment-partial',
    )
    pos = fragmentBodyEnd
  }

  return { coverage, issues: issues.length > 0 ? issues : undefined }
}

function maskDtlsRange(
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
