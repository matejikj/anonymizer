/**
 * T41 — GELF (UDP/TCP 12201): uncompressed JSON via shared body path; chunked/compressed → mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, maskBytes, sanitizeMessageBody } from './common.ts'

export const GELF_PORT = 12201

export function isGelfPortHint(src: number, dst: number): boolean {
  return src === GELF_PORT || dst === GELF_PORT
}

export function looksLikeGelf(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  // Chunked magic 0x1e 0x0f
  if (buffer[offset] === 0x1e && buffer[offset + 1] === 0x0f) return true
  // zlib / gzip
  if (buffer[offset] === 0x78 || (buffer[offset] === 0x1f && buffer[offset + 1] === 0x8b)) {
    return true
  }
  // Uncompressed JSON object
  let i = offset
  const end = offset + length
  while (i < end && (buffer[i] === 0x20 || buffer[i] === 0x09 || buffer[i] === 0x0a)) i++
  return i < end && buffer[i] === 0x7b
}

export function sanitizeGelf(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isGelfPortHint(srcPort, dstPort) && !looksLikeGelf(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []

  // Chunked GELF — cannot reassemble here; mask all fragments
  if (length >= 2 && buffer[offset] === 0x1e && buffer[offset + 1] === 0x0f) {
    // Preserve 12-byte chunk header (id/seq) structurally, mask payload
    const hdr = Math.min(12, length)
    coverage.push({ protocol: 'gelf-chunk', offset, length: hdr, status: 'covered' })
    if (length > hdr) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        offset + hdr,
        length - hdr,
        'gelf-chunk-payload',
        'gelf',
      )
      coverage.push({
        protocol: 'gelf-body',
        offset: offset + hdr,
        length: length - hdr,
        status: 'redacted',
      })
    }
    issues.push('gelf-chunk-masked')
    return { coverage, issues }
  }

  // Compressed
  if (
    buffer[offset] === 0x78
    || (buffer[offset] === 0x1f && length >= 2 && buffer[offset + 1] === 0x8b)
  ) {
    maskBytes(collector, intents, packetIndex, offset, length, 'gelf-compressed', 'gelf')
    coverage.push({ protocol: 'gelf-body', offset, length, status: 'redacted' })
    issues.push('gelf-compressed-masked')
    return { coverage, issues }
  }

  // TCP NUL-framed: strip trailing NUL for body path
  let bodyLen = length
  if (bodyLen > 0 && buffer[offset + bodyLen - 1] === 0) bodyLen -= 1

  coverage.push(
    ...sanitizeMessageBody(
      buffer,
      offset,
      bodyLen,
      collector,
      mapping,
      intents,
      packetIndex,
      'gelf',
      highPrivacy,
    ),
  )
  // Schema-known log text fields — always content (detectors alone are not enough)
  maskJsonStringFields(
    buffer,
    offset,
    bodyLen,
    ['short_message', 'full_message'],
    collector,
    intents,
    packetIndex,
  )
  if (bodyLen < length) {
    coverage.push({
      protocol: 'gelf',
      offset: offset + bodyLen,
      length: length - bodyLen,
      status: 'covered',
    })
  }

  return { coverage, issues }
}

function maskJsonStringFields(
  buffer: Uint8Array,
  offset: number,
  length: number,
  keys: readonly string[],
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = decodeAscii(buffer, offset, length)
  for (const key of keys) {
    const re = new RegExp(`"${key}"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`, 'gi')
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const val = m[1] ?? ''
      if (!val) continue
      const full = m[0]!
      const colon = full.indexOf(':')
      const q1 = full.indexOf('"', colon + 1)
      const valueStart = offset + (m.index ?? 0) + q1 + 1
      maskBytes(collector, intents, packetIndex, valueStart, val.length, 'gelf-message', 'gelf')
    }
  }
}
