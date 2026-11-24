/**
 * T37 — BFCP (RFC 8855): map conference/user IDs; preserve primitives / floor status.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { AppLayerResult } from './types'
import { looksLikePfcp } from './pfcp.ts'

export function looksLikeBfcp(data: Uint8Array, offset: number, length: number): boolean {
  // Common header: ver(3)|r(1)|res(4) + primitive(8) + payload length(8) + ...
  if (length < 12) return false
  // T60 — PFCP v1 shares version nibble 1; prefer PFCP grammar over loose BFCP length.
  if (looksLikePfcp(data, offset, length)) return false
  const b0 = data[offset]!
  const ver = (b0 >> 5) & 0x07
  if (ver !== 1) return false
  // Reserved nibble low bits should be 0 in baseline
  if ((b0 & 0x0f) !== 0 && (b0 & 0x0f) !== 0x08) return false // allow R bit only
  const primitive = data[offset + 1]!
  if (primitive < 1 || primitive > 18) return false
  const payloadLen = data[offset + 2]! // 4-byte words excluding common header
  const total = 12 + payloadLen * 4
  // Exact framing only — `total < length` false-positived on PFCP node messages (T60).
  return total === length
}

export function sanitizeBfcp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeBfcp(buffer, offset, length)) return null

  // Map 32-bit Conference ID at offset+4 and User ID at offset+8 when present (common layout)
  if (length >= 12) {
    mapU32Opaque(buffer, offset + 4, collector, mapping, intents, packetIndex, 'bfcp-conf')
    mapU32Opaque(buffer, offset + 8, collector, mapping, intents, packetIndex, 'bfcp-user')
  }
  // Attributes after common header — unknown ATTR bodies mask; keep type/length
  let cursor = offset + 12
  const end = offset + length
  while (cursor + 4 <= end) {
    const attrType = buffer[cursor]!
    const attrLen = buffer[cursor + 2]! // length in 4-octet words including header (approx)
    const bytes = Math.max(4, attrLen * 4)
    if (cursor + bytes > end) {
      maskSpan(buffer, cursor, end - cursor, collector, packetIndex, 'bfcp-attr-tail')
      break
    }
    // ERROR-INFO (type 14-ish) and unknown: mask value after 4B header
    if (attrType === 0 || attrType > 20) {
      if (bytes > 4) maskSpan(buffer, cursor + 4, bytes - 4, collector, packetIndex, 'bfcp-attr')
    } else if (bytes > 4) {
      // Floor ID etc. — map as opaque u16/u32 in value
      mapU32Opaque(buffer, cursor + 4, collector, mapping, intents, packetIndex, 'bfcp-floor')
      if (bytes > 8) {
        maskSpan(buffer, cursor + 8, bytes - 8, collector, packetIndex, 'bfcp-attr-rest')
      }
    }
    cursor += bytes
  }

  return {
    coverage: [{ protocol: 'bfcp', offset, length, status: 'covered' }],
  }
}

function mapU32Opaque(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  if (abs + 4 > buffer.length) return
  const hex = Array.from(buffer.subarray(abs, abs + 4))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const canon = canonicalizeIdentity('opaque-id', hex) ?? hex
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: 4,
      packetIndex,
      offset: abs,
      domain: `${domain}:${alias.slice(0, 12)}`,
    })
  }, { fallbackKind: 'binary-mask', protocol: 'bfcp', category: 'opaque-id', packetIndex })
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
