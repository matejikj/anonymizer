/**
 * T37 — ZRTP (RFC 6189) in RTP payload: map ZID; mask key agreement / Confirm material.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { AppLayerResult } from './types'

const ZRTP_MAGIC = new TextEncoder().encode('ZRTP')

export function looksLikeZrtp(data: Uint8Array, offset: number, length: number): boolean {
  // ZRTP packet: 0x10 | 0x00 | length | 'ZRTP' magic …
  if (length < 12) return false
  if (data[offset] !== 0x10 || data[offset + 1] !== 0x00) return false
  for (let i = 0; i < 4; i++) {
    if (data[offset + 4 + i] !== ZRTP_MAGIC[i]) return false
  }
  return true
}

export function sanitizeZrtp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeZrtp(buffer, offset, length)) return null
  const issues: string[] = ['zrtp-integrity-invalidated']

  // Message type at offset+8 (8 ASCII chars typically in Hello)
  // Hello: after header, Client ID (16), Hash images, ZID (12)
  // ZID is at a fixed offset in Hello: 12 (hdr to type) + 8 (type) + 16 (client) + 32*3? 
  // RFC 6189 §5.2 Hello: 
  //   0: preamble, 4: magic, 8: message type (8 chars), 16: version (4), 20: client id (16),
  //   36: hash image H3 (32), 68: ZID (12)
  const msgType = new TextDecoder('ascii', { fatal: false }).decode(
    buffer.subarray(offset + 8, offset + 16),
  ).replace(/\0/g, '')

  if (msgType.startsWith('Hello')) {
    // Client ID — fingerprint policy: map as opaque
    if (length >= 36) {
      mapOpaque(buffer, offset + 20, 16, collector, mapping, intents, packetIndex, 'zrtp-client')
    }
    // Hash images H3 — mask
    if (length >= 68) {
      maskSpan(buffer, offset + 36, 32, collector, packetIndex, 'zrtp-h3')
    }
    // ZID
    if (length >= 80) {
      mapOpaque(buffer, offset + 68, 12, collector, mapping, intents, packetIndex, 'zrtp-zid')
    }
    // Rest (hash image list / flags / CRC) — mask except leave CRC for recompute hint
    if (length > 80) {
      const crcLen = 4
      const mid = length - 80 - crcLen
      if (mid > 0) maskSpan(buffer, offset + 80, mid, collector, packetIndex, 'zrtp-hello-rest')
      // CRC left as-is → integrity-invalidated (documented)
    }
  } else {
    // Commit / DHPart / Confirm / etc. — mask all after type
    if (length > 16) {
      maskSpan(buffer, offset + 16, length - 16, collector, packetIndex, 'zrtp-secret')
    }
  }

  return {
    coverage: [{ protocol: 'zrtp', offset, length, status: 'covered' }],
    issues,
  }
}

function mapOpaque(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  const hex = Array.from(buffer.subarray(abs, abs + len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const canon = canonicalizeIdentity('opaque-id', hex) ?? hex
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: len,
      packetIndex,
      offset: abs,
      domain: `${domain}:${alias.slice(0, 12)}`,
    })
  }, { fallbackKind: 'binary-mask', protocol: 'zrtp', category: 'opaque-id', packetIndex })
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
