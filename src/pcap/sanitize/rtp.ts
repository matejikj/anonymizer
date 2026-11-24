/**
 * RTP / SRTP sanitizer (step 6 / enterprise step 7).
 *
 * Preserves: V, M, PT, sequence, timestamp, extension IDs/lengths.
 * Maps: SSRC and CSRCs (shared category with RTCP).
 * Masks: header-extension values (SDP extmap-known and unknown alike — values carry
 * mid/audio-level/timing PII); media payload; padding (and SRTP ciphertext).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { parseRtpHeader } from '../protocols/application/rtp/classify'
import { createMaskFill } from './maskFill'
import type { PatchCollector } from './PatchCollector'
import { looksLikeZrtp, sanitizeZrtp } from './zrtp'

const RTP_EXT_ONE_BYTE = 0xbede
const RTP_EXT_TWO_BYTE = 0x1000

export function sanitizeRtpOrSrtp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: 'rtp' | 'srtp',
  knownExtensionIds: ReadonlySet<number> = new Set(),
): boolean {
  const header = parseRtpHeader(buffer, offset, length)
  if (!header) {
    // Unparseable media-shaped payload — keep length, mask entire body.
    maskRange(collector, intents, packetIndex, offset, length, `media-opaque:${protocol}`)
    return true
  }

  // Map SSRC (bytes 8–11)
  patchSsrc(buffer, offset + 8, collector, mapping, intents, packetIndex)

  // Map CSRCs
  for (let i = 0; i < header.csrcCount; i++) {
    patchSsrc(buffer, offset + 12 + i * 4, collector, mapping, intents, packetIndex)
  }

  let payloadStart = offset + header.headerLength

  // Header extension — keep structural IDs/lengths; mask values.
  if (header.extension) {
    const extHeaderOff = offset + 12 + header.csrcCount * 4
    const profile = (buffer[extHeaderOff]! << 8) | buffer[extHeaderOff + 1]!
    const extLenWords = (buffer[extHeaderOff + 2]! << 8) | buffer[extHeaderOff + 3]!
    const extDataOff = extHeaderOff + 4
    const extDataEnd = extDataOff + extLenWords * 4
    if (extDataEnd > offset + length) {
      maskRange(
        collector,
        intents,
        packetIndex,
        offset + 12 + header.csrcCount * 4,
        length - (12 + header.csrcCount * 4),
        `media-ext-malformed:${protocol}`,
      )
      return true
    }

    maskExtensionValues(
      buffer,
      extDataOff,
      extDataEnd,
      profile,
      collector,
      intents,
      packetIndex,
      protocol,
      knownExtensionIds,
    )
    payloadStart = extDataEnd
  }

  // Payload + padding (P bit): ZRTP structured map (T37), else mask.
  const end = offset + length
  if (payloadStart < end) {
    if (looksLikeZrtp(buffer, payloadStart, end - payloadStart)) {
      sanitizeZrtp(buffer, payloadStart, end - payloadStart, collector, mapping, intents, packetIndex)
    } else {
      maskRange(
        collector,
        intents,
        packetIndex,
        payloadStart,
        end - payloadStart,
        `media-payload:${protocol}`,
      )
    }
  }

  return true
}

function maskExtensionValues(
  buffer: Uint8Array,
  start: number,
  end: number,
  profile: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  knownExtensionIds: ReadonlySet<number>,
): void {
  if (start >= end) return

  if (profile === RTP_EXT_ONE_BYTE) {
    let pos = start
    while (pos < end) {
      const b = buffer[pos]!
      if (b === 0x00) {
        // padding
        pos++
        continue
      }
      if (b === 0x0f) {
        // termination — mask rest
        if (pos < end) {
          maskRange(collector, intents, packetIndex, pos, end - pos, `rtp-ext-term:${protocol}`)
        }
        return
      }
      const id = (b >> 4) & 0x0f
      const len = (b & 0x0f) + 1
      const dataStart = pos + 1
      const dataEnd = dataStart + len
      const known = knownExtensionIds.size === 0 || knownExtensionIds.has(id)
      const domain = known
        ? `rtp-ext-value:${protocol}`
        : `rtp-ext-unknown:${protocol}`
      if (dataEnd > end) {
        maskRange(collector, intents, packetIndex, dataStart, end - dataStart, domain)
        return
      }
      maskRange(collector, intents, packetIndex, dataStart, len, domain)
      pos = dataEnd
    }
    return
  }

  if ((profile & 0xfff0) === RTP_EXT_TWO_BYTE) {
    let pos = start
    while (pos + 2 <= end) {
      const id = buffer[pos]!
      if (id === 0x00) {
        pos++
        continue
      }
      const len = buffer[pos + 1]!
      const dataStart = pos + 2
      const dataEnd = dataStart + len
      const known = knownExtensionIds.size === 0 || knownExtensionIds.has(id)
      const domain = known
        ? `rtp-ext-value:${protocol}`
        : `rtp-ext-unknown:${protocol}`
      if (dataEnd > end) {
        maskRange(collector, intents, packetIndex, dataStart, end - dataStart, domain)
        return
      }
      if (len > 0) {
        maskRange(collector, intents, packetIndex, dataStart, len, domain)
      }
      pos = dataEnd
    }
    return
  }

  // Unknown extension profile — keep profile+length (already outside this span), mask data.
  maskRange(collector, intents, packetIndex, start, end - start, `rtp-ext-unknown:${protocol}`)
}

export function patchSsrc(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const ssrc =
    ((buffer[offset]! << 24) >>> 0)
    + (buffer[offset + 1]! << 16)
    + (buffer[offset + 2]! << 8)
    + buffer[offset + 3]!
  const canonical = String(ssrc >>> 0)
  intents?.recordEntityReplacement(packetIndex, offset, 'ssrc', canonical, 4)
  collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
    const mapped = Number(liveMapping.map('ssrc', canonical)) >>> 0
    return new Uint8Array([
      (mapped >>> 24) & 0xff,
      (mapped >>> 16) & 0xff,
      (mapped >>> 8) & 0xff,
      mapped & 0xff,
    ])
  })
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, domain.startsWith('media') ? 'rtp' : 'rtp')
}
