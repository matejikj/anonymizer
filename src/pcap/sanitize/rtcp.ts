/**
 * RTCP compound-packet sanitizer (enterprise step 7).
 *
 * Maps SSRCs; preserves SR/RR loss/jitter/timing fields; redacts SDES identities,
 * BYE reason, and APP private data (4-byte name optionally preserved). Unknown/malformed
 * blocks: keep length, mask body.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { createMaskFill } from './maskFill'
import type { PatchCollector } from './PatchCollector'
import { patchSsrc } from './rtp'

const PT_SR = 200
const PT_RR = 201
const PT_SDES = 202
const PT_BYE = 203
const PT_APP = 204

const SDES_CNAME = 1
const SDES_NAME = 2
const SDES_EMAIL = 3
const SDES_PHONE = 4
const SDES_LOC = 5
const SDES_TOOL = 6
const SDES_NOTE = 7
const SDES_PRIV = 8

export function sanitizeRtcp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): boolean {
  let pos = offset
  const end = offset + length
  let sawPacket = false

  while (pos + 4 <= end) {
    const b0 = buffer[pos]!
    const version = (b0 >> 6) & 0x3
    if (version !== 2) {
      // Remainder is not a valid compound continuation — mask and stop.
      maskBody(collector, intents, packetIndex, pos, end - pos, 'rtcp-trailing')
      break
    }

    const padding = ((b0 >> 5) & 0x1) === 1
    const count = b0 & 0x1f
    const packetType = buffer[pos + 1]!
    const words = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const packetBytes = (words + 1) * 4
    if (packetBytes < 4 || pos + packetBytes > end) {
      maskBody(collector, intents, packetIndex, pos, end - pos, 'rtcp-malformed')
      break
    }

    const packetEnd = pos + packetBytes
    sawPacket = true

    switch (packetType) {
      case PT_SR:
        sanitizeSenderReport(buffer, pos, packetEnd, count, collector, mapping, intents, packetIndex)
        break
      case PT_RR:
        sanitizeReceiverReport(buffer, pos, packetEnd, count, collector, mapping, intents, packetIndex)
        break
      case PT_SDES:
        sanitizeSdes(buffer, pos, packetEnd, count, collector, mapping, intents, packetIndex)
        break
      case PT_BYE:
        sanitizeBye(buffer, pos, packetEnd, count, collector, mapping, intents, packetIndex)
        break
      case PT_APP:
        sanitizeApp(buffer, pos, packetEnd, collector, mapping, intents, packetIndex)
        break
      default:
        // Keep 4-byte header (V/P/RC/PT/length); mask body including SSRC if any.
        if (packetBytes > 4) {
          maskBody(collector, intents, packetIndex, pos + 4, packetBytes - 4, `rtcp-unknown-${packetType}`)
        }
        break
    }

    // Padding bit: trailing padding inside this RTCP packet is part of packetBytes;
    // SR/RR/SDES already handled content. If P is set on unknown path, body mask covers it.
    void padding

    pos = packetEnd
  }

  if (!sawPacket && length > 0) {
    maskBody(collector, intents, packetIndex, offset, length, 'rtcp-empty')
  }
  return true
}

function sanitizeSenderReport(
  buffer: Uint8Array,
  start: number,
  end: number,
  rc: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // header(4) + SSRC(4) + sender info(20) + RC * report block(24)
  if (start + 8 > end) {
    maskBody(collector, intents, packetIndex, start + 4, end - start - 4, 'rtcp-sr-short')
    return
  }
  patchSsrc(buffer, start + 4, collector, mapping, intents, packetIndex)
  // sender info at start+8 .. start+28 preserved (NTP, RTP ts, counts)
  let block = start + 28
  for (let i = 0; i < rc; i++) {
    if (block + 24 > end) {
      maskBody(collector, intents, packetIndex, block, end - block, 'rtcp-sr-block')
      return
    }
    patchSsrc(buffer, block, collector, mapping, intents, packetIndex)
    // fraction lost / cumulative lost / ext seq / jitter / LSR / DLSR preserved
    block += 24
  }
  if (block < end) {
    maskBody(collector, intents, packetIndex, block, end - block, 'rtcp-sr-profile')
  }
}

function sanitizeReceiverReport(
  buffer: Uint8Array,
  start: number,
  end: number,
  rc: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (start + 8 > end) {
    maskBody(collector, intents, packetIndex, start + 4, end - start - 4, 'rtcp-rr-short')
    return
  }
  patchSsrc(buffer, start + 4, collector, mapping, intents, packetIndex)
  let block = start + 8
  for (let i = 0; i < rc; i++) {
    if (block + 24 > end) {
      maskBody(collector, intents, packetIndex, block, end - block, 'rtcp-rr-block')
      return
    }
    patchSsrc(buffer, block, collector, mapping, intents, packetIndex)
    block += 24
  }
  if (block < end) {
    maskBody(collector, intents, packetIndex, block, end - block, 'rtcp-rr-profile')
  }
}

function sanitizeSdes(
  buffer: Uint8Array,
  start: number,
  end: number,
  sc: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let pos = start + 4
  for (let chunk = 0; chunk < sc && pos + 4 <= end; chunk++) {
    patchSsrc(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
    while (pos < end) {
      const type = buffer[pos]!
      if (type === 0) {
        // End of chunk — advance to next 32-bit boundary
        pos++
        while ((pos - start) % 4 !== 0 && pos < end) pos++
        break
      }
      if (pos + 1 >= end) {
        maskBody(collector, intents, packetIndex, pos, end - pos, 'rtcp-sdes-trunc')
        return
      }
      const itemLen = buffer[pos + 1]!
      const valueStart = pos + 2
      const valueEnd = valueStart + itemLen
      if (valueEnd > end) {
        maskBody(collector, intents, packetIndex, valueStart, end - valueStart, 'rtcp-sdes-trunc')
        return
      }
      if (
        itemLen > 0
        && (type === SDES_CNAME
          || type === SDES_NAME
          || type === SDES_EMAIL
          || type === SDES_PHONE
          || type === SDES_LOC
          || type === SDES_TOOL
          || type === SDES_NOTE
          || type === SDES_PRIV)
      ) {
        maskBody(collector, intents, packetIndex, valueStart, itemLen, `rtcp-sdes-${type}`)
      } else if (itemLen > 0) {
        maskBody(collector, intents, packetIndex, valueStart, itemLen, `rtcp-sdes-other-${type}`)
      }
      pos = valueEnd
    }
  }
  if (pos < end) {
    // Remaining padding / trailing
    maskBody(collector, intents, packetIndex, pos, end - pos, 'rtcp-sdes-tail')
  }
}

function sanitizeBye(
  buffer: Uint8Array,
  start: number,
  end: number,
  sc: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let pos = start + 4
  for (let i = 0; i < sc; i++) {
    if (pos + 4 > end) {
      maskBody(collector, intents, packetIndex, pos, end - pos, 'rtcp-bye-trunc')
      return
    }
    patchSsrc(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  }
  if (pos < end) {
    // Optional reason: length byte + text — mask all remaining
    maskBody(collector, intents, packetIndex, pos, end - pos, 'rtcp-bye-reason')
  }
}

function sanitizeApp(
  buffer: Uint8Array,
  start: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // header(4) + SSRC(4) + name(4) + application-dependent data
  if (start + 8 > end) {
    maskBody(collector, intents, packetIndex, start + 4, end - start - 4, 'rtcp-app-short')
    return
  }
  patchSsrc(buffer, start + 4, collector, mapping, intents, packetIndex)
  const dataStart = start + 12
  if (dataStart >= end) return

  const name = new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(start + 8, start + 12))
  // T37 — MCPTT/MCData/MCVideo floor control (TS 24.380)
  if (name === 'MCPT' || name === 'MCPC' || name === 'MCMC') {
    sanitizeMcptFloor(buffer, dataStart, end, collector, mapping, intents, packetIndex)
    return
  }
  maskBody(collector, intents, packetIndex, dataStart, end - dataStart, 'rtcp-app-data')
}

/** Floor APP: preserve short indicators; map SSRC + printable identity runs; mask rest. */
function sanitizeMcptFloor(
  buffer: Uint8Array,
  start: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let pos = start
  // First 2–4 bytes often Floor Indicator / message-type — preserve when small
  if (pos + 2 <= end) pos += 2
  if (pos + 4 <= end) {
    // Possible granted-party SSRC
    patchSsrc(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  }
  // Scan remaining for ASCII identity tokens (length>=4)
  while (pos < end) {
    if (isAsciiIdentStart(buffer[pos]!)) {
      let q = pos
      while (q < end && isAsciiIdentChar(buffer[q]!)) q++
      const len = q - pos
      if (len >= 4) {
        const raw = new TextDecoder('latin1').decode(buffer.subarray(pos, q))
        intents?.recordEntityReplacement(packetIndex, pos, 'opaque-id', raw, len, {
          kind: 'text-ascii',
          byteLength: len,
        }, raw)
        collector.addDeferred(pos, len, ({ mapping: live }) => {
          const alias = live.aliasFor('opaque-id', raw, { kind: 'text-ascii', byteLength: len }, raw)
          const out = new Uint8Array(len)
          const enc = new TextEncoder().encode(alias.slice(0, len).padEnd(len, 'x'))
          out.set(enc.subarray(0, len))
          return out
        }, { fallbackKind: 'text-x', protocol: 'rtcp', category: 'opaque-id', packetIndex })
        pos = q
        continue
      }
    }
    // Mask non-identity byte
    maskBody(collector, intents, packetIndex, pos, 1, 'rtcp-mcpt-byte')
    pos += 1
  }
}

function isAsciiIdentStart(b: number): boolean {
  return (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b === 0x2b || b === 0x40
}

function isAsciiIdentChar(b: number): boolean {
  return (
    isAsciiIdentStart(b)
    || (b >= 0x30 && b <= 0x39)
    || b === 0x2d
    || b === 0x2e
    || b === 0x5f
    || b === 0x3a
  )
}

function maskBody(
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'rtcp')
}
