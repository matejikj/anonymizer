/**
 * T37 — T.38 IFP payload: map ITU T.30 TSI/CSI ASCII fields; mask fax page / unknown IFP.
 * TBCD phone paths stay on shared {@link mapTbcdSipPhoneField} (T25 ISUP).
 */

import type { MappingLike } from '../../anonymization/mapping'
import type { IntentCollector } from '../../discovery/intentCollector'
import type { PatchCollector } from '../PatchCollector'
import { createProtocolNeutralMaskFill } from '../maskFill'
import { mapLengthPreservingAsciiIdentity } from '../telephony/asciiIdentityField'

const T30_TSI_FIELD_LEN = 20
const HDLC_FLAG = 0xff

function digitCountInSpan(buffer: Uint8Array, abs: number, len: number): number {
  let n = 0
  for (let i = 0; i < len; i++) {
    const c = buffer[abs + i]!
    if (c >= 0x30 && c <= 0x39) n++
  }
  return n
}

function isT30TsiFieldBytes(buffer: Uint8Array, abs: number, len: number): boolean {
  if (len !== T30_TSI_FIELD_LEN) return false
  if (digitCountInSpan(buffer, abs, len) < 6) return false
  for (let i = 0; i < len; i++) {
    const c = buffer[abs + i]!
    if (c === 0) continue
    if (c >= 0x30 && c <= 0x39) continue
    if (c === 0x20 || c === 0x2b || c === 0x2a || c === 0x23) continue
    return false
  }
  return true
}

function phoneCanonicalFromTsiField(buffer: Uint8Array, abs: number): string | null {
  let digits = ''
  for (let i = 0; i < T30_TSI_FIELD_LEN; i++) {
    const c = buffer[abs + i]!
    if (c >= 0x30 && c <= 0x39) digits += String.fromCharCode(c)
  }
  if (digits.length < 6) return null
  return digits.startsWith('+') ? digits : `+${digits}`
}

function collectHdlcFrameRanges(
  buffer: Uint8Array,
  ifpOffset: number,
  ifpLength: number,
): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = []
  for (let off = 0; off < ifpLength; off++) {
    if (buffer[ifpOffset + off] !== HDLC_FLAG) continue
    let end = off + 1
    while (end < ifpLength && buffer[ifpOffset + end] !== HDLC_FLAG) end++
    if (end - off < 4) continue
    if (end < ifpLength) end++
    ranges.push({ start: off, end })
    off = end - 1
  }
  return ranges
}

function overlapsMapped(
  start: number,
  end: number,
  mappedRanges: Array<{ start: number; end: number }>,
): boolean {
  for (const r of mappedRanges) {
    if (start < r.end && end > r.start) return true
  }
  return false
}

function maskSpan(
  collector: PatchCollector,
  abs: number,
  len: number,
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
}

export type T38IfpWalkResult = {
  readonly mappedTsi: boolean
  readonly issues: string[]
}

/**
 * Walk IFP bytes after UDPTL sequence number: map 20-octet T.30 TSI/CSI fields; mask the rest.
 */
export function sanitizeT38IfpPayload(
  buffer: Uint8Array,
  ifpOffset: number,
  ifpLength: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): T38IfpWalkResult {
  const issues: string[] = []
  if (ifpLength <= 0) return { mappedTsi: false, issues: ['t38-ifp-empty'] }

  const mappedRanges: Array<{ start: number; end: number }> = []
  let mappedTsi = false
  let hdlcMaskOnly = false

  for (let off = 0; off + T30_TSI_FIELD_LEN <= ifpLength; off++) {
    if (overlapsMapped(off, off + T30_TSI_FIELD_LEN, mappedRanges)) continue
    const abs = ifpOffset + off
    if (!isT30TsiFieldBytes(buffer, abs, T30_TSI_FIELD_LEN)) continue
    const phoneCanon = phoneCanonicalFromTsiField(buffer, abs)
    if (!phoneCanon) continue
    const ok = mapLengthPreservingAsciiIdentity(
      buffer,
      abs,
      T30_TSI_FIELD_LEN,
      'sip-phone',
      collector,
      mapping,
      intents,
      packetIndex,
      't38',
      't30-tsi',
      phoneCanon,
    )
    if (ok) {
      mappedTsi = true
      mappedRanges.push({ start: off, end: off + T30_TSI_FIELD_LEN })
      off += T30_TSI_FIELD_LEN - 1
    }
  }

  for (const frame of collectHdlcFrameRanges(buffer, ifpOffset, ifpLength)) {
    if (overlapsMapped(frame.start, frame.end, mappedRanges)) continue
    maskSpan(collector, ifpOffset + frame.start, frame.end - frame.start, packetIndex, 't30-hdlc')
    mappedRanges.push(frame)
    hdlcMaskOnly = true
  }

  // Mask unmapped IFP regions (page data, canaries, unknown PER, FEC copies).
  let cursor = 0
  mappedRanges.sort((a, b) => a.start - b.start)
  for (const range of mappedRanges) {
    if (range.start > cursor) {
      maskSpan(collector, ifpOffset + cursor, range.start - cursor, packetIndex, 't38-ifp')
    }
    cursor = range.end
  }
  if (cursor < ifpLength) {
    maskSpan(collector, ifpOffset + cursor, ifpLength - cursor, packetIndex, 't38-ifp')
  }

  if (mappedTsi) {
    issues.push('t30-tsi-ascii-mapped')
  }
  if (hdlcMaskOnly) {
    issues.push('t30-hdlc-mask-only')
  }
  if (!mappedTsi && !hdlcMaskOnly && ifpLength > 2) {
    issues.push('t30-per-fec-mask-only')
  }
  issues.push('t38-ifp-masked')
  return { mappedTsi, issues }
}
