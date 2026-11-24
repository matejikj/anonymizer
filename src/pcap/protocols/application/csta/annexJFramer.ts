/**
 * T49 — ECMA-323 Annex J TCP framing: 4-octet BE length + XML unit.
 */

import { looksLikeCstaXmlText } from './xmlPlan.ts'

export interface AnnexJUnit {
  readonly headerOffset: number
  readonly headerLength: number
  readonly bodyOffset: number
  readonly bodyLength: number
}

/**
 * Parse zero or more Annex J units from a TCP payload slice.
 * Rejects absurd lengths; stops on incomplete trailing unit.
 */
export function parseAnnexJUnits(
  buffer: Uint8Array,
  offset: number,
  length: number,
): readonly AnnexJUnit[] {
  const units: AnnexJUnit[] = []
  const end = offset + length
  let pos = offset
  while (pos + 4 <= end) {
    const bodyLen =
      ((buffer[pos]! << 24) | (buffer[pos + 1]! << 16) | (buffer[pos + 2]! << 8) | buffer[pos + 3]!) >>> 0
    if (bodyLen === 0 || bodyLen > 16 * 1024 * 1024) break
    if (pos + 4 + bodyLen > end) break
    const bodyOff = pos + 4
    const head = new TextDecoder('latin1').decode(
      buffer.subarray(bodyOff, bodyOff + Math.min(bodyLen, 64)),
    )
    // Body should look like XML (optional BOM / whitespace)
    const trimmed = head.replace(/^\uFEFF/, '').trimStart()
    if (!trimmed.startsWith('<')) break
    units.push({
      headerOffset: pos,
      headerLength: 4,
      bodyOffset: bodyOff,
      bodyLength: bodyLen,
    })
    pos = bodyOff + bodyLen
  }
  return units
}

export function looksLikeCstaAnnexJ(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  const units = parseAnnexJUnits(buffer, offset, length)
  if (units.length === 0) return false
  const u = units[0]!
  const text = new TextDecoder('latin1').decode(
    buffer.subarray(u.bodyOffset, u.bodyOffset + Math.min(u.bodyLength, 512)),
  )
  return looksLikeCstaXmlText(text)
}

/** Bare XML CSTA without Annex J prefix (some PBX / test captures). */
export function looksLikeBareCstaXml(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 24) return false
  const text = new TextDecoder('latin1').decode(
    buffer.subarray(offset, offset + Math.min(length, 512)),
  )
  const t = text.replace(/^\uFEFF/, '').trimStart()
  if (!t.startsWith('<')) return false
  return looksLikeCstaXmlText(t)
}
