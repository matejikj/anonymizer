/**
 * T16 — parameterized TLV / AVP walker (never throws).
 */

import { SoftCursor, type BinParseIssue } from './softCursor'

export interface TlvDescriptor {
  readonly typeWidth: 1 | 2 | 4
  readonly lengthWidth: 1 | 2 | 4
  readonly endian: 'le' | 'be'
  /** When true, length field includes type+length header bytes. */
  readonly lengthIncludesHeader: boolean
  readonly alignment: 1 | 2 | 4
  readonly maxElements: number
  readonly allowZeroLength: boolean
}

export interface TlvElement {
  readonly type: number
  /** Absolute offset of type field. */
  readonly headerOffset: number
  readonly valueOffset: number
  readonly valueLength: number
  readonly totalLength: number
}

export interface TlvWalkResult {
  readonly elements: readonly TlvElement[]
  readonly issues: readonly BinParseIssue[]
  /** Bytes consumed from start (including padding). */
  readonly consumed: number
}

const DEFAULT_DESC: TlvDescriptor = {
  typeWidth: 1,
  lengthWidth: 1,
  endian: 'be',
  lengthIncludesHeader: false,
  alignment: 1,
  maxElements: 256,
  allowZeroLength: true,
}

function readWidth(cur: SoftCursor, width: 1 | 2 | 4, le: boolean): number | null {
  if (width === 1) return cur.u8()
  if (width === 2) return cur.u16(le)
  return cur.u32(le)
}

/**
 * Walk a flat TLV sequence in `buffer[absoluteOffset, absoluteOffset+byteLength)`.
 */
export function walkTlv(
  buffer: Uint8Array,
  absoluteOffset: number,
  byteLength: number,
  descriptor: Partial<TlvDescriptor> = {},
): TlvWalkResult {
  const desc: TlvDescriptor = { ...DEFAULT_DESC, ...descriptor }
  const issues: BinParseIssue[] = []
  const elements: TlvElement[] = []
  if (byteLength <= 0 || absoluteOffset < 0 || absoluteOffset + byteLength > buffer.length) {
    return {
      elements,
      issues: [{ code: 'tlv-range', offset: Math.max(0, absoluteOffset) }],
      consumed: 0,
    }
  }

  const cur = new SoftCursor(buffer, absoluteOffset, absoluteOffset + byteLength)
  const le = desc.endian === 'le'
  const headerSize = desc.typeWidth + desc.lengthWidth

  while (cur.remaining > 0 && elements.length < desc.maxElements) {
    if (cur.remaining < headerSize) {
      issues.push({ code: 'tlv-truncated-header', offset: cur.absoluteOffset })
      break
    }
    const headerOffset = cur.absoluteOffset
    const type = readWidth(cur, desc.typeWidth, le)
    const lengthField = readWidth(cur, desc.lengthWidth, le)
    if (type === null || lengthField === null) {
      if (cur.issue) issues.push(cur.issue)
      break
    }

    let valueLength = lengthField
    if (desc.lengthIncludesHeader) {
      if (lengthField < headerSize) {
        issues.push({ code: 'tlv-length-lt-header', offset: headerOffset })
        break
      }
      valueLength = lengthField - headerSize
    }
    if (valueLength === 0 && !desc.allowZeroLength) {
      issues.push({ code: 'tlv-zero-length', offset: headerOffset })
      break
    }
    if (valueLength < 0 || cur.remaining < valueLength) {
      issues.push({ code: 'tlv-value-oob', offset: cur.absoluteOffset })
      break
    }
    const valueOffset = cur.absoluteOffset
    if (!cur.skip(valueLength)) {
      if (cur.issue) issues.push(cur.issue)
      break
    }

    let totalLength = headerSize + valueLength
    if (desc.alignment > 1) {
      const pad = (desc.alignment - (totalLength % desc.alignment)) % desc.alignment
      if (pad > 0) {
        if (cur.remaining < pad) {
          issues.push({ code: 'tlv-pad-oob', offset: cur.absoluteOffset })
          break
        }
        cur.skip(pad)
        totalLength += pad
      }
    }

    elements.push({
      type,
      headerOffset,
      valueOffset,
      valueLength,
      totalLength,
    })
  }

  return { elements, issues, consumed: cur.offset }
}
