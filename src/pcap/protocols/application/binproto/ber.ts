/**
 * T16 — ASN.1 BER/DER tag+length walker (never throws).
 * Shared helpers for X.509 / SNMP / LDAP / SPNEGO; TLS CN/SAN scan stays best-effort.
 */

import type { BinParseIssue } from './softCursor'

export type BerTagClass = 'universal' | 'application' | 'context' | 'private'

export interface BerTag {
  readonly tagClass: BerTagClass
  readonly constructed: boolean
  readonly number: number
  readonly headerOffset: number
  readonly headerLength: number
}

export interface BerLength {
  readonly length: number | null
  /** null length ⇒ indefinite (EOC-terminated). */
  readonly indefinite: boolean
  readonly contentOffset: number
  readonly headerLength: number
}

export interface BerNode {
  readonly tag: BerTag
  readonly length: BerLength
  readonly contentOffset: number
  readonly contentLength: number
  readonly children: readonly BerNode[]
}

const CLASS_NAMES: BerTagClass[] = ['universal', 'application', 'context', 'private']

export function readBerTag(
  buffer: Uint8Array,
  offset: number,
  end: number,
): BerTag | null {
  if (offset >= end) return null
  const first = buffer[offset]!
  const tagClass = CLASS_NAMES[(first >> 6) & 0x03]!
  const constructed = (first & 0x20) !== 0
  let number = first & 0x1f
  let headerLength = 1
  if (number === 0x1f) {
    // High-tag-number form
    number = 0
    let i = offset + 1
    if (i >= end) return null
    for (;;) {
      if (i >= end) return null
      const b = buffer[i++]!
      number = (number << 7) | (b & 0x7f)
      headerLength++
      if (headerLength > 6) return null
      if ((b & 0x80) === 0) break
    }
  }
  return { tagClass, constructed, number, headerOffset: offset, headerLength }
}

/**
 * Read BER length. Rejects indefinite when `allowIndefinite` is false (DER-safe default).
 */
export function readBerLength(
  buffer: Uint8Array,
  offset: number,
  end: number,
  allowIndefinite = false,
): BerLength | null {
  if (offset >= end) return null
  const first = buffer[offset]!
  if (first < 0x80) {
    return {
      length: first,
      indefinite: false,
      contentOffset: offset + 1,
      headerLength: 1,
    }
  }
  const nbytes = first & 0x7f
  if (nbytes === 0) {
    if (!allowIndefinite) return null
    return {
      length: null,
      indefinite: true,
      contentOffset: offset + 1,
      headerLength: 1,
    }
  }
  if (nbytes > 4 || offset + 1 + nbytes > end) return null
  let length = 0
  for (let i = 0; i < nbytes; i++) {
    length = (length << 8) | buffer[offset + 1 + i]!
  }
  // DER: reject non-minimal long form for small lengths.
  if (nbytes > 1 && length < 0x80) return null
  return {
    length,
    indefinite: false,
    contentOffset: offset + 1 + nbytes,
    headerLength: 1 + nbytes,
  }
}

export interface BerWalkOptions {
  readonly maxDepth?: number
  readonly maxNodes?: number
  readonly allowIndefinite?: boolean
}

/**
 * Bounded BER tree walk. Never throws; malformed branches stop with issues.
 */
export function walkBer(
  buffer: Uint8Array,
  absoluteOffset: number,
  byteLength: number,
  options: BerWalkOptions = {},
): { readonly roots: readonly BerNode[]; readonly issues: readonly BinParseIssue[] } {
  const maxDepth = options.maxDepth ?? 16
  const maxNodes = options.maxNodes ?? 512
  const allowIndefinite = options.allowIndefinite ?? false
  const issues: BinParseIssue[] = []
  let nodeCount = 0
  const end = absoluteOffset + byteLength

  const parseNode = (offset: number, depth: number, limit: number): BerNode | null => {
    if (depth > maxDepth || nodeCount >= maxNodes || offset >= limit) {
      if (depth > maxDepth) issues.push({ code: 'ber-depth', offset })
      if (nodeCount >= maxNodes) issues.push({ code: 'ber-max-nodes', offset })
      return null
    }
    const tag = readBerTag(buffer, offset, limit)
    if (!tag) {
      issues.push({ code: 'ber-tag', offset })
      return null
    }
    const len = readBerLength(buffer, offset + tag.headerLength, limit, allowIndefinite)
    if (!len) {
      issues.push({ code: 'ber-length', offset: offset + tag.headerLength })
      return null
    }
    nodeCount++
    let contentLength = len.length ?? 0
    let contentEnd: number
    if (len.indefinite) {
      // Bounded EOC search
      let i = len.contentOffset
      let nested = 0
      while (i + 1 < limit) {
        if (buffer[i] === 0x00 && buffer[i + 1] === 0x00) {
          if (nested === 0) {
            contentLength = i - len.contentOffset
            contentEnd = i + 2
            break
          }
          nested--
          i += 2
          continue
        }
        // Rough nested constructed detection — stop at budget.
        if (i - len.contentOffset > 65_536) {
          issues.push({ code: 'ber-indefinite-budget', offset: len.contentOffset })
          return null
        }
        i++
      }
      if (contentLength === 0 && !(buffer[len.contentOffset] === 0x00)) {
        // failed to find EOC
        if (i + 1 >= limit) {
          issues.push({ code: 'ber-eoc-missing', offset: len.contentOffset })
          return null
        }
      }
      contentEnd = len.contentOffset + contentLength + 2
    } else {
      contentEnd = len.contentOffset + contentLength
      if (contentEnd > limit) {
        issues.push({ code: 'ber-content-oob', offset: len.contentOffset })
        return null
      }
    }

    const children: BerNode[] = []
    if (tag.constructed) {
      let childOff = len.contentOffset
      const childLimit = len.contentOffset + contentLength
      while (childOff < childLimit) {
        const child = parseNode(childOff, depth + 1, childLimit)
        if (!child) break
        children.push(child)
        // Advance past tag + length + content (+ EOC for indefinite).
        childOff = child.tag.headerOffset + child.tag.headerLength
          + child.length.headerLength + child.contentLength
        if (child.length.indefinite) childOff += 2
      }
    }

    return {
      tag,
      length: len,
      contentOffset: len.contentOffset,
      contentLength,
      children,
    }
  }

  if (byteLength <= 0 || absoluteOffset < 0 || end > buffer.length) {
    return { roots: [], issues: [{ code: 'ber-range', offset: Math.max(0, absoluteOffset) }] }
  }

  const roots: BerNode[] = []
  let off = absoluteOffset
  while (off < end && nodeCount < maxNodes) {
    const node = parseNode(off, 0, end)
    if (!node) break
    roots.push(node)
    off = node.tag.headerOffset + node.tag.headerLength + node.length.headerLength + node.contentLength
    if (node.length.indefinite) off += 2
  }
  return { roots, issues }
}

/**
 * Compatibility helper matching historical `tlsCertIdentities` length reader
 * (permits non-minimal long form; max 3 length octets; rejects indefinite).
 * Prefer {@link readBerLength} for new BER/DER walkers.
 */
export function readAsn1LengthCompat(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { length: number; contentOffset: number } | null {
  if (offset >= end) return null
  const first = buffer[offset]!
  if (first < 0x80) {
    return { length: first, contentOffset: offset + 1 }
  }
  const nbytes = first & 0x7f
  if (nbytes === 0 || nbytes > 3 || offset + 1 + nbytes > end) return null
  let length = 0
  for (let i = 0; i < nbytes; i++) {
    length = (length << 8) | buffer[offset + 1 + i]!
  }
  return { length, contentOffset: offset + 1 + nbytes }
}
