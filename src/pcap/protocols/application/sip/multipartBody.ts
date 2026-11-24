/**
 * Lightweight multipart MIME body walker for SIP (enterprise step 8 / T02).
 * Preserves boundary framing; SDP parts get structured sanitize; other parts MASK.
 * Operates on raw wire bytes (CRLF preserved). Keeps full Content-Type (incl. boundary)
 * so nested multipart can recurse.
 */

import type { ByteSpan } from './types'
import { decodeLatin1Span } from './bytes'

const MAX_MULTIPART_PARTS = 32
/** Nesting budget for multipart-in-multipart (T02 revision). */
export const MAX_MULTIPART_NESTING = 4

export interface SipMultipartPart {
  /** Absolute span of the part body (after part headers). */
  readonly bodySpan: ByteSpan
  /** Lowercased media type without parameters. */
  readonly contentType: string | null
  /** Full Content-Type header value including parameters (needed for nested boundary). */
  readonly contentTypeHeader: string | null
  /**
   * Lowercased Content-Transfer-Encoding, or null when absent/7bit/8bit/binary
   * (identity encodings that keep wire bytes = logical body).
   */
  readonly transferEncoding: string | null
}

export interface SipMultipartParseResult {
  readonly ok: boolean
  readonly reason?: string
  readonly parts: readonly SipMultipartPart[]
}

function findBoundaryParam(contentTypeHeader: string): string | null {
  const m = /;\s*boundary\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(contentTypeHeader)
  if (!m) return null
  return m[1] ?? m[2] ?? null
}

export function isMultipartContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return base.startsWith('multipart/')
}

/** True when CTE requires an inverse decoder we do not have (fail-closed mask). */
export function isNonIdentityTransferEncoding(cte: string | null): boolean {
  if (!cte) return false
  const v = cte.trim().toLowerCase()
  if (v === '' || v === '7bit' || v === '8bit' || v === 'binary') return false
  return true
}

export function contentTypeHeaderRaw(
  messageHeaders: readonly { canonicalNameText: string; valueText: string }[],
): string | null {
  for (const h of messageHeaders) {
    if (h.canonicalNameText === 'content-type') return h.valueText
  }
  return null
}

function indexOfBytes(
  hay: Uint8Array,
  start: number,
  end: number,
  needle: Uint8Array,
): number {
  if (needle.length === 0 || start + needle.length > end) return -1
  outer: for (let i = start; i + needle.length <= end; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}

function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

/**
 * Split a multipart body into parts by boundary.
 */
export function parseSipMultipartBody(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  contentTypeHeader: string,
): SipMultipartParseResult {
  const boundary = findBoundaryParam(contentTypeHeader)
  if (!boundary) {
    return { ok: false, reason: 'multipart-missing-boundary', parts: [] }
  }

  const bodyStart = bodySpan.offset
  const bodyEnd = bodySpan.offset + bodySpan.length
  const delim = asciiBytes(`--${boundary}`)
  const parts: SipMultipartPart[] = []

  let pos = indexOfBytes(buffer, bodyStart, bodyEnd, delim)
  if (pos < 0) {
    return { ok: false, reason: 'multipart-boundary-not-found', parts: [] }
  }
  pos += delim.length
  // Optional whitespace / CRLF after opening boundary
  if (pos < bodyEnd && buffer[pos] === 0x0d) pos++
  if (pos < bodyEnd && buffer[pos] === 0x0a) pos++

  while (pos < bodyEnd && parts.length < MAX_MULTIPART_PARTS) {
    // Closing boundary `--boundary--`
    if (
      pos + 1 < bodyEnd
      && buffer[pos] === 0x2d
      && buffer[pos + 1] === 0x2d
    ) {
      break
    }

    const nextDelim = indexOfBytes(buffer, pos, bodyEnd, asciiBytes(`\r\n--${boundary}`))
    const nextDelimLf = nextDelim < 0
      ? indexOfBytes(buffer, pos, bodyEnd, asciiBytes(`\n--${boundary}`))
      : -1
    let partEnd: number
    let afterDelim: number
    if (nextDelim >= 0) {
      partEnd = nextDelim
      afterDelim = nextDelim + 2 + delim.length // \r\n + --boundary
    } else if (nextDelimLf >= 0) {
      partEnd = nextDelimLf
      afterDelim = nextDelimLf + 1 + delim.length
    } else {
      partEnd = bodyEnd
      afterDelim = bodyEnd
    }

    // Split headers / body inside part
    const headerSep = indexOfBytes(buffer, pos, partEnd, asciiBytes('\r\n\r\n'))
    const headerSepLf = headerSep < 0
      ? indexOfBytes(buffer, pos, partEnd, asciiBytes('\n\n'))
      : -1
    let bodyOff = pos
    let contentType: string | null = null
    let contentTypeHeaderPart: string | null = null
    let transferEncoding: string | null = null
    if (headerSep >= 0) {
      const headers = parsePartHeaders(buffer, pos, headerSep)
      contentType = headers.contentType
      contentTypeHeaderPart = headers.contentTypeHeader
      transferEncoding = headers.transferEncoding
      bodyOff = headerSep + 4
    } else if (headerSepLf >= 0) {
      const headers = parsePartHeaders(buffer, pos, headerSepLf)
      contentType = headers.contentType
      contentTypeHeaderPart = headers.contentTypeHeader
      transferEncoding = headers.transferEncoding
      bodyOff = headerSepLf + 2
    }

    // Trim trailing CRLF before next boundary
    let bodyEndOff = partEnd
    if (bodyEndOff > bodyOff && buffer[bodyEndOff - 1] === 0x0a) bodyEndOff--
    if (bodyEndOff > bodyOff && buffer[bodyEndOff - 1] === 0x0d) bodyEndOff--

    parts.push({
      bodySpan: { offset: bodyOff, length: Math.max(0, bodyEndOff - bodyOff) },
      contentType,
      contentTypeHeader: contentTypeHeaderPart,
      transferEncoding,
    })

    if (afterDelim >= bodyEnd) break
    pos = afterDelim
    if (pos < bodyEnd && buffer[pos] === 0x0d) pos++
    if (pos < bodyEnd && buffer[pos] === 0x0a) pos++
  }

  if (parts.length === 0) {
    return { ok: false, reason: 'multipart-no-parts', parts: [] }
  }
  return { ok: true, parts }
}

function parsePartHeaders(
  buffer: Uint8Array,
  headerStart: number,
  headerEnd: number,
): {
  contentType: string | null
  contentTypeHeader: string | null
  transferEncoding: string | null
} {
  const text = decodeLatin1Span(buffer, {
    offset: headerStart,
    length: headerEnd - headerStart,
  })
  const ct = /^Content-Type:\s*(.+)$/im.exec(text)
  const cte = /^Content-Transfer-Encoding:\s*(\S+)/im.exec(text)
  const contentTypeHeader = ct?.[1]?.trim() ?? null
  const contentType = contentTypeHeader
    ? contentTypeHeader.split(';')[0]?.trim().toLowerCase() ?? null
    : null
  const transferEncoding = cte?.[1]?.trim().toLowerCase() ?? null
  return { contentType, contentTypeHeader, transferEncoding }
}

export function isSdpPartContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return base === 'application/sdp' || base.startsWith('application/sdp')
}
