/**
 * T15 — bounded line/header tokenizer (start-line, folded headers, optional body).
 */

import {
  decodeLatin1,
  findLineBreak,
  isEmptyLine,
  isFoldContinuation,
  lineTerminatorLength,
  skipSpaces,
  type TextProtoByteSpan,
} from './bytes'
import { DEFAULT_TEXTPROTO_PARSE_LIMITS, type TextProtoParseLimits } from './limits'

export type TextProtoParseIssue =
  | 'empty'
  | 'too-large'
  | 'line-too-long'
  | 'too-many-headers'
  | 'header-name-too-long'
  | 'missing-colon'
  | 'binary-nul'
  | 'body-too-large'

export interface TextProtoHeader {
  readonly nameSpan: TextProtoByteSpan
  readonly valueSpan: TextProtoByteSpan
  /** Canonical lower-case Latin-1 name. */
  readonly name: string
  readonly valueText: string
}

export interface TextProtoMessage {
  readonly startLine: TextProtoByteSpan
  readonly startLineText: string
  readonly headers: readonly TextProtoHeader[]
  readonly body: TextProtoByteSpan | null
  readonly headerBlockEnd: number
  readonly issues: readonly TextProtoParseIssue[]
}

/**
 * Parse a text/line-header message from `buffer[offset, offset+length)`.
 * Supports `\r\n` and `\n`; folds continuation lines into the previous header value span.
 */
export function tokenizeTextProtoMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  limits: TextProtoParseLimits = DEFAULT_TEXTPROTO_PARSE_LIMITS,
): TextProtoMessage | null {
  const issues: TextProtoParseIssue[] = []
  if (length <= 0) {
    issues.push('empty')
    return null
  }
  if (length > limits.maxMessageBytes) {
    issues.push('too-large')
    return null
  }

  const end = offset + length
  for (let i = offset; i < end; i++) {
    if (buffer[i] === 0x00) {
      issues.push('binary-nul')
      return null
    }
  }

  let cursor = offset
  const firstBreak = findLineBreak(buffer, cursor, end)
  const firstTerm = lineTerminatorLength(buffer, firstBreak, end)
  if (firstBreak - cursor > limits.maxLineBytes) {
    issues.push('line-too-long')
    return null
  }
  const startLine: TextProtoByteSpan = { offset: cursor, length: firstBreak - cursor }
  const startLineText = decodeLatin1(buffer, startLine)
  cursor = firstBreak + firstTerm

  const headers: TextProtoHeader[] = []
  let headerBlockEnd = cursor

  while (cursor < end) {
    const lineBreak = findLineBreak(buffer, cursor, end)
    const term = lineTerminatorLength(buffer, lineBreak, end)
    if (lineBreak - cursor > limits.maxLineBytes) {
      issues.push('line-too-long')
      return null
    }

    if (isEmptyLine(buffer, cursor, lineBreak)) {
      headerBlockEnd = lineBreak + term
      cursor = headerBlockEnd
      break
    }

    if (isFoldContinuation(buffer, cursor, end) && headers.length > 0) {
      const prev = headers[headers.length - 1]!
      const foldedEnd = lineBreak
      const valueEnd = prev.valueSpan.offset + prev.valueSpan.length
      // Extend previous value through this continuation (including leading WS).
      const newValueSpan: TextProtoByteSpan = {
        offset: prev.valueSpan.offset,
        length: foldedEnd - prev.valueSpan.offset,
      }
      headers[headers.length - 1] = {
        ...prev,
        valueSpan: newValueSpan,
        valueText: decodeLatin1(buffer, newValueSpan),
      }
      void valueEnd
      cursor = lineBreak + term
      headerBlockEnd = cursor
      continue
    }

    if (headers.length >= limits.maxHeaderCount) {
      issues.push('too-many-headers')
      return null
    }

    const colon = findColon(buffer, cursor, lineBreak)
    if (colon < 0) {
      issues.push('missing-colon')
      return null
    }
    const nameSpan: TextProtoByteSpan = { offset: cursor, length: colon - cursor }
    if (nameSpan.length === 0 || nameSpan.length > limits.maxHeaderNameBytes) {
      issues.push('header-name-too-long')
      return null
    }
    let valueStart = skipSpaces(buffer, colon + 1, lineBreak)
    const valueSpan: TextProtoByteSpan = {
      offset: valueStart,
      length: Math.max(0, lineBreak - valueStart),
    }
    const name = decodeLatin1(buffer, nameSpan).toLowerCase()
    headers.push({
      nameSpan,
      valueSpan,
      name,
      valueText: decodeLatin1(buffer, valueSpan),
    })
    cursor = lineBreak + term
    headerBlockEnd = cursor
  }

  let body: TextProtoByteSpan | null = null
  if (cursor < end) {
    const contentLength = parseContentLength(headers)
    let bodyLen = end - cursor
    if (contentLength !== null) {
      bodyLen = Math.min(bodyLen, contentLength)
    }
    if (bodyLen > limits.maxBodyBytes) {
      issues.push('body-too-large')
      return null
    }
    if (bodyLen > 0) {
      body = { offset: cursor, length: bodyLen }
    }
  }

  return {
    startLine,
    startLineText,
    headers,
    body,
    headerBlockEnd,
    issues,
  }
}

function findColon(buffer: Uint8Array, start: number, end: number): number {
  for (let i = start; i < end; i++) {
    if (buffer[i] === 0x3a) return i
  }
  return -1
}

function parseContentLength(headers: readonly TextProtoHeader[]): number | null {
  for (let i = headers.length - 1; i >= 0; i--) {
    if (headers[i]!.name !== 'content-length') continue
    const n = Number.parseInt(headers[i]!.valueText.trim(), 10)
    if (!Number.isFinite(n) || n < 0) return null
    return n
  }
  return null
}
