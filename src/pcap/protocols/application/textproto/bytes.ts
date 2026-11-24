/**
 * T15 — byte helpers for textproto tokenizer (never throws).
 * Kept separate from SIP so SIP golden bytes stay untouched.
 */

export interface TextProtoByteSpan {
  readonly offset: number
  readonly length: number
}

const LATIN1 = new TextDecoder('latin1')

export function decodeLatin1(buffer: Uint8Array, span: TextProtoByteSpan): string {
  if (span.length === 0) return ''
  return LATIN1.decode(buffer.subarray(span.offset, span.offset + span.length))
}

export function isSpaceByte(b: number): boolean {
  return b === 0x20 || b === 0x09
}

export function isLineEndAt(buffer: Uint8Array, index: number, end: number): 'crlf' | 'lf' | null {
  if (index >= end) return null
  if (buffer[index] === 0x0a) return 'lf'
  if (buffer[index] === 0x0d && index + 1 < end && buffer[index + 1] === 0x0a) return 'crlf'
  return null
}

export function findLineBreak(buffer: Uint8Array, start: number, end: number): number {
  for (let i = start; i < end; i++) {
    const b = buffer[i]!
    if (b === 0x0a || b === 0x0d) return i
  }
  return end
}

export function lineTerminatorLength(buffer: Uint8Array, index: number, end: number): number {
  const kind = isLineEndAt(buffer, index, end)
  if (kind === 'crlf') return 2
  if (kind === 'lf') return 1
  return 0
}

export function isEmptyLine(buffer: Uint8Array, lineStart: number, lineBreak: number): boolean {
  for (let i = lineStart; i < lineBreak; i++) {
    if (!isSpaceByte(buffer[i]!)) return false
  }
  return true
}

export function skipSpaces(buffer: Uint8Array, start: number, end: number): number {
  let i = start
  while (i < end && isSpaceByte(buffer[i]!)) i++
  return i
}

/** Header folding (RFC 7230): next line starts with SP/HTAB. */
export function isFoldContinuation(buffer: Uint8Array, lineStart: number, end: number): boolean {
  if (lineStart >= end) return false
  return isSpaceByte(buffer[lineStart]!)
}
