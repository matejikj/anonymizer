/**
 * SIP message parser — byte-oriented, fail-safe (never throws).
 */

import type { SipParseLimits } from './limits';
import { DEFAULT_SIP_PARSE_LIMITS } from './limits';
import type { SipBody, SipHeader, SipMessage, SipParseDiagnostics, SipParseResult } from './types';
import {
  decodeLatin1Span,
  findLineBreak,
  isEmptyLine,
  isSpaceByte,
  lineTerminatorLength,
  spanOf,
} from './bytes';
import { parseHeaderLine, appendFoldedContinuation } from './header';
import { looksLikeSipStart, parseStartLine } from './startLine';

export interface ParseSipMessageOptions {
  readonly offset?: number;
  readonly length?: number;
  readonly limits?: SipParseLimits;
}

function emptyDiagnostics(consumed = 0): SipParseDiagnostics {
  return {
    headerCount: 0,
    maxLineLengthSeen: 0,
    consumedBytes: consumed,
    issues: [],
  };
}

function parseContentLength(headers: readonly SipHeader[]): number | null | 'invalid' | 'conflicting' {
  let found: number | null = null;
  for (const h of headers) {
    if (h.canonicalNameText !== 'content-length') continue;
    const text = h.valueText.trim();
    if (!/^\d+$/.test(text)) return 'invalid';
    const n = Number.parseInt(text, 10);
    if (!Number.isFinite(n) || n < 0) return 'invalid';
    if (found !== null && found !== n) return 'conflicting';
    found = n;
  }
  return found;
}

function findContentType(headers: readonly SipHeader[]): string | null {
  for (const h of headers) {
    if (h.canonicalNameText === 'content-type') {
      return h.valueText.trim().split(';')[0]?.trim() ?? null;
    }
  }
  return null;
}

/**
 * Parse one SIP message from `buffer[offset .. offset+length)`.
 * Returns a discriminated result — never throws on corrupted input.
 */
export function parseSipMessage(
  buffer: Uint8Array,
  options: ParseSipMessageOptions = {},
): SipParseResult {
  const offset = options.offset ?? 0;
  const length = options.length ?? buffer.length - offset;
  const limits = options.limits ?? DEFAULT_SIP_PARSE_LIMITS;
  const end = offset + length;

  if (length <= 0) {
    return { kind: 'not-sip', reason: 'empty-buffer', diagnostics: emptyDiagnostics() };
  }
  if (length > limits.maxMessageBytes) {
    return {
      kind: 'malformed',
      reason: 'message-too-large',
      diagnostics: { ...emptyDiagnostics(), issues: ['message-too-large'] },
    };
  }

  if (!looksLikeSipStart(buffer, offset, end)) {
    return { kind: 'not-sip', reason: 'no-sip-start-line', diagnostics: emptyDiagnostics() };
  }

  const firstBreak = findLineBreak(buffer, offset, end);
  if (firstBreak >= end) {
    return {
      kind: 'incomplete',
      reason: 'truncated-start-line',
      diagnostics: emptyDiagnostics(end - offset),
    };
  }

  const startParsed = parseStartLine(buffer, offset, end, firstBreak, limits);
  if (!startParsed.ok) {
    return {
      kind: startParsed.kind === 'not-sip' ? 'not-sip' : startParsed.kind,
      reason: startParsed.reason,
      diagnostics: emptyDiagnostics(firstBreak - offset),
    };
  }

  const issues: string[] = [];
  let maxLine = firstBreak - offset;
  let cursor = firstBreak;
  const termLen = lineTerminatorLength(buffer, cursor, end);
  if (termLen === 0) {
    return {
      kind: 'incomplete',
      reason: 'truncated-line-terminator',
      diagnostics: { headerCount: 0, maxLineLengthSeen: maxLine, consumedBytes: cursor - offset, issues },
    };
  }
  cursor += termLen;

  const headers: SipHeader[] = [];
  let headerBlockComplete = false;
  while (cursor < end) {
    const lineBreak = findLineBreak(buffer, cursor, end);
    if (lineBreak >= end) {
      return {
        kind: 'incomplete',
        reason: 'truncated-header-line',
        diagnostics: {
          headerCount: headers.length,
          maxLineLengthSeen: maxLine,
          consumedBytes: cursor - offset,
          issues,
        },
      };
    }

    const lineLen = lineBreak - cursor;
    maxLine = Math.max(maxLine, lineLen);

    if (isEmptyLine(buffer, cursor, lineBreak)) {
      cursor = lineBreak + lineTerminatorLength(buffer, lineBreak, end);
      headerBlockComplete = true;
      break;
    }

    if (isSpaceByte(buffer[cursor]!)) {
      if (headers.length === 0) {
        return {
          kind: 'malformed',
          reason: 'orphan-folded-line',
          diagnostics: {
            headerCount: 0,
            maxLineLengthSeen: maxLine,
            consumedBytes: lineBreak - offset,
            issues: [...issues, 'orphan-folded-line'],
          },
        };
      }
      const folded = appendFoldedContinuation(
        buffer,
        headers[headers.length - 1]!,
        cursor,
        lineBreak,
        limits,
      );
      if (!folded.ok) {
        return {
          kind: 'malformed',
          reason: folded.reason,
          diagnostics: {
            headerCount: headers.length,
            maxLineLengthSeen: maxLine,
            consumedBytes: lineBreak - offset,
            issues: [...issues, folded.reason],
          },
        };
      }
      headers[headers.length - 1] = folded.header;

      const foldTerm = lineTerminatorLength(buffer, lineBreak, end);
      if (foldTerm === 0) {
        return {
          kind: 'incomplete',
          reason: 'truncated-line-terminator',
          diagnostics: {
            headerCount: headers.length,
            maxLineLengthSeen: maxLine,
            consumedBytes: lineBreak - offset,
            issues,
          },
        };
      }
      cursor = lineBreak + foldTerm;
      continue;
    }

    if (headers.length >= limits.maxHeaderCount) {
      return {
        kind: 'malformed',
        reason: 'header-count-limit',
        diagnostics: {
          headerCount: headers.length,
          maxLineLengthSeen: maxLine,
          consumedBytes: lineBreak - offset,
          issues: [...issues, 'header-count-limit'],
        },
      };
    }

    const headerParsed = parseHeaderLine(buffer, cursor, lineBreak, limits);
    if (!headerParsed.ok) {
      return {
        kind: 'malformed',
        reason: headerParsed.reason,
        diagnostics: {
          headerCount: headers.length,
          maxLineLengthSeen: maxLine,
          consumedBytes: lineBreak - offset,
          issues: [...issues, headerParsed.reason],
        },
      };
    }
    headers.push(headerParsed.header);

    const term = lineTerminatorLength(buffer, lineBreak, end);
    if (term === 0) {
      return {
        kind: 'incomplete',
        reason: 'truncated-line-terminator',
        diagnostics: {
          headerCount: headers.length,
          maxLineLengthSeen: maxLine,
          consumedBytes: lineBreak - offset,
          issues,
        },
      };
    }
    cursor = lineBreak + term;
  }

  if (!headerBlockComplete) {
    return {
      kind: 'incomplete',
      reason: 'missing-header-body-separator',
      diagnostics: {
        headerCount: headers.length,
        maxLineLengthSeen: maxLine,
        consumedBytes: end - offset,
        issues,
      },
    };
  }

  const contentLength = parseContentLength(headers);
  if (contentLength === 'invalid' || contentLength === 'conflicting') {
    const reason = contentLength === 'conflicting'
      ? 'conflicting-content-length'
      : 'invalid-content-length';
    return {
      kind: 'malformed',
      reason,
      diagnostics: {
        headerCount: headers.length,
        maxLineLengthSeen: maxLine,
        consumedBytes: cursor - offset,
        issues: [...issues, reason],
      },
    };
  }

  let body: SipBody | null = null;
  let messageEnd = cursor;

  if (contentLength !== null) {
    if (cursor + contentLength > end) {
      return {
        kind: 'incomplete',
        reason: 'truncated-body',
        diagnostics: {
          headerCount: headers.length,
          maxLineLengthSeen: maxLine,
          consumedBytes: cursor - offset,
          issues,
        },
      };
    }
    if (contentLength > 0) {
      body = {
        span: spanOf(cursor, cursor + contentLength),
        contentType: findContentType(headers),
      };
    }
    messageEnd = cursor + contentLength;
  } else if (cursor < end) {
    body = {
      span: spanOf(cursor, end),
      contentType: findContentType(headers),
    };
    messageEnd = end;
  }

  const message: SipMessage = {
    span: spanOf(offset, messageEnd),
    startLine: startParsed.startLine,
    headers,
    body,
  };

  return {
    kind: 'complete',
    message,
    consumed: messageEnd - offset,
    diagnostics: {
      headerCount: headers.length,
      maxLineLengthSeen: maxLine,
      consumedBytes: messageEnd - offset,
      issues,
    },
  };
}

export interface ParsedSipMessageEntry {
  readonly message: SipMessage;
  readonly consumed: number;
}

export interface ParseSipMessagesResult {
  readonly messages: readonly ParsedSipMessageEntry[];
  /** Remaining unparsed payload when parsing stops before the buffer end. */
  readonly tail: SipParseResult | null;
  readonly totalConsumed: number;
}

export interface ParseSipMessagesOptions extends ParseSipMessageOptions {}

/**
 * Parse zero or more complete SIP messages from a TCP-style byte stream.
 * Stops at the first incomplete, malformed, or not-sip tail.
 */
export function parseSipMessages(
  buffer: Uint8Array,
  options: ParseSipMessagesOptions = {},
): ParseSipMessagesResult {
  const baseOffset = options.offset ?? 0;
  const totalLength = options.length ?? buffer.length - baseOffset;
  const messages: ParsedSipMessageEntry[] = [];
  let cursor = baseOffset;
  const end = baseOffset + totalLength;
  let tail: SipParseResult | null = null;

  while (cursor < end) {
    const result = parseSipMessage(buffer, {
      offset: cursor,
      length: end - cursor,
      limits: options.limits,
    });

    if (result.kind === 'complete') {
      messages.push({ message: result.message, consumed: result.consumed });
      cursor += result.consumed;
      continue;
    }

    tail = result;
    break;
  }

  return {
    messages,
    tail,
    totalConsumed: cursor - baseOffset,
  };
}

/** Decode a span as Latin-1 (exported for tests and future classifiers). */
export { decodeLatin1Span };
