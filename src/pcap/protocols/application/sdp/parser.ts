/**
 * SDP session parser — byte-oriented, fail-safe (never throws).
 */

import { parseSdpAttribute } from './attributes';
import type { SdpParseLimits } from './limits';
import { DEFAULT_SDP_PARSE_LIMITS } from './limits';
import {
  iterateSdpLines,
  parseTypedLine,
  spanOf,
  splitPortSpec,
  splitSpannedTokens,
} from './lines';
import type {
  SdpAttribute,
  SdpConnection,
  SdpMedia,
  SdpMetadataLine,
  SdpOrigin,
  SdpParseDiagnostics,
  SdpParseResult,
  SdpSession,
} from './types';

export interface ParseSdpOptions {
  readonly offset?: number;
  readonly length?: number;
  readonly limits?: SdpParseLimits;
}

function emptyDiagnostics(): SdpParseDiagnostics {
  return { lineCount: 0, mediaSectionCount: 0, issues: [] };
}

function parseOriginLine(
  buffer: Uint8Array,
  valueStart: number,
  valueEnd: number,
  lineStart: number,
  lineBreak: number,
): SdpOrigin | null {
  const tokens = splitSpannedTokens(buffer, valueStart, valueEnd, 6);
  if (tokens.length < 6) return null;
  return {
    span: spanOf(lineStart, lineBreak),
    username: tokens[0]!,
    sessionId: tokens[1]!,
    sessionVersion: tokens[2]!,
    netType: tokens[3]!,
    addrType: tokens[4]!,
    address: tokens[5]!,
  };
}

function parseConnectionLine(
  buffer: Uint8Array,
  valueStart: number,
  valueEnd: number,
  lineStart: number,
  lineBreak: number,
): SdpConnection | null {
  const tokens = splitSpannedTokens(buffer, valueStart, valueEnd, 3);
  if (tokens.length < 3) return null;
  return {
    span: spanOf(lineStart, lineBreak),
    netType: tokens[0]!,
    addrType: tokens[1]!,
    address: tokens[2]!,
  };
}

function parseMediaLine(
  buffer: Uint8Array,
  valueStart: number,
  valueEnd: number,
  lineStart: number,
  lineBreak: number,
): SdpMedia | null {
  const head = splitSpannedTokens(buffer, valueStart, valueEnd, 3);
  if (head.length < 3) return null;

  const portSpec = splitPortSpec(
    buffer,
    head[1]!.offset,
    head[1]!.offset + head[1]!.length,
  );

  const payloadStart = head[2]!.offset + head[2]!.length;
  const payloadTypes = splitSpannedTokens(buffer, payloadStart, valueEnd, 32);
  const protocol = head[2]!;

  return {
    span: spanOf(lineStart, lineBreak),
    mediaType: head[0]!,
    port: portSpec.port,
    portCount: portSpec.portCount,
    protocol,
    payloadTypes,
    connection: null,
    attributes: [],
  };
}

export function parseSdp(
  buffer: Uint8Array,
  options: ParseSdpOptions = {},
): SdpParseResult {
  const offset = options.offset ?? 0;
  const length = options.length ?? buffer.length - offset;
  const limits = options.limits ?? DEFAULT_SDP_PARSE_LIMITS;
  const end = offset + length;
  const issues: string[] = [];

  if (length <= 0) {
    return { kind: 'not-sdp', reason: 'empty-buffer', diagnostics: emptyDiagnostics() };
  }
  if (length > limits.maxSessionBytes) {
    return {
      kind: 'malformed',
      reason: 'session-too-large',
      diagnostics: { lineCount: 0, mediaSectionCount: 0, issues: ['session-too-large'] },
    };
  }

  let version: ReturnType<typeof spanOf> | null = null;
  let origin: SdpOrigin | null = null;
  let sessionConnection: SdpConnection | null = null;
  const sessionAttributes: SdpAttribute[] = [];
  const media: SdpMedia[] = [];
  const metadataLines: SdpMetadataLine[] = [];
  let currentMedia: SdpMedia | null = null;
  let sawTypedLine = false;

  const lineCount = iterateSdpLines(buffer, offset, end, (lineStart, lineBreak) => {
    const lineLen = lineBreak - lineStart;
    if (lineLen > limits.maxLineBytes) {
      issues.push('line-too-long');
      return;
    }

    const parsed = parseTypedLine(buffer, lineStart, lineBreak);
    if (!parsed.ok) {
      issues.push(parsed.reason);
      return;
    }
    sawTypedLine = true;

    const { type, valueStart, valueEnd } = parsed;
    switch (type) {
      case 'v':
        version = spanOf(valueStart, valueEnd);
        break;
      case 'o':
        origin = parseOriginLine(buffer, valueStart, valueEnd, lineStart, lineBreak);
        if (!origin) issues.push('malformed-o-line');
        break;
      case 'c':
        if (currentMedia) {
          const conn = parseConnectionLine(buffer, valueStart, valueEnd, lineStart, lineBreak);
          if (conn) {
            currentMedia = { ...currentMedia, connection: conn };
            media[media.length - 1] = currentMedia;
          } else {
            issues.push('malformed-media-c-line');
          }
        } else {
          sessionConnection = parseConnectionLine(buffer, valueStart, valueEnd, lineStart, lineBreak);
          if (!sessionConnection) issues.push('malformed-session-c-line');
        }
        break;
      case 'm': {
        if (media.length >= limits.maxMediaSections) {
          issues.push('media-section-limit');
          break;
        }
        const section = parseMediaLine(buffer, valueStart, valueEnd, lineStart, lineBreak);
        if (!section) {
          issues.push('malformed-m-line');
          break;
        }
        currentMedia = section;
        media.push(currentMedia);
        break;
      }
      case 'a': {
        const targetCount = currentMedia ? currentMedia.attributes.length : sessionAttributes.length;
        if (targetCount >= limits.maxAttributesPerSection) {
          issues.push('attribute-limit');
          break;
        }
        const attr = parseSdpAttribute(buffer, lineStart, lineBreak, valueStart, valueEnd);
        if (currentMedia) {
          currentMedia = {
            ...currentMedia,
            attributes: [...currentMedia.attributes, attr],
          };
          media[media.length - 1] = currentMedia;
        } else {
          sessionAttributes.push(attr);
        }
        break;
      }
      case 's':
      case 'i':
      case 'u':
      case 'e':
      case 'p':
      case 't':
      case 'r':
      case 'z':
      case 'k':
      case 'b':
        if (valueEnd > valueStart) {
          metadataLines.push({ type, valueSpan: spanOf(valueStart, valueEnd) });
        }
        break;
      default:
        break;
    }
  });

  if (!sawTypedLine) {
    return {
      kind: 'not-sdp',
      reason: 'no-typed-lines',
      diagnostics: { lineCount, mediaSectionCount: media.length, issues },
    };
  }

  const securityIssues = issues.filter((issue) =>
    issue === 'line-too-long'
    || issue === 'attribute-limit'
    || issue === 'media-section-limit'
  );
  if (securityIssues.length > 0) {
    return {
      kind: 'malformed',
      reason: securityIssues[0]!,
      diagnostics: { lineCount, mediaSectionCount: media.length, issues },
    };
  }

  const session: SdpSession = {
    span: spanOf(offset, end),
    version,
    origin,
    sessionConnection,
    sessionAttributes,
    media,
    metadataLines,
  };

  return {
    kind: 'complete',
    session,
    diagnostics: { lineCount, mediaSectionCount: media.length, issues },
  };
}
