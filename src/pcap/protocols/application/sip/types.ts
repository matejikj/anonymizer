/**
 * Byte-oriented SIP message model (step 2).
 * All spans are absolute offsets into the original payload buffer.
 * Decoded text fields exist only for classification / canonicalization.
 */

/** Half-open byte range `[offset, offset + length)` in the source payload. */
export interface ByteSpan {
  readonly offset: number;
  readonly length: number;
}

export interface SipParameter {
  readonly span: ByteSpan;
  readonly name: ByteSpan;
  readonly value: ByteSpan | null;
}

export interface SipUri {
  readonly span: ByteSpan;
  readonly scheme: ByteSpan;
  readonly user: ByteSpan | null;
  readonly password: ByteSpan | null;
  readonly host: ByteSpan;
  readonly port: ByteSpan | null;
  readonly parameters: readonly SipParameter[];
}

export interface SipRequestStartLine {
  readonly kind: 'request';
  readonly span: ByteSpan;
  readonly method: ByteSpan;
  readonly methodText: string;
  readonly requestUri: SipUri;
  readonly version: ByteSpan;
}

export interface SipResponseStartLine {
  readonly kind: 'response';
  readonly span: ByteSpan;
  readonly version: ByteSpan;
  readonly statusCode: ByteSpan;
  readonly statusCodeText: string;
  readonly reasonPhrase: ByteSpan;
}

export type SipStartLine = SipRequestStartLine | SipResponseStartLine;

export interface SipHeader {
  readonly span: ByteSpan;
  readonly name: ByteSpan;
  readonly nameText: string;
  /** Lowercase canonical name (`via`, `call-id`, …); compact forms expanded. */
  readonly canonicalNameText: string;
  readonly value: ByteSpan;
  readonly valueText: string;
  readonly parameters: readonly SipParameter[];
}

export interface SipBody {
  readonly span: ByteSpan;
  readonly contentType: string | null;
}

export interface SipMessage {
  readonly span: ByteSpan;
  readonly startLine: SipStartLine;
  readonly headers: readonly SipHeader[];
  readonly body: SipBody | null;
}

export interface SipParseDiagnostics {
  readonly headerCount: number;
  readonly maxLineLengthSeen: number;
  readonly consumedBytes: number;
  readonly issues: readonly string[];
}

export type SipParseResult =
  | {
      readonly kind: 'complete';
      readonly message: SipMessage;
      readonly consumed: number;
      readonly diagnostics: SipParseDiagnostics;
    }
  | {
      readonly kind: 'incomplete';
      readonly reason: string;
      readonly diagnostics: SipParseDiagnostics;
    }
  | {
      readonly kind: 'malformed';
      readonly reason: string;
      readonly diagnostics: SipParseDiagnostics;
    }
  | {
      readonly kind: 'not-sip';
      readonly reason: string;
      readonly diagnostics: SipParseDiagnostics;
    };

export function spanEnd(span: ByteSpan): number {
  return span.offset + span.length;
}

export function spansEqual(a: ByteSpan, b: ByteSpan): boolean {
  return a.offset === b.offset && a.length === b.length;
}
