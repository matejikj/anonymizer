/**
 * Configurable bounds for SIP message parsing (step 2).
 * All limits are enforced fail-closed — exceeding a limit yields `malformed`, never throws.
 */

export interface SipParseLimits {
  /** Maximum total bytes of one SIP message (headers + body). */
  readonly maxMessageBytes: number;
  /** Maximum number of header lines (excluding start-line). */
  readonly maxHeaderCount: number;
  /** Maximum bytes per line (start-line or header line, excluding CRLF/LF). */
  readonly maxLineBytes: number;
  /** Maximum header-name length in bytes. */
  readonly maxHeaderNameBytes: number;
  /** Maximum Request-URI / header URI span in bytes. */
  readonly maxUriBytes: number;
  /** Maximum semicolon-separated parameters on one URI or header value. */
  readonly maxParameterCount: number;
  /**
   * Maximum nesting depth when parsing parameter-bearing tokens.
   * Flat URI parameters count as depth 1; reserved for quoted/nested forms in later steps.
   */
  readonly maxParameterDepth: number;
}

/** Conservative defaults suitable for in-browser PCAP processing. */
export const DEFAULT_SIP_PARSE_LIMITS: SipParseLimits = {
  maxMessageBytes: 65_536,
  maxHeaderCount: 256,
  maxLineBytes: 4_096,
  maxHeaderNameBytes: 256,
  maxUriBytes: 2_048,
  maxParameterCount: 64,
  maxParameterDepth: 8,
};
