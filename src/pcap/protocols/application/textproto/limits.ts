/**
 * T15 — shared bounds for line/header text protocols (fail-closed, never throw).
 */

export interface TextProtoParseLimits {
  readonly maxMessageBytes: number
  readonly maxHeaderCount: number
  readonly maxLineBytes: number
  readonly maxHeaderNameBytes: number
  readonly maxBodyBytes: number
}

export const DEFAULT_TEXTPROTO_PARSE_LIMITS: TextProtoParseLimits = {
  maxMessageBytes: 65_536,
  maxHeaderCount: 256,
  maxLineBytes: 4_096,
  maxHeaderNameBytes: 256,
  maxBodyBytes: 65_536,
}
