/**
 * MGCP (RFC 3435) AST — spans point into the capture buffer (Latin-1).
 */

export interface ByteSpan {
  readonly offset: number
  readonly length: number
}

export type MgcpVerb =
  | 'EPCF'
  | 'CRCX'
  | 'MDCX'
  | 'DLCX'
  | 'RQNT'
  | 'NTFY'
  | 'AUEP'
  | 'AUCX'
  | 'RSIP'

export interface MgcpEndpointParts {
  readonly localSpan: ByteSpan
  readonly localText: string
  readonly domainSpan: ByteSpan | null
  readonly domainText: string | null
  /** True when domain looks like dotted IPv4 (optional brackets). */
  readonly domainIsIpv4: boolean
  /** True when domain looks like IPv6 (bracketed or bare). */
  readonly domainIsIpv6: boolean
}

export interface MgcpStartLine {
  readonly kind: 'request' | 'response'
  readonly span: ByteSpan
  readonly verb?: MgcpVerb
  readonly responseCode?: number
  readonly transactionIdSpan: ByteSpan
  readonly transactionIdText: string
  readonly endpoint?: MgcpEndpointParts
  /** Free response text after code+txid (mask). */
  readonly responseTextSpan: ByteSpan | null
}

export interface MgcpParameter {
  readonly name: string
  readonly nameSpan: ByteSpan
  readonly valueSpan: ByteSpan
  readonly valueText: string
  readonly lineSpan: ByteSpan
}

export interface MgcpMessage {
  readonly start: MgcpStartLine
  readonly parameters: readonly MgcpParameter[]
  /** SDP body after blank line (may be empty). */
  readonly bodySpan: ByteSpan | null
  /** Full message including trailing CRLF before piggyback separator. */
  readonly messageSpan: ByteSpan
}

export type MgcpClassifyResult =
  | { readonly kind: 'complete'; readonly messages: readonly MgcpMessage[]; readonly consumed: number }
  | { readonly kind: 'malformed'; readonly reason: string }
  | { readonly kind: 'not-mgcp' }
