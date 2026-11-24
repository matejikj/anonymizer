/**
 * Wireshark-like display filter AST (step 2 subset).
 */

export type DisplayFilterField =
  | 'ip.addr'
  | 'ip.src'
  | 'ip.dst'
  | 'tcp.port'
  | 'udp.port'
  | 'frame.number'
  | 'frame.len'
  | 'frame.changed'
  | 'frame.issue'
  | 'eth.addr'
  | 'protocol'

export type CompareOp = '==' | '!=' | 'contains' | '>=' | '<=' | '>' | '<'

export type FilterExpr =
  | { readonly kind: 'and'; readonly left: FilterExpr; readonly right: FilterExpr }
  | { readonly kind: 'or'; readonly left: FilterExpr; readonly right: FilterExpr }
  | { readonly kind: 'not'; readonly expr: FilterExpr }
  | { readonly kind: 'compare'; readonly field: DisplayFilterField | string; readonly op: CompareOp; readonly value: FilterValue }
  | { readonly kind: 'protocol'; readonly name: string }

export type FilterValue = string | number | boolean

export type ParseStatus = 'valid' | 'incomplete' | 'invalid'

export interface ParseResult {
  readonly status: ParseStatus
  readonly expr: FilterExpr | null
  readonly error: { readonly message: string; readonly offset: number } | null
}

export interface PacketFilterContext {
  readonly packetIndex: number
  readonly packetNumber: number
  readonly capturedLength: number
  readonly linkType: number
  readonly data: Uint8Array
  readonly protocols: readonly string[]
  readonly changed: boolean
  readonly hasIssue: boolean
  readonly srcIpv4?: string
  readonly dstIpv4?: string
  readonly srcMac?: string
  readonly dstMac?: string
  readonly srcPort?: number
  readonly dstPort?: number
  readonly l4Proto?: 'tcp' | 'udp'
}
