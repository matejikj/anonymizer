/**
 * T-01 kernel contracts — shared facts, probes, and protocol descriptors.
 * Parsers emit structure; policy compiler decides protection; projections never re-parse.
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { WireRepresentationConstraint } from '../../mapping/types'

export const PROTOCOL_LAYERS = [
  'link',
  'network',
  'tunnel',
  'transport',
  'application',
] as const
export type ProtocolLayer = (typeof PROTOCOL_LAYERS)[number]

export const PROBE_RESULTS = ['no', 'need-more', 'candidate', 'claim'] as const
export type ProbeDecision = (typeof PROBE_RESULTS)[number]

export interface ProbeResult {
  readonly decision: ProbeDecision
  /** Safe reason code — never an original value. */
  readonly reasonCode?: string
  readonly confidence?: number
}

export type DispatchSelector =
  | { readonly kind: 'linktype'; readonly value: number }
  | { readonly kind: 'ethertype'; readonly value: number }
  | { readonly kind: 'ip-protocol'; readonly value: number }
  | { readonly kind: 'udp-port'; readonly value: number }
  | { readonly kind: 'tcp-port'; readonly value: number }
  | { readonly kind: 'content-type'; readonly value: string }
  | { readonly kind: 'ppid'; readonly value: number }

export interface ProtocolCapabilities {
  readonly structured: boolean
  readonly secretsMasked: boolean
  readonly supportsTcpReassembly: boolean
  readonly supportsUdpDatagram: boolean
}

export interface HandlerResourceLimits {
  readonly maxMessageBytes: number
  readonly maxFields: number
  readonly maxNesting: number
}

export interface ProtocolDocumentation {
  readonly title: string
  readonly specRefs: readonly string[]
  readonly supportProfile: 'structured' | 'mask-only' | 'identify-only' | 'encrypted-preserved' | 'unsupported'
}

export interface ProtocolDescriptor {
  readonly id: string
  readonly layer: ProtocolLayer
  readonly selectors: readonly DispatchSelector[]
  readonly priority: number
  readonly capabilities: ProtocolCapabilities
  readonly resourceLimits: HandlerResourceLimits
  readonly documentation: ProtocolDocumentation
}

/** Borrowed view — valid only while the owning BufferLease is held. */
export interface BorrowedByteView {
  readonly bytes: Uint8Array
  readonly byteOffset: number
  readonly byteLength: number
  readonly leaseId: number
}

export interface ProbeContext {
  readonly packetIndex: number
  readonly linkType: number
  readonly transport?: 'tcp' | 'udp'
  readonly srcPort?: number
  readonly dstPort?: number
  readonly nestingDepth: number
}

export interface AnalyzeContext extends ProbeContext {
  readonly generationId: string
  readonly sourceId: string
  readonly logicalMessageId: number
}

export interface ProtocolIdentityRef {
  readonly category: IdentityCategory
  readonly canonical: string
  readonly constraint: WireRepresentationConstraint
  readonly originalSpelling?: string
}

export type RecognitionState =
  | 'recognized'
  | 'candidate'
  | 'malformed'
  | 'truncated'
  | 'encrypted'
  | 'unsupported'
  | 'requires-reassembly'

export interface ProtocolFactHeader {
  readonly protocolId: string
  readonly recognition: RecognitionState
  /** Ownership of primary leaf bytes for this fact (packet-local). */
  readonly spanOffset: number
  readonly spanLength: number
  readonly parentFactId: number
  readonly logicalMessageId: number
  readonly packetIndex: number
}
