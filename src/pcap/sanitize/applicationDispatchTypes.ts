/**
 * T-01.F — shared application dispatch registry types (avoids import cycles).
 */

import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec.ts'
import type { SemanticJournalBuilder } from '../kernel/journal.ts'
import type { SymbolicOperation } from '../kernel/operations.ts'
import type { ApplicationHandlerId } from '../kernel/applicationHandlers.ts'
import type { MappingLike } from '../anonymization/mapping'
import type { PatchCollector } from './PatchCollector.ts'
import type { InnerTransportHandler } from './tunnel.ts'
import type { LayerCoverage, SanitizationPolicy } from './types.ts'

export interface ApplicationFlowEndpoint {
  readonly srcIp: string
  readonly dstIp: string
}

export interface ApplicationDispatchContext {
  readonly data: Uint8Array
  readonly offset: number
  readonly length: number
  readonly srcPort: number
  readonly dstPort: number
  readonly transport: 'tcp' | 'udp'
  readonly flowEndpoint: ApplicationFlowEndpoint | null
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly policy: SanitizationPolicy
  readonly coverage: LayerCoverage[]
  readonly issues: string[]
  readonly lastCovered: number
  readonly packetIndex: number
  readonly intents: IntentCollector | undefined
  readonly skipAppLayer?: boolean
  readonly mediaFlowIndex?: MediaFlowIndex
  readonly payloadTime?: PayloadTimeSession
  readonly tunnelDepth?: number
  readonly generationId?: string
  readonly sourceId?: string
  /** T02.S4 — append structured map/mask ops from kernel fact projection. */
  readonly kernelSymbolicOps?: SymbolicOperation[]
  readonly journal?: SemanticJournalBuilder
  readonly onInnerTransport?: InnerTransportHandler
  /** T30 — CoAP Block2 cross-datagram transfer state (capture-scoped). */
  readonly coapBlock2?: import('./industrial/coapBlock2Session.ts').CoapBlock2Session
  /** T30 — OPC UA SecureChannel SecurityMode from OPN (capture-scoped). */
  readonly opcuaChannel?: import('./industrial/opcuaChannelSession.ts').OpcuaChannelSession
  /** T74 — proprietary / unknown payload light-inference session (diagnostic). */
  readonly proprietaryLight?: import('./proprietaryLight/session.ts').ProprietaryLightSession
}

export interface ApplicationDispatchHit {
  readonly lastCoveredOffset: number
  readonly drop?: boolean
}

export interface ApplicationDispatchEntry {
  readonly id: ApplicationHandlerId
  readonly dispatch: (ctx: ApplicationDispatchContext) => ApplicationDispatchHit | null
}
