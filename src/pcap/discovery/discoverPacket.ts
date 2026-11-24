/**
 * Per-packet discovery — transformation intents without pseudonyms (Stage 8 / T-01 freeze).
 * T07: sanitize failures isolate to this packet; never abort the capture.
 */

import type { SanitizationPolicy } from '../sanitize/types'
import { sanitizePacket, type PacketInput } from '../sanitize/engine'
import { buildIsolatedPacketResult } from '../sanitize/packetIsolation'
import { IntentCollector } from './intentCollector'
import { PassthroughMapping } from './passthroughMapping'
import type { PacketDiscoveryResult } from './types'
import type { MediaFlowIndex } from './mediaFlowIndex'
import type { ReassemblyContext } from '../reassembly/types'
import { mergePacketWithReassemblyOverlay } from '../reassembly/capturePhase'
import { mergePatchesStrict } from '../plan/mergePatchesStrict'
import { freezeSanitizationResult } from '../kernel/adapters/freezeDiscovery'
import { internCoverage, internIssues } from '../kernel/identityIntern'
import type { FrozenPacketPlan } from '../kernel/frozenPlan'

const passthrough = new PassthroughMapping()

export function discoverPacket(
  packet: PacketInput,
  packetNumber: number,
  policy: SanitizationPolicy,
  mediaFlowIndex?: MediaFlowIndex,
  reassemblyContext?: ReassemblyContext,
  session?: {
    readonly generationId?: string
    readonly sourceId?: string
    readonly journal?: import('../kernel/journal').SemanticJournalBuilder
    readonly coapBlock2?: import('../sanitize/industrial/coapBlock2Session.ts').CoapBlock2Session
    readonly opcuaChannel?: import('../sanitize/industrial/opcuaChannelSession.ts').OpcuaChannelSession
    readonly proprietaryLight?: import('../sanitize/proprietaryLight/session.ts').ProprietaryLightSession
  },
): PacketDiscoveryResult {
  const intents = new IntentCollector()
  const kernelSymbolicOps: import('../kernel/operations').SymbolicOperation[] = []
  const overlay = reassemblyContext?.overlayFor(packet.index)
  // PF-06: run the structural decode once, with a throwaway passthrough mapping, purely to
  // find intents/coverage — defer the entity/fingerprint patch bytes rather than computing
  // them against the passthrough value now and discarding them (they're never used from this
  // pass). Frozen plan materializes real bytes later without retaining packet payloads.
  let result
  try {
    result = sanitizePacket(packet, policy, passthrough, {
      intents,
      mediaFlowIndex,
      reassemblyContext,
      deferPatchResolution: true,
      generationId: session?.generationId,
      sourceId: session?.sourceId,
      journal: session?.journal,
      kernelSymbolicOps,
      coapBlock2: session?.coapBlock2,
      opcuaChannel: session?.opcuaChannel,
      proprietaryLight: session?.proprietaryLight,
    })
  } catch {
    result = buildIsolatedPacketResult({
      packetIndex: packet.index,
      capturedLength: packet.capturedLength,
      linkType: packet.linkType,
      data: packet.data,
      policy,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: 0,
      deferPatchResolution: true,
    })
  }

  let isolationFallback = isolationFromIssues(result.issues)
  const merged = mergePacketWithReassemblyOverlay(result, overlay)

  try {
    mergePatchesStrict(packet.data.length, packet.index, merged.patches)
  } catch {
    result = buildIsolatedPacketResult({
      packetIndex: packet.index,
      capturedLength: packet.capturedLength,
      linkType: packet.linkType,
      data: packet.data,
      policy,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: 0,
      priorIssues: result.issues,
      deferPatchResolution: true,
    })
    isolationFallback = { unit: 'packet', reason: 'sanitizer-exception' }
    return buildDiscoveryReturn({
      packet,
      packetNumber,
      result,
      intents: new IntentCollector(),
      overlay: undefined,
      coverage: result.coverage,
      drop: result.drop,
      truncatedLength: result.truncatedLength,
      issues: result.issues,
      isolationFallback,
    })
  }

  for (const intent of merged.intents) {
    switch (intent.kind) {
      case 'entity-replacement':
        intents.recordEntityReplacement(
          intent.packetIndex,
          intent.offset,
          intent.category,
          intent.canonical,
          intent.byteLength,
          intent.constraint,
          intent.originalSpelling,
        )
        break
      case 'drop-record':
        intents.recordDrop(intent.packetIndex)
        break
      case 'truncation':
        intents.recordTruncation(intent.packetIndex, intent.truncatedLength)
        break
      case 'fixed-redaction':
        intents.recordFixedRedaction(intent.packetIndex, intent.offset, intent.byteLength)
        break
      case 'mask-range':
        intents.recordMaskRange(
          intent.packetIndex,
          intent.offset,
          intent.byteLength,
          intent.reason,
          intent.protocol,
        )
        break
    }
  }

  if (merged.drop) intents.recordDrop(packet.index)
  if (merged.truncatedLength !== undefined && !merged.intents.some((i) => i.kind === 'truncation')) {
    intents.recordTruncation(packet.index, merged.truncatedLength)
  }

  return buildDiscoveryReturn({
    packet,
    packetNumber,
    result,
    intents,
    overlay,
    coverage: merged.coverage,
    drop: merged.drop,
    truncatedLength: merged.truncatedLength,
    issues: merged.issues,
    isolationFallback,
  })
}

function isolationFromIssues(
  issues: readonly string[],
): PacketDiscoveryResult['isolationFallback'] {
  for (const issue of issues) {
    if (issue.startsWith('isolation:payload:')) {
      return { unit: 'payload', reason: 'sanitizer-exception' }
    }
    if (issue.startsWith('isolation:')) {
      return { unit: 'packet', reason: 'sanitizer-exception' }
    }
  }
  return undefined
}

/**
 * Per-packet hint maps are merged into the session-level maps right after discovery; keeping
 * them on every retained PacketDiscoveryResult costs a Map per RTP/SIP packet for nothing.
 */
export function withoutMergedHints(pd: PacketDiscoveryResult): PacketDiscoveryResult {
  if (pd.portFlowHints === undefined && pd.mediaPortPairs === undefined) return pd
  const { portFlowHints: _hints, mediaPortPairs: _pairs, ...rest } = pd
  return rest
}

function buildDiscoveryReturn(input: {
  packet: PacketInput
  packetNumber: number
  result: import('../sanitize/types').PacketSanitizationResult
  intents: IntentCollector
  overlay: ReturnType<NonNullable<ReassemblyContext['overlayFor']>> | undefined
  coverage: PacketDiscoveryResult['coverage']
  drop: boolean
  truncatedLength?: number
  issues: readonly string[]
  isolationFallback: PacketDiscoveryResult['isolationFallback']
}): PacketDiscoveryResult {
  const frozen: FrozenPacketPlan = freezeSanitizationResult({
    packetIndex: input.packet.index,
    packetNumber: input.packetNumber,
    bufferLength: input.packet.data.length,
    result: input.result,
    intents: input.intents.intents,
    overlay: input.overlay,
  })

  // Retained for every packet of the session: no per-packet resolve closure (the plan builder
  // renders `frozenPlan` directly) and no empty per-packet hint maps (merged into session maps).
  const portFlowHints = input.intents.portFlowHints
  const mediaPortPairs = input.intents.mediaPortPairs
  return {
    packetIndex: input.packet.index,
    packetNumber: input.packetNumber,
    intents: input.intents.intents,
    portFlowHints: portFlowHints.size > 0 ? portFlowHints : undefined,
    mediaPortPairs: mediaPortPairs.size > 0 ? mediaPortPairs : undefined,
    coverage: internCoverage(input.coverage),
    issues: internIssues(input.issues),
    drop: input.drop,
    truncatedLength: input.truncatedLength,
    frozenPlan: frozen,
    isolationFallback: input.isolationFallback,
  }
}
