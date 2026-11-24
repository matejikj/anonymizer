/**
 * PCAP processing pipeline — pull-read, analyze, discover, plan (Stage 8 / T-01).
 * Production session retains source Blob + descriptors + frozen plans — not raw packets[].
 */

import { CaptureFormat } from '../domain/types'
import { openIdentityInternScope, type IdentityInternScope } from '../kernel/identityIntern'
import type {
  ClassicPcapHeader,
  PacketEnvelope,
  PacketRecordDescriptor,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
  PacketTimestamp,
} from '../domain/types'
import type { SanitizationPolicy } from '../sanitize/types'
import { openPullCaptureReader } from '../capture/pullCaptureReader'
import { hydratePayloads } from '../capture/packetHydration'
import { runCaptureReassembly } from '../reassembly/capturePhase'
import { DEFAULT_REASSEMBLY_LIMITS } from '../reassembly/limits'
import type {
  PacketReassemblyOverlay,
  ReassemblyContext,
  ReassembledView,
  SctpOwnedPayloadSpan,
} from '../reassembly/types'
import {
  DEFAULT_PROCESSING_BATCH_SIZE,
  identitiesFromDiscovery,
  summarizeDiscovery,
} from '../discovery/discoveryPipeline'
import type { SourceDiscovery, TransformationIntent } from '../discovery/types'
import { discoverPacket, withoutMergedHints } from '../discovery/discoverPacket'
import { CoapBlock2Session } from '../sanitize/industrial/coapBlock2Session.ts'
import { OpcuaChannelSession } from '../sanitize/industrial/opcuaChannelSession.ts'
import { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import { analyzePackets, type AnalysisResult } from '../protocols/analysis'
import { buildDeterministicPlan } from '../plan/deterministicPlanBuilder'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import type { MappingSnapshot } from '../../mapping/types'
import type { PcapProfile } from '../profile/schema'
import { profileToSanitizationPolicy } from '../profile/presets'
import { snapshotFromWire, type WireMappingSnapshot } from '../../mapping/protocol'
import { MAX_ENTITY_CARDINALITY } from '../../domain/capabilityContract'
import { snapshotToWire as mappingSnapshotToWire } from '../../mapping/protocol'
import type { WireSourceDiscoveryPayload } from './workerProtocol'
import { containerToWire } from './containerWireAdapter'
import { packContainerBody } from './packedCaptureWire'
import { constraintKey } from '../../mapping/constraintKey'
import { entityOccurrencesToWire } from '../coverage'
import { buildOccurrenceIndexFromIntents } from '../coverage'
import { mergePortFlowHints, type PortFlowHint } from '../anonymization/portPolicy.ts'
import { BufferLeaseArena } from '../kernel/leases'
import { SessionBudgetAccountant } from '../kernel/budgets'
import {
  frozenPlanFromJournalRecord,
  SemanticJournalBuilder,
  type SemanticJournal,
} from '../kernel/journal'
import { getSharedProtocolManifest } from '../kernel/catalog'
import type { BudgetSnapshot } from '../kernel/budgets'
import type { LeaseStats } from '../kernel/leases'
import type { PacketDiscoveryResult } from '../discovery/types'
import type { PacketInput } from '../sanitize/engine'

/** Target live raw working set per hydrate window (well under 64 MiB kernel cap). */
const STREAMING_RAW_WINDOW_BYTES = 48 * 1024 * 1024

/**
 * Worker-side discovery. Unified coverage and exact occurrences are UI projections: the main
 * thread rebuilds them from the wire payload, nothing in the worker reads them, and on a
 * 225k-packet capture they (plus the structural spans that only feed them) cost ~1.3 KB/packet.
 */
export type ProcessingDiscovery = Omit<SourceDiscovery, 'unifiedCoverage' | 'exactOccurrences'>

export interface ProcessingSession {
  generationId: string
  sourceId: string
  format: CaptureFormat
  fileName: string
  policy: SanitizationPolicy
  /** Source blob for on-demand hydration (export/preview) — not a retained packet array. */
  sourceBlob: Blob
  descriptors: PacketRecordDescriptor[]
  checkpoints: SparseCheckpoint[]
  issues: ParseIssue[]
  discovery: ProcessingDiscovery
  reassembly: ReassemblyContext
  classicHeader?: ClassicPcapHeader
  pcapngSections?: PcapngSectionInfo[]
  pcapngInterfaces?: PcapngInterfaceInfo[]
  /** Kernel budget / lease instrumentation for this generation. */
  budgetSnapshot: BudgetSnapshot
  leaseStats: LeaseStats
  /** Frozen semantic journal — canonical post-discovery interpretation (R09). */
  journal: SemanticJournal
  /**
   * @deprecated T-01 — production must not retain raw packets. Present only when
   * `retainPacketsForTests` was requested; never set by the worker path.
   */
  packets?: PacketEnvelope[]
}

export interface ProcessCaptureInput {
  blob: Blob
  fileName: string
  format: CaptureFormat
  policy: SanitizationPolicy
  generationId: string
  sourceId: string
  batchSize?: number
  onProgress?: (phase: 'parsing' | 'analyzing' | 'discovering', done: number, total: number) => void
  isCancelled?: () => boolean
  /** Test/reference only — keeps envelopes after discovery (forbidden in production worker). */
  retainPacketsForTests?: boolean
}

export async function processCapture(input: ProcessCaptureInput): Promise<ProcessingSession> {
  if (input.isCancelled?.()) throw new Error('cancelled')

  // Ensure manifest is compiled once for this realm (analysis + kernel share it).
  getSharedProtocolManifest().compile()
  const internScope = openIdentityInternScope()
  try {
    return await processCaptureScoped(input, internScope)
  } finally {
    internScope.close()
  }
}

async function processCaptureScoped(
  input: ProcessCaptureInput,
  internScope: IdentityInternScope,
): Promise<ProcessingSession> {

  const budgets = new SessionBudgetAccountant()
  const leaseArena = new BufferLeaseArena()
  const journal = new SemanticJournalBuilder(input.generationId, input.sourceId, budgets)

  input.onProgress?.('parsing', 0, input.blob.size)
  const reader = await openPullCaptureReader(input.blob, input.format, {
    leaseArena,
    onProgress: (done, total) => {
      if (input.isCancelled?.()) throw new Error('cancelled')
      input.onProgress?.('parsing', done, total)
    },
  })

  // Pass 1 — drain pull batches without retaining O(capture) packet copies (R04).
  for (;;) {
    if (input.isCancelled?.()) throw new Error('cancelled')
    const batch = await reader.pull()
    if (!batch) break
    budgets.reserve('raw', batch.bytesHydrated, 'pull-reader')
    budgets.release('raw', batch.bytesHydrated)
    batch.release()
  }

  if (input.isCancelled?.()) throw new Error('cancelled')

  const descriptors = [...reader.descriptors]
  const checkpoints = [...reader.checkpoints]
  const issues = [...reader.issues]
  const stubs: PacketEnvelope[] = envelopesFromDescriptors(descriptors)
  const totalPackets = stubs.length

  input.onProgress?.('analyzing', 0, totalPackets)

  const windows = descriptorWindows(descriptors, STREAMING_RAW_WINDOW_BYTES)
  const reassemblyAcc = createReassemblyAccumulator()
  const analysisParts: { analysis: AnalysisResult; offset: number }[] = []
  const packetDiscovery: PacketDiscoveryResult[] = []
  const allIntents: TransformationIntent[] = []
  const portFlowHints = new Map<string, PortFlowHint>()
  const mediaPortPairs = new Map<string, string>()
  const sharedMediaFlowIndex = new MediaFlowIndex()
  const coapBlock2 = new CoapBlock2Session()
  const opcuaChannel = new OpcuaChannelSession()
  let carryIndices = new Set<number>()
  let packetsDone = 0

  for (const { start, end } of windows) {
    if (input.isCancelled?.()) throw new Error('cancelled')

    const hydrateIndices = new Set<number>(carryIndices)
    for (let i = start; i < end; i++) hydrateIndices.add(i)

    await hydrateStubPayloads(input.blob, descriptors, stubs, hydrateIndices, budgets)

    const partialReassembly = runCaptureReassembly(stubs, input.policy, DEFAULT_REASSEMBLY_LIMITS, {
      journal,
    })
    mergeIntoReassemblyAccumulator(reassemblyAcc, partialReassembly)
    const reassemblyContext = reassemblyContextFromAccumulator(reassemblyAcc)

    const windowSlice = stubs.slice(start, end)
    analysisParts.push({ analysis: analyzePackets(windowSlice), offset: start })

    const windowDiscoveryStart = packetDiscovery.length
    const batchSize = input.batchSize ?? DEFAULT_PROCESSING_BATCH_SIZE
    for (let i = start; i < end; i += batchSize) {
      if (input.isCancelled?.()) throw new Error('cancelled')
      const batchEnd = Math.min(i + batchSize, end)
      for (let idx = i; idx < batchEnd; idx++) {
        const pkt = stubs[idx]!
        const packetInput: PacketInput = {
          index: idx,
          data: pkt.data,
          capturedLength: pkt.capturedLength,
          originalLength: pkt.originalLength,
          linkType: pkt.linkType,
        }
        const pd = discoverPacket(
          packetInput,
          pkt.packetNumber,
          input.policy,
          sharedMediaFlowIndex,
          reassemblyContext,
          { generationId: input.generationId, sourceId: input.sourceId, journal, coapBlock2, opcuaChannel },
        )
        allIntents.push(...pd.intents)
        if (pd.portFlowHints) {
          for (const [canonical, flow] of pd.portFlowHints) {
            const merged = mergePortFlowHints(portFlowHints.get(canonical), flow)
            if (merged) portFlowHints.set(canonical, merged)
          }
        }
        if (pd.mediaPortPairs) {
          for (const [a, b] of pd.mediaPortPairs) {
            mediaPortPairs.set(a, b)
          }
        }
        packetDiscovery.push(withoutMergedHints(pd))
      }
      packetsDone = batchEnd
      input.onProgress?.('discovering', packetsDone, totalPackets)
    }

    projectDiscoveryIntoJournal(journal, packetDiscovery.slice(windowDiscoveryStart))

    const nextCarry = carryIndicesFromReassembly(partialReassembly, start, end)
    releaseStubPayloadsExcept(stubs, nextCarry, budgets)
    carryIndices = nextCarry
  }

  releaseStubPayloadsExcept(stubs, new Set(), budgets)

  coapBlock2.finalizeDiscovery(packetDiscovery)
  internScope.close()

  const analysis = mergeAnalysisResults(analysisParts, totalPackets)
  const entityOccurrenceIndex = buildOccurrenceIndexFromIntents(
    analysis.entities,
    analysis.entityOccurrenceLists,
    allIntents
      .filter((i) => i.kind === 'entity-replacement')
      .map((i) => ({
        entityKey: `${i.category}:${i.canonical}`,
        packetIndex: i.packetIndex,
      })),
  )

  const discovery: ProcessingDiscovery = {
    generationId: input.generationId,
    sourceId: input.sourceId,
    totalPackets,
    analysis,
    intents: allIntents,
    packetDiscovery,
    portFlowHints,
    mediaPortPairs,
    entityOccurrenceIndex,
  }

  const frozenJournal = journal.freeze()

  let classicHeader: ClassicPcapHeader | undefined
  let pcapngSections: PcapngSectionInfo[] | undefined
  let pcapngInterfaces: PcapngInterfaceInfo[] | undefined

  if (reader.format === CaptureFormat.ClassicPcap) {
    classicHeader = reader.classicHeader
  } else {
    pcapngSections = reader.pcapngSections ? [...reader.pcapngSections] : undefined
    pcapngInterfaces = reader.pcapngInterfaces ? [...reader.pcapngInterfaces] : undefined
  }

  const reassembly = reassemblyContextFromAccumulator(reassemblyAcc)

  const session: ProcessingSession = {
    generationId: input.generationId,
    sourceId: input.sourceId,
    format: input.format,
    fileName: input.fileName,
    policy: input.policy,
    sourceBlob: input.blob,
    descriptors,
    checkpoints,
    issues,
    discovery,
    reassembly,
    classicHeader,
    pcapngSections,
    pcapngInterfaces,
    budgetSnapshot: budgets.snapshot(),
    leaseStats: leaseArena.stats,
    journal: frozenJournal,
  }

  if (input.retainPacketsForTests) {
    const allIndices = new Set<number>()
    for (let i = 0; i < totalPackets; i++) allIndices.add(i)
    await hydrateStubPayloads(input.blob, descriptors, stubs, allIndices, budgets)
    session.packets = stubs.map((p) => ({ ...p, data: p.data.slice() }))
    for (const pkt of session.packets) {
      budgets.release('raw', pkt.data.byteLength)
    }
  }

  return session
}

function descriptorWindows(
  descriptors: readonly PacketRecordDescriptor[],
  maxBytes: number,
): { start: number; end: number }[] {
  const windows: { start: number; end: number }[] = []
  let start = 0
  let bytes = 0
  for (let i = 0; i < descriptors.length; i++) {
    const len = descriptors[i]!.capturedLength
    if (i > start && bytes + len > maxBytes) {
      windows.push({ start, end: i })
      start = i
      bytes = 0
    }
    bytes += len
  }
  if (start < descriptors.length) {
    windows.push({ start, end: descriptors.length })
  }
  return windows
}

async function hydrateStubPayloads(
  blob: Blob,
  descriptors: readonly PacketRecordDescriptor[],
  stubs: PacketEnvelope[],
  indices: ReadonlySet<number>,
  budgets: SessionBudgetAccountant,
): Promise<void> {
  const ordered = [...indices]
    .filter((i) => stubs[i]!.data.byteLength === 0)
    .sort((a, b) => a - b)
  if (ordered.length === 0) return

  const descSlice = ordered.map((i) => descriptors[i]!)
  const hydrated = await hydratePayloads(blob, descSlice)
  for (const i of ordered) {
    const d = descriptors[i]!
    const payload = hydrated.get(d.packetNumber)
    if (!payload) continue
    const copy = payload.slice()
    budgets.reserve('raw', copy.byteLength, 'window-hydrate')
    stubs[i] = { ...stubs[i]!, data: copy }
  }
}

function releaseStubPayloadsExcept(
  stubs: PacketEnvelope[],
  keep: ReadonlySet<number>,
  budgets: SessionBudgetAccountant,
): void {
  for (let i = 0; i < stubs.length; i++) {
    if (keep.has(i)) continue
    releaseOneStubPayload(stubs, i, budgets)
  }
}

function releaseOneStubPayload(
  stubs: PacketEnvelope[],
  index: number,
  budgets: SessionBudgetAccountant,
): void {
  const pkt = stubs[index]!
  const len = pkt.data.byteLength
  if (len === 0) return
  budgets.release('raw', len)
  stubs[index] = { ...pkt, data: EMPTY_PACKET_DATA }
}

function carryIndicesFromReassembly(
  partial: ReassemblyContext,
  windowStart: number,
  windowEnd: number,
): Set<number> {
  const keep = new Set<number>()
  for (const view of partial.views) {
    if (view.status === 'complete') continue
    for (const idx of view.packetIndices) {
      if (idx >= windowStart && idx < windowEnd) keep.add(idx)
    }
  }
  return keep
}

interface ReassemblyAccumulator {
  views: ReassembledView[]
  overlays: Map<number, PacketReassemblyOverlay>
  limitExceeded: boolean
  mediaFlowIndex: MediaFlowIndex
  sctpCompletePayloadSpans: Map<number, readonly SctpOwnedPayloadSpan[]>
}

function createReassemblyAccumulator(): ReassemblyAccumulator {
  return {
    views: [],
    overlays: new Map(),
    limitExceeded: false,
    mediaFlowIndex: new MediaFlowIndex(),
    sctpCompletePayloadSpans: new Map(),
  }
}

function mergeIntoReassemblyAccumulator(
  acc: ReassemblyAccumulator,
  partial: ReassemblyContext,
): void {
  acc.views.push(...partial.views)
  for (const [idx, overlay] of partial.overlays) {
    mergeReassemblyOverlay(acc.overlays, idx, overlay)
  }
  acc.limitExceeded = acc.limitExceeded || partial.limitExceeded
  acc.mediaFlowIndex = partial.mediaFlowIndex
  if (partial.sctpCompletePayloadSpans) {
    for (const [idx, spans] of partial.sctpCompletePayloadSpans) {
      acc.sctpCompletePayloadSpans.set(idx, spans)
    }
  }
}

function mergeReassemblyOverlay(
  overlays: Map<number, PacketReassemblyOverlay>,
  idx: number,
  overlay: PacketReassemblyOverlay,
): void {
  const existing = overlays.get(idx)
  if (!existing) {
    overlays.set(idx, overlay)
    return
  }
  overlays.set(idx, {
    patches: [...existing.patches, ...overlay.patches],
    coverage: [...existing.coverage, ...overlay.coverage],
    issues: [...existing.issues, ...overlay.issues],
    drop: existing.drop || overlay.drop,
    truncatedLength: overlay.truncatedLength ?? existing.truncatedLength,
    intents: [...existing.intents, ...overlay.intents],
    skipAppLayer: existing.skipAppLayer || overlay.skipAppLayer,
  })
}

function reassemblyContextFromAccumulator(acc: ReassemblyAccumulator): ReassemblyContext {
  const sctpCompletePayloadSpans = acc.sctpCompletePayloadSpans
  return {
    views: acc.views,
    overlays: acc.overlays,
    limitExceeded: acc.limitExceeded,
    mediaFlowIndex: acc.mediaFlowIndex,
    sctpCompletePayloadSpans,
    overlayFor(packetIndex: number) {
      return acc.overlays.get(packetIndex)
    },
    isSctpCompletePayload(packetIndex: number, offset: number) {
      const spans = sctpCompletePayloadSpans.get(packetIndex)
      if (!spans) return false
      for (const span of spans) {
        if (offset >= span.offset && offset < span.offset + span.length) return true
        if (offset === span.offset) return true
      }
      return false
    },
  }
}

function mergeAnalysisResults(
  parts: readonly { analysis: AnalysisResult; offset: number }[],
  totalPackets: number,
): AnalysisResult {
  const histogram = new Map<string, number>()
  const coverageMap = new Map<
    string,
    { packetCount: number; unsupportedCount: number; issues: Set<string> }
  >()
  const entityMap = new Map<string, AnalysisResult['entities'][number]>()
  const summaries: AnalysisResult['summaries'][number][] = new Array(totalPackets)
  const entityOccurrenceLists = new Map<string, number[]>()
  const unsupportedLinkTypes = new Set<number>()
  let decodedPackets = 0
  let entityOverflow = false

  for (const { analysis, offset } of parts) {
    for (const [proto, count] of analysis.histogram.counts) {
      histogram.set(proto, (histogram.get(proto) ?? 0) + count)
    }
    for (const c of analysis.coverage) {
      let entry = coverageMap.get(c.protocolId)
      if (!entry) {
        entry = { packetCount: 0, unsupportedCount: 0, issues: new Set() }
        coverageMap.set(c.protocolId, entry)
      }
      entry.packetCount += c.packetCount
      entry.unsupportedCount += c.unsupportedCount
      for (const issue of c.issues) entry.issues.add(issue)
    }
    for (const ent of analysis.entities) {
      const existing = entityMap.get(ent.key)
      if (!existing) {
        entityMap.set(ent.key, ent)
      } else {
        entityMap.set(ent.key, {
          ...existing,
          count: existing.count + ent.count,
          firstPacket: Math.min(existing.firstPacket, ent.firstPacket),
        })
      }
    }
    for (let i = 0; i < analysis.summaries.length; i++) {
      summaries[offset + i] = analysis.summaries[i]!
    }
    for (const [key, indices] of analysis.entityOccurrenceLists) {
      const merged = [...(entityOccurrenceLists.get(key) ?? []), ...indices.map((i) => i + offset)]
      entityOccurrenceLists.set(key, merged)
    }
    for (const lt of analysis.unsupportedLinkTypes) unsupportedLinkTypes.add(lt)
    decodedPackets += analysis.decodedPackets
    entityOverflow = entityOverflow || analysis.entityOverflow
  }

  const coverage: {
    protocolId: string
    packetCount: number
    unsupportedCount: number
    issues: string[]
  }[] = []
  for (const [id, entry] of coverageMap) {
    coverage.push({
      protocolId: id,
      packetCount: entry.packetCount,
      unsupportedCount: entry.unsupportedCount,
      issues: [...entry.issues],
    })
  }

  const entities = [...entityMap.values()].sort((a, b) => a.firstPacket - b.firstPacket)

  return {
    histogram: { counts: histogram },
    coverage,
    entities,
    summaries,
    totalPackets,
    decodedPackets,
    unsupportedLinkTypes,
    entityOverflow,
    // Only ever fed buildUnifiedCoverageModel, which the worker session no longer builds.
    structuralSpans: [],
    entityOccurrenceLists,
  }
}

/**
 * Plan build prefers journal rows that carry symbolic ops (kernel-native freeze).
 * Legacy deferred `resolvePatches` closures are not serializable into the journal and
 * remain on `discovery.packetDiscovery` until sanitizers emit structured ops (R09).
 */
function packetDiscoveryForPlanBuild(
  session: ProcessingSession,
  discoveryPolicyMatches: boolean,
): readonly PacketDiscoveryResult[] | undefined {
  if (!discoveryPolicyMatches) return undefined
  const base = session.discovery.packetDiscovery
  const { journal } = session
  if (journal.packets.length === 0) return base

  const journalByIndex = new Map<number, (typeof journal.packets)[number]>()
  for (const rec of journal.packets) {
    journalByIndex.set(rec.packetIndex, rec)
  }

  return base.map((pd) => {
    const rec = journalByIndex.get(pd.packetIndex)
    if (!rec || rec.ops.length === 0) return pd
    const plan = frozenPlanFromJournalRecord(rec)
    // Journal rows carry kernel-native ops only; discovery-time legacyResolve still holds
    // application masks and other deferred patches that must run at plan/export (R09/R01).
    const legacyResolve = pd.frozenPlan?.legacyResolve
    const mergedPlan =
      legacyResolve !== undefined ? { ...plan, legacyResolve } : plan
    return {
      ...pd,
      coverage: rec.coverage,
      issues: [...rec.issues],
      drop: rec.drop,
      truncatedLength: rec.truncatedLength,
      frozenPlan: mergedPlan,
    }
  })
}

function projectDiscoveryIntoJournal(
  journal: SemanticJournalBuilder,
  windowDiscovery: readonly PacketDiscoveryResult[],
): void {
  for (const pd of windowDiscovery) {
    const plan = pd.frozenPlan
    if (!plan) continue
    // Histogram only — a JournalFact per coverage row exhausts journalMaxBytes on ~100 MiB
    // captures (~250k packets × L2–L4 layers). Kernel FactWriter still records structured facts.
    for (const c of plan.coverage) {
      journal.noteRecognition(
        c.status === 'covered' || c.status === 'redacted'
          ? 'recognized'
          : c.status === 'malformed'
            ? 'malformed'
            : c.status === 'requires-reassembly'
              ? 'requires-reassembly'
              : 'unsupported',
      )
    }
    const kernelNative = plan.ops.length > 0
    journal.addPacket({
      packetIndex: plan.packetIndex,
      packetNumber: plan.packetNumber,
      bufferLength: plan.bufferLength,
      drop: plan.drop,
      truncatedLength: plan.truncatedLength,
      coverage: plan.coverage,
      issues: plan.issues,
      // Legacy intents remain on discovery.packetDiscovery (closures / deferred bridge).
      intents: kernelNative ? plan.intents : [],
      ops: plan.ops,
      factIds: journal.factIdsForPacket(plan.packetIndex),
    })
  }
}

export function containerMetadataFromSession(session: ProcessingSession) {
  return containerToWire({
    descriptors: session.descriptors,
    checkpoints: session.checkpoints,
    issues: session.issues,
    classicHeader: session.classicHeader,
    pcapngSections: session.pcapngSections,
    pcapngInterfaces: session.pcapngInterfaces,
    packetDiscovery: session.discovery.packetDiscovery,
  })
}

/**
 * R10 — packed+transferable discover payload (descriptors + coverage columns).
 * Prefer this on the worker→UI boundary; {@link containerMetadataFromSession} remains
 * for in-process tests that do not need transferable buffers.
 */
export function containerMetadataFromSessionTransferable(session: ProcessingSession): {
  wire: ReturnType<typeof containerMetadataFromSession>
  transfers: ArrayBuffer[]
} {
  const { packed, transfers } = packContainerBody({
    summaries: session.discovery.analysis.summaries,
    descriptors: session.descriptors,
    checkpoints: session.checkpoints,
    issues: session.issues,
    classicHeader: session.classicHeader,
    pcapngSections: session.pcapngSections,
    pcapngInterfaces: session.pcapngInterfaces,
    packetDiscovery: session.discovery.packetDiscovery,
  })
  return {
    wire: {
      descriptors: [],
      checkpoints: packed.checkpoints,
      issues: packed.issues,
      classicHeader: packed.classicHeader,
      pcapngSections: packed.pcapngSections,
      pcapngInterfaces: packed.pcapngInterfaces,
      packetDiscovery: [],
      packed,
    },
    transfers,
  }
}

export function discoveryToWire(
  discovery: ProcessingDiscovery,
  options?: { readonly uniqueIdentityIntents?: boolean },
): WireSourceDiscoveryPayload {
  const summary = summarizeDiscovery(discovery)
  const uniqueIdentityIntents = options?.uniqueIdentityIntents !== false
  const entityIntents = discovery.intents.filter((i) => i.kind === 'entity-replacement')
  const mappedIntents: WireSourceDiscoveryPayload['intents'] = []
  if (uniqueIdentityIntents) {
    // Alias closure only needs one seed per (category, canonical, constraint, spelling).
    // Sending every MAC/IP occurrence (~1.4M on a 100 MiB fixture) hangs worker postMessage.
    const seen = new Set<string>()
    for (const i of entityIntents) {
      const key = `${i.category}:${i.canonical}:${constraintKey(i.constraint)}:${i.originalSpelling ?? ''}`
      if (seen.has(key)) continue
      seen.add(key)
      mappedIntents.push({
        kind: 'entity-replacement',
        packetIndex: i.packetIndex,
        offset: i.offset,
        byteLength: i.byteLength,
        category: i.category,
        canonical: i.canonical,
        constraint: i.constraint,
        originalSpelling: i.originalSpelling,
      })
    }
  } else {
    for (const i of entityIntents) {
      mappedIntents.push({
        kind: 'entity-replacement',
        packetIndex: i.packetIndex,
        offset: i.offset,
        byteLength: i.byteLength,
        category: i.category,
        canonical: i.canonical,
        constraint: i.constraint,
        originalSpelling: i.originalSpelling,
      })
    }
  }
  return {
    generationId: summary.generationId,
    sourceId: summary.sourceId,
    totalPackets: summary.totalPackets,
    decodedPackets: summary.decodedPackets,
    entityCount: summary.entityCount,
    intentCount: summary.intentCount,
    entityOverflow: summary.entityOverflow,
    coverage: summary.coverage.map((c) => ({
      protocolId: c.protocolId,
      packetCount: c.packetCount,
      unsupportedCount: c.unsupportedCount,
      issues: [...c.issues],
    })),
    entities: summary.entities.map((e) => ({
      key: e.key,
      category: e.category,
      value: e.value,
      firstPacket: e.firstPacket,
      count: e.count,
    })),
    summaries: summary.summaries.map((s) => ({
      packetNumber: s.packetNumber,
      // R10 — avoid cloning per-packet protocol string arrays (~21 MiB JSON on 100 MiB
      // captures). Histogram/UI use wire.coverage + plan.primaryProtocol instead.
      protocols: s.protocols.length > 0 ? [s.protocols[s.protocols.length - 1]!] : [],
      issues: s.issues.length > 0 ? [...s.issues] : [],
      hasUnsupported: s.hasUnsupported,
    })),
    intents: mappedIntents,
    entityOccurrences: entityOccurrencesToWire(discovery.entityOccurrenceIndex),
    portFlowHints: [...discovery.portFlowHints.entries()].map(([canonical, flow]) => ({
      canonical,
      flow,
    })),
  }
}

/** Slim envelopes from descriptors — no payload bytes (plan metadata only). */
export function envelopesFromDescriptors(
  descriptors: readonly PacketRecordDescriptor[],
): PacketEnvelope[] {
  return descriptors.map((d) => ({
    packetNumber: d.packetNumber,
    timestamp: d.timestamp as PacketTimestamp,
    capturedLength: d.capturedLength,
    originalLength: d.originalLength,
    linkType: d.linkType,
    interfaceId: d.interfaceId,
    sectionIndex: d.sectionIndex,
    fileOffset: d.fileOffset,
    data: EMPTY_PACKET_DATA,
  }))
}

const EMPTY_PACKET_DATA = new Uint8Array(0)

export function buildPlanFromSession(
  session: ProcessingSession,
  snapshot: MappingSnapshot,
  profile: PcapProfile,
  onProgress?: (done: number, total: number) => void,
  options?: {
    readonly sourceId?: string
    readonly unresolvedClosureFailures?: readonly {
      readonly packetIndex: number
      readonly category: string
    }[]
  },
): PcapPlanSnapshot {
  const policy = profileToSanitizationPolicy(profile)
  // PF-19: discovery's fast path reuses discovery-time coverage/drop/truncatedLength/issues
  // verbatim — only valid when the policy building the plan now is the one discovery ran under.
  const discoveryPolicyMatches = JSON.stringify(policy) === JSON.stringify(session.policy)
  const metaPackets = session.packets ?? envelopesFromDescriptors(session.descriptors)
  const packetDiscovery = packetDiscoveryForPlanBuild(session, discoveryPolicyMatches)
  const entities = session.discovery.analysis?.entities ?? []
  const leakOriginals = entities.slice(0, MAX_ENTITY_CARDINALITY).map((e) => ({
    category: e.category,
    value: e.value,
    packetNumber: e.firstPacket,
  }))

  return buildDeterministicPlan({
    generationId: session.generationId,
    profile,
    format: session.format,
    fileName: session.fileName,
    packets: metaPackets,
    policy,
    snapshot,
    reassemblyContext: session.reassembly,
    classicHeader: session.classicHeader,
    pcapngSections: session.pcapngSections,
    pcapngInterfaces: session.pcapngInterfaces,
    packetDiscovery,
    bufferLengths: session.descriptors.map((d) => d.capturedLength),
    onProgress,
    sourceId: options?.sourceId ?? session.sourceId,
    unresolvedClosureFailures: options?.unresolvedClosureFailures,
    leakOriginals,
  })
}

export function buildPlanFromWireSnapshot(
  session: ProcessingSession,
  wire: WireMappingSnapshot,
  profile: PcapProfile,
  onProgress?: (done: number, total: number) => void,
  options?: {
    readonly unresolvedClosureFailures?: readonly {
      readonly packetIndex: number
      readonly category: string
    }[]
  },
): PcapPlanSnapshot {
  return buildPlanFromSession(session, snapshotFromWire(wire), profile, onProgress, {
    unresolvedClosureFailures: options?.unresolvedClosureFailures,
  })
}

export { identitiesFromDiscovery, mappingSnapshotToWire }
