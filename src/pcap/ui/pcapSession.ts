/**
 * Module-scoped slim PCAP session (Stage 9) — no persistent PacketEnvelope[] copies.
 * Packet payloads load on demand via pcapPreviewController.
 */

import type { CaptureFormat, ParseIssue } from '../domain/types'
import { mergeCoverageRollup } from '../processing/packedCaptureWire'
import { indexedPacketProtocols } from '../coverage/packetProtocolIndex'
import type { AnalysisResult, EntityEntry, PacketSummary } from '../protocols/analysis'
import type { LayerCoverage, SanitizationPolicy } from '../sanitize/types'
import type { PacketDiscoveryResult } from '../discovery/types'
import { createDefaultPcapProfile, profileToSanitizationPolicy } from '../profile/presets'
import type { PcapProfile } from '../profile/schema'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import { EMPTY_INCIDENT_LOG_SNAPSHOT, PCAP_ENGINE_VERSION, hashProfile } from '../export/planSnapshot'
import type { PcapSourceDescriptor } from './pcapSourceDescriptor'
import type { PacketRecordDescriptor } from '../domain/types'
import type { EntityOccurrenceIndex, UnifiedCoverageModel, UnifiedLayerCoverage } from '../coverage/types'
import {
  buildSessionCoverage,
  countUnsupportedFromUnified,
  packetHasProtocol,
  unifiedSpansForPacket,
} from '../coverage'
import { analysisFromWire } from '../processing/discoveryWireAdapter'
import { planPacketDropped } from '../processing/planWireAdapter'
import {
  parseDisplayFilter,
  evaluateDisplayFilter,
  entityKeyFromExpression,
  isEntityFilterExpression,
  type PacketFilterContext,
} from '../displayFilter'
import type { EndpointPair } from './packetListRowModel'
import { withViewMappedEndpoints, mapEndpointValues } from './viewFilterContext'
import { counterpartEndpointPair, type CounterpartEndpointFields } from './counterpartFieldExtraction'

function emptyAnalysis(): AnalysisResult {
  return {
    histogram: { counts: new Map() },
    coverage: [],
    entities: [],
    summaries: [],
    totalPackets: 0,
    decodedPackets: 0,
    unsupportedLinkTypes: new Set(),
    entityOverflow: false,
    structuralSpans: [],
    entityOccurrenceLists: new Map(),
  }
}

export type PcapPhase = 'empty' | 'preflight' | 'analyzing' | 'workspace' | 'error'

export type AnonymizationStatus = 'covered' | 'exposed' | 'blocked'
export type IntegrityStatus = 'ok' | 'warnings' | 'unverifiable'
export type CompatibilityStatus = 'valid' | 'valid-with-drops' | 'blocked'

export interface PcapFilterState {
  packetFrom: number | null
  packetTo: number | null
  protocol: string
  entityKey: string
  textQuery: string
  issueOnly: boolean
  changedOnly: boolean
}

export interface PcapSessionStatuses {
  anonymization: AnonymizationStatus
  integrity: IntegrityStatus
  compatibility: CompatibilityStatus
  truncatedCount: number
  unsupportedCount: number
  droppedCount: number
  changedCount: number
  reassemblyCount: number
  heuristicCount: number
  issueCount: number
}

/** Slim PCAP session — compatible with SourceArtifact pcap descriptor. */
export interface PcapSession {
  readonly generation: number
  readonly generationId: string
  readonly fileName: string
  readonly fileSize: number
  readonly format: CaptureFormat
  readonly sourceFile: File
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly issues: readonly ParseIssue[]
  readonly analysis: AnalysisResult
  readonly packetDiscovery: readonly PacketDiscoveryResult[]
  readonly unifiedCoverage: UnifiedCoverageModel
  readonly entityOccurrenceIndex: EntityOccurrenceIndex
  readonly plan: PcapPlanSnapshot
  readonly mappingRevision: number
  readonly profile: PcapProfile
  readonly profileHash: string
  readonly policy: SanitizationPolicy
  readonly statuses: PcapSessionStatuses
  /** R10 — worker-side coverage totals; kept so plan rebuilds recompute honest statuses. */
  readonly coverageRollup?: import('../processing/packedCaptureWire').WireCoverageRollup
  readonly classicHeader?: PcapSourceDescriptor['classicHeader']
  readonly pcapngSections?: PcapSourceDescriptor['pcapngSections']
  readonly pcapngInterfaces?: PcapSourceDescriptor['pcapngInterfaces']
  /** 'recover' — the loaded file is anonymized and `counterpartSource` holds its deanonymized bytes. */
  readonly sessionKind: 'anonymize' | 'recover'
  readonly counterpartSource?: RecoveryCounterpartSource
}

/** Independent byte source for the "anonymized" pane of a recovery session. */
export interface RecoveryCounterpartSource {
  readonly blob: Blob
  readonly byOriginalPacketNumber: ReadonlyMap<number, PacketRecordDescriptor>
  readonly anonymizedToOriginal: ReadonlyArray<number>
  /** Precomputed real addressing fields, keyed by anonymized packet number — see
   * `counterpartFieldExtraction.ts` for why these can't just reuse the alias-mapped entity data. */
  readonly endpointsByAnonymizedPacketNumber: ReadonlyMap<number, CounterpartEndpointFields>
}

let session: PcapSession | null = null
let generationCounter = 0

export function getPcapSession(): PcapSession | null {
  return session
}

export function clearPcapSession(): void {
  session = null
}

export function getPacketCount(): number {
  return session?.descriptors.length ?? 0
}

export interface CreateSlimPcapSessionInput {
  descriptor: PcapSourceDescriptor
  generationId: string
  analysis: AnalysisResult
  packetDiscovery: readonly PacketDiscoveryResult[]
  unifiedCoverage?: UnifiedCoverageModel
  entityOccurrenceIndex?: EntityOccurrenceIndex
  entityIntents?: ReadonlyArray<{ category: string; canonical: string; packetIndex: number }>
  /** R10 — worker-side sanitizer coverage totals when per-span rows are not on the UI thread. */
  coverageRollup?: import('../processing/packedCaptureWire').WireCoverageRollup
  plan: PcapPlanSnapshot
  mappingRevision: number
  profile: PcapProfile
}

export function createSlimPcapSession(input: CreateSlimPcapSessionInput): PcapSession {
  generationCounter++
  const policy = profileToSanitizationPolicy(input.profile)
  const coverageBundle =
    input.unifiedCoverage && input.entityOccurrenceIndex
      ? { unifiedCoverage: input.unifiedCoverage, entityOccurrenceIndex: input.entityOccurrenceIndex }
      : buildSessionCoverage({
          packetCount: input.descriptor.descriptors.length,
          analysis: input.analysis,
          packetDiscovery: input.packetDiscovery,
          entityIntents: input.entityIntents,
        })
  const unifiedCoverage = mergeCoverageRollup(coverageBundle.unifiedCoverage, input.coverageRollup)
  const statuses = computeStatusesFromDiscovery({
    issues: input.descriptor.issues,
    analysis: input.analysis,
    packetDiscovery: input.packetDiscovery,
    unifiedCoverage,
    entityOccurrenceIndex: coverageBundle.entityOccurrenceIndex,
    plan: input.plan,
    policy,
    coverageRollup: input.coverageRollup,
  })

  session = {
    generation: generationCounter,
    generationId: input.generationId,
    fileName: input.descriptor.fileName,
    fileSize: input.descriptor.fileSize,
    format: input.descriptor.format,
    sourceFile: input.descriptor.sourceFile,
    descriptors: input.descriptor.descriptors,
    issues: input.descriptor.issues,
    analysis: input.analysis,
    packetDiscovery: input.packetDiscovery,
    unifiedCoverage,
    entityOccurrenceIndex: coverageBundle.entityOccurrenceIndex,
    plan: input.plan,
    mappingRevision: input.mappingRevision,
    profile: input.profile,
    profileHash: hashProfile(input.profile),
    policy,
    statuses,
    coverageRollup: input.coverageRollup,
    classicHeader: input.descriptor.classicHeader,
    pcapngSections: input.descriptor.pcapngSections,
    pcapngInterfaces: input.descriptor.pcapngInterfaces,
    sessionKind: 'anonymize',
  }
  return session
}

/**
 * Attaches an independently-sourced deanonymized byte counterpart to the current session and
 * marks it as a recovery session. Mutates the published session in place — call after the
 * session has already been created normally by loading the anonymized file.
 */
export function attachRecoveryCounterpart(counterpart: RecoveryCounterpartSource): void {
  if (!session) return
  session = { ...session, sessionKind: 'recover', counterpartSource: counterpart }
}

/** Minimal session for preflight/replace tests — no packets. */
export function createMinimalPcapSession(init: {
  fileName: string
  fileSize: number
  format: CaptureFormat
  issues?: ParseIssue[]
  profile?: PcapProfile
}): PcapSession {
  generationCounter++
  const profile = init.profile ?? createDefaultPcapProfile().profile
  const policy = profileToSanitizationPolicy(profile)
  const emptyFile = new File([], init.fileName)
  const plan: PcapPlanSnapshot = {
    generationId: String(generationCounter),
    pcapLevel: profile.preset,
    profileId: profile.id,
    profileHash: hashProfile(profile),
    format: init.format,
    fileName: init.fileName,
    engineVersion: PCAP_ENGINE_VERSION,
    packets: [],
    droppedPacketNumbers: [],
    timestamps: profile.mapping.timestamps,
    timestampAnchorSeed: hashProfile(profile),
    changeCategoryTotals: {
      mapped: 0,
      redacted: 0,
      'masked-content': 0,
      'preserved-encrypted': 0,
      'preserved-for-diagnostics': 0,
      'user-requested-drop': 0,
      blocked: 0,
    },
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
    incidents: EMPTY_INCIDENT_LOG_SNAPSHOT,
  }
  const analysis: AnalysisResult = emptyAnalysis()
  const coverageBundle = buildSessionCoverage({
    packetCount: 0,
    analysis,
    packetDiscovery: [],
  })

  session = {
    generation: generationCounter,
    generationId: String(generationCounter),
    fileName: init.fileName,
    fileSize: init.fileSize,
    format: init.format,
    sourceFile: emptyFile,
    descriptors: [],
    issues: init.issues ?? [],
    analysis,
    packetDiscovery: [],
    unifiedCoverage: coverageBundle.unifiedCoverage,
    entityOccurrenceIndex: coverageBundle.entityOccurrenceIndex,
    plan,
    mappingRevision: 0,
    profile,
    profileHash: hashProfile(profile),
    policy,
    statuses: computeStatusesFromDiscovery({
      issues: init.issues ?? [],
      analysis,
      unifiedCoverage: coverageBundle.unifiedCoverage,
      entityOccurrenceIndex: coverageBundle.entityOccurrenceIndex,
      plan,
      policy,
    }),
    sessionKind: 'anonymize',
  }
  return session
}

export function updateSessionPlan(plan: PcapPlanSnapshot, profile: PcapProfile, mappingRevision: number): void {
  if (!session) return
  const policy = profileToSanitizationPolicy(profile)
  session = {
    ...session,
    plan,
    profile,
    profileHash: hashProfile(profile),
    policy,
    mappingRevision,
    statuses: computeStatusesFromDiscovery({
      issues: session.issues,
      analysis: session.analysis,
      packetDiscovery: session.packetDiscovery,
      unifiedCoverage: session.unifiedCoverage,
      entityOccurrenceIndex: session.entityOccurrenceIndex,
      plan,
      policy,
      coverageRollup: session.coverageRollup,
    }),
  }
}

/**
 * Full refresh for a PCAP anonymization level switch whose policy actually changed the
 * sanitization dispatch (media disposition, SIP fail-closed handling, TTL/window
 * preservation, heuristic scan on/off, ...). `updateSessionPlan` only replaces the plan
 * itself and reuses discovery's per-packet coverage/drop/analysis verbatim — correct only
 * when the policy hasn't changed since discovery ran. Those fields are policy-dependent, not
 * just the mapped byte *values* the fast plan-rebuild path defers, so switching levels needs
 * discovery re-run under the new policy too — otherwise the privacy report (and the coverage
 * tab, status badges, ...) keep evaluating stale disposition from whichever level the file
 * was first opened under.
 */
export function updateSessionDiscoveryAndPlan(input: {
  analysis: AnalysisResult
  packetDiscovery: readonly PacketDiscoveryResult[]
  unifiedCoverage: UnifiedCoverageModel
  entityOccurrenceIndex: EntityOccurrenceIndex
  issues: readonly ParseIssue[]
  plan: PcapPlanSnapshot
  profile: PcapProfile
  mappingRevision: number
  /** R10 — rollup from the re-run discover; `packetDiscovery` is empty on the packed path. */
  coverageRollup?: import('../processing/packedCaptureWire').WireCoverageRollup
}): void {
  if (!session) return
  const policy = profileToSanitizationPolicy(input.profile)
  const unifiedCoverage = mergeCoverageRollup(input.unifiedCoverage, input.coverageRollup)
  session = {
    ...session,
    analysis: input.analysis,
    packetDiscovery: input.packetDiscovery,
    unifiedCoverage,
    coverageRollup: input.coverageRollup,
    entityOccurrenceIndex: input.entityOccurrenceIndex,
    issues: [...input.issues],
    plan: input.plan,
    profile: input.profile,
    profileHash: hashProfile(input.profile),
    policy,
    mappingRevision: input.mappingRevision,
    statuses: computeStatusesFromDiscovery({
      issues: input.issues,
      analysis: input.analysis,
      packetDiscovery: input.packetDiscovery,
      unifiedCoverage,
      entityOccurrenceIndex: input.entityOccurrenceIndex,
      plan: input.plan,
      policy,
      coverageRollup: input.coverageRollup,
    }),
  }
}

export function computeStatusesFromDiscovery(input: {
  issues: readonly ParseIssue[]
  analysis: AnalysisResult
  packetDiscovery?: readonly PacketDiscoveryResult[]
  unifiedCoverage: UnifiedCoverageModel
  entityOccurrenceIndex?: EntityOccurrenceIndex
  plan: PcapPlanSnapshot
  policy: SanitizationPolicy
  coverageRollup?: import('../processing/packedCaptureWire').WireCoverageRollup
}): PcapSessionStatuses {
  let truncatedCount = 0
  let unsupportedCount = countUnsupportedFromUnified(input.unifiedCoverage)
  let droppedCount = input.plan.droppedPacketNumbers.length
  let changedCount = 0
  let reassemblyCount = 0
  let heuristicCount = input.unifiedCoverage.totalHeuristicSpans
  let issueCount = input.issues.length
  let preservedUnsafeCount = 0

  if (input.coverageRollup) {
    truncatedCount = input.coverageRollup.truncatedPacketCount
    preservedUnsafeCount = input.coverageRollup.preservedUnsafeSpans
    heuristicCount = Math.max(heuristicCount, input.coverageRollup.totalHeuristicSpans)
    droppedCount += input.coverageRollup.discoveryDropCount
    issueCount += input.coverageRollup.discoveryIssueCount
    // Packed path: `perPacket` only carries analysis spans, sanitizer spans are in the rollup.
    // Take the larger of the two per kind instead of summing (they can describe the same span).
    let analysisReassembly = 0
    let analysisMalformed = 0
    for (const spans of input.unifiedCoverage.perPacket) {
      for (const span of spans) {
        if (span.status === 'requires-reassembly') analysisReassembly++
        if (span.status === 'malformed') analysisMalformed++
      }
    }
    reassemblyCount = Math.max(analysisReassembly, input.coverageRollup.requiresReassemblySpans)
    issueCount += Math.max(analysisMalformed, input.coverageRollup.malformedSpans)
  } else {
    for (const spans of input.unifiedCoverage.perPacket) {
      if (spans.some((s) => s.status === 'truncated')) truncatedCount++
      for (const span of spans) {
        if (span.status === 'requires-reassembly') reassemblyCount++
        if (span.status === 'malformed') issueCount++
        if (span.status === 'preserved-unsafe') preservedUnsafeCount++
      }
    }

    if (input.packetDiscovery) {
      for (const pd of input.packetDiscovery) {
        if (pd.drop) droppedCount++
        issueCount += pd.issues.length
      }
    }
  }

  for (const summary of input.analysis.summaries) {
    issueCount += summary.issues.length
  }

  if (typeof input.plan.packetsWithChanges === 'number') {
    changedCount = input.plan.packetsWithChanges
  } else {
    for (const p of input.plan.packets) {
      if (p.patches.length > 0 || p.truncatedLength !== undefined) changedCount++
    }
  }

  let anonymization: AnonymizationStatus = 'covered'
  if (
    unsupportedCount > 0
    && !input.policy.truncateUnsupported
    // Step 4/7: mask-in-place handles unsupported payloads without leaving content exposed.
    && input.policy.unsupportedPayloadPolicy !== 'mask-in-place'
  ) {
    anonymization = 'exposed'
  }
  // PF-19: must match buildPrivacyReport's requiresUnsafeConfirmation (privacyReport.ts) —
  // otherwise the export dialog can decide the export "looks safe" (no risk section shown,
  // no acknowledgement recorded) while the stricter privacy-report assertion still rejects it
  // for the very same preserved-unsafe spans, leaving the user stuck with no way to proceed.
  if (preservedUnsafeCount > 0) {
    anonymization = 'exposed'
  }

  const fatalIssues = input.issues.filter((i) => i.severity >= 2)
  if (fatalIssues.length > 0) anonymization = 'blocked'
  if (input.analysis.entityOverflow) anonymization = 'blocked'
  if (input.entityOccurrenceIndex?.overflow) anonymization = 'blocked'

  if (
    anonymization === 'covered'
    && unsupportedCount > 0
    && !input.policy.truncateUnsupported
    && input.policy.unsupportedPayloadPolicy !== 'mask-in-place'
  ) {
    anonymization = 'exposed'
  }

  const integrity: IntegrityStatus =
    reassemblyCount > 0 || heuristicCount > 0 ? 'unverifiable' : issueCount > 0 ? 'warnings' : 'ok'

  const compatibility: CompatibilityStatus =
    fatalIssues.length > 0 ? 'blocked' : droppedCount > 0 ? 'valid-with-drops' : 'valid'

  return {
    anonymization,
    integrity,
    compatibility,
    truncatedCount,
    unsupportedCount,
    droppedCount,
    changedCount,
    reassemblyCount,
    heuristicCount,
    issueCount,
  }
}

export interface PacketRowMeta {
  summary: PacketSummary | null
  descriptor: PacketRecordDescriptor | null
  discovery: PacketDiscoveryResult | null
  changed: boolean
  drop: boolean
}

export function getPacketRowMeta(packetIndex: number): PacketRowMeta {
  if (!session || packetIndex < 0 || packetIndex >= session.descriptors.length) {
    return { summary: null, descriptor: null, discovery: null, changed: false, drop: false }
  }
  const descriptor = session.descriptors[packetIndex]!
  const discovery = session.packetDiscovery[packetIndex] ?? null
  const planPkt = session.plan.packets[packetIndex]
  const changed = !!planPkt && (planPkt.patches.length > 0 || planPkt.truncatedLength !== undefined)
  const drop = planPkt?.drop ?? discovery?.drop ?? false
  return {
    summary: session.analysis.summaries[packetIndex] ?? null,
    descriptor,
    discovery,
    changed,
    drop,
  }
}

export function filterPacketIndices(
  filter: PcapFilterState,
  displayExpression = '',
  options: { readonly dataView?: 'original' | 'anonymized' } = {},
): number[] {
  if (!session) return []
  const applied = displayExpression.trim()
  const parsed = applied.length > 0 ? parseDisplayFilter(applied) : { status: 'valid' as const, expr: null, error: null }
  const entityKeyFromExpr = isEntityFilterExpression(applied) ? entityKeyFromExpression(applied) : null
  const indices: number[] = []
  const anonymized = options.dataView === 'anonymized'
  const isRecovery = session.sessionKind === 'recover'

  for (let i = 0; i < session.descriptors.length; i++) {
    const descriptor = session.descriptors[i]!
    const num = descriptor.packetNumber
    const discovery = session.packetDiscovery[i]
    const drop = planPacketDropped(session.plan, i) || (discovery?.drop ?? false)

    // Anonymized Wireshark list must not invent rows for packets removed by policy — except in
    // a recovery session, where the "anonymized" pane is really the same packet list rendered
    // with deanonymized bytes, and every anonymized packet has a real counterpart by construction.
    if (anonymized && drop && !isRecovery) continue

    if (parsed.status === 'valid' && parsed.expr) {
      const ctx = buildFilterContextFromSession(i, anonymized ? 'anonymized' : 'original')
      if (!ctx || !evaluateDisplayFilter(parsed.expr, ctx)) continue
    }

    if (filter.packetFrom !== null && num < filter.packetFrom) continue
    if (filter.packetTo !== null && num > filter.packetTo) continue

    const summary = session.analysis.summaries[i]
    const unifiedSpans = unifiedSpansForPacket(session.unifiedCoverage, i)

    if (filter.protocol) {
      if (!packetHasProtocol(session.unifiedCoverage, i, filter.protocol)) continue
    }
    if (filter.issueOnly) {
      const hasIssue =
        (summary?.issues.length ?? 0) > 0 ||
        (discovery?.issues.length ?? 0) > 0 ||
        unifiedSpans.some((s) => s.status === 'malformed' || s.status === 'unsupported' || s.status === 'requires-reassembly')
      if (!hasIssue) continue
    }
    if (filter.changedOnly) {
      const planPkt = session.plan.packets[i]
      const changed = !!planPkt && (planPkt.patches.length > 0 || planPkt.truncatedLength !== undefined)
      if (!changed) continue
    }
    const entityKey = entityKeyFromExpr ?? filter.entityKey
    if (entityKey) {
      if (!session.entityOccurrenceIndex.hasEntity(entityKey, i)) continue
    }
    if (filter.textQuery.trim() && !packetMatchesTextQuery(i, filter.textQuery.trim().toLowerCase(), summary, discovery, unifiedSpans)) {
      continue
    }

    indices.push(i)
  }
  return indices
}

/** Counterpart visibility for dual-pane selection sync. */
export type PacketCounterpartState =
  | { readonly kind: 'present'; readonly packetIndex: number }
  | { readonly kind: 'dropped'; readonly originalPacketNumber: number; readonly reason: string }
  | { readonly kind: 'filtered'; readonly packetIndex: number }

export function resolveAnonymizedCounterpart(
  sourcePacketIndex: number,
  anonymizedFilteredIndices: readonly number[],
): PacketCounterpartState {
  if (!session || sourcePacketIndex < 0 || sourcePacketIndex >= session.descriptors.length) {
    return { kind: 'dropped', originalPacketNumber: 0, reason: 'unknown' }
  }
  const planPkt = session.plan.packets[sourcePacketIndex]
  const discovery = session.packetDiscovery[sourcePacketIndex]
  const drop = planPkt?.drop ?? discovery?.drop ?? false
  const packetNumber = session.descriptors[sourcePacketIndex]!.packetNumber
  if (drop) {
    return {
      kind: 'dropped',
      originalPacketNumber: packetNumber,
      reason: discovery?.issues[0] ?? 'policy-drop',
    }
  }
  if (anonymizedFilteredIndices.includes(sourcePacketIndex)) {
    return { kind: 'present', packetIndex: sourcePacketIndex }
  }
  return { kind: 'filtered', packetIndex: sourcePacketIndex }
}

export function buildFilterContextFromSession(
  packetIndex: number,
  dataView: 'original' | 'anonymized' = 'original',
): PacketFilterContext | null {
  if (!session || packetIndex < 0 || packetIndex >= session.descriptors.length) return null
  const descriptor = session.descriptors[packetIndex]!
  const summary = session.analysis.summaries[packetIndex]
  const discovery = session.packetDiscovery[packetIndex]
  const meta = getPacketRowMeta(packetIndex)
  const unifiedSpans = unifiedSpansForPacket(session.unifiedCoverage, packetIndex)
  const planPkt = session.plan.packets[packetIndex]

  const ipv4 = entityValuesOnPacket(packetIndex, 'ipv4')
  const mac = entityValuesOnPacket(packetIndex, 'mac')
  const ports = entityValuesOnPacket(packetIndex, 'port')

  const hasIssue =
    (summary?.issues.length ?? 0) > 0 ||
    (discovery?.issues.length ?? 0) > 0 ||
    unifiedSpans.some((s) => s.status === 'malformed' || s.status === 'unsupported' || s.status === 'requires-reassembly')

  const tcpPorts = ports.filter((p) => p.startsWith('tcp/')).map((p) => Number.parseInt(p.slice(4), 10))
  const udpPorts = ports.filter((p) => p.startsWith('udp/')).map((p) => Number.parseInt(p.slice(4), 10))
  const l4Proto = tcpPorts.length > 0 ? 'tcp' as const : udpPorts.length > 0 ? 'udp' as const : undefined

  const base: PacketFilterContext = {
    packetIndex,
    packetNumber: descriptor.packetNumber,
    capturedLength: descriptor.capturedLength,
    linkType: descriptor.linkType,
    data: new Uint8Array(0),
    protocols: getPacketProtocols(packetIndex, true),
    changed: !!planPkt && (planPkt.patches.length > 0 || planPkt.truncatedLength !== undefined) || meta.changed,
    hasIssue,
    srcIpv4: ipv4[0],
    dstIpv4: ipv4[1] ?? ipv4[0],
    srcMac: mac[0],
    dstMac: mac[1] ?? mac[0],
    srcPort: l4Proto === 'tcp' ? tcpPorts[0] : l4Proto === 'udp' ? udpPorts[0] : undefined,
    dstPort: l4Proto === 'tcp' ? tcpPorts[1] : l4Proto === 'udp' ? udpPorts[1] : undefined,
    l4Proto,
  }
  if (dataView === 'anonymized' && session.sessionKind === 'recover' && session.counterpartSource) {
    const fields = session.counterpartSource.endpointsByAnonymizedPacketNumber.get(descriptor.packetNumber)
    return {
      ...base,
      srcIpv4: fields?.srcIpv4,
      dstIpv4: fields?.dstIpv4 ?? fields?.srcIpv4,
      srcMac: fields?.srcMac,
      dstMac: fields?.dstMac ?? fields?.srcMac,
      srcPort: fields?.srcPort,
      dstPort: fields?.dstPort,
      l4Proto: fields?.l4Proto ?? base.l4Proto,
    }
  }
  return withViewMappedEndpoints(base, dataView)
}

/** Structural decode + sanitizer coverage; filtering also needs generic payload family membership. */
export function getPacketProtocols(packetIndex: number, includePayload = false): readonly string[] {
  if (!session || packetIndex < 0 || packetIndex >= session.descriptors.length) return []
  const out = new Set<string>()
  for (const protocol of indexedPacketProtocols(session.unifiedCoverage.packetProtocols, packetIndex)) {
    if (includePayload || protocol !== 'payload') out.add(protocol)
  }
  for (const p of session.analysis.summaries[packetIndex]?.protocols ?? []) {
    if (p) out.add(p)
  }
  for (const span of unifiedSpansForPacket(session.unifiedCoverage, packetIndex)) {
    if (span.protocol && (includePayload || span.protocol !== 'payload')) out.add(span.protocol)
  }
  return [...out]
}

export function getPacketEndpoints(
  packetIndex: number,
  dataView: 'original' | 'anonymized' = 'original',
): EndpointPair {
  if (!session || packetIndex < 0 || packetIndex >= session.descriptors.length) {
    return { source: '—', dest: '—' }
  }
  if (dataView === 'anonymized' && session.sessionKind === 'recover' && session.counterpartSource) {
    const packetNumber = session.descriptors[packetIndex]!.packetNumber
    const fields = session.counterpartSource.endpointsByAnonymizedPacketNumber.get(packetNumber)
    return counterpartEndpointPair(fields)
  }
  const ipv4 = mapEndpointValues(entityValuesOnPacket(packetIndex, 'ipv4'), 'ipv4', dataView)
  if (ipv4.length > 0) {
    return { source: ipv4[0]!, dest: ipv4[1] ?? ipv4[0]! }
  }
  const mac = mapEndpointValues(entityValuesOnPacket(packetIndex, 'mac'), 'mac', dataView)
  if (mac.length > 0) {
    return { source: mac[0]!, dest: mac[1] ?? mac[0]! }
  }
  return { source: '—', dest: '—' }
}

// Reverse index (packetIndex + category -> entity values), keyed by the occurrence index's
// object identity. `session.analysis`/`session.entityOccurrenceIndex` are always carried over
// unchanged across updateSessionPlan() (see the `...session` spread above) and only replaced
// wholesale when a new capture is loaded, so this is a correct cache boundary without manual
// invalidation. Without it, entityValuesOnPacket was O(entities) per call — up to several
// calls per rendered/colored packet — which dominated PCAP UI cost on large captures.
//
// Keyed by a packed `packetIndex * CATEGORY_KEY_STRIDE + categoryId` number rather than a
// `${packetIndex}:${category}` template string — same grouping, same per-packet value order
// (entities are iterated in the same order as before), just without allocating one string per
// (packet, category) combination that has any occurrence (hundreds of thousands on a large
// capture).
const CATEGORY_KEY_STRIDE = 64
const categoryIds = new Map<string, number>()
function categoryId(category: string): number {
  let id = categoryIds.get(category)
  if (id === undefined) {
    id = categoryIds.size
    categoryIds.set(category, id)
  }
  return id
}

interface PacketEntityValuesIndex {
  readonly byKey: ReadonlyMap<number, readonly string[]>
  /** Distinct categories actually present in this session's entities — lets callers (text
   * search) enumerate "every entity value on this packet" without knowing category names. */
  readonly categories: readonly string[]
}

const packetEntityValuesCache = new WeakMap<EntityOccurrenceIndex, PacketEntityValuesIndex>()

function buildPacketEntityValuesIndex(
  entities: readonly EntityEntry[],
  occurrenceIndex: EntityOccurrenceIndex,
): PacketEntityValuesIndex {
  const out = new Map<number, string[]>()
  const categories = new Set<string>()
  for (const e of entities) {
    categories.add(e.category)
    const catId = categoryId(e.category)
    for (const packetIndex of occurrenceIndex.packetsForEntity(e.key)) {
      const cacheKey = packetIndex * CATEGORY_KEY_STRIDE + catId
      const list = out.get(cacheKey)
      if (list) list.push(e.value)
      else out.set(cacheKey, [e.value])
    }
  }
  return { byKey: out, categories: [...categories] }
}

function getPacketEntityValuesIndex(): PacketEntityValuesIndex | null {
  if (!session) return null
  let index = packetEntityValuesCache.get(session.entityOccurrenceIndex)
  if (!index) {
    index = buildPacketEntityValuesIndex(session.analysis.entities, session.entityOccurrenceIndex)
    packetEntityValuesCache.set(session.entityOccurrenceIndex, index)
  }
  return index
}

function entityValuesOnPacket(packetIndex: number, category: string): string[] {
  const index = getPacketEntityValuesIndex()
  if (!index) return []
  return [...(index.byKey.get(packetIndex * CATEGORY_KEY_STRIDE + categoryId(category)) ?? [])]
}

function packetMatchesTextQuery(
  packetIndex: number,
  queryLower: string,
  summary: PacketSummary | undefined,
  discovery: PacketDiscoveryResult | undefined,
  unifiedSpans: readonly UnifiedLayerCoverage[],
): boolean {
  if (!session) return false
  const parts: string[] = [String(session.descriptors[packetIndex]!.packetNumber)]
  if (summary) {
    for (const p of summary.protocols) parts.push(p)
    for (const issue of summary.issues) parts.push(String(issue))
  }
  if (discovery) {
    for (const issue of discovery.issues) parts.push(issue)
    // Was: iterate this packet's entity-replacement intents for their canonical value +
    // category. The session no longer retains per-packet intents (see `containerToWire`) —
    // same original-value search, driven by the already-built `entityOccurrenceIndex` instead.
    const entityIndex = getPacketEntityValuesIndex()
    if (entityIndex) {
      for (const category of entityIndex.categories) {
        for (const value of entityValuesOnPacket(packetIndex, category)) {
          parts.push(value, category)
        }
      }
    }
  }
  for (const span of unifiedSpans) {
    parts.push(span.protocol, span.status)
  }
  return parts.join(' ').toLowerCase().includes(queryLower)
}

export function findPacketIndexByNumber(packetNumber: number): number {
  if (!session) return -1
  return session.descriptors.findIndex((d) => d.packetNumber === packetNumber)
}

export const DEFAULT_PCAP_FILTER: PcapFilterState = {
  packetFrom: null,
  packetTo: null,
  protocol: '',
  entityKey: '',
  textQuery: '',
  issueOnly: false,
  changedOnly: false,
}

export function buildSessionPlanSnapshot(): PcapPlanSnapshot | null {
  return session?.plan ?? null
}

export function countUnsupportedLayers(): number {
  if (!session) return 0
  return countUnsupportedFromUnified(session.unifiedCoverage)
}

export function getUnifiedCoverageForPacket(packetIndex: number): readonly UnifiedLayerCoverage[] {
  if (!session) return []
  return unifiedSpansForPacket(session.unifiedCoverage, packetIndex)
}

export function getUnifiedCoverageModel(): UnifiedCoverageModel | null {
  return session?.unifiedCoverage ?? null
}

export { emptyAnalysis, analysisFromWire }

export function getPacketDiscoveryCoverage(packetIndex: number): readonly LayerCoverage[] {
  return session?.packetDiscovery[packetIndex]?.coverage ?? []
}
