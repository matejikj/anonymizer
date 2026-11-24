/**
 * Transferable packed wire for discover → main-thread (R10 / PF scale).
 *
 * Nested object graphs for 100 MiB captures (~235k packets, ~1.6M coverage rows,
 * ~1.4M intents) are hundreds of MiB and hang Chromium structured-clone during
 * worker postMessage. Parallel typed arrays + string tables transfer by ownership.
 */

import type {
  ClassicPcapHeader,
  PacketRecordDescriptor,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
} from '../domain/types'
import type { PacketDiscoveryResult } from '../discovery/types'
import type { LayerCoverage } from '../sanitize/types'
import type { UnifiedCoverageModel, UnifiedProtocolSummary } from '../coverage/types'
import { dominantStatus } from '../coverage/mergeRules'
import { familyForProtocol } from '../coverage/protocolFamilies'
import { issueImpliesCryptoModified } from '../trust/cryptoIntegrity'
import { parseTlsBranchIssue } from '../sanitize/tlsBranches'
import { buildPacketProtocolIndex, type PackedPacketProtocols } from '../coverage/packetProtocolIndex'

export interface WirePackedCheckpoint {
  readonly packetNumber: number
  readonly fileOffset: number
}

export interface WirePackedTimestampProfile {
  readonly unitsPerSecond: string
  readonly offsetSeconds: string
}

/** Parallel descriptor columns — transferred as ArrayBuffers. */
export interface WirePackedDescriptors {
  readonly count: number
  readonly packetNumber: Uint32Array
  readonly capturedLength: Uint32Array
  readonly originalLength: Uint32Array
  readonly linkType: Uint16Array
  readonly interfaceId: Uint16Array
  readonly sectionIndex: Uint16Array
  readonly fileOffset: Float64Array
  readonly dataOffset: Uint32Array
  readonly ticksLo: Uint32Array
  readonly ticksHi: Uint32Array
  readonly tsProfileId: Uint16Array
  readonly tsProfiles: readonly WirePackedTimestampProfile[]
}

/**
 * Aggregate sanitizer coverage for the main thread (R10).
 * Full per-span coverage stays in the processing worker for plan build; expanding
 * ~1.6M LayerCoverage objects on the UI thread after discover hangs Chromium.
 */
export interface WireCoverageRollup {
  readonly packetProtocols?: PackedPacketProtocols
  readonly totalUnsupportedSpans: number
  readonly totalTruncatedSpans: number
  readonly totalHeuristicSpans: number
  readonly preservedUnsafeSpans: number
  readonly processingFailedSpans: number
  /** Sanitizer spans that need reassembly / are malformed — drive the integrity status. */
  readonly requiresReassemblySpans: number
  readonly malformedSpans: number
  readonly truncatedPacketCount: number
  readonly discoveryDropCount: number
  readonly discoveryIssueCount: number
  /** Sanitizer spans aggregated per protocol × status (bounded by distinct ids, not packets). */
  readonly coverageKinds: readonly WireCoverageKind[]
  /** Bounded per-protocol summaries; no per-packet coverage objects on the UI thread. */
  readonly protocolSummaries?: readonly UnifiedProtocolSummary[]
  /** Distinct safe discovery issue tokens (tls-branch:*, …) — never original values. */
  readonly issueTokens: readonly string[]
}

export interface WireCoverageKind {
  readonly protocol: string
  readonly status: string
  readonly count: number
  readonly bytes: number
}

/** Hard bounds — protocol ids / issue tokens can embed packet-controlled numbers or names. */
export const ROLLUP_MAX_COVERAGE_KINDS = 512
export const ROLLUP_MAX_ISSUE_TOKENS = 1024
export const ROLLUP_MAX_ISSUE_TOKENS_HARD = 2048
export const ROLLUP_OVERFLOW_PROTOCOL = 'other'

/**
 * Protocol ids whose exact value changes a downstream decision (media disposition in
 * `resolveCoverageDisposition`, TLS crypto/branch matchers) — never collapsed into 'other'.
 */
const ROLLUP_EXACT_PROTOCOLS: ReadonlySet<string> = new Set([
  'rtp', 'rtcp', 'srtp', 'media', 'voip-media',
  'tls', 'tls-clienthello', 'tls-serverhello', 'tls-certificate', 'tls-1.2', 'tls-1.3', 'tls-ech',
])

/** Incremental protocol × status aggregation shared by both rollup builders. */
class CoverageKindAccumulator {
  private readonly kinds = new Map<string, { protocol: string; status: string; count: number; bytes: number }>()
  private readonly protocols = new Map<string, { packetCount: number; lastPacket: number; spanCount: number; unsupportedCount: number; status: LayerCoverage['status'] }>()
  private readonly families = new Map<string, { packetCount: number; lastPacket: number }>()

  add(protocol: string, status: LayerCoverage['status'], length: number, packetIndex: number): void {
    let key = `${protocol}\u0000${status}`
    let k = this.kinds.get(key)
    if (!k && this.kinds.size >= ROLLUP_MAX_COVERAGE_KINDS && !ROLLUP_EXACT_PROTOCOLS.has(protocol)) {
      // Past the cap, packet-derived ids (e.g. `sctp-ppid-<n>`) fold per status — the status
      // (and so exposed/fail-closed accounting) is preserved, only the protocol label is lost.
      protocol = ROLLUP_OVERFLOW_PROTOCOL
      key = `${protocol}\u0000${status}`
      k = this.kinds.get(key)
    }
    if (k) {
      k.count++
      k.bytes += Math.max(0, length)
    } else {
      this.kinds.set(key, { protocol, status, count: 1, bytes: Math.max(0, length) })
    }
    let p = this.protocols.get(protocol)
    if (!p) {
      p = { packetCount: 0, lastPacket: -1, spanCount: 0, unsupportedCount: 0, status: 'covered' }
      this.protocols.set(protocol, p)
    }
    if (p.lastPacket !== packetIndex) { p.packetCount++; p.lastPacket = packetIndex }
    p.spanCount++
    if (status === 'unsupported') p.unsupportedCount++
    p.status = dominantStatus(p.status, status)
    const familyId = familyForProtocol(protocol).familyId
    const family = this.families.get(familyId)
    if (!family) this.families.set(familyId, { packetCount: 1, lastPacket: packetIndex })
    else if (family.lastPacket !== packetIndex) { family.packetCount++; family.lastPacket = packetIndex }
  }

  toArray(): WireCoverageKind[] {
    return [...this.kinds.values()]
  }

  protocolSummaries(): UnifiedProtocolSummary[] {
    return [...this.protocols].map(([protocol, p]) => ({
      protocol, packetCount: p.packetCount, spanCount: p.spanCount, unsupportedCount: p.unsupportedCount,
      structuralSpanCount: 0, sanitizerSpanCount: p.spanCount, dominantStatus: p.status, issues: [],
      familyPacketCount: this.families.get(familyForProtocol(protocol).familyId)!.packetCount,
    }))
  }
}

/** Distinct safe issue tokens with a bounded footprint. */
class IssueTokenCollector {
  private readonly tokens = new Set<string>()

  add(token: string): void {
    if (this.tokens.has(token)) return
    const must = issueImpliesCryptoModified(token) || parseTlsBranchIssue(token) !== null
    if (!must && this.tokens.size >= ROLLUP_MAX_ISSUE_TOKENS) {
      // Packet-derived suffixes (`sctp-unknown-ppid:<n>`, header names) fold to their prefix.
      const colon = token.indexOf(':')
      const folded = colon > 0 ? token.slice(0, colon) : token
      if (this.tokens.size >= ROLLUP_MAX_ISSUE_TOKENS_HARD) return
      this.tokens.add(folded)
      return
    }
    this.tokens.add(token)
  }

  toArray(): string[] {
    return [...this.tokens]
  }
}

/**
 * UI-side stand-in for per-span sanitizer coverage on the packed path: one entry per
 * protocol × status, weighted by `aggregateCount` (see {@link LayerCoverage.aggregateCount}).
 */
export function coverageFromRollup(rollup: WireCoverageRollup): LayerCoverage[] {
  return rollup.coverageKinds.map((k) => ({
    protocol: k.protocol,
    offset: 0,
    length: k.bytes,
    status: k.status as LayerCoverage['status'],
    aggregateCount: k.count,
  }))
}

/**
 * Sanitizer coverage for export bookkeeping / privacy report / correlation gate: the real
 * per-packet spans when present, otherwise the weighted rollup kinds (R10 packed path).
 */
export function sanitizerCoverageForExport(
  packetDiscovery: readonly PacketDiscoveryResult[],
  rollup: WireCoverageRollup | undefined,
): LayerCoverage[] {
  if (packetDiscovery.length === 0 && rollup) return coverageFromRollup(rollup)
  const out: LayerCoverage[] = []
  for (const pd of packetDiscovery) {
    for (const span of pd.coverage) out.push(span)
  }
  return out
}

/** Safe discovery issue tokens for export reports (same fallback as coverage). */
export function discoveryIssuesForExport(
  packetDiscovery: readonly PacketDiscoveryResult[],
  rollup: WireCoverageRollup | undefined,
): readonly string[] {
  if (packetDiscovery.length === 0 && rollup) return rollup.issueTokens
  const out: string[] = []
  for (const pd of packetDiscovery) {
    for (const issue of pd.issues) out.push(issue)
  }
  return out
}

/**
 * R10 — packed discover leaves `packetDiscovery` empty on the UI thread, so span totals built
 * from it undercount; take the worker-side rollup totals when they are higher.
 */
export function mergeCoverageRollup(
  unifiedCoverage: UnifiedCoverageModel,
  coverageRollup: WireCoverageRollup | undefined,
): UnifiedCoverageModel {
  if (!coverageRollup) return unifiedCoverage
  const protocols = new Map(unifiedCoverage.byProtocol.map(p => [p.protocol, p]))
  for (const p of coverageRollup.protocolSummaries ?? []) {
    const previous = protocols.get(p.protocol)
    protocols.set(p.protocol, previous ? {
      ...previous,
      packetCount: Math.max(previous.packetCount, p.packetCount),
      familyPacketCount: Math.max(previous.familyPacketCount ?? 0, p.familyPacketCount ?? 0),
      spanCount: Math.max(previous.spanCount, p.spanCount),
      sanitizerSpanCount: Math.max(previous.sanitizerSpanCount, p.sanitizerSpanCount),
      unsupportedCount: Math.max(previous.unsupportedCount, p.unsupportedCount),
      dominantStatus: dominantStatus(previous.dominantStatus, p.dominantStatus),
    } : p)
  }
  const byProtocol = [...protocols.values()].sort((a, b) => a.protocol.localeCompare(b.protocol))
  return {
    ...unifiedCoverage,
    packetProtocols: coverageRollup.packetProtocols ?? unifiedCoverage.packetProtocols,
    byProtocol,
    histogram: new Map(byProtocol.filter(p => p.packetCount > 0).map(p => [p.protocol, p.packetCount])),
    totalUnsupportedSpans: Math.max(unifiedCoverage.totalUnsupportedSpans, coverageRollup.totalUnsupportedSpans),
    totalTruncatedSpans: Math.max(unifiedCoverage.totalTruncatedSpans, coverageRollup.totalTruncatedSpans),
    totalHeuristicSpans: Math.max(unifiedCoverage.totalHeuristicSpans, coverageRollup.totalHeuristicSpans),
  }
}

export interface WirePackedPacketDiscovery {
  readonly count: number
  readonly packetIndex: Uint32Array
  readonly packetNumber: Uint32Array
  /** bit0 = drop, bit1 = has truncatedLength */
  readonly flags: Uint8Array
  readonly truncatedLength: Uint32Array
  /** Deduped issue strings; `issueIds` indexes into this table (0xffff = end of packet's list). */
  readonly issueTable: readonly string[]
  /** Flat list of issue-table ids, grouped by packet in `packetIndex` order, terminated by 0xffff. */
  readonly issueIds: Uint16Array
  readonly coverageRollup: WireCoverageRollup
}

export interface WirePackedContainer {
  readonly descriptors: WirePackedDescriptors
  /** Optional full packed PD — currently unused on UI; rollup carries honesty totals. */
  readonly packetDiscovery?: WirePackedPacketDiscovery
  readonly coverageRollup: WireCoverageRollup
  readonly checkpoints: WirePackedCheckpoint[]
  readonly issues: ParseIssue[]
  readonly classicHeader?: unknown
  readonly pcapngSections?: unknown[]
  readonly pcapngInterfaces?: unknown[]
}

function transferBufferOf(view: ArrayBufferView): ArrayBuffer {
  const buf = view.buffer
  if (buf instanceof ArrayBuffer) return buf
  // Defensive copy if a SharedArrayBuffer ever appears (Transferable list wants ArrayBuffer).
  const copy = new ArrayBuffer(view.byteLength)
  new Uint8Array(copy).set(new Uint8Array(buf, view.byteOffset, view.byteLength))
  return copy
}

function collectTransferBuffers(packed: WirePackedContainer): ArrayBuffer[] {
  const d = packed.descriptors
  const buffers: ArrayBuffer[] = [
    transferBufferOf(d.packetNumber),
    transferBufferOf(d.capturedLength),
    transferBufferOf(d.originalLength),
    transferBufferOf(d.linkType),
    transferBufferOf(d.interfaceId),
    transferBufferOf(d.sectionIndex),
    transferBufferOf(d.fileOffset),
    transferBufferOf(d.dataOffset),
    transferBufferOf(d.ticksLo),
    transferBufferOf(d.ticksHi),
    transferBufferOf(d.tsProfileId),
  ]
  const protocols = packed.coverageRollup.packetProtocols
  if (protocols) buffers.push(transferBufferOf(protocols.offsets), transferBufferOf(protocols.protocolIds))
  return [...new Set(buffers)]
}

/** Compute rollup without allocating packed PD columns (R10 discover path). */
export function coverageRollupFromDiscovery(
  packetDiscovery: readonly PacketDiscoveryResult[],
): WireCoverageRollup {
  let totalUnsupportedSpans = 0
  let totalTruncatedSpans = 0
  let totalHeuristicSpans = 0
  let preservedUnsafeSpans = 0
  let processingFailedSpans = 0
  let requiresReassemblySpans = 0
  let malformedSpans = 0
  const kinds = new CoverageKindAccumulator()
  const issueTokens = new IssueTokenCollector()
  let truncatedPacketCount = 0
  let discoveryDropCount = 0
  let discoveryIssueCount = 0
  for (const [packetIndex, pd] of packetDiscovery.entries()) {
    if (pd.drop) discoveryDropCount++
    if (pd.truncatedLength !== undefined) truncatedPacketCount++
    discoveryIssueCount += pd.issues.length
    for (const iss of pd.issues) issueTokens.add(iss)
    for (const c of pd.coverage) {
      kinds.add(c.protocol, c.status, c.length, packetIndex)
      switch (c.status) {
        case 'unsupported':
          totalUnsupportedSpans++
          break
        case 'truncated':
          totalTruncatedSpans++
          break
        case 'heuristic':
          totalHeuristicSpans++
          break
        case 'preserved-unsafe':
          preservedUnsafeSpans++
          break
        case 'processing-failed':
          processingFailedSpans++
          break
        case 'requires-reassembly':
          requiresReassemblySpans++
          break
        case 'malformed':
          malformedSpans++
          break
        default:
          break
      }
    }
  }
  return {
    totalUnsupportedSpans,
    totalTruncatedSpans,
    totalHeuristicSpans,
    preservedUnsafeSpans,
    processingFailedSpans,
    requiresReassemblySpans,
    malformedSpans,
    truncatedPacketCount,
    discoveryDropCount,
    discoveryIssueCount,
    coverageKinds: kinds.toArray(),
    protocolSummaries: kinds.protocolSummaries(),
    issueTokens: issueTokens.toArray(),
  }
}

export function packDescriptors(descriptors: readonly PacketRecordDescriptor[]): WirePackedDescriptors {
  const n = descriptors.length
  const packetNumber = new Uint32Array(n)
  const capturedLength = new Uint32Array(n)
  const originalLength = new Uint32Array(n)
  const linkType = new Uint16Array(n)
  const interfaceId = new Uint16Array(n)
  const sectionIndex = new Uint16Array(n)
  const fileOffset = new Float64Array(n)
  const dataOffset = new Uint32Array(n)
  const ticksLo = new Uint32Array(n)
  const ticksHi = new Uint32Array(n)
  const tsProfileId = new Uint16Array(n)
  const profileKeys: string[] = []
  const profileIndex = new Map<string, number>()
  const tsProfiles: WirePackedTimestampProfile[] = []

  for (let i = 0; i < n; i++) {
    const d = descriptors[i]!
    packetNumber[i] = d.packetNumber >>> 0
    capturedLength[i] = d.capturedLength >>> 0
    originalLength[i] = d.originalLength >>> 0
    linkType[i] = d.linkType & 0xffff
    interfaceId[i] = d.interfaceId & 0xffff
    sectionIndex[i] = d.sectionIndex & 0xffff
    fileOffset[i] = d.fileOffset
    dataOffset[i] = d.dataOffset >>> 0
    const ticks = d.timestamp.ticks
    ticksLo[i] = Number(ticks & 0xffffffffn)
    ticksHi[i] = Number((ticks >> 32n) & 0xffffffffn)
    const pk = `${d.timestamp.unitsPerSecond}\0${d.timestamp.offsetSeconds}`
    let pid = profileIndex.get(pk)
    if (pid === undefined) {
      pid = tsProfiles.length
      profileIndex.set(pk, pid)
      profileKeys.push(pk)
      tsProfiles.push({
        unitsPerSecond: d.timestamp.unitsPerSecond.toString(),
        offsetSeconds: d.timestamp.offsetSeconds.toString(),
      })
    }
    tsProfileId[i] = pid & 0xffff
  }

  return {
    count: n,
    packetNumber,
    capturedLength,
    originalLength,
    linkType,
    interfaceId,
    sectionIndex,
    fileOffset,
    dataOffset,
    ticksLo,
    ticksHi,
    tsProfileId,
    tsProfiles,
  }
}

export function unpackDescriptors(packed: WirePackedDescriptors): PacketRecordDescriptor[] {
  const n = packed.count
  const out: PacketRecordDescriptor[] = new Array(n)
  const profileBigints = packed.tsProfiles.map((p) => ({
    unitsPerSecond: BigInt(p.unitsPerSecond),
    offsetSeconds: BigInt(p.offsetSeconds),
  }))
  for (let i = 0; i < n; i++) {
    const lo = BigInt(packed.ticksLo[i]!)
    const hi = BigInt(packed.ticksHi[i]!)
    const profile = profileBigints[packed.tsProfileId[i]!]!
    out[i] = {
      packetNumber: packed.packetNumber[i]!,
      timestamp: {
        ticks: (hi << 32n) | lo,
        unitsPerSecond: profile.unitsPerSecond,
        offsetSeconds: profile.offsetSeconds,
      },
      capturedLength: packed.capturedLength[i]!,
      originalLength: packed.originalLength[i]!,
      linkType: packed.linkType[i]!,
      interfaceId: packed.interfaceId[i]!,
      sectionIndex: packed.sectionIndex[i]!,
      fileOffset: packed.fileOffset[i]!,
      dataOffset: packed.dataOffset[i]!,
    }
  }
  return out
}

export function packPacketDiscovery(
  packetDiscovery: readonly PacketDiscoveryResult[],
): WirePackedPacketDiscovery {
  const n = packetDiscovery.length
  const packetIndex = new Uint32Array(n)
  const packetNumber = new Uint32Array(n)
  const flags = new Uint8Array(n)
  const truncatedLength = new Uint32Array(n)

  let issueIdSlots = 0
  for (const pd of packetDiscovery) {
    // one id per issue + one 0xffff terminator per packet
    issueIdSlots += pd.issues.length + 1
  }

  const issueIndex = new Map<string, number>()
  const issueTable: string[] = []
  const issueIds = new Uint16Array(issueIdSlots)

  let issueAt = 0
  for (let i = 0; i < n; i++) {
    const pd = packetDiscovery[i]!
    packetIndex[i] = pd.packetIndex >>> 0
    packetNumber[i] = pd.packetNumber >>> 0
    let f = 0
    if (pd.drop) f |= 1
    if (pd.truncatedLength !== undefined) {
      f |= 2
      truncatedLength[i] = pd.truncatedLength >>> 0
    }
    flags[i] = f
    for (const iss of pd.issues) {
      let iid = issueIndex.get(iss)
      if (iid === undefined) {
        iid = issueTable.length
        if (iid >= 0xffff) throw new Error('packedCaptureWire: issue table overflow')
        issueIndex.set(iss, iid)
        issueTable.push(iss)
      }
      issueIds[issueAt++] = iid & 0xffff
    }
    issueIds[issueAt++] = 0xffff
  }

  return {
    count: n,
    packetIndex,
    packetNumber,
    flags,
    truncatedLength,
    issueTable,
    issueIds,
    // Single source of truth for the rollup — no second copy of the span switch to drift.
    coverageRollup: coverageRollupFromDiscovery(packetDiscovery),
  }
}

/**
 * Rebuild lightweight per-packet discovery rows for the UI thread.
 * Coverage spans are intentionally omitted — see {@link WireCoverageRollup}.
 */
export function unpackPacketDiscovery(packed: WirePackedPacketDiscovery): PacketDiscoveryResult[] {
  const n = packed.count
  const out: PacketDiscoveryResult[] = new Array(n)
  let issueAt = 0
  for (let i = 0; i < n; i++) {
    const f = packed.flags[i]!
    const issues: string[] = []
    while (issueAt < packed.issueIds.length) {
      const id = packed.issueIds[issueAt++]!
      if (id === 0xffff) break
      const text = packed.issueTable[id]
      if (text !== undefined) issues.push(text)
    }
    out[i] = {
      packetIndex: packed.packetIndex[i]!,
      packetNumber: packed.packetNumber[i]!,
      drop: (f & 1) !== 0,
      truncatedLength: (f & 2) !== 0 ? packed.truncatedLength[i]! : undefined,
      issues,
      intents: [],
      coverage: [],
    }
  }
  return out
}

export function coverageRollupFromPacked(
  packed: WirePackedContainer | undefined,
): WireCoverageRollup | undefined {
  return packed?.coverageRollup ?? packed?.packetDiscovery?.coverageRollup
}

export function packContainerBody(input: {
  summaries?: readonly { readonly protocols: readonly string[] }[]
  descriptors: readonly PacketRecordDescriptor[]
  checkpoints: readonly SparseCheckpoint[]
  issues: readonly ParseIssue[]
  classicHeader?: ClassicPcapHeader
  pcapngSections?: PcapngSectionInfo[]
  pcapngInterfaces?: PcapngInterfaceInfo[]
  packetDiscovery: readonly PacketDiscoveryResult[]
}): { packed: WirePackedContainer; transfers: ArrayBuffer[] } {
  const rollup = coverageRollupFromDiscovery(input.packetDiscovery)
  const packetProtocols = buildPacketProtocolIndex(input.descriptors.length, input.summaries ?? [],
    input.packetDiscovery, rollup.coverageKinds)
  const packed: WirePackedContainer = {
    descriptors: packDescriptors(input.descriptors),
    coverageRollup: { ...rollup, packetProtocols },
    checkpoints: input.checkpoints.map((c) => ({ packetNumber: c.packetNumber, fileOffset: c.fileOffset })),
    issues: [...input.issues],
    classicHeader: input.classicHeader,
    pcapngSections: input.pcapngSections ? [...input.pcapngSections] : undefined,
    pcapngInterfaces: input.pcapngInterfaces ? [...input.pcapngInterfaces] : undefined,
  }
  return { packed, transfers: collectTransferBuffers(packed) }
}
