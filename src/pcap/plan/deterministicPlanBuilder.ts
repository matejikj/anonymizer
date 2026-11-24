/**
 * Deterministic PCAP plan builder from MappingSnapshot (Stage 8).
 * Pure function — no RNG, no mutable mapping registry.
 */

import type {
  CaptureFormat,
  ClassicPcapHeader,
  PacketEnvelope,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
} from '../domain/types'
import type { MappingSnapshot } from '../../mapping/types'
import { IncidentLog } from '../../domain/anonymizationIncident'
import type { PcapProfile } from '../profile/schema'
import type { SanitizationPolicy } from '../sanitize/types'
import type { PacketSanitizationResult } from '../sanitize/types'
import { sanitizePacket, type PacketInput } from '../sanitize/engine'
import type { PacketDiscoveryResult } from '../discovery/types'
import { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import { mergePacketWithReassemblyOverlay, applyReassemblyPatchesToResults } from '../reassembly/capturePhase'
import { SnapshotMappingAdapter } from './snapshotMappingAdapter'
import {
  buildPlanSnapshot,
  derivePlanEntropySeed,
  type PcapPlanSnapshot,
} from '../export/planSnapshot'
import { mergePatchesStrict } from './mergePatchesStrict'
import { FingerprintSession } from '../anonymization/fingerprintSession'
import {
  buildIsolatedPacketResult,
  recordIsolationIncident,
} from '../sanitize/packetIsolation'
import { createPayloadTimeSession } from '../kernel/payloadTimeCodec'
import { resolveFrozenPacketPlan } from '../kernel/frozenPlan'

/** Matches discoveryPipeline.ts's DEFAULT_PROCESSING_BATCH_SIZE — same reporting granularity. */
const PROGRESS_BATCH_SIZE = 64

export function buildSanitizationFromSnapshot(
  packets: readonly PacketEnvelope[],
  policy: SanitizationPolicy,
  snapshot: MappingSnapshot,
  reassemblyContext?: import('../reassembly/types').ReassemblyContext,
  fingerprintSeed?: string,
  /**
   * PF-06: discovery's own per-packet results, each carrying a `resolvePatches` / frozen plan
   * that materializes final patches against the real mapping without re-running the structural
   * decode (DNS/SIP/TLS/heuristic/etc. dispatch) discovery already did once. When provided
   * (the production worker path — see processingPipeline.ts), this replaces the entire
   * per-packet `sanitizePacket()` call below. Optional and falls back to the original
   * eager path so other callers (in-process orchestration, profile-rebuild-from-analysis,
   * tests) keep working unchanged.
   */
  packetDiscovery?: readonly PacketDiscoveryResult[],
  /** UI progress splash — reported every PROGRESS_BATCH_SIZE packets, matching discovery's
   * own batching (discoveryPipeline.ts's DEFAULT_PROCESSING_BATCH_SIZE) so the plan-build
   * overview step advances instead of sitting at 0 for the whole phase. */
  onProgress?: (done: number, total: number) => void,
  /** T-01 — captured lengths when `packets` are payload-less descriptor stubs. */
  bufferLengths?: readonly number[],
  /** T04 — shared incident log across packets for this plan build. */
  incidentLog?: IncidentLog,
  sourceId?: string,
  /** T14 — absolute payload time session (same seed/Δ as capture TimestampMapping). */
  payloadTime?: import('../kernel/payloadTimeCodec').PayloadTimeSession,
  /** T21 — processing generation scope for NetFlow/IPFIX template caches (eager path). */
  generationId?: string,
): PacketSanitizationResult[] {
  const mapping = new SnapshotMappingAdapter(snapshot)
  const mediaFlowIndex = reassemblyContext?.mediaFlowIndex ?? new MediaFlowIndex()
  const fingerprints = new FingerprintSession(fingerprintSeed)
  const log = incidentLog
  const results: PacketSanitizationResult[] = []
  for (let i = 0; i < packets.length; i++) {
    const pkt = packets[i]!
    const bufferLength = bufferLengths?.[i] ?? pkt.data.length

    if ((i > 0 && i % PROGRESS_BATCH_SIZE === 0) || i === packets.length - 1) {
      onProgress?.(i + 1, packets.length)
    }

    const resolveCtx = {
      mapping,
      fingerprints,
      incidentLog: log,
      sourceId: sourceId ?? 'pcap',
      packetIndex: i,
      packetNumber: pkt.packetNumber,
      payloadTime,
    }

    const discovered = packetDiscovery?.[i]
    if (discovered?.isolationFallback && log) {
      recordIsolationIncident(log, {
        sourceId: sourceId ?? 'pcap',
        packetIndex: i,
        packetNumber: pkt.packetNumber,
        unit: discovered.isolationFallback.unit,
        reason: discovered.isolationFallback.reason,
        stage: 'discovery',
        protocol: 'processing-failed',
      })
    }
    // Frozen discovery plan (production) or an explicit resolve callback (adapters/tests).
    const frozenPlan = discovered?.frozenPlan
    const resolveDiscovered = frozenPlan
      ? (ctx: typeof resolveCtx) => resolveFrozenPacketPlan(frozenPlan, ctx)
      : discovered?.resolvePatches
    if (discovered && resolveDiscovered) {
      try {
        results.push({
          packetIndex: i,
          patches: resolveDiscovered(resolveCtx),
          truncatedLength: discovered.truncatedLength,
          coverage: [...discovered.coverage],
          drop: discovered.drop,
          issues: [...discovered.issues],
        })
      } catch {
        const isolated = buildIsolatedPacketResult({
          packetIndex: i,
          capturedLength: pkt.capturedLength,
          linkType: pkt.linkType,
          data: pkt.data.length > 0 ? pkt.data : new Uint8Array(bufferLength),
          policy,
          unit: 'packet',
          reason: 'sanitizer-exception',
          safePrefixEnd: 0,
        })
        recordIsolationIncident(log, {
          sourceId: sourceId ?? 'pcap',
          packetIndex: i,
          packetNumber: pkt.packetNumber,
          unit: 'packet',
          reason: 'sanitizer-exception',
          stage: 'plan',
          protocol: 'processing-failed',
        })
        results.push(isolated)
      }
      continue
    }

    const input: PacketInput = {
      index: i,
      data: pkt.data,
      capturedLength: pkt.capturedLength,
      originalLength: pkt.originalLength,
      linkType: pkt.linkType,
    }
    const overlay = reassemblyContext?.overlayFor(i)
    let base: PacketSanitizationResult
    try {
      base = sanitizePacket(input, policy, mapping, {
        mediaFlowIndex,
        reassemblyContext,
        fingerprints,
        generationId,
        sourceId: sourceId ?? 'pcap',
        payloadTime,
        incidentLog: log,
      })
    } catch {
      base = buildIsolatedPacketResult({
        packetIndex: i,
        capturedLength: pkt.capturedLength,
        linkType: pkt.linkType,
        data: pkt.data,
        policy,
        unit: 'packet',
        reason: 'sanitizer-exception',
        safePrefixEnd: 0,
      })
      recordIsolationIncident(log, {
        sourceId: sourceId ?? 'pcap',
        packetIndex: i,
        packetNumber: pkt.packetNumber,
        unit: 'packet',
        reason: 'sanitizer-exception',
        stage: 'plan',
        protocol: 'processing-failed',
      })
    }
    try {
      const merged = mergePacketWithReassemblyOverlay(base, overlay)
      const patches = mergePatchesStrict(bufferLength, i, merged.patches)
      results.push({
        packetIndex: i,
        patches,
        truncatedLength: merged.truncatedLength,
        coverage: merged.coverage,
        drop: merged.drop,
        issues: merged.issues,
      })
    } catch {
      const isolated = buildIsolatedPacketResult({
        packetIndex: i,
        capturedLength: pkt.capturedLength,
        linkType: pkt.linkType,
        data: pkt.data,
        policy,
        unit: 'packet',
        reason: 'sanitizer-exception',
        safePrefixEnd: 0,
      })
      recordIsolationIncident(log, {
        sourceId: sourceId ?? 'pcap',
        packetIndex: i,
        packetNumber: pkt.packetNumber,
        unit: 'packet',
        reason: 'sanitizer-exception',
        stage: 'plan',
        protocol: 'processing-failed',
      })
      results.push(isolated)
    }
  }
  if (reassemblyContext) {
    try {
      applyReassemblyPatchesToResults(
        results,
        reassemblyContext,
        mapping,
        packets,
        bufferLengths,
        payloadTime,
        policy.preset === 'high-privacy',
      )
    } catch {
      // T07: reassembly failure must not abort plan — leave per-packet results as-is.
      log?.record({
        unit: 'packet',
        sourceId: sourceId ?? 'pcap',
        stage: 'reassembly',
        reason: 'sanitizer-exception',
        fallback: 'packet-masked',
        protocol: 'reassembly',
      })
    }
  }
  return results
}

/** Minimal failure shape for incident recording (wire or in-process). */
export type ClosureIncidentFailure = {
  readonly packetIndex: number
  readonly category: string
}

function recordClosureIncidents(
  log: IncidentLog,
  failures: readonly ClosureIncidentFailure[],
  sourceId: string,
  packetNumberForIndex?: (packetIndex: number) => number | undefined,
): void {
  for (const f of failures) {
    log.record({
      unit: 'field',
      sourceId,
      packetIndex: f.packetIndex,
      packetNumber: packetNumberForIndex?.(f.packetIndex),
      category: f.category,
      stage: 'mapping',
      reason: 'mapping-alias-missing',
      fallback: 'field-masked',
    })
  }
}

export function buildDeterministicPlan(input: {
  generationId: string
  profile: PcapProfile
  format: CaptureFormat
  fileName: string
  packets: readonly PacketEnvelope[]
  policy: SanitizationPolicy
  snapshot: MappingSnapshot
  reassemblyContext?: import('../reassembly/types').ReassemblyContext
  classicHeader?: ClassicPcapHeader
  pcapngSections?: readonly PcapngSectionInfo[]
  pcapngInterfaces?: readonly PcapngInterfaceInfo[]
  /** PF-06 — see buildSanitizationFromSnapshot. */
  packetDiscovery?: readonly PacketDiscoveryResult[]
  bufferLengths?: readonly number[]
  onProgress?: (done: number, total: number) => void
  /** T04 */
  sourceId?: string
  unresolvedClosureFailures?: readonly ClosureIncidentFailure[]
  incidentLog?: IncidentLog
}): PcapPlanSnapshot {
  const entropySeed = derivePlanEntropySeed(input.generationId)
  const incidentLog = input.incidentLog ?? new IncidentLog()
  const sourceId = input.sourceId ?? (input.fileName || 'pcap')
  if (input.unresolvedClosureFailures?.length) {
    recordClosureIncidents(
      incidentLog,
      input.unresolvedClosureFailures,
      sourceId,
      (idx) => input.packets[idx]?.packetNumber,
    )
  }
  // T14 — bind payload time to the same plan seed + first capture timestamp as export.
  const payloadTime = createPayloadTimeSession(input.profile.mapping.timestamps, entropySeed)
  const firstPkt = input.packets[0]
  if (firstPkt) payloadTime.bindCaptureReference(firstPkt.timestamp)
  const sanitization = buildSanitizationFromSnapshot(
    input.packets,
    input.policy,
    input.snapshot,
    input.reassemblyContext,
    entropySeed,
    input.packetDiscovery,
    input.onProgress,
    input.bufferLengths,
    incidentLog,
    sourceId,
    payloadTime,
    input.generationId,
  )
  return buildPlanSnapshot({
    generationId: input.generationId,
    profile: input.profile,
    format: input.format,
    fileName: input.fileName,
    packets: input.packets,
    sanitization,
    classicHeader: input.classicHeader,
    pcapngSections: input.pcapngSections,
    pcapngInterfaces: input.pcapngInterfaces,
    timestampAnchorSeed: entropySeed,
    incidentLog,
    sourceId,
  })
}

/** Stable wire signature for parity tests — patches sorted by packet/index/offset. */
export function planWireSignature(plan: PcapPlanSnapshot): string {
  const parts: string[] = []
  for (const p of plan.packets) {
    parts.push(`${p.index}:${p.packetNumber}:${p.drop ? 'D' : 'K'}:${p.truncatedLength ?? '-'}`)
    const sorted = [...p.patches].sort((a, b) => a.offset - b.offset)
    for (const patch of sorted) {
      parts.push(`${patch.offset}:${hex(patch.data)}`)
    }
  }
  return parts.join('|')
}

function hex(data: Uint8Array): string {
  return Array.from(data).map((b) => b.toString(16).padStart(2, '0')).join('')
}
