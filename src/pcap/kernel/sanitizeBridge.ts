/**
 * Production bridge: kernel-native ProtocolModules → PatchCollector / coverage.
 * Used so onboarding modules (echo-udp-example, rnd-dispatch-lite) participate in
 * sanitize/export without a second hand-written branch in engine.ts.
 */

import type { IntentCollector } from '../discovery/intentCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { PatchCollector } from '../sanitize/PatchCollector'
import type { LayerCoverage } from '../sanitize/types'
import { FingerprintSession } from '../anonymization/fingerprintSession'
import { getSharedProtocolManifest } from './catalog'
import { createFactWriter } from './factWriter'
import { SemanticJournalBuilder } from './journal'
import { renderSymbolicOperations, type SymbolicOperation } from './operations'
import type { ManifestEntry } from './manifest'
import type { KernelProtocolModule } from './protocolModule'
import type { AnalyzeContext, BorrowedByteView, ProbeContext } from './types'

export interface KernelSanitizeHit {
  readonly protocolId: string
  readonly lastCoveredOffset: number
}

/**
 * Probe+analyze kernel-native application modules indexed by UDP/TCP port.
 * Returns null when no module claims the payload.
 */
export function tryKernelNativeApplicationSanitize(input: {
  readonly buffer: Uint8Array
  readonly offset: number
  readonly length: number
  readonly srcPort: number
  readonly dstPort: number
  readonly transport: 'tcp' | 'udp'
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly intents: IntentCollector | undefined
  readonly coverage: LayerCoverage[]
  readonly issues: string[]
  readonly packetIndex: number
  readonly linkType?: number
  /** When set, only this kernel-native application module may claim (T-01.F in-order dispatch). */
  readonly protocolId?: string
}): KernelSanitizeHit | null {
  if (input.length <= 0) return null
  const index = getSharedProtocolManifest().compile()
  let candidates: ManifestEntry[]
  if (input.protocolId) {
    const pinned = index.byId.get(input.protocolId)
    if (
      !pinned
      || pinned.legacy !== undefined
      || pinned.module.descriptor.layer !== 'application'
    ) {
      return null
    }
    candidates = [pinned]
  } else {
    const portMap = input.transport === 'udp' ? index.byUdpPort : index.byTcpPort
    candidates = uniqueEntries([
      ...(portMap.get(input.srcPort) ?? []),
      ...(portMap.get(input.dstPort) ?? []),
    ]).filter((e) => e.legacy === undefined && e.module.descriptor.layer === 'application')
  }

  if (candidates.length === 0) return null

  const view: BorrowedByteView = {
    bytes: input.buffer.subarray(input.offset, input.offset + input.length),
    byteOffset: 0,
    byteLength: input.length,
    leaseId: 0,
  }
  const probeCtx: ProbeContext = {
    packetIndex: input.packetIndex,
    linkType: input.linkType ?? 1,
    nestingDepth: 0,
    transport: input.transport,
    srcPort: input.srcPort,
    dstPort: input.dstPort,
  }

  let claimed: KernelProtocolModule | null = null
  let probes = 0
  for (const entry of candidates) {
    if (probes >= index.maxProbesPerUnit) break
    probes++
    const probeBytes = Math.min(view.byteLength, index.maxProbeBytes)
    const probeView: BorrowedByteView = {
      bytes: view.bytes.subarray(0, probeBytes),
      byteOffset: 0,
      byteLength: probeBytes,
      leaseId: 0,
    }
    const decision = entry.module.probe(probeView, probeCtx)
    if (decision.decision === 'claim' || decision.decision === 'candidate') {
      claimed = entry.module
      if (decision.decision === 'claim') break
    }
  }
  if (!claimed) return null
  if (input.protocolId && claimed.descriptor.id !== input.protocolId) return null

  const journal = new SemanticJournalBuilder(`sanitize-${input.packetIndex}`, 'pcap')
  const ops: SymbolicOperation[] = []
  const out = createFactWriter(journal, ops)
  const analyzeCtx: AnalyzeContext = {
    generationId: `sanitize-${input.packetIndex}`,
    sourceId: 'pcap',
    packetIndex: input.packetIndex,
    linkType: input.linkType ?? 1,
    nestingDepth: 0,
    logicalMessageId: input.packetIndex,
    transport: input.transport,
    srcPort: input.srcPort,
    dstPort: input.dstPort,
  }
  claimed.analyze(view, analyzeCtx, out)

  // Relocate ops from payload-relative offsets to absolute packet offsets.
  // R01: never render `map` ops with discovery PassthroughMapping (would bake originals).
  // Defer map encode until MappingAuthority.resolve via PatchCollector.addDeferred.
  const absOps = ops.map((op) => shiftOp(op, input.offset, input.packetIndex))
  const fingerprints = new FingerprintSession(`kernel-${input.packetIndex}`)
  for (const op of absOps) {
    if (op.kind === 'map') {
      const mapOp = op
      input.collector.addDeferred(
        mapOp.offset,
        mapOp.length,
        ({ mapping: live }) => {
          const rendered = renderSymbolicOperations([mapOp], { mapping: live, fingerprints })
          return rendered[0]?.data ?? null
        },
        {
          fallbackKind: 'binary-mask',
          protocol: claimed.descriptor.id,
          category: mapOp.category,
          packetIndex: input.packetIndex,
          canonical: mapOp.canonical,
          constraint: mapOp.constraint,
          encoder: mapOp.encoder,
          originalSpelling: mapOp.originalSpelling,
        },
      )
      continue
    }
    if (op.kind === 'preserve' || op.kind === 'checksum') continue
    const rendered = renderSymbolicOperations([op], {
      mapping: input.mapping,
      fingerprints,
    })
    for (const p of rendered) {
      if (op.kind === 'mask' || op.kind === 'secret') {
        input.collector.maskRange(p.offset, p.data)
      } else {
        input.collector.add(p.offset, p.data)
      }
    }
  }

  const frozen = journal.freeze()
  let coveredEnd = input.offset
  for (const fact of frozen.facts) {
    if (fact.coverageStatus) {
      const absOff = input.offset + fact.spanOffset
      input.coverage.push({
        protocol: fact.protocolId,
        offset: absOff,
        length: fact.spanLength,
        status: fact.coverageStatus,
      })
      coveredEnd = Math.max(coveredEnd, absOff + fact.spanLength)
    }
    if (fact.identityRef && input.intents) {
      input.intents.recordEntityReplacement(
        input.packetIndex,
        input.offset + fact.spanOffset,
        fact.identityRef.category,
        fact.identityRef.canonical,
        fact.spanLength,
        fact.identityRef.constraint,
        fact.identityRef.canonical,
      )
    }
  }
  for (const op of absOps) {
    if (op.kind === 'mask' || op.kind === 'secret') {
      input.intents?.recordMaskRange(
        input.packetIndex,
        op.offset,
        op.length,
        op.kind === 'mask' ? op.domain : op.reasonCode,
        claimed.descriptor.id,
      )
      input.coverage.push({
        protocol: claimed.descriptor.id,
        offset: op.offset,
        length: op.length,
        status: 'redacted',
      })
      coveredEnd = Math.max(coveredEnd, op.offset + op.length)
    }
  }

  if (coveredEnd <= input.offset) {
    input.coverage.push({
      protocol: claimed.descriptor.id,
      offset: input.offset,
      length: input.length,
      status: 'covered',
    })
    coveredEnd = input.offset + input.length
  }

  return {
    protocolId: claimed.descriptor.id,
    lastCoveredOffset: Math.max(coveredEnd, input.offset + input.length),
  }
}

function uniqueEntries<T extends { module: KernelProtocolModule }>(entries: readonly T[]): T[] {
  const seen = new Set<string>()
  const out: T[] = []
  for (const e of entries) {
    if (seen.has(e.module.descriptor.id)) continue
    seen.add(e.module.descriptor.id)
    out.push(e)
  }
  return out
}

function shiftOp(op: SymbolicOperation, base: number, packetIndex: number): SymbolicOperation {
  switch (op.kind) {
    case 'map':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'mask':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'secret':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'fingerprint':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'session-version-shift':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'preserve':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'fixed':
      return { ...op, packetIndex, offset: op.offset + base }
    case 'checksum':
      return { ...op, packetIndex }
    default:
      return op
  }
}
