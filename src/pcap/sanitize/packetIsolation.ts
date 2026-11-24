/**
 * T07 — packet/payload isolation fallback when sanitization throws.
 * Decision is deterministic so discovery and plan agree.
 */

import type { IncidentLog } from '../../domain/anonymizationIncident'
import type { IncidentReason } from '../../domain/anonymizationIncident'
import { createProtocolNeutralMaskFill } from './maskFill'
import type {
  BytePatch,
  LayerCoverage,
  PacketSanitizationResult,
  SanitizationPolicy,
} from './types'
import { PatchCollector } from './PatchCollector'

export type IsolationUnit = 'payload' | 'packet'

export interface IsolationDecision {
  readonly unit: IsolationUnit
  readonly reason: IncidentReason
  /** Byte offset where mask/truncate starts (after safe prefix / link header). */
  readonly safePrefixEnd: number
}

/**
 * Link-header end for common DLT values — used when L3/L4 failed before coverage
 * recorded a safe prefix. Masks from here (diagnostic) or drops (high-privacy).
 */
export function linkLayerEnd(linkType: number, data: Uint8Array): number {
  switch (linkType) {
    case 1: {
      // Ethernet + optional VLAN tags
      if (data.length < 14) return 0
      let offset = 12
      let etherType = (data[offset]! << 8) | data[offset + 1]!
      while ((etherType === 0x8100 || etherType === 0x88a8) && offset + 4 <= data.length) {
        offset += 4
        etherType = (data[offset]! << 8) | data[offset + 1]!
      }
      return Math.min(offset + 2, data.length)
    }
    case 113:
      return data.length >= 16 ? 16 : 0
    case 276:
      return data.length >= 20 ? 20 : 0
    case 177: // LINKTYPE_LINUX_LAPD — whole frame is signalling
      return 0
    case 101:
    case 228:
    case 229:
      return 0
    default:
      return 0
  }
}

/** App-layer failure → payload unit; outer failure → packet unit. */
export function isolationUnitForScope(scope: 'application' | 'packet'): IsolationUnit {
  return scope === 'application' ? 'payload' : 'packet'
}

export function recordIsolationIncident(
  log: IncidentLog | undefined,
  input: {
    readonly sourceId: string
    readonly packetIndex: number
    readonly packetNumber?: number
    readonly protocol?: string
    readonly unit: IsolationUnit
    readonly reason: IncidentReason
    readonly stage?: 'discovery' | 'plan' | 'reassembly' | 'export'
  },
): void {
  log?.record({
    unit: input.unit === 'payload' ? 'payload' : 'packet',
    sourceId: input.sourceId,
    packetIndex: input.packetIndex,
    packetNumber: input.packetNumber,
    protocol: input.protocol,
    stage: input.stage ?? 'discovery',
    reason: input.reason,
    fallback: input.unit === 'payload' ? 'payload-masked' : 'packet-masked',
  })
}

/**
 * Build a fail-closed PacketSanitizationResult for an isolation event.
 * Diagnostic: mask from safePrefixEnd (or entire frame if 0).
 * High-privacy: payload → truncate; packet → drop.
 */
export function buildIsolatedPacketResult(input: {
  readonly packetIndex: number
  readonly capturedLength: number
  readonly linkType: number
  readonly data: Uint8Array
  readonly policy: SanitizationPolicy
  readonly unit: IsolationUnit
  readonly reason: IncidentReason
  /** Already-covered safe prefix; 0 means use link-layer end or full mask. */
  readonly safePrefixEnd: number
  readonly priorCoverage?: readonly LayerCoverage[]
  readonly priorIssues?: readonly string[]
  readonly deferPatchResolution?: boolean
}): PacketSanitizationResult {
  const issues = [...(input.priorIssues ?? []), `isolation:${input.unit}:${input.reason}`]
  const coverage: LayerCoverage[] = [...(input.priorCoverage ?? [])]

  const highPrivacy = input.policy.preset === 'high-privacy'

  if (input.unit === 'packet' && highPrivacy) {
    coverage.push({
      protocol: 'processing-failed',
      offset: 0,
      length: input.capturedLength,
      status: 'processing-failed',
    })
    return {
      packetIndex: input.packetIndex,
      patches: [],
      drop: true,
      coverage,
      issues,
    }
  }

  let maskFrom = input.safePrefixEnd
  if (maskFrom <= 0) {
    maskFrom = linkLayerEnd(input.linkType, input.data)
  }
  // Unparseable L2: mask the entire frame (including MAC) — never leave raw bytes.
  if (maskFrom <= 0 && input.capturedLength > 0) {
    maskFrom = 0
  }

  if (input.unit === 'payload' && highPrivacy) {
    coverage.push({
      protocol: 'processing-failed',
      offset: maskFrom,
      length: Math.max(0, input.capturedLength - maskFrom),
      status: 'processing-failed',
    })
    return {
      packetIndex: input.packetIndex,
      patches: [],
      drop: false,
      truncatedLength: maskFrom,
      coverage,
      issues,
    }
  }

  // Diagnostic (or packet-level diagnostic): length-preserving mask.
  const collector = new PatchCollector(input.capturedLength)
  const maskLen = input.capturedLength - maskFrom
  if (maskLen > 0) {
    const fill = createProtocolNeutralMaskFill({
      length: maskLen,
      packetIndex: input.packetIndex,
      offset: maskFrom,
      domain: `isolation:${input.unit}`,
    })
    collector.maskRange(maskFrom, fill)
  }
  coverage.push({
    protocol: 'processing-failed',
    offset: maskFrom,
    length: Math.max(0, maskLen),
    status: 'processing-failed',
  })

  const patches = collector.getPatches()
  if (input.deferPatchResolution) {
    return {
      packetIndex: input.packetIndex,
      patches,
      drop: false,
      coverage,
      issues,
      resolvePatches: () => patches,
    }
  }
  return {
    packetIndex: input.packetIndex,
    patches,
    drop: false,
    coverage,
    issues,
  }
}

/** Convert isolation result patches into a stable resolvePatches callback. */
export function fixedResolvePatches(patches: readonly BytePatch[]): () => BytePatch[] {
  const copy = patches.map((p) => ({ offset: p.offset, data: p.data.slice() }))
  return () => copy.map((p) => ({ offset: p.offset, data: p.data.slice() }))
}
