/**
 * Frozen per-packet plan — symbolic ops + optional legacy deferred bridge.
 * Must not retain packet payload Uint8Arrays; mask fills are regenerated on render.
 */

import type { BytePatch, DeferredPatchContext, LayerCoverage } from '../sanitize/types'
import type { TransformationIntent } from '../discovery/types'
import type { SymbolicOperation } from './operations'
import { renderSymbolicOperations } from './operations'
import { createProtocolNeutralMaskFill, createMaskFill } from '../sanitize/maskFill'

export interface FrozenPacketPlan {
  readonly packetIndex: number
  readonly packetNumber: number
  readonly bufferLength: number
  readonly drop: boolean
  readonly truncatedLength?: number
  readonly coverage: readonly LayerCoverage[]
  readonly issues: readonly string[]
  readonly intents: readonly TransformationIntent[]
  readonly ops: readonly SymbolicOperation[]
  /**
   * Legacy bridge for deferred mapping computes that still close over identity strings
   * (never over packet payloads). Removed once sanitizers emit structured map ops.
   */
  readonly legacyResolve?: (ctx: DeferredPatchContext) => BytePatch[]
}

export function resolveFrozenPacketPlan(
  plan: FrozenPacketPlan,
  ctx: DeferredPatchContext,
): BytePatch[] {
  const fromOps = renderSymbolicOperations(plan.ops, {
    mapping: ctx.mapping,
    fingerprints: ctx.fingerprints,
    incidentLog: ctx.incidentLog,
    sourceId: ctx.sourceId,
    packetNumber: ctx.packetNumber ?? plan.packetNumber,
  })
  if (!plan.legacyResolve) return mergePatchesByOffset(fromOps)
  const fromLegacy = plan.legacyResolve(ctx)
  // Journal-native map ops win over legacy deferred bytes at the same offset.
  return mergePatchesByOffset([...fromLegacy, ...fromOps])
}

/** Convert concrete mask fills back to symbolic ops when they match deterministic generators. */
export function symbolicizeMaskPatches(
  packetIndex: number,
  patches: readonly BytePatch[],
  domains: readonly string[] = ['application', 'payload', 'protocol-neutral'],
): { readonly ops: SymbolicOperation[]; readonly remainder: BytePatch[] } {
  const ops: SymbolicOperation[] = []
  const remainder: BytePatch[] = []
  for (const p of patches) {
    let matched = false
    for (const domain of domains) {
      const expected = createProtocolNeutralMaskFill({
        length: p.data.length,
        packetIndex,
        offset: p.offset,
        domain,
      })
      if (bytesEqual(expected, p.data)) {
        ops.push({
          kind: 'mask',
          packetIndex,
          offset: p.offset,
          length: p.data.length,
          fillKind: 'protocol-neutral',
          domain,
          reasonCode: 'symbolicized-mask',
        })
        matched = true
        break
      }
      const stream = createMaskFill({
        length: p.data.length,
        packetIndex,
        offset: p.offset,
        domain,
        mode: 'stream',
      })
      if (bytesEqual(stream, p.data)) {
        ops.push({
          kind: 'mask',
          packetIndex,
          offset: p.offset,
          length: p.data.length,
          fillKind: 'domain-stream',
          domain,
          reasonCode: 'symbolicized-mask',
        })
        matched = true
        break
      }
    }
    if (!matched) {
      // Keep small concrete patches (IPs, ports) — not full-payload mask buffers.
      remainder.push(p)
    }
  }
  return { ops, remainder }
}

function mergePatchesByOffset(patches: readonly BytePatch[]): BytePatch[] {
  const byOffset = new Map<number, BytePatch>()
  for (const p of patches) byOffset.set(p.offset, p)
  return [...byOffset.values()].sort((a, b) => a.offset - b.offset)
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
