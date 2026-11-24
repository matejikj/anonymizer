/**
 * Freeze discovery sanitize results into FrozenPacketPlan without retaining packet payloads.
 */

import type { PacketSanitizationResult, DeferredPatchContext, BytePatch } from '../../sanitize/types'
import type { TransformationIntent } from '../../discovery/types'
import type { PacketReassemblyOverlay } from '../../reassembly/types'
import { mergePacketWithReassemblyOverlay } from '../../reassembly/capturePhase'
import { mergePatchesStrict } from '../../plan/mergePatchesStrict'
import type { FrozenPacketPlan } from '../frozenPlan'
import { symbolicizeMaskPatches } from '../frozenPlan'
import type { SymbolicOperation } from '../operations'

export function freezeSanitizationResult(input: {
  packetIndex: number
  packetNumber: number
  bufferLength: number
  result: PacketSanitizationResult
  intents: readonly TransformationIntent[]
  overlay?: PacketReassemblyOverlay
}): FrozenPacketPlan {
  const { result, overlay, bufferLength, packetIndex, packetNumber, intents } = input
  const resolveBase = result.resolvePatches
  const journalOps = result.symbolicMapOps ?? []
  const journalBackedDeferred =
    result.deferredFullySymbolized === true && overlay === undefined

  // Legacy deferred bridge still resolves placeholder bytes at plan time (R01).
  // When every deferred patch is mirrored as a journal op, render purely from ops (T-01.B).
  // Eager concrete patches (e.g. SIP multipart CTE body mask via patchFixedLengthAscii) are
  // NOT deferred — they must still be kept as fixed/mask ops or they vanish from export.
  if (resolveBase || overlay) {
    const common: FrozenPacketPlan = {
      packetIndex,
      packetNumber,
      bufferLength,
      drop: result.drop,
      truncatedLength: result.truncatedLength,
      coverage: result.coverage,
      issues: result.issues,
      intents,
      ops: journalOps,
    }
    if (journalBackedDeferred) {
      const journalOffsets = new Set(
        journalOps.map((op) => (op.kind === 'checksum' ? -1 : op.offset)),
      )
      // Drop zero-filled deferred placeholders already covered by journal ops.
      const eagerPatches = result.patches.filter(
        (p) => !journalOffsets.has(p.offset) && !isAllZeroPatch(p.data),
      )
      if (eagerPatches.length === 0) return common
      const { ops: maskOps, remainder } = symbolicizeMaskPatches(packetIndex, eagerPatches)
      const fixedOps: SymbolicOperation[] = remainder.map((p) => ({
        kind: 'fixed' as const,
        packetIndex,
        offset: p.offset,
        data: p.data.slice(),
      }))
      return { ...common, ops: [...journalOps, ...maskOps, ...fixedOps] }
    }
    return {
      ...common,
      legacyResolve: (ctx: DeferredPatchContext): BytePatch[] => {
        const base = resolveBase ? resolveBase(ctx) : result.patches
        const remerged = mergePacketWithReassemblyOverlay({ ...result, patches: base }, overlay)
        return mergePatchesStrict(bufferLength, packetIndex, remerged.patches)
      },
    }
  }

  const { ops: maskOps, remainder } = symbolicizeMaskPatches(packetIndex, result.patches)
  const fixedOps: SymbolicOperation[] = remainder.map((p) => ({
    kind: 'fixed' as const,
    packetIndex,
    offset: p.offset,
    data: p.data.slice(),
  }))

  return {
    packetIndex,
    packetNumber,
    bufferLength,
    drop: result.drop,
    truncatedLength: result.truncatedLength,
    coverage: result.coverage,
    issues: result.issues,
    intents,
    ops: [...maskOps, ...fixedOps],
  }
}

function isAllZeroPatch(data: Uint8Array): boolean {
  for (let i = 0; i < data.length; i++) {
    if (data[i] !== 0) return false
  }
  return data.length > 0
}
