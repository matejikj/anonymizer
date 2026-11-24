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
import { internCoverage, internIssues, internSharedOp, internString } from '../identityIntern'

export function freezeSanitizationResult(input: {
  packetIndex: number
  packetNumber: number
  bufferLength: number
  result: PacketSanitizationResult
  intents: readonly TransformationIntent[]
  overlay?: PacketReassemblyOverlay
}): FrozenPacketPlan {
  const { result, overlay, bufferLength, packetIndex, packetNumber, intents } = input
  const merged = mergePacketWithReassemblyOverlay(result, overlay)
  const domainsAt = maskDomainsFromIntents(intents)
  const resolveBase = result.resolvePatches
  const journalOps = (result.symbolicMapOps ?? []).map((op) => internSharedOp(op, packetIndex))
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
      drop: merged.drop,
      truncatedLength: merged.truncatedLength,
      coverage: internCoverage(merged.coverage),
      issues: internIssues(merged.issues),
      intents,
      ops: journalOps,
    }
    if (journalBackedDeferred) {
      const journalOffsets = new Set(
        journalOps.map((op) => (op.kind === 'checksum' ? -1 : op.offset)),
      )
      // Drop deferred placeholders — isDeferredFullySymbolized guarantees each winning one has a
      // journal op at its offset. Never filter by content: an eager mask fill can legitimately be
      // all zeros (1-byte RTP extension values: ~1 in 256 packets) and would export the original.
      const eagerPatches = result.patches.filter((p) => !journalOffsets.has(p.offset))
      if (eagerPatches.length === 0) return common
      const symbolized = symbolicizeMaskPatches(packetIndex, eagerPatches, undefined, domainsAt)
      const maskOps = symbolized.ops.map((op) => internSharedOp(op, packetIndex))
      const remainder = symbolized.remainder
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

  const symbolized = symbolicizeMaskPatches(packetIndex, result.patches, undefined, domainsAt)
  const maskOps = symbolized.ops.map((op) => internSharedOp(op, packetIndex))
  const remainder = symbolized.remainder
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
    coverage: internCoverage(result.coverage),
    issues: internIssues(result.issues),
    intents,
    ops: [...maskOps, ...fixedOps],
  }
}

/**
 * Mask fills are seeded by a domain string the sanitizer knows but the patch does not carry.
 * Mask-range intents recorded alongside (e.g. RTP `media-opaque:rtp`, `strip-payload` →
 * `media-strip:<protocol>`) name it, so the mask can be stored as a regenerable op instead of
 * a copied payload. symbolicizeMaskPatches still byte-compares, so a wrong guess is harmless.
 */
function maskDomainsFromIntents(
  intents: readonly TransformationIntent[],
): ((offset: number) => readonly string[] | undefined) | undefined {
  let byOffset: Map<number, string[]> | undefined
  for (const it of intents) {
    if (it.kind !== 'mask-range') continue
    byOffset ??= new Map()
    byOffset.set(it.offset, [internString(it.reason), internString(`media-strip:${it.protocol}`)])
  }
  return byOffset ? (offset) => byOffset.get(offset) : undefined
}
