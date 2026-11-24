/**
 * Collects and validates non-overlapping, length-preserving byte patches.
 * Protocol modules MUST NOT write directly to the packet buffer.
 */

import type { IncidentReason } from '../../domain/anonymizationIncident'
import { MappingLookupError, MappingPatchError } from '../anonymization/mappingErrors'
import { createFieldFallbackBytes, type FieldFallbackKind } from './fieldFallback'
import type { IdentityCategory } from '../../mapping/identityCategories'
import type {
  FingerprintOperation,
  MapOperation,
  MaskOperation,
  SessionVersionShiftOperation,
  SymbolicOperation,
} from '../kernel/operations'
import type {
  BytePatch,
  DeferredPatchCompute,
  DeferredPatchContext,
  DeferredPatchMeta,
} from './types'

const DEFAULT_META: DeferredPatchMeta = { fallbackKind: 'binary-mask' }

export class PatchCollector {
  private readonly _patches: BytePatch[] = []
  private readonly _deferred = new Map<number, DeferredPatchCompute>()
  private readonly _deferredMeta = new Map<number, DeferredPatchMeta>()
  /** R09 — parallel structured map ops for journal-backed plan (keyed like deferred). */
  private readonly _symbolicMapByOffset = new Map<number, MapOperation>()
  /** T-01.B — parallel mask/secret ops for maskRangeDeferred (keyed like deferred). */
  private readonly _symbolicMaskByOffset = new Map<number, MaskOperation>()
  /** T-01.B — fingerprint ops for IPv4 ID / flow label / TCP seq deferrals. */
  private readonly _symbolicFingerprintByOffset = new Map<number, FingerprintOperation>()
  /** T-01.B / T01 — session-version shift ops (derived from mapped session-id). */
  private readonly _symbolicSessionVersionByOffset = new Map<number, SessionVersionShiftOperation>()
  private readonly _bufferLength: number

  constructor(bufferLength: number) {
    this._bufferLength = bufferLength
  }

  /** Add a length-preserving patch. Throws on overlap or out-of-bounds. */
  add(offset: number, data: Uint8Array): void {
    if (offset < 0 || offset + data.length > this._bufferLength) {
      throw new MappingPatchError(
        'length-mismatch',
        `Patch out of bounds: offset=${offset} len=${data.length} buffer=${this._bufferLength}`,
      )
    }
    const end = offset + data.length
    for (const p of this._patches) {
      const pEnd = p.offset + p.data.length
      if (offset < pEnd && end > p.offset) {
        throw new MappingPatchError(
          'patch-overlap',
          `Patch overlap: [${offset},${end}) vs [${p.offset},${pEnd})`,
        )
      }
    }
    this._patches.push({ offset, data })
  }

  /**
   * Replace any patches overlapping [offset, offset+data.length) with a single
   * mask span (step 4 in-place masking over heuristic/partial patches).
   */
  maskRange(offset: number, data: Uint8Array): void {
    if (offset < 0 || offset + data.length > this._bufferLength) {
      throw new MappingPatchError(
        'length-mismatch',
        `Mask out of bounds: offset=${offset} len=${data.length} buffer=${this._bufferLength}`,
      )
    }
    const end = offset + data.length
    const kept: BytePatch[] = []
    for (const p of this._patches) {
      const pEnd = p.offset + p.data.length
      if (pEnd <= offset || p.offset >= end) {
        kept.push(p)
      } else if (this._deferred.has(p.offset)) {
        // The evicted patch's deferred compute is keyed by offset only. Without removing it
        // here, it would be orphaned and could wrongly reattach in resolveDeferred() to
        // whatever unrelated patch a later add()/addDeferred() installs at this same offset.
        this._deferred.delete(p.offset)
        this._deferredMeta.delete(p.offset)
        this._symbolicMapByOffset.delete(p.offset)
        this._symbolicMaskByOffset.delete(p.offset)
        this._symbolicFingerprintByOffset.delete(p.offset)
      }
    }
    this._patches.length = 0
    this._patches.push(...kept, { offset, data })
  }

  /** Add a patch from a numeric array for convenience. */
  addBytes(offset: number, bytes: number[]): void {
    this.add(offset, new Uint8Array(bytes))
  }

  /**
   * PF-06: reserve [offset, offset+length) now — participating in the exact same
   * overlap/bounds bookkeeping as `add()` — but defer computing the actual replacement
   * bytes until `resolveDeferred()` runs. Overlap resolution never inspects patch content,
   * only offset/length, so running it now with a placeholder and computing real bytes later
   * produces an identical winner set to computing everything eagerly.
   *
   * T04: optional `meta.fallbackKind` decides the fail-closed fill when compute throws.
   */
  addDeferred(
    offset: number,
    length: number,
    compute: DeferredPatchCompute,
    meta?: Partial<DeferredPatchMeta>,
  ): void {
    this.add(offset, new Uint8Array(length))
    this._deferred.set(offset, compute)
    this._deferredMeta.set(offset, {
      fallbackKind: meta?.fallbackKind ?? DEFAULT_META.fallbackKind,
      protocol: meta?.protocol,
      category: meta?.category,
      packetIndex: meta?.packetIndex,
      sourceId: meta?.sourceId,
      canonical: meta?.canonical,
      constraint: meta?.constraint,
      encoder: meta?.encoder,
      originalSpelling: meta?.originalSpelling,
      fingerprintField: meta?.fingerprintField,
      srcIp: meta?.srcIp,
      dstIp: meta?.dstIp,
      ipProto: meta?.ipProto,
      originalU16: meta?.originalU16,
      originalU32: meta?.originalU32,
      srcPort: meta?.srcPort,
      dstPort: meta?.dstPort,
      flowHeaderByte0: meta?.flowHeaderByte0,
      flowHeaderByte1: meta?.flowHeaderByte1,
      tcpSeqKind: meta?.tcpSeqKind,
      maskDomain: meta?.maskDomain,
      maskFillKind: meta?.maskFillKind,
      reasonCode: meta?.reasonCode,
      sessionVersionDigits: meta?.sessionVersionDigits,
      sessionIdCanonicalForVersion: meta?.sessionIdCanonicalForVersion,
    })
    this.recordDeferredSymbolicMap(offset, length, meta)
    this.recordDeferredSymbolicFingerprint(offset, length, meta)
    this.recordDeferredSymbolicSessionVersion(offset, length, meta)
  }

  /** Deferred counterpart to `maskRange()` — see `addDeferred()`. */
  maskRangeDeferred(
    offset: number,
    length: number,
    compute: DeferredPatchCompute,
    meta?: Partial<DeferredPatchMeta>,
  ): void {
    this.maskRange(offset, new Uint8Array(length))
    this._deferred.set(offset, compute)
    this._deferredMeta.set(offset, {
      fallbackKind: meta?.fallbackKind ?? DEFAULT_META.fallbackKind,
      protocol: meta?.protocol,
      category: meta?.category,
      packetIndex: meta?.packetIndex,
      sourceId: meta?.sourceId,
      canonical: meta?.canonical,
      constraint: meta?.constraint,
      encoder: meta?.encoder,
      originalSpelling: meta?.originalSpelling,
      fingerprintField: meta?.fingerprintField,
      srcIp: meta?.srcIp,
      dstIp: meta?.dstIp,
      ipProto: meta?.ipProto,
      originalU16: meta?.originalU16,
      originalU32: meta?.originalU32,
      srcPort: meta?.srcPort,
      dstPort: meta?.dstPort,
      flowHeaderByte0: meta?.flowHeaderByte0,
      flowHeaderByte1: meta?.flowHeaderByte1,
      tcpSeqKind: meta?.tcpSeqKind,
      maskDomain: meta?.maskDomain,
      maskFillKind: meta?.maskFillKind,
      reasonCode: meta?.reasonCode,
      sessionVersionDigits: meta?.sessionVersionDigits,
      sessionIdCanonicalForVersion: meta?.sessionIdCanonicalForVersion,
    })
    this.recordDeferredSymbolicMask(offset, length, meta)
    this.recordDeferredSymbolicFingerprint(offset, length, meta)
  }

  /** Structured map ops mirrored from deferred registrations (survives until evicted). */
  getSymbolicMapOps(): readonly SymbolicOperation[] {
    return [...this._symbolicMapByOffset.values()].sort((a, b) => a.offset - b.offset)
  }

  /** Mask ops mirrored from maskRangeDeferred registrations (survives until evicted). */
  getSymbolicMaskOps(): readonly SymbolicOperation[] {
    return [...this._symbolicMaskByOffset.values()].sort((a, b) => a.offset - b.offset)
  }

  getSymbolicFingerprintOps(): readonly SymbolicOperation[] {
    return [...this._symbolicFingerprintByOffset.values()].sort((a, b) => a.offset - b.offset)
  }

  getSymbolicSessionVersionOps(): readonly SymbolicOperation[] {
    return [...this._symbolicSessionVersionByOffset.values()].sort((a, b) => a.offset - b.offset)
  }

  /** Map + mask + fingerprint + session-version journal ops for freezeSanitizationResult / SemanticJournal. */
  getSymbolicJournalOps(): readonly SymbolicOperation[] {
    return [
      ...this.getSymbolicMapOps(),
      ...this.getSymbolicMaskOps(),
      ...this.getSymbolicFingerprintOps(),
      ...this.getSymbolicSessionVersionOps(),
    ].sort((a, b) => symbolicOpOffset(a) - symbolicOpOffset(b))
  }

  /**
   * True when every still-winning deferred patch has a journal symbolic op at the same offset/length.
   * Enables omitting legacyResolve when plan/export can render purely from ops.
   */
  isDeferredFullySymbolized(): boolean {
    if (this._deferred.size === 0) return true
    for (const p of this._patches) {
      const compute = this._deferred.get(p.offset)
      if (!compute) continue
      const mapOp = this._symbolicMapByOffset.get(p.offset)
      if (mapOp && mapOp.length === p.data.length) continue
      const maskOp = this._symbolicMaskByOffset.get(p.offset)
      if (maskOp && maskOp.length === p.data.length) continue
      const fpOp = this._symbolicFingerprintByOffset.get(p.offset)
      if (fpOp && fpOp.length === p.data.length) continue
      const svOp = this._symbolicSessionVersionByOffset.get(p.offset)
      if (svOp && svOp.length === p.data.length) continue
      return false
    }
    return true
  }

  /** True once any patch was reserved via addDeferred()/maskRangeDeferred(). */
  get hasDeferred(): boolean {
    return this._deferred.size > 0
  }

  /**
   * Resolve every still-winning deferred patch against a live mapping/fingerprint context,
   * replacing placeholder bytes with real ones (or dropping the patch if compute() returns
   * null — e.g. port-wire's no-op-if-unchanged suppression). No-op if nothing is deferred.
   * Patches evicted by a later maskRange() before this runs are never resolved — their
   * deferred entry is simply never looked up, matching what would happen if the original
   * eager code had never computed those bytes at all.
   *
   * T04: per-deferred try/catch — on failure apply length-preserving field fallback and
   * record a value-free incident. Never leaves NUL placeholders or original bytes.
   */
  resolveDeferred(ctx: DeferredPatchContext): void {
    if (this._deferred.size === 0) return
    const resolved: BytePatch[] = []
    for (const p of this._patches) {
      const compute = this._deferred.get(p.offset)
      if (!compute) {
        resolved.push(p)
        continue
      }
      const meta = this._deferredMeta.get(p.offset) ?? DEFAULT_META
      const reservedLen = p.data.length
      try {
        const bytes = compute(ctx)
        if (bytes === null) continue
        if (bytes.length !== reservedLen) {
          throw new MappingPatchError(
            'length-mismatch',
            `Deferred patch changed length at offset=${p.offset}: reserved=${reservedLen} resolved=${bytes.length}`,
          )
        }
        resolved.push({ offset: p.offset, data: bytes })
      } catch (err) {
        // Structural overlap/bounds bugs stay fatal; only deferred compute failures fall closed.
        if (err instanceof MappingPatchError && err.code === 'patch-overlap') throw err
        const fill = createFieldFallbackBytes({
          length: reservedLen,
          kind: meta.fallbackKind,
          packetIndex: meta.packetIndex ?? ctx.packetIndex ?? 0,
          offset: p.offset,
          domain: meta.protocol ?? meta.category ?? 'field-fallback',
        })
        if (fill.length !== reservedLen) {
          throw new MappingPatchError(
            'length-mismatch',
            `Field fallback length mismatch at offset=${p.offset}`,
          )
        }
        resolved.push({ offset: p.offset, data: fill })
        ctx.incidentLog?.record({
          unit: 'field',
          sourceId: meta.sourceId ?? ctx.sourceId ?? 'pcap',
          packetIndex: meta.packetIndex ?? ctx.packetIndex,
          packetNumber: ctx.packetNumber,
          protocol: meta.protocol,
          category: meta.category,
          stage: 'plan',
          reason: classifyDeferredFailure(err),
          fallback: 'field-masked',
        })
      }
    }
    this._patches.length = 0
    this._patches.push(...resolved)
    this._deferred.clear()
    this._deferredMeta.clear()
    // Symbolic map ops are journal metadata — not cleared with deferred resolution.
  }

  private recordDeferredSymbolicMap(
    offset: number,
    length: number,
    meta: Partial<DeferredPatchMeta> | undefined,
  ): void {
    if (
      !meta?.protocol
      || !meta.category
      || !meta.canonical
      || !meta.constraint
      || !meta.encoder
      || meta.packetIndex === undefined
    ) {
      return
    }
    this._symbolicMapByOffset.set(offset, {
      kind: 'map',
      packetIndex: meta.packetIndex,
      offset,
      length,
      category: meta.category as IdentityCategory,
      canonical: meta.canonical,
      constraint: meta.constraint,
      encoder: meta.encoder,
      originalSpelling: meta.originalSpelling,
    })
  }

  private recordDeferredSymbolicFingerprint(
    offset: number,
    length: number,
    meta: Partial<DeferredPatchMeta> | undefined,
  ): void {
    if (
      meta?.packetIndex === undefined
      || !meta.fingerprintField
      || !meta.reasonCode
      || !meta.srcIp
      || !meta.dstIp
    ) {
      return
    }
    this._symbolicFingerprintByOffset.set(offset, {
      kind: 'fingerprint',
      packetIndex: meta.packetIndex,
      offset,
      length,
      field: meta.fingerprintField,
      reasonCode: meta.reasonCode,
      srcIp: meta.srcIp,
      dstIp: meta.dstIp,
      ipProto: meta.ipProto,
      originalU16: meta.originalU16,
      originalU32: meta.originalU32,
      srcPort: meta.srcPort,
      dstPort: meta.dstPort,
      flowHeaderByte0: meta.flowHeaderByte0,
      flowHeaderByte1: meta.flowHeaderByte1,
      tcpSeqKind: meta.tcpSeqKind,
    })
  }

  private recordDeferredSymbolicMask(
    offset: number,
    length: number,
    meta: Partial<DeferredPatchMeta> | undefined,
  ): void {
    if (
      meta?.packetIndex === undefined
      || !meta.maskDomain
      || !meta.maskFillKind
      || !meta.reasonCode
    ) {
      return
    }
    this._symbolicMaskByOffset.set(offset, {
      kind: 'mask',
      packetIndex: meta.packetIndex,
      offset,
      length,
      fillKind: meta.maskFillKind,
      domain: meta.maskDomain,
      reasonCode: meta.reasonCode,
    })
  }

  private recordDeferredSymbolicSessionVersion(
    offset: number,
    length: number,
    meta: Partial<DeferredPatchMeta> | undefined,
  ): void {
    if (
      meta?.packetIndex === undefined
      || meta.sessionVersionDigits === undefined
      || meta.sessionIdCanonicalForVersion === undefined
    ) {
      return
    }
    this._symbolicSessionVersionByOffset.set(offset, {
      kind: 'session-version-shift',
      packetIndex: meta.packetIndex,
      offset,
      length,
      versionDigits: meta.sessionVersionDigits,
      sessionIdCanonical: meta.sessionIdCanonicalForVersion,
      reasonCode: meta.reasonCode ?? 'sdp-session-version-shift',
    })
  }

  /** Get all patches sorted by offset. */
  getPatches(): BytePatch[] {
    return this._patches.slice().sort((a, b) => a.offset - b.offset)
  }

  get count(): number {
    return this._patches.length
  }
}

function symbolicOpOffset(op: SymbolicOperation): number {
  return op.kind === 'checksum' ? 0 : op.offset
}

function classifyDeferredFailure(err: unknown): IncidentReason {
  if (err instanceof MappingLookupError) {
    if (err.code === 'canonicalize-failed') return 'mapping-canonicalize-failed'
    return 'mapping-alias-missing'
  }
  if (err instanceof MappingPatchError && err.code === 'length-mismatch') {
    return 'patch-length-mismatch'
  }
  return 'sanitizer-exception'
}

/** @internal — exported for tests that assert fallback kind wiring. */
export type { FieldFallbackKind }
