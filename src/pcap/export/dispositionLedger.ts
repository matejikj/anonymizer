/**
 * T62 — export disposition ledger (I2).
 *
 * Every exported byte gets exactly one FinalDisposition. Unclaimed bytes are
 * fail-closed by residual sweep (mask in diagnostic, truncate trailing in
 * high-privacy) and recorded as value-free `ledger-unclaimed` incidents.
 *
 * Aggregates only land on PcapPlanSnapshot / export report; full ranges stay
 * in the private plan-build path and are not wire-transferred.
 */

import type { IncidentLog } from '../../domain/anonymizationIncident'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import type { BytePatch, LayerCoverage } from '../sanitize/types'
import { createProtocolNeutralMaskFill } from '../sanitize/maskFill'
import type { SymbolicOperation } from '../kernel/operations'
import { buildProtocolSupportMatrix } from '../docs/protocolSupportMatrix'
import {
  fieldPolicyAllowsPreserveSafe,
} from '../kernel/fieldPolicy'
import {
  getHandlerFieldPolicy,
  hasDetailedFieldPolicy,
} from '../protocols/fieldPolicy'

export const FINAL_DISPOSITIONS = [
  'map',
  'mask',
  'truncate',
  'drop',
  'time',
  'encrypted-proven',
  'preserve-safe',
  /** T74 — diagnostic light inference left bytes unclassified but intentionally kept. */
  'preserve-inferred',
  'derived',
] as const

export type FinalDisposition = (typeof FINAL_DISPOSITIONS)[number]

export interface LedgerRange {
  readonly start: number
  readonly end: number
  readonly disposition: FinalDisposition
  readonly protocol: string
  readonly reasonCode: string
}

/** Byte counts by disposition (and optional protocol / reason breakdown). */
export interface DispositionLedgerAggregate {
  readonly byDisposition: Readonly<Record<FinalDisposition, number>>
  readonly byProtocol: Readonly<Record<string, number>>
  readonly byReason: Readonly<Record<string, number>>
  readonly unclaimedBytesBeforeSweep: number
  readonly residualMaskedBytes: number
  readonly residualTruncatedBytes: number
  readonly packetCount: number
}

export interface PacketDispositionLedger {
  readonly packetIndex: number
  readonly length: number
  readonly ranges: readonly LedgerRange[]
  readonly unclaimedBytes: number
}

export interface ResidualSweepResult {
  readonly patches: readonly BytePatch[]
  readonly truncatedLength?: number
  readonly residualMaskedBytes: number
  readonly residualTruncatedBytes: number
  readonly rangesAfterSweep: readonly LedgerRange[]
}

/** Structural L2/L3/L4 ids commonly used on LayerCoverage spans. */
const STRUCTURAL_PRESERVE_SAFE = new Set<string>([
  'ethernet',
  'vlan',
  'qinq',
  'arp',
  'ipv4',
  'ipv6',
  'icmp',
  'icmpv6',
  'tcp',
  'udp',
  'sctp',
  'gre',
  'mpls',
  'ppp',
  'pppoe',
  'null',
  'loop',
  'radiotap',
  'sll',
  'nflog',
])

let structuredProtocolCache: ReadonlySet<string> | null = null

/**
 * Transitional T62 rule: structured matrix handlers (and structural L2–L4)
 * may treat unpatched `covered` bytes as preserve-safe until field-policy
 * `preserve` declarations land (T63 canary).
 */
export function isStructuredPreserveSafeProtocol(protocol: string): boolean {
  if (STRUCTURAL_PRESERVE_SAFE.has(protocol)) return true
  if (protocol.startsWith('ipv4') || protocol.startsWith('ipv6')) return true
  if (protocol.startsWith('tcp-') || protocol.startsWith('udp-') || protocol.startsWith('sctp-')) {
    return true
  }
  return structuredPreserveSafeProtocols().has(protocol)
}

function structuredPreserveSafeProtocols(): ReadonlySet<string> {
  if (structuredProtocolCache) return structuredProtocolCache
  const set = new Set<string>(STRUCTURAL_PRESERVE_SAFE)
  for (const row of buildProtocolSupportMatrix()) {
    if (!row.structured) continue
    set.add(row.id)
    const colon = row.id.indexOf(':')
    if (colon >= 0) {
      const bare = row.id.slice(colon + 1)
      set.add(bare)
      // geneve-l2tp → geneve, l2tp
      for (const part of bare.split('-')) {
        if (part.length > 0) set.add(part)
      }
    }
  }
  structuredProtocolCache = set
  return set
}

export function emptyDispositionAggregate(): DispositionLedgerAggregate {
  return {
    byDisposition: emptyDispositionCounts(),
    byProtocol: {},
    byReason: {},
    unclaimedBytesBeforeSweep: 0,
    residualMaskedBytes: 0,
    residualTruncatedBytes: 0,
    packetCount: 0,
  }
}

function emptyDispositionCounts(): Record<FinalDisposition, number> {
  return {
    map: 0,
    mask: 0,
    truncate: 0,
    drop: 0,
    time: 0,
    'encrypted-proven': 0,
    'preserve-safe': 0,
    'preserve-inferred': 0,
    derived: 0,
  }
}

function clampRange(start: number, end: number, length: number): { start: number; end: number } | null {
  const s = Math.max(0, Math.min(start, length))
  const e = Math.max(0, Math.min(end, length))
  if (e <= s) return null
  return { start: s, end: e }
}

/**
 * Claim bytes that are still unclaimed. First writer wins — call sites must
 * apply stronger dispositions (patches) before softer ones (preserve-safe).
 */
function claimBytes(
  claimed: (FinalDisposition | null)[],
  protocols: (string | null)[],
  reasons: (string | null)[],
  start: number,
  end: number,
  disposition: FinalDisposition,
  protocol: string,
  reasonCode: string,
): void {
  const bounds = clampRange(start, end, claimed.length)
  if (!bounds) return
  for (let i = bounds.start; i < bounds.end; i++) {
    if (claimed[i] !== null) continue
    claimed[i] = disposition
    protocols[i] = protocol
    reasons[i] = reasonCode
  }
}

function dispositionFromSymbolicOp(op: SymbolicOperation): {
  disposition: FinalDisposition
  reasonCode: string
  start: number
  end: number
  protocol: string
} | null {
  switch (op.kind) {
    case 'map':
      return {
        disposition: 'map',
        reasonCode: `map:${op.category}`,
        start: op.offset,
        end: op.offset + op.length,
        protocol: op.category,
      }
    case 'fingerprint':
      return {
        disposition: 'map',
        reasonCode: `fingerprint:${op.field}`,
        start: op.offset,
        end: op.offset + op.length,
        protocol: op.field,
      }
    case 'mask':
      return {
        disposition: 'mask',
        reasonCode: op.reasonCode || 'mask',
        start: op.offset,
        end: op.offset + op.length,
        protocol: op.domain || 'payload',
      }
    case 'secret':
      return {
        disposition: 'mask',
        reasonCode: op.reasonCode || 'secret',
        start: op.offset,
        end: op.offset + op.length,
        protocol: 'secret',
      }
    case 'session-version-shift':
      return {
        disposition: 'derived',
        reasonCode: op.reasonCode || 'session-version-shift',
        start: op.offset,
        end: op.offset + op.length,
        protocol: 'sdp',
      }
    case 'fixed':
      return {
        disposition: 'mask',
        reasonCode: 'fixed-bytes',
        start: op.offset,
        end: op.offset + op.data.length,
        protocol: 'fixed',
      }
    case 'preserve':
      return {
        disposition: 'preserve-safe',
        reasonCode: op.reasonCode || 'preserve',
        start: op.offset,
        end: op.offset + op.length,
        protocol: 'preserve',
      }
    case 'checksum':
      // Checksums materialize at export recompute — no byte span on the op.
      return null
    default: {
      const _exhaustive: never = op
      void _exhaustive
      return null
    }
  }
}

function coalesceRanges(
  claimed: readonly (FinalDisposition | null)[],
  protocols: readonly (string | null)[],
  reasons: readonly (string | null)[],
): LedgerRange[] {
  const ranges: LedgerRange[] = []
  let i = 0
  while (i < claimed.length) {
    const d = claimed[i]
    if (d === null) {
      i++
      continue
    }
    const protocol = protocols[i] ?? 'unknown'
    const reasonCode = reasons[i] ?? d
    let j = i + 1
    while (
      j < claimed.length
      && claimed[j] === d
      && (protocols[j] ?? 'unknown') === protocol
      && (reasons[j] ?? d) === reasonCode
    ) {
      j++
    }
    ranges.push({ start: i, end: j, disposition: d, protocol, reasonCode })
    i = j
  }
  return ranges
}

function countUnclaimed(claimed: readonly (FinalDisposition | null)[]): number {
  let n = 0
  for (const d of claimed) if (d === null) n++
  return n
}

export interface BuildPacketLedgerInput {
  readonly packetIndex: number
  readonly length: number
  readonly drop: boolean
  readonly truncatedLength?: number
  readonly patches: readonly BytePatch[]
  readonly coverage: readonly LayerCoverage[]
  readonly symbolicOps?: readonly SymbolicOperation[]
  /** Used for level-scoped preserve-safe field policy (T63.2). */
  readonly level?: PcapAnonymizationLevel
}

/**
 * Build a per-packet ledger before residual sweep. Unclaimed bytes remain gaps.
 */
export function buildPacketDispositionLedger(input: BuildPacketLedgerInput): PacketDispositionLedger {
  const length = Math.max(0, input.length)
  const claimed: (FinalDisposition | null)[] = new Array(length).fill(null)
  const protocols: (string | null)[] = new Array(length).fill(null)
  const reasons: (string | null)[] = new Array(length).fill(null)

  if (input.drop) {
    claimBytes(claimed, protocols, reasons, 0, length, 'drop', 'packet', 'drop')
    return {
      packetIndex: input.packetIndex,
      length,
      ranges: coalesceRanges(claimed, protocols, reasons),
      unclaimedBytes: 0,
    }
  }

  if (input.truncatedLength !== undefined && input.truncatedLength < length) {
    claimBytes(
      claimed,
      protocols,
      reasons,
      input.truncatedLength,
      length,
      'truncate',
      'packet',
      'truncated',
    )
  }

  const exportLength =
    input.truncatedLength !== undefined ? Math.min(input.truncatedLength, length) : length

  // Patches / symbolic ops first (strong claims).
  if (input.symbolicOps && input.symbolicOps.length > 0) {
    const claimedByOp = new Set<string>()
    for (const op of input.symbolicOps) {
      const mapped = dispositionFromSymbolicOp(op)
      if (!mapped) continue
      claimBytes(
        claimed,
        protocols,
        reasons,
        mapped.start,
        Math.min(mapped.end, exportLength),
        mapped.disposition,
        mapped.protocol,
        mapped.reasonCode,
      )
      claimedByOp.add(`${mapped.start}:${mapped.end - mapped.start}`)
    }
    for (const patch of input.patches) {
      const key = `${patch.offset}:${patch.data.length}`
      if (claimedByOp.has(key)) continue
      // Eager / unmatched patches — conservative mask.
      claimBytes(
        claimed,
        protocols,
        reasons,
        patch.offset,
        Math.min(patch.offset + patch.data.length, exportLength),
        'mask',
        'patch',
        'eager-patch',
      )
    }
  } else {
    for (const patch of input.patches) {
      // No symbolic ops — classify eager patches conservatively as mask.
      claimBytes(
        claimed,
        protocols,
        reasons,
        patch.offset,
        Math.min(patch.offset + patch.data.length, exportLength),
        'mask',
        'patch',
        'eager-patch',
      )
    }
  }

  // Coverage: encrypted + explicit preserve + transitional covered structured.
  for (const span of input.coverage) {
    const spanEnd = Math.min(span.offset + span.length, exportLength)
    if (spanEnd <= span.offset) continue

    if (span.status === 'encrypted') {
      claimBytes(
        claimed,
        protocols,
        reasons,
        span.offset,
        spanEnd,
        'encrypted-proven',
        span.protocol,
        'encrypted',
      )
      continue
    }

    if (span.status === 'preserved-safe' || span.status === 'preserved-for-diagnostics') {
      const disposition =
        span.protocol === 'proprietary-light' || span.protocol.startsWith('proprietary-light')
          ? 'preserve-inferred'
          : 'preserve-safe'
      claimBytes(
        claimed,
        protocols,
        reasons,
        span.offset,
        spanEnd,
        disposition,
        span.protocol,
        span.status,
      )
      continue
    }

    if (span.preserve && span.preserve.length > 0) {
      for (const [off, len] of span.preserve) {
        claimBytes(
          claimed,
          protocols,
          reasons,
          off,
          Math.min(off + len, spanEnd),
          'preserve-safe',
          span.protocol,
          'field-preserve',
        )
      }
    }

    if (span.status !== 'covered') continue

    // T63.2 — detailed field policy with wire locators: only those preserve spans
    // are safe; remaining covered bytes stay unclaimed for residual sweep.
    // Tables without locators yet keep the transitional structured rule.
    if (hasDetailedFieldPolicy(span.protocol)) {
      const table = getHandlerFieldPolicy(span.protocol)
      let locatedPreserve = 0
      if (table) {
        for (const field of table.fields) {
          if (!fieldPolicyAllowsPreserveSafe(field, input.level)) continue
          const wire = field.wire
          if (!wire || wire.kind !== 'relative') continue
          const start = span.offset + wire.offset
          const end = start + wire.length
          if (start < span.offset || end > spanEnd) continue
          claimBytes(
            claimed,
            protocols,
            reasons,
            start,
            end,
            'preserve-safe',
            span.protocol,
            `field-policy:${field.fieldPath}`,
          )
          locatedPreserve += 1
        }
      }
      if (locatedPreserve > 0) continue
    }

    // Transitional: structured handlers (or detailed tables still missing locators).
    if (isStructuredPreserveSafeProtocol(span.protocol)) {
      claimBytes(
        claimed,
        protocols,
        reasons,
        span.offset,
        spanEnd,
        'preserve-safe',
        span.protocol,
        'structured-covered-transitional',
      )
    }
  }

  return {
    packetIndex: input.packetIndex,
    length: exportLength,
    ranges: coalesceRanges(claimed, protocols, reasons),
    unclaimedBytes: countUnclaimed(claimed.slice(0, exportLength)),
  }
}

/**
 * Fill unclaimed bytes: diagnostic masks in place; high-privacy truncates a
 * trailing unclaimed suffix and masks mid-packet holes (length-safe).
 */
export function applyResidualSweep(input: {
  readonly packetIndex: number
  readonly length: number
  readonly level: PcapAnonymizationLevel
  readonly ledger: PacketDispositionLedger
  readonly existingTruncatedLength?: number
  readonly incidentLog?: IncidentLog
  readonly sourceId?: string
  readonly packetNumber?: number
  readonly protocolHint?: string
}): ResidualSweepResult {
  const exportLength =
    input.existingTruncatedLength !== undefined
      ? Math.min(input.existingTruncatedLength, input.length)
      : input.ledger.length

  const claimed: (FinalDisposition | null)[] = new Array(exportLength).fill(null)
  const protocols: (string | null)[] = new Array(exportLength).fill(null)
  const reasons: (string | null)[] = new Array(exportLength).fill(null)

  for (const range of input.ledger.ranges) {
    const end = Math.min(range.end, exportLength)
    for (let i = range.start; i < end; i++) {
      claimed[i] = range.disposition
      protocols[i] = range.protocol
      reasons[i] = range.reasonCode
    }
  }

  const unclaimedRuns: Array<{ start: number; end: number }> = []
  let i = 0
  while (i < exportLength) {
    if (claimed[i] !== null) {
      i++
      continue
    }
    let j = i + 1
    while (j < exportLength && claimed[j] === null) j++
    unclaimedRuns.push({ start: i, end: j })
    i = j
  }

  if (unclaimedRuns.length === 0) {
    return {
      patches: [],
      truncatedLength: input.existingTruncatedLength,
      residualMaskedBytes: 0,
      residualTruncatedBytes: 0,
      rangesAfterSweep: input.ledger.ranges,
    }
  }

  const protocol = input.protocolHint ?? 'unknown'
  input.incidentLog?.record({
    unit: 'payload',
    sourceId: input.sourceId ?? 'pcap',
    packetIndex: input.packetIndex,
    packetNumber: input.packetNumber,
    protocol,
    stage: 'plan',
    reason: 'ledger-unclaimed',
    fallback: 'payload-masked',
  })

  let truncatedLength = input.existingTruncatedLength
  let residualTruncatedBytes = 0
  const maskRuns = [...unclaimedRuns]

  if (input.level === 'high-privacy') {
    const last = maskRuns[maskRuns.length - 1]
    if (last && last.end === exportLength) {
      // Trailing unclaimed suffix → truncate (high-privacy).
      truncatedLength =
        truncatedLength !== undefined
          ? Math.min(truncatedLength, last.start)
          : last.start
      residualTruncatedBytes = last.end - last.start
      maskRuns.pop()
      claimBytes(
        claimed,
        protocols,
        reasons,
        last.start,
        last.end,
        'truncate',
        protocol,
        'ledger-unclaimed-truncate',
      )
    }
  }

  const patches: BytePatch[] = []
  let residualMaskedBytes = 0
  for (const run of maskRuns) {
    const len = run.end - run.start
    if (len <= 0) continue
    const data = createProtocolNeutralMaskFill({
      length: len,
      packetIndex: input.packetIndex,
      offset: run.start,
      domain: 'ledger-residual',
    })
    patches.push({ offset: run.start, data })
    residualMaskedBytes += len
    claimBytes(
      claimed,
      protocols,
      reasons,
      run.start,
      run.end,
      'mask',
      protocol,
      'ledger-unclaimed-mask',
    )
  }

  const finalLength =
    truncatedLength !== undefined ? Math.min(truncatedLength, exportLength) : exportLength

  return {
    patches,
    truncatedLength:
      truncatedLength !== undefined && truncatedLength < input.length
        ? truncatedLength
        : input.existingTruncatedLength,
    residualMaskedBytes,
    residualTruncatedBytes,
    rangesAfterSweep: coalesceRanges(
      claimed.slice(0, finalLength),
      protocols.slice(0, finalLength),
      reasons.slice(0, finalLength),
    ),
  }
}

export function aggregateDispositionRanges(
  ranges: readonly LedgerRange[],
  into: {
    byDisposition: Record<FinalDisposition, number>
    byProtocol: Record<string, number>
    byReason: Record<string, number>
  },
): void {
  for (const r of ranges) {
    const bytes = Math.max(0, r.end - r.start)
    into.byDisposition[r.disposition] = (into.byDisposition[r.disposition] ?? 0) + bytes
    into.byProtocol[r.protocol] = (into.byProtocol[r.protocol] ?? 0) + bytes
    into.byReason[r.reasonCode] = (into.byReason[r.reasonCode] ?? 0) + bytes
  }
}

export function mergeDispositionAggregates(
  a: DispositionLedgerAggregate,
  b: DispositionLedgerAggregate,
): DispositionLedgerAggregate {
  const byDisposition = emptyDispositionCounts()
  for (const d of FINAL_DISPOSITIONS) {
    byDisposition[d] = (a.byDisposition[d] ?? 0) + (b.byDisposition[d] ?? 0)
  }
  const byProtocol: Record<string, number> = { ...a.byProtocol }
  for (const [k, v] of Object.entries(b.byProtocol)) {
    byProtocol[k] = (byProtocol[k] ?? 0) + v
  }
  const byReason: Record<string, number> = { ...a.byReason }
  for (const [k, v] of Object.entries(b.byReason)) {
    byReason[k] = (byReason[k] ?? 0) + v
  }
  return {
    byDisposition,
    byProtocol,
    byReason,
    unclaimedBytesBeforeSweep: a.unclaimedBytesBeforeSweep + b.unclaimedBytesBeforeSweep,
    residualMaskedBytes: a.residualMaskedBytes + b.residualMaskedBytes,
    residualTruncatedBytes: a.residualTruncatedBytes + b.residualTruncatedBytes,
    packetCount: a.packetCount + b.packetCount,
  }
}

/**
 * Plan-build finalize: ledger → residual sweep → updated patches / truncation.
 * Used by `buildPlanSnapshot` so preview and export share the same masks.
 */
export function finalizePacketDisposition(input: {
  readonly packetIndex: number
  readonly length: number
  readonly drop: boolean
  readonly truncatedLength?: number
  readonly patches: readonly BytePatch[]
  readonly coverage: readonly LayerCoverage[]
  readonly symbolicOps?: readonly SymbolicOperation[]
  readonly level: PcapAnonymizationLevel
  readonly incidentLog?: IncidentLog
  readonly sourceId?: string
  readonly packetNumber?: number
}): {
  readonly patches: readonly BytePatch[]
  readonly truncatedLength?: number
  readonly ranges: readonly LedgerRange[]
  readonly unclaimedBytesBeforeSweep: number
  readonly residualMaskedBytes: number
  readonly residualTruncatedBytes: number
} {
  if (input.drop) {
    const ledger = buildPacketDispositionLedger({
      packetIndex: input.packetIndex,
      length: input.length,
      drop: true,
      patches: [],
      coverage: input.coverage,
    })
    return {
      patches: input.patches,
      truncatedLength: input.truncatedLength,
      ranges: ledger.ranges,
      unclaimedBytesBeforeSweep: 0,
      residualMaskedBytes: 0,
      residualTruncatedBytes: 0,
    }
  }

  const ledger = buildPacketDispositionLedger({
    packetIndex: input.packetIndex,
    length: input.length,
    drop: false,
    truncatedLength: input.truncatedLength,
    patches: input.patches,
    coverage: input.coverage,
    symbolicOps: input.symbolicOps,
    level: input.level,
  })

  const sweep = applyResidualSweep({
    packetIndex: input.packetIndex,
    length: input.length,
    level: input.level,
    ledger,
    existingTruncatedLength: input.truncatedLength,
    incidentLog: input.incidentLog,
    sourceId: input.sourceId,
    packetNumber: input.packetNumber,
    protocolHint: input.coverage[input.coverage.length - 1]?.protocol,
  })

  const patches =
    sweep.patches.length === 0
      ? input.patches
      : [...input.patches, ...sweep.patches]

  return {
    patches,
    truncatedLength: sweep.truncatedLength,
    ranges: sweep.rangesAfterSweep,
    unclaimedBytesBeforeSweep: ledger.unclaimedBytes,
    residualMaskedBytes: sweep.residualMaskedBytes,
    residualTruncatedBytes: sweep.residualTruncatedBytes,
  }
}

/**
 * Export-time ledger over already-finalized plan patches (I2 check).
 * Without coverage, only patch/truncate/drop claims are made — residual must
 * already have run at plan build.
 */
export function buildExportPacketLedger(input: {
  readonly packetIndex: number
  readonly length: number
  readonly drop: boolean
  readonly truncatedLength?: number
  readonly patches: readonly BytePatch[]
}): PacketDispositionLedger {
  return buildPacketDispositionLedger({
    packetIndex: input.packetIndex,
    length: input.length,
    drop: input.drop,
    truncatedLength: input.truncatedLength,
    patches: input.patches,
    coverage: [],
  })
}
