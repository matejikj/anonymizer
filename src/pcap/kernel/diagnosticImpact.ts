/**
 * Minimal diagnosticImpact ledger (T-01 / PROTOCOL-IMPLEMENTATION-CONTRACT §6).
 * Public codes and byte counts only — never original field values or paths.
 */

export const DIAGNOSTIC_IMPACT_REASONS = [
  'secret-redacted',
  'content-redacted',
  'unknown-schema',
  'invalid-length',
  'budget-exceeded',
  'unwritable-transform',
  'integrity-invalidated',
] as const
export type DiagnosticImpactReason = (typeof DIAGNOSTIC_IMPACT_REASONS)[number]

export const PRIMARY_DISPOSITIONS = [
  'preserve',
  'map',
  'mask',
  'time',
  'encrypted',
  'unsupported',
] as const
export type PrimaryDisposition = (typeof PRIMARY_DISPOSITIONS)[number]

export interface DiagnosticImpactEntry {
  readonly protocolId: string
  readonly variant?: string
  /** Local packet/message reference — never a raw identity. */
  readonly packetIndex: number
  readonly logicalMessageId?: number
  readonly byteCount: number
  readonly reason: DiagnosticImpactReason
  readonly disposition: PrimaryDisposition
}

export interface DiagnosticImpactLedger {
  readonly entries: readonly DiagnosticImpactEntry[]
  readonly totalBytesByReason: Readonly<Record<DiagnosticImpactReason, number>>
  readonly totalBytesByDisposition: Readonly<Record<PrimaryDisposition, number>>
}

export function emptyDiagnosticImpactLedger(): DiagnosticImpactLedger {
  return {
    entries: [],
    totalBytesByReason: zeroReasons(),
    totalBytesByDisposition: zeroDispositions(),
  }
}

export function buildDiagnosticImpactLedger(
  entries: readonly DiagnosticImpactEntry[],
): DiagnosticImpactLedger {
  const totalBytesByReason = zeroReasons()
  const totalBytesByDisposition = zeroDispositions()
  for (const e of entries) {
    totalBytesByReason[e.reason] += e.byteCount
    totalBytesByDisposition[e.disposition] += e.byteCount
  }
  return { entries, totalBytesByReason, totalBytesByDisposition }
}

function zeroReasons(): Record<DiagnosticImpactReason, number> {
  return {
    'secret-redacted': 0,
    'content-redacted': 0,
    'unknown-schema': 0,
    'invalid-length': 0,
    'budget-exceeded': 0,
    'unwritable-transform': 0,
    'integrity-invalidated': 0,
  }
}

function zeroDispositions(): Record<PrimaryDisposition, number> {
  return {
    preserve: 0,
    map: 0,
    mask: 0,
    time: 0,
    encrypted: 0,
    unsupported: 0,
  }
}
