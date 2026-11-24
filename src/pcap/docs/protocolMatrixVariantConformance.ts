/**
 * T32 — per-variant conformance contract for generated support matrix rows.
 * Structured / encrypted-phase public claims require registered vitest evidence
 * (negative unknown/malformed path + diagnostic invariant). Ceilings cap known
 * overclaimers (OpenVPN/QUIC/DTLS/SSH) regardless of HANDLER_NOTES typos.
 */

import type { SupportProtection } from './protocolSupportMatrix.ts'
import { STRUCTURED_MATRIX_EVIDENCE } from './protocolMatrixStructuredEvidence.ts'

export const MATRIX_NEGATIVE_PATH_MARKERS = [
  'malformed',
  'unknown',
  'unsupported',
  'fail-closed',
  'must-not',
  'redacted',
  'negative',
  'heuristic',
  'requires-reassembly',
  'truncate',
  'opaque',
  'mask',
] as const

export const MATRIX_DIAGNOSTIC_INVARIANT_MARKERS = [
  'packet count',
  'originalLength',
  'capturedLength',
  'length-preserving',
  'runDiagnosticExportPipeline',
  'validationValid',
  'packets.length',
  '.length)',
  'preserve',
] as const

export interface VariantConformanceSpec {
  /** Hard cap on published protection (overrides HANDLER_NOTES). */
  readonly protectionCeiling: SupportProtection
  readonly evidenceModules: readonly string[]
  readonly negativePathMarkers?: readonly string[]
  readonly diagnosticInvariantMarkers?: readonly string[]
  /** When true, matrix row must not emit structured even if notes claim it. */
  readonly denyStructured?: boolean
  /** When true, matrix row must not emit provenCiphertext. */
  readonly denyProvenCiphertext?: boolean
}

/** Handlers that previously overclaimed encrypted/structured support (T28/R02). */
export const VARIANT_CONFORMANCE_SPECS: Readonly<
  Record<string, VariantConformanceSpec>
> = {
  openvpn: {
    protectionCeiling: 'mask-only',
    evidenceModules: [
      'tests/pcap/unit/t28EncryptedTransports.test.ts',
      'tests/pcap/unit/t32ProtocolSupportMatrix.test.ts',
    ],
    negativePathMarkers: ['openvpn-data', 'redacted', 'requires-reassembly'],
    diagnosticInvariantMarkers: ['runDiagnosticExportPipeline', 'capturedLength'],
    denyStructured: true,
    denyProvenCiphertext: true,
  },
  quic: {
    protectionCeiling: 'mask-only',
    evidenceModules: ['tests/pcap/unit/t28EncryptedTransports.test.ts'],
    negativePathMarkers: ['Initial', 'mask', 'redacted'],
    diagnosticInvariantMarkers: ['capturedLength', 'sanitizeQuic'],
    denyStructured: true,
    denyProvenCiphertext: true,
  },
  dtls: {
    protectionCeiling: 'mask-only',
    evidenceModules: ['tests/pcap/unit/t28EncryptedTransports.test.ts'],
    negativePathMarkers: ['requires-reassembly', 'redacted', 'DTLS'],
    diagnosticInvariantMarkers: ['runDiagnosticExportPipeline', 'validationValid'],
    denyStructured: true,
    denyProvenCiphertext: true,
  },
  ssh: {
    protectionCeiling: 'mask-only',
    evidenceModules: ['tests/pcap/unit/t28EncryptedTransports.test.ts'],
    negativePathMarkers: ['NEWKEYS', 'mask', 'opaque'],
    diagnosticInvariantMarkers: ['capturedLength', 'applyPatches'],
    denyStructured: true,
    denyProvenCiphertext: true,
  },
}

export interface HandlerNoteForConformance {
  readonly protection: SupportProtection
  readonly provenCiphertext?: boolean
  readonly limitation?: string
}

export interface EffectiveMatrixFlags {
  readonly protection: SupportProtection
  readonly identification: boolean
  readonly structured: boolean
  readonly provenCiphertext: boolean
  readonly limitation?: string
}

function protectionFlags(p: SupportProtection): Omit<EffectiveMatrixFlags, 'protection' | 'limitation'> {
  switch (p) {
    case 'structured':
      return { identification: true, structured: true, provenCiphertext: false }
    case 'encrypted-phase':
      return { identification: true, structured: true, provenCiphertext: true }
    case 'container':
      return { identification: true, structured: true, provenCiphertext: false }
    case 'decode-map':
      return { identification: true, structured: true, provenCiphertext: false }
    case 'mask-only':
      return { identification: true, structured: false, provenCiphertext: false }
    case 'identify-mask':
      return { identification: true, structured: false, provenCiphertext: false }
  }
}

function hasRegisteredStructuredEvidence(handlerId: string): boolean {
  const spec = VARIANT_CONFORMANCE_SPECS[handlerId]
  if (spec) return spec.evidenceModules.length > 0
  return Object.prototype.hasOwnProperty.call(STRUCTURED_MATRIX_EVIDENCE, handlerId)
}

/** Apply conformance ceilings and evidence gates for one application handler row. */
export function resolveEffectiveAppHandlerFlags(
  handlerId: string,
  note: HandlerNoteForConformance,
): EffectiveMatrixFlags {
  const spec = VARIANT_CONFORMANCE_SPECS[handlerId]
  let protection = note.protection
  let limitation = note.limitation

  if (spec?.protectionCeiling) {
    protection = spec.protectionCeiling
  } else if (
    (protection === 'structured' || protection === 'encrypted-phase') &&
    !hasRegisteredStructuredEvidence(handlerId)
  ) {
    protection = 'mask-only'
    limitation = limitation
      ? `${limitation}; matrix: chybí conformance evidence — structured zakázáno`
      : 'matrix: chybí conformance evidence — structured zakázáno'
  }

  const flags = protectionFlags(protection)
  let structured = flags.structured
  let provenCiphertext = note.provenCiphertext ?? flags.provenCiphertext

  if (spec?.denyStructured) structured = false
  if (spec?.denyProvenCiphertext) provenCiphertext = false

  if (protection !== 'encrypted-phase') provenCiphertext = false
  if (protection === 'mask-only' || protection === 'identify-mask') structured = false

  return {
    protection,
    identification: flags.identification,
    structured,
    provenCiphertext,
    limitation,
  }
}

function moduleHasMarkers(
  content: string,
  negativeMarkers: readonly string[],
  diagnosticMarkers: readonly string[],
): { negative: boolean; diagnostic: boolean } {
  const lower = content.toLowerCase()
  const negative = negativeMarkers.some((m) => lower.includes(m.toLowerCase()))
  const diagnostic = diagnosticMarkers.some((m) => lower.includes(m.toLowerCase()))
  return { negative, diagnostic }
}

export interface MatrixConformanceViolation {
  readonly handlerId: string
  readonly message: string
}

/** Filesystem-backed validation for vitest (not for browser bundle). */
export function collectMatrixConformanceViolations(
  anonymizerRoot: string,
  readText: (absPath: string) => string,
): MatrixConformanceViolation[] {
  const violations: MatrixConformanceViolation[] = []
  const defaultNeg = MATRIX_NEGATIVE_PATH_MARKERS
  const defaultDiag = MATRIX_DIAGNOSTIC_INVARIANT_MARKERS

  const checkEvidence = (
    handlerId: string,
    modules: readonly string[],
    negativeMarkers: readonly string[],
    diagnosticMarkers: readonly string[],
  ): void => {
    if (modules.length === 0) {
      violations.push({
        handlerId,
        message: 'structured/encrypted claim without registered evidence modules',
      })
      return
    }
    let anyNegative = false
    let anyDiagnostic = false
    for (const rel of modules) {
      const abs = `${anonymizerRoot}/${rel}`
      let content: string
      try {
        content = readText(abs)
      } catch {
        violations.push({ handlerId, message: `missing evidence module ${rel}` })
        continue
      }
      const hit = moduleHasMarkers(content, negativeMarkers, diagnosticMarkers)
      anyNegative ||= hit.negative
      anyDiagnostic ||= hit.diagnostic
    }
    if (!anyNegative) {
      violations.push({
        handlerId,
        message: `evidence lacks negative/unknown/malformed path markers (${modules.join(', ')})`,
      })
    }
    if (!anyDiagnostic) {
      violations.push({
        handlerId,
        message: `evidence lacks diagnostic invariant markers (${modules.join(', ')})`,
      })
    }
  }

  for (const [handlerId, spec] of Object.entries(VARIANT_CONFORMANCE_SPECS)) {
    checkEvidence(
      handlerId,
      spec.evidenceModules,
      spec.negativePathMarkers ?? defaultNeg,
      spec.diagnosticInvariantMarkers ?? defaultDiag,
    )
  }

  for (const [handlerId, modules] of Object.entries(STRUCTURED_MATRIX_EVIDENCE)) {
    if (VARIANT_CONFORMANCE_SPECS[handlerId]) continue
    checkEvidence(handlerId, modules, defaultNeg, defaultDiag)
  }

  return violations
}
