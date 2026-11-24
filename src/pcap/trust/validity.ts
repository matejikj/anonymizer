/**
 * Enterprise step 1 — multi-layer validity model for export reports.
 *
 * Do not claim "wire-valid" as a single boolean. Transport checksums can be correct
 * while TLS Finished / STUN MESSAGE-INTEGRITY / STIR Identity are MODIFIED.
 */

export const VALIDITY_STATUSES = ['VALID', 'MODIFIED', 'UNKNOWN'] as const

export type ValidityStatus = (typeof VALIDITY_STATUSES)[number]

export interface ExportValidityLayers {
  readonly capture_structure: ValidityStatus
  readonly network_checksums: ValidityStatus
  readonly application_structure: ValidityStatus
  readonly cryptographic_integrity: ValidityStatus
}

export function isValidityStatus(value: unknown): value is ValidityStatus {
  return value === 'VALID' || value === 'MODIFIED' || value === 'UNKNOWN'
}

export function isExportValidityLayers(value: unknown): value is ExportValidityLayers {
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return (
    isValidityStatus(v.capture_structure)
    && isValidityStatus(v.network_checksums)
    && isValidityStatus(v.application_structure)
    && isValidityStatus(v.cryptographic_integrity)
  )
}

export interface BuildValidityLayersInput {
  /** Structural capture / baseline validation passed. */
  readonly validationValid: boolean
  /** Count of new blocking structural issues introduced by sanitization. */
  readonly newBlockingIssueCount?: number
  /** Checksum disposition totals from the export checksum report. */
  readonly checksumCounts?: Readonly<Partial<Record<string, number>>>
  /** Unsupported / unhandled application layers or plaintext regions. */
  readonly unsupportedLayers?: number
  /** Explicit crypto status when known (STUN MI, TLS, STIR). Default UNKNOWN until steps 6–8. */
  readonly cryptographicIntegrity?: ValidityStatus
}

function checksumLayerStatus(
  counts: Readonly<Partial<Record<string, number>>> | undefined,
): ValidityStatus {
  if (!counts) return 'UNKNOWN'
  const offload = (counts['offload-suspected'] ?? 0) + (counts['not-verifiable'] ?? 0)
  const invalid = counts['input-invalid'] ?? 0
  const touched =
    (counts.recomputed ?? 0)
    + (counts['incrementally-updated'] ?? 0)
    + (counts.unchanged ?? 0)
    + (counts['preserved-zero'] ?? 0)
    + invalid
    + offload
  if (touched === 0) return 'UNKNOWN'
  if (offload > 0) return 'UNKNOWN'
  if (invalid > 0) return 'MODIFIED'
  return 'VALID'
}

/**
 * Derive honest validity layers from currently available export signals.
 * cryptographic_integrity stays UNKNOWN until protocol steps mark MODIFIED
 * (enterprise step 6–8: TLS handshake / SIP Identity / STUN MI).
 */
export function buildValidityLayers(input: BuildValidityLayersInput): ExportValidityLayers {
  const blocking = input.newBlockingIssueCount ?? 0
  const capture_structure =
    !input.validationValid || blocking > 0 ? 'MODIFIED' : 'VALID'

  const unsupported = input.unsupportedLayers ?? 0
  const application_structure = unsupported > 0 ? 'UNKNOWN' : 'VALID'

  return {
    capture_structure,
    network_checksums: checksumLayerStatus(input.checksumCounts),
    application_structure,
    cryptographic_integrity: input.cryptographicIntegrity ?? 'UNKNOWN',
  }
}
