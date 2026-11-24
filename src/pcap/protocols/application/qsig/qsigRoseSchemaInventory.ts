/**
 * T51 — pinned QSIG ROSE dictionary inventory (explicit subset, not full ECMA catalog).
 */

import { QSIG_OP, QSIG_PINNED_OPERATIONS } from './qsigRoseSchema.ts'

export const QSIG_ROSE_SCHEMA_PIN = {
  gf: 'ECMA-165 4th ed. (GF ROSE transport)',
  services: 'ECMA-164 name ID, ECMA-174 call diversion, ECMA-178 call transfer (subset)',
  encoding: 'BER (ECMA-165 clause 11.4)',
  moduleId: 'qsig.pisn.facility.rose.pinned',
} as const

/** Highest-value supplementary-service invoke operations covered by sanitizer + tests. */
export const QSIG_PINNED_OPERATION_CODES: readonly number[] = [
  QSIG_OP.CALLING_NAME,
  QSIG_OP.CALLED_NAME,
  QSIG_OP.CONNECTED_NAME,
  QSIG_OP.BUSY_NAME,
  QSIG_OP.CALL_TRANSFER_IDENTITY,
  QSIG_OP.CALL_TRANSFER_INITIATE,
  QSIG_OP.CALL_TRANSFER_SETUP,
  QSIG_OP.CALL_TRANSFER_ACTIVE,
  QSIG_OP.CALL_TRANSFER_COMPLETE,
  QSIG_OP.ACTIVATE_DIVERSION,
  QSIG_OP.DEACTIVATE_DIVERSION,
  QSIG_OP.INTERROGATE_DIVERSION,
  QSIG_OP.CALL_REROUTING,
  QSIG_OP.DIVERTING_LEG_INFO1,
  QSIG_OP.DIVERTING_LEG_INFO2,
  QSIG_OP.DIVERTING_LEG_INFO3,
]

/** Sanity: inventory matches schema map keys. */
export function qsigPinnedInventoryMatchesSchema(): boolean {
  return QSIG_PINNED_OPERATION_CODES.every((op) => QSIG_PINNED_OPERATIONS[op] !== undefined)
}

/**
 * Explicit non-claim: auto-generated full QSIG ECMA operation/argument dictionaries (B-SCHEMA)
 * remain out of scope — unknown opcodes mask argument only; ACSE/DSE dialog portions mask-only.
 */
export const QSIG_FULL_ECM_CATALOG_CLAIM = false
