/**
 * T57 — pinned TS 36.413 v18.1.0 APER inventory (explicit subset, not code-generated object sets).
 */

import { S1AP_IE, S1AP_PROC } from './s1apSchema.ts'

export const S1AP_SCHEMA_PIN = {
  ts: 'TS 36.413 v18.1.0',
  encoding: 'aligned BASIC-PER (APER)',
  moduleId: 's1ap.ts36413.r18',
} as const

/** Core mobility / attach / bearer procedures covered by sanitizer + tests. */
export const S1AP_PINNED_PROCEDURES: readonly number[] = [
  S1AP_PROC.HANDOVER_PREPARATION,
  S1AP_PROC.PATH_SWITCH_REQUEST,
  S1AP_PROC.E_RAB_SETUP,
  S1AP_PROC.PAGING,
  S1AP_PROC.INITIAL_CONTEXT_SETUP,
  S1AP_PROC.DOWNLINK_NAS_TRANSPORT,
  S1AP_PROC.INITIAL_UE_MESSAGE,
  S1AP_PROC.UPLINK_NAS_TRANSPORT,
  S1AP_PROC.RESET,
  S1AP_PROC.ERROR_INDICATION,
  S1AP_PROC.S1_SETUP,
  S1AP_PROC.UE_CONTEXT_RELEASE,
]

/** Protocol IE ids with typed value schemas in ieValueSchema(). */
export const S1AP_PINNED_IE_IDS: readonly number[] = [
  S1AP_IE.MME_UE_S1AP_ID,
  S1AP_IE.HANDOVER_TYPE,
  S1AP_IE.CAUSE,
  S1AP_IE.ENB_UE_S1AP_ID,
  S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_BEARER,
  S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_CTX,
  S1AP_IE.NAS_PDU,
  S1AP_IE.GUMMEI,
  S1AP_IE.GLOBAL_ENB_ID,
  S1AP_IE.ENB_NAME,
  S1AP_IE.MME_NAME,
  S1AP_IE.GLOBAL_MME_ID,
  S1AP_IE.TAI,
  S1AP_IE.SECURITY_KEY,
  S1AP_IE.S_TMSI,
  S1AP_IE.EUTRAN_CGI,
  S1AP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
  S1AP_IE.TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
  S1AP_IE.UE_AGGREGATE_MAXIMUM_BITRATE,
]

/**
 * Explicit non-claims: full Release 18 procedure/object-set code generation (R09) remains out of scope.
 * RRC-in-transparent-container, complete QoS IE trees, and every extension branch are mask-only or absent.
 */
export const S1AP_FULL_TS36_413_CLAIM = false
