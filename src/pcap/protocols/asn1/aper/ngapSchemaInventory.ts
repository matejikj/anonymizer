/**
 * T58 — pinned TS 38.413 v18.9.0 APER inventory + typed N2 transfer ids for T61.
 */

import { NGAP_IE, NGAP_PROC } from './ngapSchema.ts'
import type { N2TransferSchemaId } from './ngapSchema.ts'

export const NGAP_SCHEMA_PIN = {
  ts: 'TS 38.413 v18.9.0',
  encoding: 'aligned BASIC-PER (APER)',
  moduleId: 'ngap.ts38413.r18',
} as const

export const NGAP_PINNED_PROCEDURES: readonly number[] = [
  NGAP_PROC.HANDOVER_PREPARATION,
  NGAP_PROC.DOWNLINK_NAS_TRANSPORT,
  NGAP_PROC.PATH_SWITCH_REQUEST,
  NGAP_PROC.ERROR_INDICATION,
  NGAP_PROC.INITIAL_CONTEXT_SETUP,
  NGAP_PROC.INITIAL_UE_MESSAGE,
  NGAP_PROC.NG_SETUP,
  NGAP_PROC.PDU_SESSION_RESOURCE_SETUP,
  NGAP_PROC.RESET,
  NGAP_PROC.UPLINK_NAS_TRANSPORT,
  NGAP_PROC.PAGING,
]

export const NGAP_PINNED_IE_IDS: readonly number[] = [
  NGAP_IE.AMF_NAME,
  NGAP_IE.GLOBAL_RAN_NODE_ID,
  NGAP_IE.GUAMI,
  NGAP_IE.AMF_UE_NGAP_ID,
  NGAP_IE.CAUSE,
  NGAP_IE.FIVE_G_S_TMSI,
  NGAP_IE.NAS_PDU,
  NGAP_IE.PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ,
  NGAP_IE.RAN_NODE_NAME,
  NGAP_IE.RAN_UE_NGAP_ID,
  NGAP_IE.SECURITY_KEY,
  NGAP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
  NGAP_IE.TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
  NGAP_IE.USER_LOCATION,
  NGAP_IE.UL_NGU_UP_TNL,
  NGAP_IE.TAI,
  NGAP_IE.PDU_SESSION_SETUP_ITEM,
]

export const NGAP_PINNED_N2_TRANSFER_SCHEMAS: readonly N2TransferSchemaId[] = [
  'ngap.PDUSessionResourceSetupRequestTransfer',
  'ngap.PDUSessionResourceSetupResponseTransfer',
  'ngap.PDUSessionResourceModifyRequestTransfer',
]

/** Full normative ASN.1 dictionary / every N2 transfer type is not shipped. */
export const NGAP_FULL_TS38_413_CLAIM = false
