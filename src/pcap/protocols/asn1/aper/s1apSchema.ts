/**
 * T57 — pinned S1AP APER schema baseline (TS 36.413 Release 18 subset).
 * ProtocolIE values are open-type; known IE contents decoded by sanitizer after id dispatch.
 * Not a full dictionary — unknown/critical IE → mask.
 */

import type { AperSchemaModule, AperTypeDesc } from './schemaTypes.ts'

/** TS 36.413 ProtocolIE-ID / ProcedureCode constants (baseline). */
export const S1AP_IE = {
  MME_UE_S1AP_ID: 0,
  HANDOVER_TYPE: 1,
  CAUSE: 2,
  ENB_UE_S1AP_ID: 8,
  E_RAB_TO_BE_SETUP_ITEM_BEARER: 17,
  E_RAB_TO_BE_SETUP_ITEM_CTX: 52,
  NAS_PDU: 26,
  GUMMEI: 48,
  GLOBAL_ENB_ID: 59,
  ENB_NAME: 60,
  MME_NAME: 61,
  GLOBAL_MME_ID: 63,
  TAI: 67,
  SECURITY_KEY: 73,
  S_TMSI: 96,
  EUTRAN_CGI: 100,
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER: 104,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER: 105,
  UE_AGGREGATE_MAXIMUM_BITRATE: 108,
} as const

export const S1AP_PROC = {
  HANDOVER_PREPARATION: 0,
  PATH_SWITCH_REQUEST: 3,
  E_RAB_SETUP: 5,
  PAGING: 8,
  INITIAL_CONTEXT_SETUP: 9,
  DOWNLINK_NAS_TRANSPORT: 11,
  INITIAL_UE_MESSAGE: 12,
  UPLINK_NAS_TRANSPORT: 13,
  RESET: 14,
  ERROR_INDICATION: 15,
  S1_SETUP: 17,
  UE_CONTEXT_RELEASE: 23,
} as const

const CRITICALITY: AperTypeDesc = {
  kind: 'enumerated',
  names: ['reject', 'ignore', 'notify'],
}

/** MME-UE-S1AP-ID INTEGER (0..2^32-1) — T56 large-range path (2-octet simplified). */
export const MME_UE_S1AP_ID_TYPE: AperTypeDesc = {
  kind: 'integer',
  lower: 0,
  upper: 4_294_967_295,
}

/** ENB-UE-S1AP-ID INTEGER (0..2^24-1). */
export const ENB_UE_S1AP_ID_TYPE: AperTypeDesc = {
  kind: 'integer',
  lower: 0,
  upper: 16_777_215,
}

/** Cause ::= CHOICE { radioNetwork, transport, nas, protocol, misc } — baseline enum preserve. */
export const CAUSE_TYPE: AperTypeDesc = {
  kind: 'choice',
  extensible: true,
  alts: [
    {
      name: 'radioNetwork',
      type: { kind: 'enumerated', names: ['unspecified', 'tx2relocoverall-expiry', 'successful-handover', 'release-due-to-eutran-generated-reason', 'handover-cancelled', 'partial-handover', 'ho-failure-in-target-EPC-eNB-or-target-system', 'ho-target-not-allowed', 'tS1relocoverall-expiry', 'tS1relocprep-expiry', 'cell-not-available', 'unknown-targetID', 'no-radio-resources-available-in-target-cell', 'unknown-mme-ue-s1ap-id', 'unknown-enb-ue-s1ap-id', 'unknown-pair-ue-s1ap-id'] },
      role: 'preserve',
    },
    {
      name: 'transport',
      type: { kind: 'enumerated', names: ['transport-resource-unavailable', 'unspecified'] },
      role: 'preserve',
    },
    {
      name: 'nas',
      type: { kind: 'enumerated', names: ['normal-release', 'authentication-failure', 'detach', 'unspecified', 'csg-membership-expiry'] },
      role: 'preserve',
    },
    {
      name: 'protocol',
      type: { kind: 'enumerated', names: ['transfer-syntax-error', 'abstract-syntax-error-reject', 'abstract-syntax-error-ignore-and-notify', 'message-not-compatible-with-receiver-state', 'semantic-error', 'abstract-syntax-error-falsely-constructed-message', 'unspecified'] },
      role: 'preserve',
    },
    {
      name: 'misc',
      type: { kind: 'enumerated', names: ['control-processing-overload', 'not-enough-user-plane-processing-resources', 'hardware-failure', 'om-intervention', 'unspecified', 'unknown-PLMN'] },
      role: 'preserve',
    },
  ],
}

/** NAS-PDU ::= OCTET STRING */
export const NAS_PDU_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 1,
  sizeUpper: 2048,
}

/** SecurityKey ::= BIT STRING (SIZE(256)) — always mask. */
export const SECURITY_KEY_TYPE: AperTypeDesc = {
  kind: 'bit-string',
  sizeLower: 256,
  sizeUpper: 256,
}

/** GTP-TEID ::= OCTET STRING (SIZE(4)) */
export const GTP_TEID_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 4,
  sizeUpper: 4,
}

/**
 * TransportLayerAddress ::= BIT STRING (SIZE(1..160,...)) — baseline fixed 32 (IPv4) or 128 (IPv6).
 * Encoded as constrained bit-string without extension in our pinned tables.
 */
export const TRANSPORT_LAYER_ADDRESS_V4: AperTypeDesc = {
  kind: 'bit-string',
  sizeLower: 32,
  sizeUpper: 32,
}

export const TRANSPORT_LAYER_ADDRESS_V6: AperTypeDesc = {
  kind: 'bit-string',
  sizeLower: 128,
  sizeUpper: 128,
}

/**
 * Simplified E-RAB setup item (bearer/context): e-RAB-ID + TLA(v4) + GTP-TEID.
 * Omits full QoS SEQUENCE — synthetic corpus uses this pinned shape.
 */
export const E_RAB_SETUP_ITEM_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'eRabId',
      type: { kind: 'integer', lower: 0, upper: 15 },
      role: 'preserve',
    },
    {
      name: 'transportLayerAddress',
      type: TRANSPORT_LAYER_ADDRESS_V4,
      role: 'map',
      mappingCategory: 'ipv4',
    },
    {
      name: 'gtpTeid',
      type: GTP_TEID_TYPE,
      role: 'map',
      mappingCategory: 'teid',
    },
  ],
}

/** Global-ENB-ID: pLMNidentity (3) + eNB-ID macro BIT STRING (20). */
export const GLOBAL_ENB_ID_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNidentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'preserve', // PLMN policy: preserve MCC/MNC structure (T16)
    },
    {
      name: 'eNB-ID',
      type: {
        kind: 'choice',
        extensible: false,
        alts: [
          {
            name: 'macroENB-ID',
            type: { kind: 'bit-string', sizeLower: 20, sizeUpper: 20 },
            role: 'map',
            mappingCategory: 'opaque-id',
          },
        ],
      },
    },
  ],
}

/** PrintableString-like name as OCTET STRING. */
export const NODE_NAME_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 1,
  sizeUpper: 150,
}

/** GUMMEI — PLMN preserve; MME group/code mask (TS 36.413 baseline). */
export const GUMMEI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNidentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'preserve',
    },
    {
      name: 'mMEGroupID',
      type: { kind: 'octet-string', sizeLower: 2, sizeUpper: 2 },
      role: 'mask',
    },
    {
      name: 'mMECode',
      type: { kind: 'octet-string', sizeLower: 1, sizeUpper: 1 },
      role: 'mask',
    },
  ],
}

/** S-TMSI — temporary subscriber identity; always mask in baseline. */
export const S_TMSI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'mMEC',
      type: { kind: 'octet-string', sizeLower: 1, sizeUpper: 1 },
      role: 'mask',
    },
    {
      name: 'mTMSI',
      type: { kind: 'octet-string', sizeLower: 4, sizeUpper: 4 },
      role: 'mask',
    },
  ],
}

/** E-UTRAN-CGI — cell identity location; mask cellIdentity. */
export const EUTRAN_CGI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNidentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'preserve',
    },
    {
      name: 'cellIdentity',
      type: { kind: 'bit-string', sizeLower: 28, sizeUpper: 28 },
      role: 'mask',
    },
  ],
}

/** Global-MME-ID — same pinned shape as GUMMEI for synthetic corpus. */
export const GLOBAL_MME_ID_TYPE: AperTypeDesc = GUMMEI_TYPE

/** Handover / RRC transparent containers — no RRC schema; mask body. */
export const TRANSPARENT_CONTAINER_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 1,
  sizeUpper: 4096,
}

/** UE-AMBR — diagnostic bitrate preserve (pinned INTEGER widths). */
export const UE_AGGREGATE_MAXIMUM_BITRATE_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'uEaggregateMaximumBitRateDL',
      type: { kind: 'integer', lower: 0, upper: 4_294_967_295 },
      role: 'preserve',
    },
    {
      name: 'uEaggregateMaximumBitRateUL',
      type: { kind: 'integer', lower: 0, upper: 4_294_967_295 },
      role: 'preserve',
    },
  ],
}

/** TAI: pLMNidentity + TAC (2) — location default mask. */
export const TAI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNidentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'mask',
    },
    {
      name: 'tAC',
      type: { kind: 'octet-string', sizeLower: 2, sizeUpper: 2 },
      role: 'mask',
    },
  ],
}

const PROTOCOL_IE_FIELD: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'id',
      type: { kind: 'integer', lower: 0, upper: 65535 },
      role: 'preserve',
    },
    {
      name: 'criticality',
      type: CRITICALITY,
      role: 'preserve',
    },
    {
      name: 'value',
      type: { kind: 'open-type' }, // opaque — sanitizer dispatches by id
      role: 'opaque',
    },
  ],
}

const PROTOCOL_IE_CONTAINER: AperTypeDesc = {
  kind: 'sequence-of',
  element: PROTOCOL_IE_FIELD,
  sizeLower: 0,
  sizeUpper: 64,
}

const MESSAGE_ENVELOPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'procedureCode',
      type: { kind: 'integer', lower: 0, upper: 255 },
      role: 'preserve',
    },
    {
      name: 'criticality',
      type: CRITICALITY,
      role: 'preserve',
    },
    {
      name: 'value',
      type: {
        kind: 'open-type',
        contained: PROTOCOL_IE_CONTAINER,
      },
      role: 'preserve',
    },
  ],
}

/** S1AP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome, ... } */
export const S1AP_PDU_TYPE: AperTypeDesc = {
  kind: 'choice',
  extensible: true,
  alts: [
    { name: 'initiatingMessage', type: MESSAGE_ENVELOPE, role: 'preserve' },
    { name: 'successfulOutcome', type: MESSAGE_ENVELOPE, role: 'preserve' },
    { name: 'unsuccessfulOutcome', type: MESSAGE_ENVELOPE, role: 'preserve' },
  ],
}

export const S1AP_SCHEMA_MODULE: AperSchemaModule = {
  id: 's1ap.ts36413.r18',
  revision: 'ts36.413-v18.1.0-baseline',
  root: S1AP_PDU_TYPE,
}

export function ieValueSchema(ieId: number): AperTypeDesc | null {
  switch (ieId) {
    case S1AP_IE.MME_UE_S1AP_ID:
      return MME_UE_S1AP_ID_TYPE
    case S1AP_IE.ENB_UE_S1AP_ID:
      return ENB_UE_S1AP_ID_TYPE
    case S1AP_IE.CAUSE:
      return CAUSE_TYPE
    case S1AP_IE.NAS_PDU:
      return NAS_PDU_TYPE
    case S1AP_IE.SECURITY_KEY:
      return SECURITY_KEY_TYPE
    case S1AP_IE.GLOBAL_ENB_ID:
      return GLOBAL_ENB_ID_TYPE
    case S1AP_IE.ENB_NAME:
    case S1AP_IE.MME_NAME:
      return NODE_NAME_TYPE
    case S1AP_IE.TAI:
      return TAI_TYPE
    case S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_BEARER:
    case S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_CTX:
      return E_RAB_SETUP_ITEM_TYPE
    case S1AP_IE.GUMMEI:
    case S1AP_IE.GLOBAL_MME_ID:
      return GUMMEI_TYPE
    case S1AP_IE.S_TMSI:
      return S_TMSI_TYPE
    case S1AP_IE.EUTRAN_CGI:
      return EUTRAN_CGI_TYPE
    case S1AP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER:
    case S1AP_IE.TARGET_TO_SOURCE_TRANSPARENT_CONTAINER:
      return TRANSPARENT_CONTAINER_TYPE
    case S1AP_IE.UE_AGGREGATE_MAXIMUM_BITRATE:
      return UE_AGGREGATE_MAXIMUM_BITRATE_TYPE
    default:
      return null
  }
}
