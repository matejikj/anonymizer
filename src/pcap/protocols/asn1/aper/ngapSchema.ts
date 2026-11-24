/**
 * T58 — pinned NGAP APER schema baseline (TS 38.413 Release 18 subset).
 * Separate from S1AP object sets; N2 transfer types exposed for T61 adapter.
 */

import type { AperSchemaModule, AperTypeDesc } from './schemaTypes.ts'

/** TS 38.413 ProtocolIE-ID / ProcedureCode (baseline). */
export const NGAP_IE = {
  AMF_NAME: 1,
  GUAMI: 28,
  GLOBAL_RAN_NODE_ID: 27,
  AMF_UE_NGAP_ID: 10,
  CAUSE: 15,
  FIVE_G_S_TMSI: 26,
  NAS_PDU: 38,
  PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ: 74,
  RAN_NODE_NAME: 82,
  RAN_UE_NGAP_ID: 85,
  SECURITY_KEY: 94,
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER: 101,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER: 102,
  USER_LOCATION: 121,
  UL_NGU_UP_TNL: 139,
  TAI: 213,
  /** Pinned open-type id for single PDU session setup item in synthetic corpus. */
  PDU_SESSION_SETUP_ITEM: 74,
} as const

export const NGAP_PROC = {
  HANDOVER_PREPARATION: 0,
  DOWNLINK_NAS_TRANSPORT: 4,
  ERROR_INDICATION: 9,
  INITIAL_CONTEXT_SETUP: 14,
  INITIAL_UE_MESSAGE: 15,
  NG_SETUP: 21,
  PDU_SESSION_RESOURCE_SETUP: 29,
  RESET: 36,
  UPLINK_NAS_TRANSPORT: 46,
  PAGING: 24,
  PATH_SWITCH_REQUEST: 13,
} as const

/** Typed N2 transfer schema IDs for T61 (not whole NGAP-PDU). */
export type N2TransferSchemaId =
  | 'ngap.PDUSessionResourceSetupRequestTransfer'
  | 'ngap.PDUSessionResourceSetupResponseTransfer'
  | 'ngap.PDUSessionResourceModifyRequestTransfer'

const CRITICALITY: AperTypeDesc = {
  kind: 'enumerated',
  names: ['reject', 'ignore', 'notify'],
}

/** AMF-UE-NGAP-ID INTEGER (0..2^40-1) — X.691 §12.2.3 five-octet APER field. */
export const AMF_UE_NGAP_ID_TYPE: AperTypeDesc = {
  kind: 'integer',
  lower: 0,
  upper: 1_099_511_627_775, // 2^40-1
}

/** RAN-UE-NGAP-ID INTEGER (0..2^32-1). */
export const RAN_UE_NGAP_ID_TYPE: AperTypeDesc = {
  kind: 'integer',
  lower: 0,
  upper: 4_294_967_295,
}

export const NGAP_CAUSE_TYPE: AperTypeDesc = {
  kind: 'choice',
  extensible: true,
  alts: [
    {
      name: 'radioNetwork',
      type: {
        kind: 'enumerated',
        names: [
          'unspecified',
          'txnrelocoverall-expiry',
          'successful-handover',
          'release-due-to-ngran-generated-reason',
          'release-due-to-5gc-generated-reason',
          'handover-cancelled',
          'partial-handover',
          'ho-failure-in-target-5GC-ngran-node-or-target-system',
          'ho-target-not-allowed',
          'tngrelocoverall-expiry',
          'tngrelocprep-expiry',
          'cell-not-available',
          'unknown-targetID',
          'no-radio-resources-available-in-target-cell',
          'unknown-local-UE-NGAP-ID',
          'inconsistent-remote-UE-NGAP-ID',
        ],
      },
      role: 'preserve',
    },
    {
      name: 'transport',
      type: { kind: 'enumerated', names: ['transport-resource-unavailable', 'unspecified'] },
      role: 'preserve',
    },
    {
      name: 'nas',
      type: {
        kind: 'enumerated',
        names: ['normal-release', 'authentication-failure', 'deregister', 'unspecified'],
      },
      role: 'preserve',
    },
    {
      name: 'protocol',
      type: {
        kind: 'enumerated',
        names: [
          'transfer-syntax-error',
          'abstract-syntax-error-reject',
          'abstract-syntax-error-ignore-and-notify',
          'message-not-compatible-with-receiver-state',
          'semantic-error',
          'abstract-syntax-error-falsely-constructed-message',
          'unspecified',
        ],
      },
      role: 'preserve',
    },
    {
      name: 'misc',
      type: {
        kind: 'enumerated',
        names: [
          'control-processing-overload',
          'not-enough-user-plane-processing-resources',
          'hardware-failure',
          'om-intervention',
          'unknown-PLMN-or-SNPN',
          'unspecified',
        ],
      },
      role: 'preserve',
    },
  ],
}

export const NGAP_NAS_PDU_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 1,
  sizeUpper: 2048,
}

export const NGAP_SECURITY_KEY_TYPE: AperTypeDesc = {
  kind: 'bit-string',
  sizeLower: 256,
  sizeUpper: 256,
}

export const NGAP_NODE_NAME_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 1,
  sizeUpper: 150,
}

export const NGAP_TAI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNIdentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'mask',
    },
    {
      name: 'tAC',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'mask',
    },
  ],
}

/** NR-CGI pinned shape (PLMN + 36-bit cellIdentity). */
export const NR_CGI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNIdentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'mask',
    },
    {
      name: 'nRCellIdentity',
      type: { kind: 'bit-string', sizeLower: 36, sizeUpper: 36 },
      role: 'mask',
    },
  ],
}

/** E-UTRA-CGI for UserLocation eUTRA branch. */
export const NGAP_EUTRA_CGI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNIdentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'mask',
    },
    {
      name: 'eUTRACellIdentity',
      type: { kind: 'bit-string', sizeLower: 28, sizeUpper: 28 },
      role: 'mask',
    },
  ],
}

/**
 * UserLocationInformation — NR/E-UTRA branches (not full spec extension set).
 */
export const USER_LOCATION_INFORMATION_TYPE: AperTypeDesc = {
  kind: 'choice',
  extensible: true,
  alts: [
    {
      name: 'nRLocation',
      type: {
        kind: 'sequence',
        extensible: false,
        fields: [
          { name: 'tAI', type: NGAP_TAI_TYPE, role: 'mask' },
          { name: 'nR-CGI', type: NR_CGI_TYPE, role: 'mask' },
        ],
      },
      role: 'mask',
    },
    {
      name: 'eUTRALocation',
      type: {
        kind: 'sequence',
        extensible: false,
        fields: [
          { name: 'tAI', type: NGAP_TAI_TYPE, role: 'mask' },
          { name: 'eUTRA-CGI', type: NGAP_EUTRA_CGI_TYPE, role: 'mask' },
        ],
      },
      role: 'mask',
    },
  ],
}

/** GUAMI — PLMN preserve; AMF id bytes mask (pinned octet bundle, not full BIT STRING pack). */
export const GUAMI_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pLMNIdentity',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'preserve',
    },
    {
      name: 'aMFIdentifier',
      type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
      role: 'mask',
    },
  ],
}

/** GlobalRANNodeID — globalGNB-ID branch only in baseline corpus. */
export const GLOBAL_RAN_NODE_ID_TYPE: AperTypeDesc = {
  kind: 'choice',
  extensible: false,
  alts: [
    {
      name: 'globalGNB-ID',
      type: {
        kind: 'sequence',
        extensible: false,
        fields: [
          {
            name: 'pLMNIdentity',
            type: { kind: 'octet-string', sizeLower: 3, sizeUpper: 3 },
            role: 'preserve',
          },
          {
            name: 'gNB-ID',
            type: { kind: 'bit-string', sizeLower: 32, sizeUpper: 32 },
            role: 'map',
            mappingCategory: 'opaque-id',
          },
        ],
      },
    },
  ],
}

/** UL NG-U UP TNL — IPv4 + GTP-TEID (same pinned tunnel shape as E-RAB). */
export const UL_NGU_UP_TNL_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'transportLayerAddress',
      type: { kind: 'bit-string', sizeLower: 32, sizeUpper: 32 },
      role: 'map',
      mappingCategory: 'ipv4',
    },
    {
      name: 'gtpTeid',
      type: { kind: 'octet-string', sizeLower: 4, sizeUpper: 4 },
      role: 'map',
      mappingCategory: 'teid',
    },
  ],
}

/** Handover / RRC transparent containers — mask without RRC codec. */
export const NGAP_TRANSPARENT_CONTAINER_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 1,
  sizeUpper: 4096,
}

/** FiveG-S-TMSI: AMF Set ID + AMF Pointer + 5G-TMSI — baseline opaque mask/map. */
export const FIVE_G_S_TMSI_TYPE: AperTypeDesc = {
  kind: 'octet-string',
  sizeLower: 6,
  sizeUpper: 6,
}

/**
 * Pinned PDU session / NG-U tunnel item (synthetic corpus shape).
 * Real transfer is ProtocolIE-Container; T61 uses typed transfer schemas below.
 */
export const PDU_SESSION_SETUP_ITEM_TYPE: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pduSessionId',
      type: { kind: 'integer', lower: 0, upper: 255 },
      role: 'preserve',
    },
    {
      name: 'transportLayerAddress',
      type: { kind: 'bit-string', sizeLower: 32, sizeUpper: 32 },
      role: 'map',
      mappingCategory: 'ipv4',
    },
    {
      name: 'gtpTeid',
      type: { kind: 'octet-string', sizeLower: 4, sizeUpper: 4 },
      role: 'map',
      mappingCategory: 'teid',
    },
  ],
}

/**
 * Typed N2 PDUSessionResourceSetupRequestTransfer (pinned, not full 3GPP IE list).
 * Used standalone by T61 and nested when IE content matches.
 */
export const N2_PDU_SESSION_SETUP_REQ_TRANSFER: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pduSessionId',
      type: { kind: 'integer', lower: 0, upper: 255 },
      role: 'preserve',
    },
    {
      name: 'ulNguUpTnl',
      type: {
        kind: 'sequence',
        extensible: false,
        fields: [
          {
            name: 'transportLayerAddress',
            type: { kind: 'bit-string', sizeLower: 32, sizeUpper: 32 },
            role: 'map',
            mappingCategory: 'ipv4',
          },
          {
            name: 'gtpTeid',
            type: { kind: 'octet-string', sizeLower: 4, sizeUpper: 4 },
            role: 'map',
            mappingCategory: 'teid',
          },
        ],
      },
    },
  ],
}

/** Pinned modify transfer — session id preserve; QoS list opaque mask. */
export const N2_PDU_SESSION_MODIFY_REQ_TRANSFER: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pduSessionId',
      type: { kind: 'integer', lower: 0, upper: 255 },
      role: 'preserve',
    },
    {
      name: 'qosFlowAddOrModifyRequestList',
      type: { kind: 'octet-string', sizeLower: 0, sizeUpper: 512 },
      role: 'mask',
    },
  ],
}

export const N2_PDU_SESSION_SETUP_RES_TRANSFER: AperTypeDesc = {
  kind: 'sequence',
  extensible: false,
  fields: [
    {
      name: 'pduSessionId',
      type: { kind: 'integer', lower: 0, upper: 255 },
      role: 'preserve',
    },
    {
      name: 'dlNguUpTnl',
      type: {
        kind: 'sequence',
        extensible: false,
        fields: [
          {
            name: 'transportLayerAddress',
            type: { kind: 'bit-string', sizeLower: 32, sizeUpper: 32 },
            role: 'map',
            mappingCategory: 'ipv4',
          },
          {
            name: 'gtpTeid',
            type: { kind: 'octet-string', sizeLower: 4, sizeUpper: 4 },
            role: 'map',
            mappingCategory: 'teid',
          },
        ],
      },
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
      type: { kind: 'open-type' },
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

export const NGAP_PDU_TYPE: AperTypeDesc = {
  kind: 'choice',
  extensible: true,
  alts: [
    { name: 'initiatingMessage', type: MESSAGE_ENVELOPE, role: 'preserve' },
    { name: 'successfulOutcome', type: MESSAGE_ENVELOPE, role: 'preserve' },
    { name: 'unsuccessfulOutcome', type: MESSAGE_ENVELOPE, role: 'preserve' },
  ],
}

export const NGAP_SCHEMA_MODULE: AperSchemaModule = {
  id: 'ngap.ts38413.r18',
  revision: 'ts38.413-v18.9.0-baseline',
  root: NGAP_PDU_TYPE,
}

export const N2_TRANSFER_SCHEMAS: ReadonlyMap<N2TransferSchemaId, AperTypeDesc> = new Map([
  ['ngap.PDUSessionResourceSetupRequestTransfer', N2_PDU_SESSION_SETUP_REQ_TRANSFER],
  ['ngap.PDUSessionResourceSetupResponseTransfer', N2_PDU_SESSION_SETUP_RES_TRANSFER],
  ['ngap.PDUSessionResourceModifyRequestTransfer', N2_PDU_SESSION_MODIFY_REQ_TRANSFER],
])

export function ngapIeValueSchema(ieId: number): AperTypeDesc | null {
  switch (ieId) {
    case NGAP_IE.AMF_UE_NGAP_ID:
      return AMF_UE_NGAP_ID_TYPE
    case NGAP_IE.RAN_UE_NGAP_ID:
      return RAN_UE_NGAP_ID_TYPE
    case NGAP_IE.CAUSE:
      return NGAP_CAUSE_TYPE
    case NGAP_IE.NAS_PDU:
      return NGAP_NAS_PDU_TYPE
    case NGAP_IE.SECURITY_KEY:
      return NGAP_SECURITY_KEY_TYPE
    case NGAP_IE.AMF_NAME:
    case NGAP_IE.RAN_NODE_NAME:
      return NGAP_NODE_NAME_TYPE
    case NGAP_IE.TAI:
      return NGAP_TAI_TYPE
    case NGAP_IE.USER_LOCATION:
      return USER_LOCATION_INFORMATION_TYPE
    case NGAP_IE.FIVE_G_S_TMSI:
      return FIVE_G_S_TMSI_TYPE
    case NGAP_IE.GUAMI:
      return GUAMI_TYPE
    case NGAP_IE.GLOBAL_RAN_NODE_ID:
      return GLOBAL_RAN_NODE_ID_TYPE
    case NGAP_IE.UL_NGU_UP_TNL:
      return UL_NGU_UP_TNL_TYPE
    case NGAP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER:
    case NGAP_IE.TARGET_TO_SOURCE_TRANSPARENT_CONTAINER:
      return NGAP_TRANSPARENT_CONTAINER_TYPE
    case NGAP_IE.PDU_SESSION_SETUP_ITEM:
      return PDU_SESSION_SETUP_ITEM_TYPE
    default:
      return null
  }
}

export function n2TransferSchema(id: N2TransferSchemaId): AperTypeDesc | undefined {
  return N2_TRANSFER_SCHEMAS.get(id)
}
