/**
 * T56 — schema-driven ASN.1 BASIC-PER Aligned (APER) toolkit.
 * Encoding adapter for T57/T58; not a protocol handler and not UPER/H.225/RRC.
 */

export { BitCursor, createBitScratch, type BitSpan, type AperParseIssue } from './bitCursor.ts'
export {
  constrainedBitWidth,
  readNormallySmallLength,
  readUnconstrainedLength,
  writeNormallySmallLength,
  writeUnconstrainedLength,
} from './lengthDeterminant.ts'
export {
  constrainedIntegerOctets,
  constrainedWholeNumberCase,
  octetsToHoldIntegerRange,
  readConstrainedWholeNumber,
  writeConstrainedWholeNumber,
  readConstrainedInteger,
  writeConstrainedInteger,
  constrainedIntegerFieldBitLength,
  readEnumerated,
  writeEnumerated,
  readBoolean,
  writeBoolean,
  encodeConstrainedIntegerBytes,
} from './integers.ts'
export {
  decodeAper,
  encodeAper,
  rewriteConstrainedIntegerLeaf,
  type BitPatch,
} from './codec.ts'
export {
  compileBitRewrites,
  applyCompiledPatches,
  physicalByteRanges,
  type BitRewrite,
  type CompiledBytePatch,
} from './patchCompiler.ts'
export type {
  AperTypeDesc,
  AperFieldDesc,
  AperSchemaModule,
  AperFieldRole,
  DecodedLeaf,
  DecodeResult,
} from './schemaTypes.ts'
export {
  TOY_MODULE_A,
  TOY_MODULE_B,
  APER_SCHEMA_REGISTRY,
  getAperSchema,
} from './toySchemas.ts'
export {
  S1AP_SCHEMA_MODULE,
  S1AP_PDU_TYPE,
  S1AP_IE,
  S1AP_PROC,
  ieValueSchema,
  MME_UE_S1AP_ID_TYPE,
  ENB_UE_S1AP_ID_TYPE,
  NAS_PDU_TYPE,
  CAUSE_TYPE,
  E_RAB_SETUP_ITEM_TYPE,
  GLOBAL_ENB_ID_TYPE,
  TAI_TYPE,
  SECURITY_KEY_TYPE,
  NODE_NAME_TYPE,
  GUMMEI_TYPE,
  S_TMSI_TYPE,
  EUTRAN_CGI_TYPE,
  TRANSPARENT_CONTAINER_TYPE,
  UE_AGGREGATE_MAXIMUM_BITRATE_TYPE,
} from './s1apSchema.ts'
export {
  S1AP_SCHEMA_PIN,
  S1AP_PINNED_PROCEDURES,
  S1AP_PINNED_IE_IDS,
  S1AP_FULL_TS36_413_CLAIM,
} from './s1apSchemaInventory.ts'
export {
  NGAP_SCHEMA_MODULE,
  NGAP_PDU_TYPE,
  NGAP_IE,
  NGAP_PROC,
  ngapIeValueSchema,
  n2TransferSchema,
  N2_TRANSFER_SCHEMAS,
  AMF_UE_NGAP_ID_TYPE,
  RAN_UE_NGAP_ID_TYPE,
  NGAP_NAS_PDU_TYPE,
  NGAP_CAUSE_TYPE,
  NGAP_NODE_NAME_TYPE,
  NGAP_TAI_TYPE,
  NGAP_SECURITY_KEY_TYPE,
  FIVE_G_S_TMSI_TYPE,
  PDU_SESSION_SETUP_ITEM_TYPE,
  N2_PDU_SESSION_SETUP_REQ_TRANSFER,
  N2_PDU_SESSION_SETUP_RES_TRANSFER,
  type N2TransferSchemaId,
  UL_NGU_UP_TNL_TYPE,
  GUAMI_TYPE,
  GLOBAL_RAN_NODE_ID_TYPE,
  USER_LOCATION_INFORMATION_TYPE,
  NGAP_TRANSPARENT_CONTAINER_TYPE,
} from './ngapSchema.ts'
export {
  NGAP_SCHEMA_PIN,
  NGAP_PINNED_PROCEDURES,
  NGAP_PINNED_IE_IDS,
  NGAP_PINNED_N2_TRANSFER_SCHEMAS,
  NGAP_FULL_TS38_413_CLAIM,
} from './ngapSchemaInventory.ts'
