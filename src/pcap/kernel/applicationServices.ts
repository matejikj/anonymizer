/**
 * T14 — application service ports over the T-01 kernel (no second handler registry).
 */

export {
  categoryDescriptor,
  OPAQUE_ID_CATEGORY,
  type CategoryDescriptor,
} from './categoryDescriptors'
export {
  PayloadTimeSession,
  createPayloadTimeSession,
  type PayloadTimeKind,
  type PayloadTimeRewrite,
} from './payloadTimeCodec'
export {
  DEFAULT_UNKNOWN_FIELD_POLICY,
  validateFieldPolicyDictionary,
  assertFieldPolicyDictionary,
  fieldPolicyAllowsPreserveSafe,
  fieldPolicyRequiresCanaryAbsence,
  resolveFieldWireSpan,
  type FieldPolicyDescriptor,
  type FieldPolicy,
  type FieldIdentityRole,
  type FieldPolicyValidationError,
  type FieldCanaryKind,
  type FieldWireLocator,
} from './fieldPolicy'
export {
  validateEncryptedClassification,
  assertEncryptedClassification,
  CONFIDENTIALITY_PHASES,
  type EncryptedClassification,
  type ConfidentialityPhase,
} from './encryptedClassification'
export {
  MEDIA_DESCRIPTION_FACT,
  projectMediaDescriptionFact,
  type MediaDescriptionFact,
} from './mediaFacts'
