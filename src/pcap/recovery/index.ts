/**
 * PCAP reversible anonymization — integration contract (step 1).
 *
 * Recovery binds to PcapAnonymizationLevel + policyHash + generationId on the
 * immutable plan. It must not depend on text profile schema, PCAP profile CRUD,
 * or ruleset JSON.
 *
 * Runtime writers/readers land in later steps; disabled recovery must not alter
 * the existing anonymized export hot path.
 */

export * from './domain'
export * from './codec/formatConstants'
export {
  RECOVERY_FORMAT_VECTOR_EMPTY,
  RECOVERY_FRAME_TYPE_VECTORS,
  buildPreambleLayoutVector,
  buildEmptyDataFrameHeaderVector,
  bytesToHex,
} from './codec/formatVectors'
export * from './codec/preambleCodec'
export * from './codec/frameCodec'
export * from './codec/footerCodec'
export * from './codec/manifestCodec'
export * from './codec/categoryIds'
export * from './codec/compactIndexCodec'
export * from './codec/literalFrameCodec'
export * from './worker/protocol'
export {
  preflightRecoveryPairViaWorker,
  unlockRecoveryPairViaWorker,
  searchRecoveryViaWorker,
  openPacketViaWorker,
  restorePacketViaWorker,
  restoreAllViaWorker,
  lockRecoverySessionViaWorker,
  disposePcapRestoreWorker,
} from './worker/client'
