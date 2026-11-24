/** MGCP (RFC 3435) structured anonymization (T11). */

export type {
  ByteSpan,
  MgcpClassifyResult,
  MgcpMessage,
  MgcpParameter,
  MgcpStartLine,
  MgcpVerb,
} from './types.ts'
export { classifyMgcpPayload, isMgcpPortHint, parseMgcpDatagram } from './parse.ts'
export {
  analyzeMgcpMessages,
  MGCP_MASK_BYTE,
  type MgcpAnalyzeResult,
  type MgcpOperation,
} from './analyze.ts'
export { applyMgcpPlan, sanitizeMgcpMessages } from './apply.ts'
export { recordMgcpDiscoveryIntents } from './discoverIntents.ts'
