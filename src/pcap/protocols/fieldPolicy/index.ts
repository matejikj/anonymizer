/**
 * T63.2 — machine-readable field policies for canary conformance and preserve-safe claims.
 */

export {
  getHandlerFieldPolicy,
  hasDetailedFieldPolicy,
  listFieldPolicyHandlerIds,
  listPreserveSafeFields,
  missingApplicationHandlerFieldPolicies,
  type HandlerFieldPolicyTable,
} from './registry'
export { STRUCTURAL_FIELD_POLICIES } from './structural'
export { DEFAULT_HANDLER_FIELD_POLICY } from './defaults'
export { HTTP_HANDLER_FIELD_POLICY } from './http'
export { SIP_HANDLER_FIELD_POLICY } from './sip'
export { DNS_HANDLER_FIELD_POLICY } from './dns'
