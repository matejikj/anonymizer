/**
 * T63.2 — canary conformance helpers (harness test file deferred to F1).
 */

export { buildFieldCanary, bufferContainsCanary } from './canaryBytes'
export {
  injectFieldPolicyCanaries,
  type CanaryInjectionResult,
  type InjectedCanary,
} from './canaryInject'
export { findSurvivingCanaries, type SurvivingCanary } from './canaryScan'
