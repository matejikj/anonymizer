/**
 * Correlation session policy state — resolutions and resolve options (Stage 26).
 */

import type { CustomRule } from '../../domain/types'
import type { CrossFormatCategory } from '../../mapping/crossFormat/types'
import type { CorrelationResolveOptions } from '../../mapping/types'
import { compileCorrelationPolicy } from './effectivePolicy'
import {
  applyCategoryResolution,
  compatibilityAllowsProcessing,
  deriveSessionOutcome,
  evaluateProfileCompatibility,
} from './compatibility'
import {
  PROFILE_COMPATIBILITY_OUTCOME,
  type CompileCorrelationPolicyOptions,
  type CorrelationSessionPolicy,
  type ProfileCompatibilityReport,
  type ProfileConflictResolution,
  type SessionCategoryResolution,
} from './types'

let activeReport: ProfileCompatibilityReport | null = null
const categoryResolutions = new Map<CrossFormatCategory, SessionCategoryResolution>()
let rebuildRequired = false
let exportBlocked = false

export function resetCorrelationSessionPolicy(): void {
  activeReport = null
  categoryResolutions.clear()
  rebuildRequired = false
  exportBlocked = false
}

export function compileAndEvaluateSessionPolicy(
  options: CompileCorrelationPolicyOptions,
): ProfileCompatibilityReport {
  const policy = compileCorrelationPolicy(options)
  const report = evaluateProfileCompatibility(policy)
  activeReport = report
  categoryResolutions.clear()
  rebuildRequired = false
  exportBlocked = report.outcome === PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict
  return report
}

export function getProfileCompatibilityReport(): ProfileCompatibilityReport | null {
  return activeReport
}

export function resolveProfileConflict(
  category: CrossFormatCategory,
  resolution: ProfileConflictResolution,
): ProfileCompatibilityReport | null {
  if (!activeReport) return null
  const next = applyCategoryResolution(activeReport, category, resolution)
  activeReport = next

  if (resolution.kind === PROFILE_COMPATIBILITY_OUTCOME.SessionOverride
    || resolution.kind === PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory) {
    categoryResolutions.set(category, {
      category,
      outcome: resolution.kind,
    })
  } else {
    categoryResolutions.delete(category)
  }

  exportBlocked = !compatibilityAllowsProcessing(next)
  rebuildRequired = [...categoryResolutions.values()].some(
    (r) => r.outcome === PROFILE_COMPATIBILITY_OUTCOME.SessionOverride,
  )
  return next
}

export function getCorrelationSessionPolicy(): CorrelationSessionPolicy | null {
  if (!activeReport) return null
  const uncorrelated = new Set<CrossFormatCategory>()
  let crossFormatLinking = false
  for (const [cat, res] of categoryResolutions) {
    if (res.outcome === PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory) {
      uncorrelated.add(cat)
    }
    if (res.outcome === PROFILE_COMPATIBILITY_OUTCOME.SessionOverride) {
      crossFormatLinking = true
    }
  }
  const outcome = deriveSessionOutcome(
    new Map([...categoryResolutions.entries()].map(([k, v]) => [k, { kind: v.outcome }])),
  )
  if (outcome === PROFILE_COMPATIBILITY_OUTCOME.Compatible && activeReport.conflicts.length === 0) {
    crossFormatLinking = activeReport.policy.text != null && activeReport.policy.pcap != null
  }
  return {
    effectivePolicy: activeReport.policy,
    categoryResolutions: new Map(categoryResolutions),
    crossFormatLinking,
    uncorrelatedCategories: uncorrelated,
    rebuildRequired,
    exportBlocked,
  }
}

export function sessionPolicyAllowsProcessing(): boolean {
  if (!activeReport) return true
  if (categoryResolutions.size > 0) {
    return !exportBlocked
  }
  return compatibilityAllowsProcessing(activeReport)
}

export function correlationResolveOptionsFromSessionPolicy(): CorrelationResolveOptions {
  const policy = getCorrelationSessionPolicy()
  if (!policy) return {}
  return {
    crossFormatLinking: policy.crossFormatLinking,
    uncorrelatedCategories: policy.uncorrelatedCategories.size > 0
      ? [...policy.uncorrelatedCategories]
      : undefined,
  }
}

const CF_TO_RULE_CATEGORY: Partial<Record<CrossFormatCategory, CustomRule['category']>> = {
  ipv4: 'ip',
  ipv6: 'ip',
  hostname: 'hostname',
  phone: 'sip-phone',
  email: 'email',
  user: 'user-id',
}

export function applySessionPolicyToCustomRules(
  customRules: readonly CustomRule[],
): readonly CustomRule[] {
  const policy = getCorrelationSessionPolicy()
  if (!policy) return customRules

  const overrideCategories = new Set<CrossFormatCategory>()
  for (const [cat, res] of policy.categoryResolutions) {
    if (res.outcome === PROFILE_COMPATIBILITY_OUTCOME.SessionOverride) {
      overrideCategories.add(cat)
    }
  }

  if (overrideCategories.size === 0) return customRules

  return customRules.filter((rule) => {
    for (const cf of overrideCategories) {
      const ruleCat = CF_TO_RULE_CATEGORY[cf]
      if (ruleCat && rule.category === ruleCat && rule.replacementMode === 'fixed') {
        return false
      }
    }
    return true
  })
}

export function setRebuildRequired(required: boolean): void {
  rebuildRequired = required
}

export function isExportBlockedBySessionPolicy(): boolean {
  return exportBlocked || rebuildRequired
}
