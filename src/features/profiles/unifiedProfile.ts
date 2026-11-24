/**
 * Text detection profile helpers.
 * PCAP anonymization level is a separate runtime setting — never embedded here.
 */

import type { RulesetConfig } from '../../domain/configSchema.ts'
import {
  BUILTIN_UNIFIED_PROFILE_ID,
  SUPPORTED_SCHEMA_VERSION,
  createDefaultRulesetConfig,
} from '../../domain/configSchema.ts'
import { cloneRulesetConfig, parseRulesetJsonText } from '../../domain/rulesetValidate.ts'
import bundledTeamProduction from '../../../profiles/rnd-team-production.json'

export { BUILTIN_UNIFIED_PROFILE_ID }

export function isBuiltInUnifiedProfile(id: string): boolean {
  return id === BUILTIN_UNIFIED_PROFILE_ID
}

/** Normalize stored/imported text config; strips any non-text fields via serialize round-trip. */
export function normalizeUnifiedConfig(config: RulesetConfig): RulesetConfig {
  const next = cloneRulesetConfig(config)
  if (next.schemaVersion < SUPPORTED_SCHEMA_VERSION) {
    next.schemaVersion = SUPPORTED_SCHEMA_VERSION
  }
  return next
}

export function loadBundledTeamProductionUnified(): RulesetConfig {
  const parsed = parseRulesetJsonText(JSON.stringify(bundledTeamProduction))
  if (!parsed.ok) {
    const fallback = createDefaultRulesetConfig()
    fallback.profile.id = BUILTIN_UNIFIED_PROFILE_ID
    fallback.profile.name = 'RND Team — Production'
    fallback.schemaVersion = SUPPORTED_SCHEMA_VERSION
    return fallback
  }
  return normalizeUnifiedConfig(parsed.config)
}

export function createNewUnifiedDefaultConfig(name = 'Nový profil'): RulesetConfig {
  const base = createDefaultRulesetConfig()
  const id = `profile-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
  base.profile.id = id
  base.profile.name = name
  base.schemaVersion = SUPPORTED_SCHEMA_VERSION
  return base
}
