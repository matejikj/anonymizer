/**
 * Ruleset config used by the detection Worker (ARCHITECTURE §10).
 * Zod parse/serialize lives in `rulesetValidate.ts` (Krok 8).
 */

import type { Category, CustomRule, DetectorConfig } from './types.ts'
import { DEFAULT_DETECTOR_CONFIG, PRIORITY } from './types.ts'

export const RND_LOG_ANONYMIZER_SCHEMA_URN = 'urn:rnd-log-anonymizer:schema:ruleset:1' as const
export const SUPPORTED_SCHEMA_VERSION = 2 as const
export const LEGACY_SCHEMA_VERSION = 1 as const
export const BUILTIN_UNIFIED_PROFILE_ID = 'rnd-team-production' as const

export const MAX_RULE_PATTERN_LENGTH = 2000
export const MAX_RULE_REPLACEMENT_LENGTH = 2000

export interface RulesetBuiltinToggles {
  ip: boolean
  hostname: boolean
  'sip-phone': boolean
  email: boolean
  person: boolean
  'user-id': boolean
  'internal-id': boolean
  port: boolean
}

export interface RulesetSettings {
  hostnameSuffixes: string[]
  userIdPrefixes: string[]
  internalIdPrefixes: string[]
}

export interface RulesetRuleReplacement {
  kind: 'fixed' | 'generated'
  value?: string
}

export interface RulesetRule {
  id: string
  name: string
  enabled: boolean
  kind: 'literal' | 'regex'
  pattern: string
  caseSensitive?: boolean
  wholeWord?: boolean
  category: Category
  replacement: RulesetRuleReplacement
  description?: string
  /** Higher = stronger; defaults from list order (later = higher). */
  priority?: number
}

export interface RulesetProfile {
  id: string
  name: string
  description?: string
  builtins: RulesetBuiltinToggles
  settings: RulesetSettings
  rules: RulesetRule[]
}

/** Text-only detection ruleset. PCAP anonymization is a separate runtime level. */
export interface RulesetConfig {
  $schema?: string
  format: 'rnd-log-anonymizer-ruleset'
  schemaVersion: number
  profile: RulesetProfile
}

export const DEFAULT_BUILTIN_TOGGLES: RulesetBuiltinToggles = {
  ip: true,
  hostname: true,
  'sip-phone': true,
  email: true,
  person: true,
  'user-id': true,
  'internal-id': true,
  port: true,
}

export function createDefaultRulesetConfig(): RulesetConfig {
  return {
    $schema: RND_LOG_ANONYMIZER_SCHEMA_URN,
    format: 'rnd-log-anonymizer-ruleset',
    schemaVersion: SUPPORTED_SCHEMA_VERSION,
    profile: {
      id: BUILTIN_UNIFIED_PROFILE_ID,
      name: 'RND Team — Production (Maximální Bezpečnost + Debugovatelnost)',
      builtins: { ...DEFAULT_BUILTIN_TOGGLES },
      settings: {
        hostnameSuffixes: [...DEFAULT_DETECTOR_CONFIG.hostnameSuffixes],
        userIdPrefixes: [...DEFAULT_DETECTOR_CONFIG.userIdPrefixes],
        internalIdPrefixes: ['MP_', 'GRP_'],
      },
      rules: [],
    },
  }
}

/** Convert profile → DetectorConfig; optionally exclude failed rule IDs. */
export function rulesetToDetectorConfig(
  config: RulesetConfig,
  options: { excludeRuleIds?: ReadonlySet<string> } = {},
): DetectorConfig {
  const { profile } = config
  const exclude = options.excludeRuleIds ?? new Set<string>()
  const prefixes = profile.settings.internalIdPrefixes
  const internalIdPatterns = prefixes.map(
    (p) => new RegExp(`\\b${escapeRegExp(p)}[A-Za-z0-9_]+\\b`, 'g'),
  )

  const customRules: CustomRule[] = []
  profile.rules.forEach((rule, index) => {
    if (!rule.enabled || exclude.has(rule.id)) return
    if (rule.pattern.length > MAX_RULE_PATTERN_LENGTH) return
    if (rule.pattern.includes('\n') || rule.pattern.includes('\r')) return
    const fixed = rule.replacement.kind === 'fixed' ? rule.replacement.value : undefined
    if (fixed != null) {
      if (fixed.length > MAX_RULE_REPLACEMENT_LENGTH) return
      if (fixed.includes('\n') || fixed.includes('\r')) return
    }
    customRules.push({
      id: rule.id,
      name: rule.name,
      kind: rule.kind,
      pattern: rule.pattern,
      category: rule.category,
      enabled: true,
      priority: rule.priority ?? PRIORITY.customMin + index,
      caseSensitive: rule.caseSensitive,
      wholeWord: rule.wholeWord,
      replacementMode: rule.replacement.kind === 'fixed' ? 'fixed' : 'auto',
      fixedReplacement: fixed,
    })
  })

  return {
    hostnameSuffixes: profile.settings.hostnameSuffixes.map((s) =>
      s.startsWith('.') ? s : `.${s}`,
    ),
    userIdPrefixes: profile.settings.userIdPrefixes,
    internalIdPatterns,
    customRules,
  }
}

export function builtinEnabled(
  toggles: RulesetBuiltinToggles,
  category: keyof RulesetBuiltinToggles,
): boolean {
  return toggles[category]
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
