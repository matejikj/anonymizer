/**
 * In-memory active ruleset for the browser session.
 * Persistence is via `profileRepository` / `profileController` (Krok 8).
 */

import {
  createDefaultRulesetConfig,
  type RulesetConfig,
  type RulesetRule,
} from '../../domain/configSchema.ts'

let active: RulesetConfig = createDefaultRulesetConfig()
let revision = 0

export function getActiveProfile(): RulesetConfig {
  return active
}

export function getActiveProfileRevision(): number {
  return revision
}

export function setActiveProfile(next: RulesetConfig): void {
  active = next
  revision += 1
}

export function bumpActiveProfileRevisionForTests(): void {
  revision += 1
}

export function resetActiveProfile(): void {
  active = createDefaultRulesetConfig()
  revision += 1
}

export function listActiveRules(): RulesetRule[] {
  return active.profile.rules
}

export function getActiveRule(id: string): RulesetRule | undefined {
  return active.profile.rules.find((r) => r.id === id)
}

export function replaceActiveRules(rules: RulesetRule[]): RulesetConfig {
  active = {
    ...active,
    profile: {
      ...active.profile,
      rules: rules,
    },
  }
  revision += 1
  return active
}

export function nextRuleId(): string {
  return `rule-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

export function nextRulePriority(rules: RulesetRule[]): number {
  let max = 1000
  for (const r of rules) {
    if ((r.priority ?? 1000) > max) max = r.priority ?? 1000
  }
  return max + 1
}
