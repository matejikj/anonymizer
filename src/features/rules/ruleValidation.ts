/**
 * Validation for custom literal/regex rules (ARCHITECTURE §3.4 / §7.3).
 */

import {
  MAX_RULE_PATTERN_LENGTH,
  MAX_RULE_REPLACEMENT_LENGTH,
  type RulesetRule,
} from '../../domain/configSchema.ts'
import type { Category } from '../../domain/types.ts'

export type RuleDraft = {
  id?: string
  name: string
  kind: 'literal' | 'regex'
  pattern: string
  caseSensitive: boolean
  wholeWord: boolean
  category: Category
  replacementMode: 'auto' | 'fixed'
  fixedReplacement: string
  description: string
  enabled: boolean
}

export type RuleValidationIssue = {
  field?: 'pattern' | 'name' | 'fixedReplacement' | 'kind'
  code: string
  message: string
  severity: 'error' | 'warning'
}

export function emptyRuleDraft(): RuleDraft {
  return {
    name: '',
    kind: 'literal',
    pattern: '',
    caseSensitive: true,
    wholeWord: false,
    category: 'custom',
    replacementMode: 'auto',
    fixedReplacement: '',
    description: '',
    enabled: true,
  }
}

export function draftFromRule(rule: RulesetRule): RuleDraft {
  return {
    id: rule.id,
    name: rule.name,
    kind: rule.kind,
    pattern: rule.pattern,
    caseSensitive: rule.caseSensitive !== false,
    wholeWord: rule.wholeWord === true,
    category: rule.category,
    replacementMode: rule.replacement.kind === 'fixed' ? 'fixed' : 'auto',
    fixedReplacement: rule.replacement.value ?? '',
    description: rule.description ?? '',
    enabled: rule.enabled,
  }
}

export function suggestRuleName(draft: Pick<RuleDraft, 'kind' | 'pattern'>): string {
  const raw = draft.pattern.trim().replace(/\s+/g, ' ')
  if (!raw) return draft.kind === 'regex' ? 'Nový regex' : 'Nový literal'
  const prefix = draft.kind === 'regex' ? 'Regex' : 'Literal'
  const short = raw.length > 40 ? `${raw.slice(0, 37)}…` : raw
  return `${prefix}: ${short}`
}

export function validateRuleDraft(draft: RuleDraft): RuleValidationIssue[] {
  const issues: RuleValidationIssue[] = []
  const pattern = draft.pattern

  if (!draft.name.trim()) {
    issues.push({
      field: 'name',
      code: 'name-required',
      message: 'Zadejte název pravidla.',
      severity: 'error',
    })
  }

  if (!pattern) {
    issues.push({
      field: 'pattern',
      code: 'pattern-required',
      message: 'Zadejte, co se má hledat.',
      severity: 'error',
    })
    return issues
  }

  if (pattern.includes('\n') || pattern.includes('\r')) {
    issues.push({
      field: 'pattern',
      code: 'pattern-newline',
      message: 'Vzor nesmí obsahovat konec řádku.',
      severity: 'error',
    })
  }

  if (pattern.length > MAX_RULE_PATTERN_LENGTH) {
    issues.push({
      field: 'pattern',
      code: 'pattern-too-long',
      message: `Vzor smí mít nejvýše ${MAX_RULE_PATTERN_LENGTH} znaků.`,
      severity: 'error',
    })
  }

  if (draft.kind === 'regex') {
    if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
      issues.push({
        field: 'pattern',
        code: 'regex-slashes',
        message: 'Regex zadávejte bez okolních lomítek /…/.',
        severity: 'error',
      })
    }
    try {
      const flags = draft.caseSensitive ? 'g' : 'gi'
      // Reject user-supplied flags smuggled into pattern
      void new RegExp(pattern, flags)
      if (regexCanMatchEmpty(pattern, draft.caseSensitive)) {
        issues.push({
          field: 'pattern',
          code: 'zero-length',
          message: 'Regex nesmí umět najít shodu nulové délky.',
          severity: 'error',
        })
      }
    } catch (err) {
      issues.push({
        field: 'pattern',
        code: 'regex-syntax',
        message: err instanceof Error ? `Neplatný regex: ${err.message}` : 'Neplatný regex.',
        severity: 'error',
      })
    }
  }

  if (draft.replacementMode === 'fixed') {
    const fixed = draft.fixedReplacement
    if (!fixed) {
      issues.push({
        field: 'fixedReplacement',
        code: 'replacement-required',
        message: 'Zadejte vlastní text náhrady.',
        severity: 'error',
      })
    } else {
      if (fixed.includes('\n') || fixed.includes('\r')) {
        issues.push({
          field: 'fixedReplacement',
          code: 'replacement-newline',
          message: 'Náhrada nesmí obsahovat konec řádku.',
          severity: 'error',
        })
      }
      if (fixed.length > MAX_RULE_REPLACEMENT_LENGTH) {
        issues.push({
          field: 'fixedReplacement',
          code: 'replacement-too-long',
          message: `Náhrada smí mít nejvýše ${MAX_RULE_REPLACEMENT_LENGTH} znaků.`,
          severity: 'error',
        })
      }
      issues.push({
        field: 'fixedReplacement',
        code: 'fixed-collapses',
        message: 'Fixní náhrada sloučí různé hodnoty do jedné — export je méně rozlišitelný.',
        severity: 'warning',
      })
    }
  }

  return issues
}

export function ruleDraftIsSavable(draft: RuleDraft): boolean {
  return validateRuleDraft(draft).every((i) => i.severity !== 'error')
}

export function draftToRulesetRule(draft: RuleDraft, id: string, priority: number): RulesetRule {
  return {
    id,
    name: draft.name.trim() || suggestRuleName(draft),
    enabled: draft.enabled,
    kind: draft.kind,
    pattern: draft.pattern,
    caseSensitive: draft.caseSensitive,
    wholeWord: draft.kind === 'literal' ? draft.wholeWord : undefined,
    category: draft.category,
    replacement:
      draft.replacementMode === 'fixed'
        ? { kind: 'fixed', value: draft.fixedReplacement }
        : { kind: 'generated' },
    description: draft.description.trim() || undefined,
    priority,
  }
}

/** True when the regex can produce a zero-length match (ARCHITECTURE §7.3). */
export function regexCanMatchEmpty(pattern: string, caseSensitive: boolean): boolean {
  try {
    const flags = caseSensitive ? 'g' : 'gi'
    const reEmpty = new RegExp(pattern, flags)
    const onEmpty = reEmpty.exec('')
    if (onEmpty && onEmpty[0].length === 0) return true

    const reProbe = new RegExp(pattern, flags)
    const onProbe = reProbe.exec('x')
    if (onProbe && onProbe[0].length === 0) return true
    return false
  } catch {
    return false
  }
}
