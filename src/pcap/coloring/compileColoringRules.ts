/**
 * Compile coloring rules via display-filter parser (config-time only).
 */

import { parseDisplayFilter } from '../displayFilter'
import type { PcapColoringRule, CompiledColoringRule, CompileColoringRulesResult } from './types'
import { COLORING_LIMITS, NO_COLOR_SLOT, TEMP_CONVERSATION_SLOT_BASE } from './types'
import { sanitizeColorPair } from './colorValidation'

let revisionCounter = 0

export function nextColoringRulesRevision(): number {
  revisionCounter += 1
  return revisionCounter
}

export function validateColoringRuleInput(rule: PcapColoringRule): string | null {
  if (rule.name.length > COLORING_LIMITS.maxNameLength) return 'name-too-long'
  if (new TextEncoder().encode(rule.filter).length > COLORING_LIMITS.maxFilterBytes) return 'filter-too-long'
  return null
}

export function compileColoringRules(
  rules: readonly PcapColoringRule[],
  revision = nextColoringRulesRevision(),
): CompileColoringRulesResult {
  const sorted = [...rules].sort((a, b) => a.priority - b.priority)
  const persistent = sorted.filter((r) => r.source !== 'temporary-conversation')
  const temporary = sorted.filter((r) => r.source === 'temporary-conversation')

  if (persistent.length > COLORING_LIMITS.maxPersistentRules) {
    return {
      rules: [],
      revision,
      errors: [{ ruleId: '*', message: `Max ${COLORING_LIMITS.maxPersistentRules} persistent rules`, offset: 0 }],
    }
  }
  if (temporary.length > COLORING_LIMITS.maxTemporarySlots) {
    return {
      rules: [],
      revision,
      errors: [{ ruleId: '*', message: `Max ${COLORING_LIMITS.maxTemporarySlots} temporary rules`, offset: 0 }],
    }
  }

  const errors: { ruleId: string; message: string; offset: number }[] = []
  const compiled: CompiledColoringRule[] = []
  let persistentSlot = 1
  let temporarySlot = TEMP_CONVERSATION_SLOT_BASE

  const assign = (rule: PcapColoringRule): CompiledColoringRule => {
    const inputError = validateColoringRuleInput(rule)
    if (inputError) {
      const err = { message: inputError, offset: 0 }
      errors.push({ ruleId: rule.id, ...err })
      return {
        id: rule.id,
        name: rule.name,
        enabled: false,
        priority: rule.priority,
        filter: rule.filter,
        expr: null,
        slot: NO_COLOR_SLOT,
        light: sanitizeColorPair(rule.light),
        dark: sanitizeColorPair(rule.dark),
        source: rule.source,
        error: err,
      }
    }

    const parsed = parseDisplayFilter(rule.filter)
    const slot =
      rule.source === 'temporary-conversation' ? temporarySlot++ : persistentSlot++

    if (parsed.status !== 'valid') {
      const err = parsed.error ?? { message: 'Invalid filter', offset: 0 }
      errors.push({ ruleId: rule.id, message: err.message, offset: err.offset })
      return {
        id: rule.id,
        name: rule.name,
        enabled: false,
        priority: rule.priority,
        filter: rule.filter,
        expr: null,
        slot,
        light: sanitizeColorPair(rule.light),
        dark: sanitizeColorPair(rule.dark),
        source: rule.source,
        error: err,
      }
    }

    return {
      id: rule.id,
      name: rule.name,
      enabled: rule.enabled,
      priority: rule.priority,
      filter: rule.filter,
      expr: parsed.expr,
      slot,
      light: sanitizeColorPair(rule.light),
      dark: sanitizeColorPair(rule.dark),
      source: rule.source,
      error: null,
    }
  }

  for (const rule of temporary) compiled.push(assign(rule))
  for (const rule of persistent) compiled.push(assign(rule))

  return { rules: compiled, revision, errors }
}

export function buildColorPalette(compiled: readonly CompiledColoringRule[]): Map<number, { light: { foreground: string; background: string }; dark: { foreground: string; background: string } }> {
  const palette = new Map<number, { light: { foreground: string; background: string }; dark: { foreground: string; background: string } }>()
  for (const rule of compiled) {
    if (rule.slot === NO_COLOR_SLOT) continue
    palette.set(rule.slot, { light: rule.light, dark: rule.dark })
  }
  return palette
}
