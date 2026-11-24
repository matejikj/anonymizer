/**
 * CRUD for custom rules + undo for delete (ARCHITECTURE §3.4 / Krok 7).
 */

import type { RulesetRule } from '../../domain/configSchema.ts'
import {
  getActiveProfile,
  listActiveRules,
  nextRuleId,
  nextRulePriority,
  replaceActiveRules,
} from './activeProfile.ts'
import {
  draftToRulesetRule,
  draftFromRule,
  emptyRuleDraft,
  ruleDraftIsSavable,
  type RuleDraft,
} from './ruleValidation.ts'
import { reanalyzeWithActiveProfile } from '../../app/sessionController.ts'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import { markProfileDirty } from '../profiles/profileController.ts'

async function refreshAfterRuleChange(): Promise<void> {
  if (useAppStore.getState().phase === 'correlation-review') {
    await import('../../correlation/rebuildCorrelationAfterTextProfileChange.ts').then((m) =>
      m.rebuildCorrelationAfterTextProfileChange(),
    )
    return
  }
  await reanalyzeWithActiveProfile()
}

let undoStack: RulesetRule | null = null
let undoTimer: ReturnType<typeof setTimeout> | null = null

export function clearRuleUndo(): void {
  undoStack = null
  if (undoTimer) {
    clearTimeout(undoTimer)
    undoTimer = null
  }
  useAppStore.getState().setToast(null)
}

export async function saveRuleDraft(draft: RuleDraft): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!ruleDraftIsSavable(draft)) {
    return { ok: false, reason: 'invalid' }
  }
  const rules = [...listActiveRules()]
  if (draft.id) {
    const idx = rules.findIndex((r) => r.id === draft.id)
    if (idx < 0) return { ok: false, reason: 'missing' }
    const prev = rules[idx]!
    rules[idx] = draftToRulesetRule(draft, draft.id, prev.priority ?? nextRulePriority(rules))
  } else {
    const id = nextRuleId()
    rules.push(draftToRulesetRule(draft, id, nextRulePriority(rules)))
  }
  replaceActiveRules(rules)
  clearRuleUndo()
  markProfileDirty()
  await refreshAfterRuleChange()
  return { ok: true }
}

export async function toggleRuleEnabled(id: string, enabled: boolean): Promise<void> {
  const rules = listActiveRules().map((r) => (r.id === id ? { ...r, enabled } : r))
  replaceActiveRules(rules)
  markProfileDirty()
  await refreshAfterRuleChange()
}

export async function duplicateRule(id: string): Promise<void> {
  const src = listActiveRules().find((r) => r.id === id)
  if (!src) return
  const draft = draftFromRule(src)
  draft.id = undefined
  draft.name = `${src.name} (kopie)`
  const rules = [...listActiveRules()]
  rules.push(draftToRulesetRule(draft, nextRuleId(), nextRulePriority(rules)))
  replaceActiveRules(rules)
  markProfileDirty()
  await refreshAfterRuleChange()
}

export async function deleteRule(id: string): Promise<void> {
  const rules = listActiveRules()
  const removed = rules.find((r) => r.id === id)
  if (!removed) return
  replaceActiveRules(rules.filter((r) => r.id !== id))
  markProfileDirty()
  undoStack = removed
  if (undoTimer) clearTimeout(undoTimer)
  useAppStore.getState().setToast({
    message: cs.rules.deletedToast.replace('{name}', removed.name),
    undoLabel: cs.rules.undo,
    kind: 'rule-undo',
  })
  undoTimer = setTimeout(() => {
    undoStack = null
    useAppStore.getState().setToast(null)
  }, 8_000)
  await refreshAfterRuleChange()
}

export async function undoDeleteRule(): Promise<void> {
  if (!undoStack) return
  const restored = undoStack
  clearRuleUndo()
  const rules = [...listActiveRules(), restored]
  replaceActiveRules(rules)
  markProfileDirty()
  await refreshAfterRuleChange()
}

export function beginCreateRule(): RuleDraft {
  return emptyRuleDraft()
}

export function beginEditRule(id: string): RuleDraft | null {
  const rule = listActiveRules().find((r) => r.id === id)
  return rule ? draftFromRule(rule) : null
}

export function getProfileRuleCount(): number {
  return getActiveProfile().profile.rules.length
}
