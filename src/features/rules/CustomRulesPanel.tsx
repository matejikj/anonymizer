import { useEffect, useState } from 'react'
import { useAppStore } from '../../app/store.ts'
import { getActiveProfile, getActiveProfileRevision, listActiveRules } from './activeProfile.ts'
import {
  beginCreateRule,
  beginEditRule,
  deleteRule,
  duplicateRule,
  toggleRuleEnabled,
} from './ruleActions.ts'
import { RuleForm } from './RuleForm.tsx'
import type { RuleDraft } from './ruleValidation.ts'
import { Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function CustomRulesPanel() {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const formOpen = useAppStore((s) => s.ruleFormOpen)
  const editingId = useAppStore((s) => s.editingRuleId)
  const profileDirty = useAppStore((s) => s.profileDirty)
  const [profileRev, setProfileRev] = useState(() => getActiveProfileRevision())
  const [draft, setDraft] = useState<RuleDraft | null>(null)

  // Re-read profile revision after session / form changes (module state outside React).
  useEffect(() => {
    setProfileRev(getActiveProfileRevision())
  }, [sessionEpoch, formOpen])

  const rules = listActiveRules()
  const profileName = getActiveProfile().profile.name
  // Touch profileRev so list refreshes when revision changes without a session bump.
  void profileRev

  useEffect(() => {
    if (!formOpen) {
      setDraft(null)
      return
    }
    if (editingId) {
      const d = beginEditRule(editingId)
      if (d) setDraft(d)
      return
    }
    setDraft((current) => current ?? beginCreateRule())
  }, [formOpen, editingId])

  const openCreate = () => {
    setDraft(beginCreateRule())
    useAppStore.getState().setEditingRuleId(null)
    useAppStore.getState().setRuleFormOpen(true)
  }

  const openEdit = (id: string) => {
    const d = beginEditRule(id)
    if (!d) return
    setDraft(d)
    useAppStore.getState().setEditingRuleId(id)
    useAppStore.getState().setRuleFormOpen(true)
  }

  const closeForm = () => {
    setDraft(null)
    useAppStore.getState().setRuleFormOpen(false)
    useAppStore.getState().setEditingRuleId(null)
    setProfileRev(getActiveProfileRevision())
  }

  const runRuleMutation = async (fn: () => Promise<void>) => {
    useAppStore.getState().setPlanBusy(true)
    try {
      await fn()
    } finally {
      useAppStore.getState().setPlanBusy(false)
      useAppStore.getState().bumpSessionEpoch()
      setProfileRev(getActiveProfileRevision())
    }
  }

  return (
    <div className="custom-rules" data-testid="custom-rules">
      <p className="custom-rules__profile" data-testid="custom-rules-profile">
        <span>{cs.rules.activeProfileLabel}: </span>
        <strong>{profileName}</strong>
        {profileDirty ? (
          <span className="custom-rules__dirty" data-testid="custom-rules-dirty">
            {' · '}
            {cs.profiles.dirty}
          </span>
        ) : null}
      </p>
      {formOpen && draft ? (
        <RuleForm
          key={editingId ?? 'new-rule'}
          initial={draft}
          onClose={closeForm}
        />
      ) : (
        <>
          <div className="custom-rules__toolbar">
            <Button variant="primary" data-testid="add-rule" onClick={openCreate}>
              {cs.rules.add}
            </Button>
          </div>
          {rules.length === 0 ? (
            <p className="review-empty">{cs.rules.empty}</p>
          ) : (
            <ul className="custom-rules__list">
              {rules.map((rule) => (
                <li key={rule.id} className="custom-rules__row" data-testid={`rule-row-${rule.id}`}>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      data-testid={`rule-enabled-${rule.id}`}
                      aria-label={cs.rules.enabled}
                      onChange={(e) => {
                        void runRuleMutation(() => toggleRuleEnabled(rule.id, e.target.checked))
                      }}
                    />
                    <span />
                  </label>
                  <div className="custom-rules__meta">
                    <strong>{rule.name}</strong>
                    <span>
                      {rule.kind === 'regex' ? cs.rules.kindRegex : cs.rules.kindLiteral}
                      {' · '}
                      <code>
                        {rule.pattern.length > 48 ? `${rule.pattern.slice(0, 45)}…` : rule.pattern}
                      </code>
                    </span>
                  </div>
                  <div className="custom-rules__actions">
                    <Button variant="ghost" data-testid={`rule-edit-${rule.id}`} onClick={() => openEdit(rule.id)}>
                      {cs.rules.edit}
                    </Button>
                    <Button
                      variant="ghost"
                      data-testid={`rule-dup-${rule.id}`}
                      onClick={() => {
                        void runRuleMutation(() => duplicateRule(rule.id))
                      }}
                    >
                      {cs.rules.duplicate}
                    </Button>
                    <Button
                      variant="ghost"
                      data-testid={`rule-delete-${rule.id}`}
                      onClick={() => {
                        void runRuleMutation(() => deleteRule(rule.id))
                      }}
                    >
                      {cs.rules.delete}
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}
