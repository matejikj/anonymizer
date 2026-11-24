import { useMemo, useState } from 'react'
import type { Category } from '../../domain/types.ts'
import { ALL_CATEGORIES } from '../review/entityState.ts'
import { CATEGORY_LABELS } from '../review/categoryLabels.ts'
import {
  suggestRuleName,
  validateRuleDraft,
  ruleDraftIsSavable,
  type RuleDraft,
} from './ruleValidation.ts'
import { previewRuleDraft } from './rulePreview.ts'
import { saveRuleDraft } from './ruleActions.ts'
import { useAppStore } from '../../app/store.ts'
import { Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function RuleForm(props: {
  initial: RuleDraft
  onClose: () => void
}) {
  const [draft, setDraft] = useState<RuleDraft>(props.initial)
  const [moreOpen, setMoreOpen] = useState(
    Boolean(props.initial.description) ||
      props.initial.category !== 'custom' ||
      props.initial.wholeWord ||
      !props.initial.caseSensitive,
  )
  const [saving, setSaving] = useState(false)
  const [nameTouched, setNameTouched] = useState(Boolean(props.initial.id))
  const importProgress = useAppStore((s) => s.importProgress)

  const issues = useMemo(() => validateRuleDraft(draft), [draft])
  const errors = issues.filter((i) => i.severity === 'error')
  const warnings = issues.filter((i) => i.severity === 'warning')
  const savable = ruleDraftIsSavable(draft)
  const preview = useMemo(() => previewRuleDraft(draft), [draft])
  const savingPct =
    saving && importProgress.totalBytes && importProgress.totalBytes > 0
      ? Math.min(100, Math.round((importProgress.processedBytes / importProgress.totalBytes) * 100))
      : null

  const patch = (partial: Partial<RuleDraft>) => {
    setDraft((d) => {
      const next = { ...d, ...partial }
      if (!nameTouched && (partial.pattern != null || partial.kind != null)) {
        next.name = suggestRuleName(next)
      }
      return next
    })
  }

  const onSave = async () => {
    if (!savable || saving) return
    setSaving(true)
    try {
      const result = await saveRuleDraft(draft)
      if (result.ok) {
        useAppStore.getState().bumpSessionEpoch()
        props.onClose()
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="rule-form" data-testid="rule-form">
      <section className="rule-form__section">
        <h3 className="rule-form__section-title">{cs.rules.sectionPattern}</h3>
        <label className="rule-form__field">
          <span>{cs.rules.patternLabel}</span>
          <input
            type="text"
            value={draft.pattern}
            data-testid="rule-pattern"
            placeholder={
              draft.kind === 'regex'
                ? cs.rules.patternPlaceholderRegex
                : cs.rules.patternPlaceholderLiteral
            }
            onChange={(e) => patch({ pattern: e.target.value })}
          />
        </label>

        <div className="rule-form__segment" role="group" aria-label={cs.rules.kindGroup}>
          <button
            type="button"
            className={draft.kind === 'literal' ? 'is-active' : ''}
            data-testid="rule-kind-literal"
            onClick={() => patch({ kind: 'literal' })}
          >
            {cs.rules.kindLiteral}
          </button>
          <button
            type="button"
            className={draft.kind === 'regex' ? 'is-active' : ''}
            data-testid="rule-kind-regex"
            onClick={() => patch({ kind: 'regex' })}
          >
            {cs.rules.kindRegex}
          </button>
        </div>
      </section>

      <section className="rule-form__section">
        <h3 className="rule-form__section-title">{cs.rules.sectionReplace}</h3>
        <fieldset className="rule-form__fieldset">
          <legend className="visually-hidden">{cs.rules.replaceLabel}</legend>
          <label className="rule-form__radio">
            <input
              type="radio"
              name="replacementMode"
              checked={draft.replacementMode === 'auto'}
              onChange={() => patch({ replacementMode: 'auto' })}
            />
            {cs.rules.replaceAuto}
          </label>
          <label className="rule-form__radio">
            <input
              type="radio"
              name="replacementMode"
              checked={draft.replacementMode === 'fixed'}
              data-testid="rule-replace-fixed"
              onChange={() => patch({ replacementMode: 'fixed' })}
            />
            {cs.rules.replaceFixed}
          </label>
          {draft.replacementMode === 'fixed' ? (
            <input
              type="text"
              value={draft.fixedReplacement}
              data-testid="rule-fixed-replacement"
              placeholder={cs.rules.fixedPlaceholder}
              onChange={(e) => patch({ fixedReplacement: e.target.value })}
            />
          ) : null}
        </fieldset>
      </section>

      <section className="rule-form__section">
        <h3 className="rule-form__section-title">{cs.rules.sectionMeta}</h3>
        <label className="rule-form__field">
          <span>{cs.rules.nameLabel}</span>
          <input
            type="text"
            value={draft.name}
            data-testid="rule-name"
            onChange={(e) => {
              setNameTouched(true)
              patch({ name: e.target.value })
            }}
          />
        </label>

        <button
          type="button"
          className="rule-form__more"
          data-testid="rule-more-options"
          aria-expanded={moreOpen}
          onClick={() => setMoreOpen((v) => !v)}
        >
          {cs.rules.moreOptions}
        </button>

        {moreOpen ? (
          <div className="rule-form__advanced" data-testid="rule-advanced">
            <label className="rule-form__field">
              <span>{cs.rules.categoryLabel}</span>
              <select
                value={draft.category}
                data-testid="rule-category"
                onChange={(e) => patch({ category: e.target.value as Category })}
              >
                {ALL_CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {CATEGORY_LABELS[c]}
                  </option>
                ))}
              </select>
            </label>
            <label className="rule-form__check">
              <input
                type="checkbox"
                checked={draft.caseSensitive}
                data-testid="rule-case-sensitive"
                onChange={(e) => patch({ caseSensitive: e.target.checked })}
              />
              {cs.rules.caseSensitive}
            </label>
            {draft.kind === 'literal' ? (
              <label className="rule-form__check">
                <input
                  type="checkbox"
                  checked={draft.wholeWord}
                  data-testid="rule-whole-word"
                  onChange={(e) => patch({ wholeWord: e.target.checked })}
                />
                {cs.rules.wholeWord}
              </label>
            ) : null}
            <label className="rule-form__field">
              <span>{cs.rules.descriptionLabel}</span>
              <input
                type="text"
                value={draft.description}
                placeholder={cs.rules.descriptionPlaceholder}
                onChange={(e) => patch({ description: e.target.value })}
              />
            </label>
          </div>
        ) : null}
      </section>

      {errors.map((e) => (
        <p key={e.code} className="rule-form__error" role="alert" data-testid="rule-error">
          {e.message}
        </p>
      ))}
      {warnings.map((w) => (
        <p key={w.code} className="rule-form__warn" data-testid="rule-warning">
          {w.message}
        </p>
      ))}
      {draft.kind === 'literal' && draft.pattern ? (
        <p className="rule-form__hint">{cs.rules.literalSensitiveHint}</p>
      ) : null}

      {preview.ready ? (
        <div className="rule-preview" data-testid="rule-preview">
          <p data-testid="rule-match-count">
            {preview.truncated
              ? cs.rules.matchCountTruncated
                  .replace('{n}', String(preview.matchCount))
                  .replace('{lines}', '50000')
              : cs.rules.matchCount.replace('{n}', String(preview.matchCount))}
          </p>
          {preview.samples.length > 0 ? (
            <>
              <strong>{cs.rules.samplesTitle}</strong>
              <ul className="rule-preview__samples">
                {preview.samples.map((s, i) => (
                  <li key={i} data-testid="rule-sample">
                    <span className="rule-preview__line">Ř.{s.line}</span>
                    <code>
                      {s.before}
                      <mark>{s.match}</mark>
                      {s.after}
                    </code>
                    <span className="rule-preview__arrow">→ {s.replacementPreview}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="rule-form__hint">{cs.rules.noMatchesYet}</p>
          )}
          {preview.collisions.length > 0 ? (
            <>
              <strong>{cs.rules.collisionsTitle}</strong>
              <ul>
                {preview.collisions.map((c, i) => (
                  <li key={i} className="rule-form__warn" data-testid="rule-collision">
                    {c.detail}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>
      ) : null}

      {saving ? (
        <div
          className="rule-form__progress"
          role="status"
          aria-live="polite"
          data-testid="rule-form-progress"
        >
          <div className="rule-form__progress-row">
            <span className="spinner" aria-hidden="true" />
            <p>{cs.rules.savingProgress}</p>
          </div>
          {savingPct != null ? (
            <>
              <div
                className="progress-bar"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={savingPct}
              >
                <div className="progress-bar__fill" style={{ width: `${savingPct}%` }} />
              </div>
              <span>{savingPct} %</span>
            </>
          ) : null}
        </div>
      ) : null}

      <div className="rule-form__actions">
        <Button variant="ghost" disabled={saving} onClick={props.onClose}>
          {cs.rules.cancel}
        </Button>
        <Button
          variant="primary"
          data-testid="rule-save"
          disabled={!savable || saving}
          busy={saving}
          onClick={() => void onSave()}
        >
          {saving ? cs.rules.saving : cs.rules.save}
        </Button>
      </div>
    </div>
  )
}
