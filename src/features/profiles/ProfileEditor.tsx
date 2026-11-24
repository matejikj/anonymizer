import { useRef, useState } from 'react'
import { getActiveProfile } from '../rules/activeProfile.ts'
import {
  saveActiveProfile,
  updateActiveMeta,
} from './profileController.ts'
import { reanalyzeWithActiveProfile } from '../../app/sessionController.ts'
import { getLastImportedText } from '../../app/sessionController.ts'
import { useAppStore } from '../../app/store.ts'
import { DEFAULT_BUILTIN_TOGGLES, type RulesetBuiltinToggles } from '../../domain/configSchema.ts'
import { CATEGORY_LABELS } from '../review/categoryLabels.ts'
import { ModalPortal } from '../../components/ui/ModalPortal.tsx'
import { useModalFocusTrap } from '../../components/ui/useModalFocusTrap.ts'
import { Button } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'
import { isBuiltInUnifiedProfile } from './unifiedProfile.ts'

const BUILTIN_KEYS = Object.keys(DEFAULT_BUILTIN_TOGGLES) as Array<keyof RulesetBuiltinToggles>

export function ProfileEditor(props: { onClose: () => void }) {
  const active = getActiveProfile()
  const isDefault = isBuiltInUnifiedProfile(active.profile.id)
  const [name, setName] = useState(active.profile.name)
  const [description, setDescription] = useState(active.profile.description ?? '')
  const [builtins, setBuiltins] = useState({ ...active.profile.builtins })
  const [suffixes, setSuffixes] = useState(active.profile.settings.hostnameSuffixes.join(', '))
  const [userPrefixes, setUserPrefixes] = useState(
    active.profile.settings.userIdPrefixes.join(', '),
  )
  const [internalPrefixes, setInternalPrefixes] = useState(
    active.profile.settings.internalIdPrefixes.join(', '),
  )
  const [saving, setSaving] = useState(false)
  const dialogRef = useRef<HTMLDivElement>(null)

  useModalFocusTrap({ open: true, onClose: props.onClose, dialogRef })

  const applyLocal = async (alsoSave: boolean) => {
    updateActiveMeta({
      name: name.trim() || active.profile.name,
      description,
      builtins,
      settings: {
        hostnameSuffixes: splitList(suffixes),
        userIdPrefixes: splitList(userPrefixes),
        internalIdPrefixes: splitList(internalPrefixes),
      },
    })
    if (getLastImportedText()) {
      useAppStore.getState().setPlanBusy(true)
      try {
        await reanalyzeWithActiveProfile()
      } finally {
        useAppStore.getState().setPlanBusy(false)
      }
    }
    if (alsoSave) {
      setSaving(true)
      try {
        await saveActiveProfile()
        props.onClose()
      } finally {
        setSaving(false)
      }
    }
  }

  return (
    <ModalPortal>
      <div
        className="modal-backdrop"
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) props.onClose()
        }}
      >
        <div
          ref={dialogRef}
          className="modal modal--wide"
          role="dialog"
          aria-modal="true"
          aria-labelledby="profile-editor-title"
          data-testid="profile-editor"
        >
          <h2 id="profile-editor-title">{cs.profiles.editTitle}</h2>

          <section className="modal-section">
            <h3 className="modal-section__title">{cs.profiles.sectionIdentity}</h3>
            <label className="rule-form__field">
              <span>{cs.profiles.name}</span>
              <input
                type="text"
                value={name}
                data-testid="profile-name"
                disabled={isDefault}
                title={isDefault ? cs.profiles.defaultNameLocked : undefined}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            {isDefault ? (
              <p className="rule-form__hint" data-testid="profile-default-name-hint">
                {cs.profiles.defaultNameLocked}
              </p>
            ) : null}
            <label className="rule-form__field">
              <span>{cs.profiles.description}</span>
              <input
                type="text"
                value={description}
                data-testid="profile-description"
                onChange={(e) => setDescription(e.target.value)}
              />
            </label>
          </section>

          <section className="modal-section">
            <h3 className="modal-section__title">{cs.profiles.builtins}</h3>
            <p className="modal-section__lead">{cs.profiles.builtinsLead}</p>
            <div className="modal-check-grid">
              {BUILTIN_KEYS.map((key) => (
                <label key={key} className="rule-form__check">
                  <input
                    type="checkbox"
                    checked={builtins[key]}
                    data-testid={`builtin-${key}`}
                    onChange={(e) => setBuiltins((b) => ({ ...b, [key]: e.target.checked }))}
                  />
                  {CATEGORY_LABELS[key]}
                </label>
              ))}
            </div>
          </section>

          <section className="modal-section">
            <h3 className="modal-section__title">{cs.profiles.sectionSettings}</h3>
            <label className="rule-form__field">
              <span>{cs.profiles.hostnameSuffixes}</span>
              <input type="text" value={suffixes} onChange={(e) => setSuffixes(e.target.value)} />
            </label>
            <label className="rule-form__field">
              <span>{cs.profiles.userIdPrefixes}</span>
              <input
                type="text"
                value={userPrefixes}
                onChange={(e) => setUserPrefixes(e.target.value)}
              />
            </label>
            <label className="rule-form__field">
              <span>{cs.profiles.internalIdPrefixes}</span>
              <input
                type="text"
                value={internalPrefixes}
                onChange={(e) => setInternalPrefixes(e.target.value)}
              />
            </label>
          </section>

          <p className="rule-form__hint">
            {cs.profiles.rulesHint.replace('{n}', String(active.profile.rules.length))}
          </p>

          <div className="modal__actions">
            <Button variant="ghost" onClick={props.onClose}>
              {cs.profiles.cancel}
            </Button>
            <Button variant="secondary" data-testid="profile-apply" onClick={() => void applyLocal(false)}>
              {cs.profiles.apply}
            </Button>
            <Button
              variant="primary"
              data-testid="profile-editor-save"
              disabled={saving}
              busy={saving}
              onClick={() => void applyLocal(true)}
            >
              {saving ? cs.profiles.saving : cs.profiles.save}
            </Button>
          </div>
        </div>
      </div>
    </ModalPortal>
  )
}

function splitList(raw: string): string[] {
  return raw
    .split(/[,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}
