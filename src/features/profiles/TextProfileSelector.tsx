import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '../../app/store.ts'
import {
  activateProfile,
  bootstrapProfiles,
  createNewProfile,
  deleteActiveProfile,
  downloadTextFile,
  duplicateActiveProfile,
  prepareExport,
  refreshProfileList,
  revertActiveProfile,
  saveActiveProfile,
} from './profileController.ts'
import type { StoredProfile } from '../../persistence/profileRepository.ts'
import { cs } from '../../i18n/cs.ts'
import { ProfileEditor } from './ProfileEditor.tsx'
import { ImportProfileDialog } from './ImportProfileDialog.tsx'
import { ClearDataDialog } from './ClearDataDialog.tsx'
import { DirtySwitchDialog } from './DirtySwitchDialog.tsx'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { isBuiltInUnifiedProfile } from './unifiedProfile.ts'

export function TextProfileSelector() {
  const dirty = useAppStore((s) => s.profileDirty)
  const profileEpoch = useAppStore((s) => s.profileEpoch)
  const activeId = useAppStore((s) => s.activeProfileId)
  const dialog = useAppStore((s) => s.profileDialog)
  const [profiles, setProfiles] = useState<StoredProfile[]>([])
  const [menuOpen, setMenuOpen] = useState(false)
  const [pending, setPending] = useState(false)
  const pendingRef = useRef(false)
  const listRequest = useRef(0)
  const menuWrapRef = useRef<HTMLDivElement>(null)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  /** IndexedDB reads resolve asynchronously — never set state after unmount. */
  const reloadProfiles = () => {
    const request = ++listRequest.current
    return refreshProfileList().then((list) => {
      if (mountedRef.current && request === listRequest.current) setProfiles(list)
    })
  }

  const runMutation = async (action: () => Promise<unknown>) => {
    if (pendingRef.current) return
    pendingRef.current = true
    setPending(true)
    try {
      await action()
      await reloadProfiles()
    } catch {
      useAppStore.getState().setToast({ message: cs.profiles.operationFailed })
    } finally {
      pendingRef.current = false
      if (mountedRef.current) setPending(false)
    }
  }

  const removeProfile = () => {
    setMenuOpen(false)
    void runMutation(async () => {
      const result = await deleteActiveProfile()
      useAppStore.getState().setToast({
        message: result.ok ? cs.profiles.deleted : cs.profiles.cannotDeleteDefault,
      })
    })
  }

  useEffect(() => {
    void bootstrapProfiles().then(reloadProfiles)
  }, [])

  useEffect(() => {
    void reloadProfiles()
  }, [profileEpoch])

  useEffect(() => {
    if (!menuOpen) return
    const onDoc = (event: MouseEvent) => {
      if (menuWrapRef.current?.contains(event.target as Node)) return
      setMenuOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [menuOpen])

  const requestSwitch = (id: string) => runMutation(async () => {
    const result = await activateProfile(id)
    if (!result.ok && result.reason === 'dirty') {
      useAppStore.getState().setPendingSwitchProfileId(id)
      useAppStore.getState().setProfileDialog('switch-dirty')
      return
    }
    setMenuOpen(false)
  })

  const onExport = () => {
    const { warnings } = prepareExport()
    if (warnings.length > 0) {
      useAppStore.getState().setProfileDialog('export-warn')
    } else {
      const prepared = prepareExport()
      downloadTextFile(prepared.fileName, prepared.json)
      useAppStore.getState().setToast({ message: cs.profiles.exported })
    }
  }

  const closeMenu = () => setMenuOpen(false)
  const isBuiltin = isBuiltInUnifiedProfile(activeId)

  return (
    <div className="profile-selector" data-testid="profile-selector" data-profile-mode="text">
      <div className="profile-selector__row">
        <label className="profile-selector__label">
          <span className="profile-selector__field-label">{cs.header.unifiedProfileSection}</span>
          <select
            data-testid="profile-select"
            value={activeId}
            disabled={pending}
            onChange={(e) => void requestSwitch(e.target.value)}
            aria-invalid={dirty || undefined}
            aria-label={cs.profiles.selectLabel}
          >
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {isBuiltInUnifiedProfile(p.id) ? ` (${cs.profiles.defaultBadge})` : ''}
              </option>
            ))}
          </select>
        </label>

        <div className="profile-selector__actions">
          <Button
            variant="ghost"
            size="tiny"
            data-testid="profile-edit"
            disabled={pending}
            onClick={() => useAppStore.getState().setProfileDialog('edit')}
          >
            {cs.profiles.editShort}
          </Button>
          <Button
            variant="ghost"
            size="tiny"
            data-testid="profile-new"
            disabled={pending}
            onClick={() => void runMutation(() => createNewProfile())}
          >
            {cs.profiles.newShort}
          </Button>
          <Button
            variant="ghost"
            size="tiny"
            data-testid="profile-delete-direct"
            aria-label={cs.profiles.delete}
            disabled={pending || isBuiltin}
            title={isBuiltin ? cs.profiles.cannotDeleteDefault : cs.profiles.delete}
            onClick={removeProfile}
          >
            {cs.profiles.deleteShort}
          </Button>
          {dirty ? (
            <>
              <span className="profile-selector__dirty" data-testid="profile-dirty">
                {cs.profiles.dirty}
              </span>
              <Button
                variant="secondary"
                size="tiny"
                data-testid="profile-save"
                disabled={pending}
                onClick={() => void runMutation(() => saveActiveProfile())}
              >
                {cs.profiles.save}
              </Button>
              <Button
                variant="ghost"
                size="tiny"
                data-testid="profile-revert"
                disabled={pending}
                onClick={() => void runMutation(() => revertActiveProfile())}
              >
                {cs.profiles.revertShort}
              </Button>
            </>
          ) : null}
          <div className="profile-selector__menu-wrap" ref={menuWrapRef}>
            <Button
              variant="ghost"
              size="tiny"
              data-testid="profile-menu-btn"
              disabled={pending}
              aria-expanded={menuOpen}
              aria-haspopup="menu"
              aria-label={cs.profiles.menuAria}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {cs.profiles.menu}
            </Button>
            {menuOpen ? (
              <ul className="profile-menu" role="menu" data-testid="profile-menu">
                <li className="profile-menu__group" role="presentation">
                  <button
                    type="button"
                    role="menuitem"
                    data-testid="profile-duplicate"
                    onClick={() => {
                      closeMenu()
                      void runMutation(() => duplicateActiveProfile())
                    }}
                  >
                    {cs.profiles.duplicate}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    data-testid="profile-import"
                    onClick={() => {
                      closeMenu()
                      useAppStore.getState().setProfileDialog('import')
                    }}
                  >
                    {cs.profiles.importJson}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    data-testid="profile-export"
                    onClick={() => {
                      closeMenu()
                      onExport()
                    }}
                  >
                    {cs.profiles.exportJson}
                  </button>
                </li>

                <li className="profile-menu__sep" role="separator" />

                <li className="profile-menu__group" role="presentation">
                  <button
                    type="button"
                    role="menuitem"
                    data-testid="profile-delete"
                    className="profile-menu__danger"
                    disabled={isBuiltin}
                    title={isBuiltin ? cs.profiles.cannotDeleteDefault : undefined}
                    onClick={removeProfile}
                  >
                    {cs.profiles.delete}
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    data-testid="profile-clear-data"
                    className="profile-menu__danger"
                    onClick={() => {
                      closeMenu()
                      useAppStore.getState().setProfileDialog('clear-data')
                    }}
                  >
                    {cs.profiles.clearData}
                  </button>
                </li>
              </ul>
            ) : null}
          </div>
        </div>
      </div>

      {dialog === 'edit' ? <ProfileEditor onClose={() => useAppStore.getState().setProfileDialog('none')} /> : null}
      {dialog === 'import' ? (
        <ImportProfileDialog onClose={() => useAppStore.getState().setProfileDialog('none')} />
      ) : null}
      {dialog === 'export-warn' ? <TextExportWarnDialog /> : null}
      {dialog === 'clear-data' ? (
        <ClearDataDialog onClose={() => useAppStore.getState().setProfileDialog('none')} />
      ) : null}
      {dialog === 'switch-dirty' ? <DirtySwitchDialog /> : null}
    </div>
  )
}

function TextExportWarnDialog() {
  const prepared = prepareExport()
  return (
    <AccessibleModal
      open
      onClose={() => useAppStore.getState().setProfileDialog('none')}
      titleId="export-warn-title"
      title={cs.profiles.exportWarnTitle}
      testId="export-warn-dialog"
      actions={
        <>
          <Button variant="ghost" onClick={() => useAppStore.getState().setProfileDialog('none')}>
            {cs.profiles.cancel}
          </Button>
          <Button
            variant="primary"
            data-testid="export-confirm"
            onClick={() => {
              downloadTextFile(prepared.fileName, prepared.json)
              useAppStore.getState().setProfileDialog('none')
              useAppStore.getState().setToast({ message: cs.profiles.exported })
            }}
          >
            {cs.profiles.exportAnyway}
          </Button>
        </>
      }
    >
      <p>{cs.profiles.exportWarnBody}</p>
      <ul>
        {prepared.warnings.slice(0, 8).map((w) => (
          <li key={w.path}>{w.message}</li>
        ))}
      </ul>
    </AccessibleModal>
  )
}
