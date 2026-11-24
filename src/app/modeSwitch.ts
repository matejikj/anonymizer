import { useAppStore, type AppMode } from './store.ts'

export function isCurrentModeProfileDirty(): boolean {
  const mode = useAppStore.getState().activeMode
  // PCAP level is not an editable dirty profile — only text ruleset can block mode switch.
  if (mode === 'pcap') return false
  return useAppStore.getState().profileDirty
}

/** Switch app mode; blocks when the active mode profile has unsaved edits. */
export function requestModeSwitch(next: AppMode): void {
  const store = useAppStore.getState()
  if (store.activeMode === next) return
  if (isCurrentModeProfileDirty()) {
    store.setPendingSwitchMode(next)
    store.setProfileDialog('mode-switch-dirty')
    return
  }
  store.setActiveMode(next)
}
