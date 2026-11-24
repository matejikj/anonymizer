/**
 * Light / dark theme (ARCHITECTURE §15 — optional manual switch).
 * Preference in localStorage; applied on documentElement[data-theme].
 */

import { loadPreference, savePreference } from '../persistence/preferencesRepository.ts'

export type ThemePreference = 'light' | 'dark'
export type ResolvedTheme = 'light' | 'dark'

const CYCLE: ThemePreference[] = ['light', 'dark']

function osTheme(): ResolvedTheme {
  if (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  ) {
    return 'dark'
  }
  return 'light'
}

export function loadThemePreference(): ThemePreference {
  const raw = loadPreference<string>('theme', 'light')
  if (raw === 'light' || raw === 'dark') return raw
  // Former 'system' (and unknown values) → concrete theme once.
  const migrated = raw === 'system' ? osTheme() : 'light'
  savePreference('theme', migrated)
  return migrated
}

export function saveThemePreference(pref: ThemePreference): void {
  savePreference('theme', pref)
}

export function resolveTheme(pref: ThemePreference): ResolvedTheme {
  return pref
}

export function applyResolvedTheme(resolved: ResolvedTheme): void {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  const reduce =
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (!reduce) root.classList.add('theme-animating')
  root.setAttribute('data-theme', resolved)
  if (!reduce) {
    window.setTimeout(() => root.classList.remove('theme-animating'), 220)
  }
}

export function applyThemePreference(pref: ThemePreference): ResolvedTheme {
  const resolved = resolveTheme(pref)
  applyResolvedTheme(resolved)
  return resolved
}

export function nextThemePreference(current: ThemePreference): ThemePreference {
  const i = CYCLE.indexOf(current)
  return CYCLE[(i + 1) % CYCLE.length]!
}

/** Call once at startup / when preference changes; no OS media listener. */
export function initTheme(pref: ThemePreference): () => void {
  applyThemePreference(pref)
  return () => {}
}
