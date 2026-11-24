/**
 * Small UI preferences — localStorage only, never log content (ARCHITECTURE §9.2).
 */

const PREFIX = 'rnd-log-anonymizer:pref:'

export type PrefKey =
  | 'wrap'
  | 'splitterRatio'
  | 'theme'
  | 'activeMode'
  | 'lastTextProfileId'
  | 'onboardingComplete'

export function loadPreference<T>(key: PrefKey, fallback: T): T {
  try {
    const raw = localStorage.getItem(PREFIX + key)
    if (raw == null) return fallback
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

export function savePreference(key: PrefKey, value: unknown): void {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value))
  } catch {
    // Quota / private mode — ignore
  }
}

export const DEFAULT_SPLITTER_RATIO = 0.5
export const MIN_PANE_PX = 360
