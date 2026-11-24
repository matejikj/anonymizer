import { useEffect } from 'react'
import { useAppStore } from '../../app/store.ts'
import {
  initTheme,
  nextThemePreference,
  resolveTheme,
  type ThemePreference,
} from '../../app/theme.ts'
import { cs } from '../../i18n/cs.ts'
import { IconButton } from '../../design-system/index.ts'

function labelFor(pref: ThemePreference): string {
  return pref === 'dark' ? cs.theme.night : cs.theme.day
}

export function ThemeToggle() {
  const pref = useAppStore((s) => s.themePreference)

  useEffect(() => initTheme(pref), [pref])

  const resolved = resolveTheme(pref)
  const next = nextThemePreference(pref)

  return (
    <IconButton
      className="theme-toggle"
      data-testid="theme-toggle"
      data-theme-pref={pref}
      data-theme-resolved={resolved}
      label={`${cs.theme.toggle}: ${labelFor(pref)}. ${cs.theme.next}: ${labelFor(next)}`}
      title={`${labelFor(pref)} → ${labelFor(next)}`}
      onClick={() => useAppStore.getState().setThemePreference(next)}
    >
      <span className={`theme-toggle__swatch theme-toggle__swatch--${resolved}`} aria-hidden="true" />
    </IconButton>
  )
}
