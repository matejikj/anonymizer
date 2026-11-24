/**
 * Clear Glass Operations — interactive + semantic state matrix (Stage 7).
 * Consumed by tests and reference fixtures; UI may set data-state / data-status.
 */

export const THEME_STATES = ['light', 'dark'] as const
export type ThemeState = (typeof THEME_STATES)[number]

export const INTERACTIVE_STATES = [
  'default',
  'hover',
  'active',
  'focus',
  'disabled',
  'loading',
  'error',
  'success',
  'warning',
  'empty',
] as const
export type InteractiveState = (typeof INTERACTIVE_STATES)[number]

export const SEMANTIC_STATUS = ['safe', 'warn', 'blocked', 'neutral'] as const
export type SemanticStatus = (typeof SEMANTIC_STATUS)[number]

/** Alias labels used in coverage / PCAP verdicts. */
export const SEMANTIC_STATUS_ALIASES = {
  exposed: 'warn',
  danger: 'blocked',
  unverifiable: 'neutral',
} as const

export const MOTION_PREFERENCES = ['no-preference', 'reduce'] as const
export type MotionPreference = (typeof MOTION_PREFERENCES)[number]

export const COLOR_PREFERENCES = ['none', 'forced-colors'] as const
export type ColorPreference = (typeof COLOR_PREFERENCES)[number]

export const DENSITY_MODES = ['compact', 'default', 'comfortable'] as const
export type DensityMode = (typeof DENSITY_MODES)[number]

export const SURFACE_LEVELS = ['canvas', 'data', 'raised', 'glass'] as const
export type SurfaceLevel = (typeof SURFACE_LEVELS)[number]

/** Surfaces that may use liquid glass (blur + translucent fill). */
export const GLASS_ALLOWED_SURFACES = [
  'header',
  'command-bar',
  'inspector',
  'popover',
  'drawer',
  'modal',
  'toast',
  'onboarding',
] as const

/** Surfaces where glass / backdrop-filter is forbidden. */
export const GLASS_FORBIDDEN_SURFACES = [
  'editor',
  'packet-grid',
  'coverage-table',
  'long-form',
  'data-plane',
] as const

export interface StateMatrixEntry {
  readonly theme: ThemeState
  readonly interactive: InteractiveState
  readonly status: SemanticStatus
  readonly density: DensityMode
  readonly reducedMotion: boolean
  readonly forcedColors: boolean
}

/** Deterministic matrix size for contract tests (not every combo exploded). */
export function enumerateFoundationMatrix(): readonly StateMatrixEntry[] {
  const entries: StateMatrixEntry[] = []
  for (const theme of THEME_STATES) {
    for (const status of SEMANTIC_STATUS) {
      entries.push({
        theme,
        interactive: 'default',
        status,
        density: 'compact',
        reducedMotion: false,
        forcedColors: false,
      })
    }
  }
  for (const interactive of INTERACTIVE_STATES) {
    entries.push({
      theme: 'light',
      interactive,
      status: 'neutral',
      density: 'compact',
      reducedMotion: false,
      forcedColors: false,
    })
  }
  entries.push({
    theme: 'dark',
    interactive: 'focus',
    status: 'safe',
    density: 'comfortable',
    reducedMotion: true,
    forcedColors: false,
  })
  entries.push({
    theme: 'light',
    interactive: 'disabled',
    status: 'blocked',
    density: 'default',
    reducedMotion: false,
    forcedColors: true,
  })
  return entries
}
