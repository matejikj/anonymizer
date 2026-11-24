/**
 * Forensic Bench — three reference compositions.
 * Chrome slots are matte instrument (opaque raised + hairline), not translucent glass.
 * Palette = cold graphite + signal teal. Not a runtime router.
 */

export const DESIGN_DIRECTION = 'Forensic Bench' as const

export const REFERENCE_SCREENS = ['landing', 'text-workspace', 'pcap-workspace'] as const
export type ReferenceScreen = (typeof REFERENCE_SCREENS)[number]

export const REFERENCE_VIEWPORT = { width: 1440, height: 1000 } as const

export interface ReferenceComposition {
  readonly id: ReferenceScreen
  readonly shell: readonly string[]
  readonly density: 'compact' | 'comfortable'
  /** Chrome slots (matte raised) — historically named `glass`. */
  readonly glass: readonly string[]
  readonly opaque: readonly string[]
}

export const REFERENCE_COMPOSITIONS: readonly ReferenceComposition[] = [
  {
    id: 'landing',
    shell: ['header', 'stepper', 'canvas'],
    density: 'compact',
    glass: ['header'],
    opaque: ['hero-dropzone', 'secondary-actions'],
  },
  {
    id: 'text-workspace',
    shell: ['header', 'stepper', 'command-bar', 'data-plane'],
    density: 'compact',
    glass: ['header', 'command-bar'],
    opaque: ['dual-log', 'editor'],
  },
  {
    id: 'pcap-workspace',
    shell: ['header', 'stepper', 'command-bar', 'data-plane', 'inspector'],
    density: 'compact',
    glass: ['header', 'command-bar', 'inspector'],
    opaque: ['packet-grid', 'coverage-table'],
  },
]
