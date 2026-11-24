import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  enumerateFoundationMatrix,
  GLASS_ALLOWED_SURFACES,
  GLASS_FORBIDDEN_SURFACES,
  INTERACTIVE_STATES,
  SEMANTIC_STATUS,
  THEME_STATES,
} from '../../src/styles/stateMatrix.ts'
import {
  DESIGN_DIRECTION,
  REFERENCE_COMPOSITIONS,
  REFERENCE_SCREENS,
  REFERENCE_VIEWPORT,
} from '../../src/styles/referenceCompositions.ts'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

const TOKEN_KEYS = [
  '--surface-canvas',
  '--surface-data',
  '--surface-raised',
  '--surface-glass',
  '--color-accent',
  '--color-accent-glow',
  '--color-ok',
  '--color-warn',
  '--color-danger',
  '--color-neutral',
  '--glass-fill',
  '--glass-border',
  '--glass-highlight',
  '--glass-blur',
  '--glass-opacity',
  '--glass-saturate',
  '--glass-backdrop',
  '--glass-shadow',
  '--text-display',
  '--text-page-title',
  '--text-section-title',
  '--text-body',
  '--text-meta',
  '--text-label',
  '--text-mono',
  '--radius-control',
  '--radius-panel',
  '--radius-overlay',
  '--motion-fast',
  '--motion-default',
  '--motion-slow',
  '--z-sticky',
  '--z-modal',
  '--z-toast',
  '--control-height-compact',
  '--control-height-default',
  '--control-height-comfortable',
  '--hit-target-min',
  '--status-safe',
  '--status-warn',
  '--status-blocked',
  '--status-neutral',
  '--icon-stroke',
] as const

describe('Clear Glass Operations foundations', () => {
  const tokens = read('src/styles/tokens.css')
  const foundations = read('src/styles/foundations.css')
  const appCss = read('src/styles/app.css')
  const stateMatrix = read('src/styles/stateMatrix.ts')
  const icons = read('src/components/ui/icons.tsx')

  it('names the design direction and glass rules in stateMatrix + tokens', () => {
    expect(DESIGN_DIRECTION).toBe('Forensic Bench')
    expect(stateMatrix).toMatch(/Clear Glass Operations/)
    expect(tokens).toMatch(/--surface-canvas/)
    expect([...GLASS_FORBIDDEN_SURFACES]).toEqual(
      expect.arrayContaining(['editor', 'packet-grid', 'coverage-table', 'data-plane']),
    )
  })

  it('exposes a complete token contract for light and dark', () => {
    expect(tokens).toMatch(/\[data-theme='light'\]/)
    expect(tokens).toMatch(/\[data-theme='dark'\]/)
    for (const key of TOKEN_KEYS) {
      expect(tokens, key).toContain(key)
    }
    expect(tokens).toMatch(/prefers-reduced-motion/)
    expect(tokens).toMatch(/forced-colors/)
    expect(tokens).toMatch(/backdrop-filter is unavailable/)
  })

  it('forbids remote fonts, images, and network URLs in style foundations', () => {
    const css = `${tokens}\n${foundations}`
    expect(css).not.toMatch(/@import\s+url\(/)
    expect(css).not.toMatch(/https?:\/\//)
    expect(css).not.toMatch(/fonts\.google/)
    expect(css).not.toMatch(/woff2?/)
    expect(tokens).toMatch(/system-ui/)
    expect(tokens).toMatch(/ui-monospace/)
  })

  it('keeps glass off data-plane selectors', () => {
    expect(tokens).toMatch(/\.surface-data/)
    expect(foundations).toMatch(/backdrop-filter:\s*none/)
    const dataBlock = foundations.match(/\.app-main,[\s\S]*?\.editor-pane \{[\s\S]*?\}/)?.[0] ?? ''
    expect(dataBlock).toContain('backdrop-filter: none')
    expect(appCss).not.toMatch(/\.cm-editor[^{]*\{[^}]*backdrop-filter:\s*blur/)
    expect(appCss).not.toMatch(/\.dual-log[^{]*\{[^}]*backdrop-filter:\s*blur/)
  })

  it('enumerates the interactive and semantic state matrix', () => {
    expect(THEME_STATES).toEqual(['light', 'dark'])
    expect([...INTERACTIVE_STATES]).toEqual(
      expect.arrayContaining(['hover', 'focus', 'disabled', 'loading', 'error']),
    )
    expect([...SEMANTIC_STATUS]).toEqual(['safe', 'warn', 'blocked', 'neutral'])
    expect([...GLASS_ALLOWED_SURFACES]).toEqual(
      expect.arrayContaining(['header', 'command-bar', 'modal', 'toast']),
    )
    expect([...GLASS_FORBIDDEN_SURFACES]).toEqual(
      expect.arrayContaining(['editor', 'packet-grid', 'coverage-table', 'data-plane']),
    )
    const matrix = enumerateFoundationMatrix()
    expect(matrix.some((e) => e.reducedMotion)).toBe(true)
    expect(matrix.some((e) => e.forcedColors)).toBe(true)
    expect(matrix.some((e) => e.theme === 'dark' && e.status === 'blocked')).toBe(true)
  })

  it('defines the three reference compositions as one shell', () => {
    expect(DESIGN_DIRECTION).toBe('Forensic Bench')
    expect(REFERENCE_SCREENS).toEqual(['landing', 'text-workspace', 'pcap-workspace'])
    expect(REFERENCE_VIEWPORT).toEqual({ width: 1440, height: 1000 })
    expect(REFERENCE_COMPOSITIONS).toHaveLength(3)
    for (const screen of REFERENCE_COMPOSITIONS) {
      expect(screen.shell).toEqual(expect.arrayContaining(['header']))
      expect(screen.opaque.length).toBeGreaterThan(0)
    }
    expect(REFERENCE_COMPOSITIONS[0]?.density).toBe('compact')
    expect(REFERENCE_COMPOSITIONS[1]?.density).toBe('compact')
    expect(REFERENCE_COMPOSITIONS[2]?.glass).toEqual(expect.arrayContaining(['command-bar']))
  })

  it('locks Forensic Bench product palette anchors (no SaaS sky / candy cyan)', () => {
    expect(tokens).toMatch(/--color-accent:\s*#0e5860/)
    expect(tokens).toMatch(/--color-accent-glow:\s*#3a969e/)
    expect(tokens).toMatch(/\[data-theme='dark'\][\s\S]*?--color-accent:\s*#6bb8bf/)
    expect(tokens).not.toMatch(/--color-accent:\s*#1a4f8c/)
    expect(tokens).not.toMatch(/--color-accent:\s*#7eb6ef/)
    expect(tokens).not.toMatch(/--color-accent-glow:\s*#5eb0d8/)
  })
  it('ships an outline SVG set with 1.75 stroke and 16/18/20 sizes', () => {
    expect(icons).toContain('const STROKE = 1.75')
    expect(icons).toMatch(/size\?: 16 \| 18 \| 20/)
    expect(icons).toMatch(/export function IconHelp/)
    expect(icons).toMatch(/export function IconLock/)
    expect(icons).toMatch(/export const IconClose = IconX/)
    expect(icons).toMatch(/export function IconExport/)
    expect(icons).toMatch(/export function IconMore/)
  })
})
