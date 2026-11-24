import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('FORENSIC_BENCH step 4 — flat instrument controls', () => {
  const primitives = read('src/styles/primitives.css')
  const iconButton = read('src/design-system/IconButton.tsx')
  const button = read('src/design-system/Button.tsx')

  it('keeps primary flat (no soft drop shadow / brightness filter)', () => {
    const primary = primitives.match(/\.btn--primary \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(primary).toMatch(/box-shadow:\s*none/)
    expect(primary).not.toMatch(/box-shadow:\s*0 1px/)
    expect(primitives).toMatch(/\.btn--primary:hover:not\(:disabled\) \{[\s\S]*?filter:\s*none/)
  })

  it('uses hairline secondary and clean ghost', () => {
    const secondary = primitives.match(/\.btn--secondary \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(secondary).toMatch(/border-color:\s*var\(--color-border-subtle\)/)
    expect(secondary).toMatch(/box-shadow:\s*none/)
    expect(secondary).not.toMatch(/inset 0 0 0 1px/)
    const ghost = primitives.match(/\.btn--ghost \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(ghost).toMatch(/background:\s*transparent/)
    expect(ghost).toMatch(/color:\s*var\(--color-ink-muted\)/)
  })

  it('defines IconButton as transparent ink-muted instrument control', () => {
    const icon = primitives.match(/\.btn--icon \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(icon).toMatch(/background:\s*transparent/)
    expect(icon).toMatch(/color:\s*var\(--color-ink-muted\)/)
    expect(icon).toMatch(/border-radius:\s*var\(--radius-control\)/)
    expect(icon).toMatch(/min-width:\s*var\(--hit-target-min\)/)
    expect(icon).not.toMatch(/border-radius:\s*999px/)
    expect(iconButton).toMatch(/btn--icon/)
    expect(iconButton).toMatch(/data-control="icon-button"/)
  })

  it('maps Button variants to btn classes without custom shadows', () => {
    expect(button).toMatch(/primary: 'btn--primary'/)
    expect(button).toMatch(/secondary: 'btn--secondary'/)
    expect(button).toMatch(/ghost: 'btn--ghost'/)
  })

  it('keeps CTA tabs off pill radius (status chips may stay 999px)', () => {
    const corr = read('src/styles/corr-workspace.css')
    const patterns = read('src/styles/patterns.css')
    const tab = corr.match(/\.corr-entities__tab \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(tab).toMatch(/border-radius:\s*var\(--radius-control\)/)
    expect(tab).not.toMatch(/999px/)
    const helpTab = patterns.match(/\.help-panel__tab \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(helpTab).toMatch(/border-radius:\s*var\(--radius-control\)/)
    expect(helpTab).not.toMatch(/999px/)
    // Status chips remain pill — intentional
    expect(read('src/styles/features.css')).toMatch(/\.status-chip \{[\s\S]*?border-radius:\s*999px/)
  })

  it('forbids .btn rules using pill radius', () => {
    const btnBlocks = primitives.match(/\.btn[^{]*\{[^}]*\}/g) ?? []
    for (const block of btnBlocks) {
      expect(block, block.slice(0, 40)).not.toMatch(/border-radius:\s*999px/)
    }
  })
})
