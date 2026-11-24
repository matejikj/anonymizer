import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('FORENSIC_BENCH step 2 — instrument menubar', () => {
  const header = read('src/components/ui/AppHeader.tsx')
  const shell = read('src/styles/shell.css')
  const icons = read('src/components/ui/icons.tsx')

  it('uses compact brand + icon privacy (not text pill)', () => {
    expect(header).toMatch(/app-header__privacy/)
    expect(header).toMatch(/IconLock/)
    expect(header).toMatch(/visually-hidden/)
    expect(header).toMatch(/data-testid="app-privacy-badge"/)
    expect(header).not.toMatch(/app-header__privacy-pill/)
    expect(icons).toMatch(/export function IconLock/)
  })

  // Wrapping and visible documentation/help labels are covered in the browser by
  // docs-help.spec.ts. The former 48px/icon-only source guards prevented those labels.

  it('keeps brand at meta weight (not display/body hero)', () => {
    expect(shell).toMatch(/\.app-header__name \{[\s\S]*?font-size:\s*var\(--text-meta\)/)
    expect(shell).toMatch(/\.app-header__name \{[\s\S]*?font-weight:\s*var\(--weight-medium\)/)
    expect(shell).not.toMatch(/\.app-header__name \{[\s\S]*?font-size:\s*var\(--text-body\)/)
    expect(shell).not.toMatch(/\.app-header__name \{[\s\S]*?font-weight:\s*var\(--weight-semibold\)/)
  })

  it('quiets stepper active state (no glow shadow)', () => {
    expect(shell).toMatch(/\.session-stepper__item--active \{[\s\S]*?box-shadow:\s*none/)
    expect(shell).toMatch(
      /\.session-stepper__item--active \.session-stepper__dot \{[\s\S]*?box-shadow:\s*none/,
    )
    expect(shell).not.toMatch(/box-shadow:\s*0 0 0 3px color-mix\(in srgb, var\(--color-accent\)/)
  })

})
