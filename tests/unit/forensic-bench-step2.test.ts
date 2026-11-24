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
  const foundations = read('src/styles/foundations.css')
  const icons = read('src/components/ui/icons.tsx')

  it('uses compact brand + icon privacy (not text pill)', () => {
    expect(header).toMatch(/app-header__privacy/)
    expect(header).toMatch(/IconLock/)
    expect(header).toMatch(/visually-hidden/)
    expect(header).toMatch(/data-testid="app-privacy-badge"/)
    expect(header).not.toMatch(/app-header__privacy-pill/)
    expect(icons).toMatch(/export function IconLock/)
  })

  it('keeps header menubar height ≤ 48px', () => {
    expect(shell).toMatch(/\.app-header \{[\s\S]*?min-height:\s*44px/)
    expect(shell).toMatch(/\.app-header \{[\s\S]*?max-height:\s*48px/)
    expect(foundations).toMatch(/\.app-header \{[\s\S]*?min-height:\s*44px/)
    expect(foundations).toMatch(/\.app-header \{[\s\S]*?max-height:\s*48px/)
  })

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

  it('flattens header nav IconButtons to ink-muted instrument controls', () => {
    expect(shell).toMatch(/\.app-header__nav \.btn--icon \{[\s\S]*?background:\s*transparent/)
    expect(shell).toMatch(/\.app-header__nav \.btn--icon \{[\s\S]*?color:\s*var\(--color-ink-muted\)/)
    expect(header).toMatch(/IconButton/)
    expect(header).toMatch(/ThemeToggle/)
  })
})
