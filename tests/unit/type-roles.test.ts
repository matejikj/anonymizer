import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(process.cwd())

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('DESIGN_MOVES step 4 — type role adoption', () => {
  it('defines the type role utilities once in base.css', () => {
    const base = read('src/styles/base.css')
    for (const role of [
      '.type-display',
      '.type-page-title',
      '.type-section-title',
      '.type-body',
      '.type-meta',
      '.type-label',
      '.type-mono',
    ]) {
      expect(base).toContain(role)
    }
    expect(base).toMatch(/\.type-page-title,\s*\n\.type-title/)
    const foundations = read('src/styles/foundations.css')
    expect(foundations).not.toMatch(/\/\* Type utility roles \*\//)
    expect(foundations).not.toMatch(/^\.type-display\s*\{/m)
    expect(foundations).not.toMatch(/^\.type-page-title\s*\{/m)
  })

  it('keeps corr workspace/overview titles on section tokens, not body', () => {
    const css = read('src/styles/corr-workspace.css')
    const workspaceTitle = css.match(/\.corr-workspace__title\s*\{[^}]+\}/)?.[0] ?? ''
    const overviewTitle = css.match(/\.corr-overview__title\s*\{[^}]+\}/)?.[0] ?? ''
    expect(workspaceTitle).toContain('--text-section-title')
    expect(workspaceTitle).not.toContain('--text-body')
    expect(overviewTitle).toContain('--text-section-title')
    expect(overviewTitle).not.toContain('--text-body')
  })

  it('keeps type-display utility defined but unused in product screens', () => {
    const landing = read('src/features/correlation-staging/MultiSourceDropzone.tsx')
    expect(landing).toMatch(/type-page-title/)
    expect(landing).not.toMatch(/type-display/)
    const splash = read('src/design-system/ProgressSplash.tsx')
    expect(splash).toMatch(/progress-splash__title type-page-title/)
    expect(splash).not.toMatch(/type-display/)
    expect(read('src/features/workspace/AppShell.tsx')).not.toMatch(/type-display/)
  })

  it('uses label/meta tokens for stepper and PCAP status chrome', () => {
    const shell = read('src/styles/shell.css')
    expect(shell).toMatch(/\.session-stepper__item\s*\{[\s\S]*?font-size:\s*var\(--text-label\)/)
    const features = read('src/styles/pcap-features.css')
    expect(features).toMatch(/\.pcap-status-bar\s*\{[\s\S]*?font-size:\s*var\(--text-meta\)/)
  })
})
