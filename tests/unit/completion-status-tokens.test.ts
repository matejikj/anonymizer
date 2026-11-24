import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('DESIGN_MOVES step 5 — completion status tokens', () => {
  it('uses ok/warn tokens and no success/warning fallbacks in completion CSS', () => {
    const css = read('src/styles/corr-export-completion.css')
    const completionBlocks = [
      ...css.matchAll(/\.corr-completion[^{]*\{[^}]*\}/g),
      ...css.matchAll(/\.corr-completion__[^{]*\{[^}]*\}/g),
    ].map((m) => m[0])
    const joined = completionBlocks.join('\n')
    expect(joined).not.toMatch(/--color-success/)
    expect(joined).not.toMatch(/--color-warning/)
    expect(joined).toMatch(/--color-ok/)
    expect(joined).toMatch(/--color-warn/)
    expect(css).not.toMatch(/\.corr-completion__zone\b/)
    expect(css).not.toMatch(/\.corr-completion__badge\b/)
  })

  it('renders completion with StatusChip pattern and block sections', () => {
    const view = read('src/features/correlation-workspace/CorrelationCompletionView.tsx')
    expect(view).toContain('StatusChip')
    expect(view).toContain('corr-completion__block--safe')
    expect(view).toContain('corr-completion__block--private')
    expect(view).not.toContain('corr-completion__zone')
    expect(view).not.toContain('corr-completion__badge')
  })
})
