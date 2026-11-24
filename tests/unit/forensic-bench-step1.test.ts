import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('FORENSIC_BENCH step 1 — token contract', () => {
  const tokens = read('src/styles/tokens.css')
  const foundations = read('src/styles/foundations.css')
  const shell = read('src/styles/shell.css')
  const ds = read('src/styles/design-system.css')
  const appShell = read('src/features/workspace/AppShell.tsx')
  const gallery = read('src/design-system/gallery/main.tsx')

  it('locks Bench radii 6 / 8 / 10', () => {
    expect(tokens).toMatch(/--radius-control:\s*6px/)
    expect(tokens).toMatch(/--radius-panel:\s*8px/)
    expect(tokens).toMatch(/--radius-overlay:\s*10px/)
    expect(tokens).not.toMatch(/--radius-control:\s*10px/)
    expect(tokens).not.toMatch(/--radius-panel:\s*14px/)
    expect(tokens).not.toMatch(/--radius-overlay:\s*18px/)
  })

  it('clamps motion to 120–160 ms', () => {
    expect(tokens).toMatch(/--motion-fast:\s*120ms/)
    expect(tokens).toMatch(/--motion-default:\s*140ms/)
    expect(tokens).toMatch(/--motion-slow:\s*160ms/)
    expect(tokens).not.toMatch(/--motion-default:\s*180ms/)
    expect(tokens).not.toMatch(/--motion-slow:\s*240ms/)
  })

  it('makes chrome matte (no blur / soft glass shadow)', () => {
    expect(tokens).toMatch(/--glass-blur:\s*0px/)
    expect(tokens).toMatch(/--glass-backdrop:\s*none/)
    expect(tokens).toMatch(/--glass-shadow:\s*none/)
    expect(tokens).toMatch(/--shadow-sm:\s*none/)
    expect(tokens).toMatch(/--shadow-shell:\s*none/)
    expect(tokens).toMatch(/--surface-glass:\s*var\(--surface-raised\)/)
  })

  it('uses opaque raised header and command chrome', () => {
    expect(foundations).toMatch(/\.app-header \{[\s\S]*?background:\s*var\(--surface-raised\)/)
    expect(foundations).toMatch(/\.app-header \{[\s\S]*?backdrop-filter:\s*none/)
    expect(shell).toMatch(/\.app-header \{[\s\S]*?background:\s*var\(--surface-raised\)/)
    expect(ds).toMatch(/\.ds-command-bar \{[\s\S]*?background:\s*var\(--surface-raised\)/)
    expect(ds).toMatch(/\.ds-command-bar \{[\s\S]*?backdrop-filter:\s*none/)
  })

  it('sets data-design forensic-bench on app shell and gallery', () => {
    expect(appShell).toMatch(/data-design="forensic-bench"/)
    expect(gallery).toMatch(/data-design="forensic-bench"/)
    expect(appShell).not.toMatch(/data-design="clear-glass-operations"/)
  })

  it('keeps Forensic Bench palette anchors', () => {
    expect(tokens).toMatch(/--color-accent:\s*#0e5860/)
    expect(tokens).toMatch(/\[data-theme='dark'\][\s\S]*?--color-accent:\s*#6bb8bf/)
  })
})
