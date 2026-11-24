import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()
const srcDir = join(root, 'src')

function read(rel: string): string {
  return readFileSync(join(srcDir, rel), 'utf8')
}

function* walkTs(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      yield* walkTs(full)
      continue
    }
    if (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) yield full
  }
}

describe('DESIGN_MOVES step 6 — EmptyDropzone removed', () => {
  it('deletes the legacy text EmptyDropzone module', () => {
    expect(() =>
      statSync(join(srcDir, 'features/import-log/EmptyDropzone.tsx')),
    ).toThrow()
  })

  it('keeps MultiSourceDropzone as the only app landing entry', () => {
    const shell = read('features/workspace/AppShell.tsx')
    expect(shell).toContain('MultiSourceDropzone')
    expect(shell).not.toMatch(/EmptyDropzone/)
    expect(shell).toMatch(/showLanding\s*\?\s*<MultiSourceDropzone/)

    const landing = read('features/correlation-staging/MultiSourceDropzone.tsx')
    expect(landing).toContain('data-testid="landing"')
    expect(landing).toContain('try-sample')
    expect(landing).toContain('paste-toggle')
    expect(landing).toContain('SAMPLE_LOG')
  })

  it('has no remaining imports of text EmptyDropzone under src/', () => {
    const offenders: string[] = []
    for (const file of walkTs(srcDir)) {
      if (file.endsWith(`${join('pcap', 'ui', 'PcapEmptyDropzone.tsx')}`)) continue
      const text = readFileSync(file, 'utf8')
      if (
        text.includes('features/import-log/EmptyDropzone') ||
        /import\s*\{[^}]*\bEmptyDropzone\b/.test(text) ||
        /from\s+['"][^'"]*EmptyDropzone['"]/.test(text)
      ) {
        offenders.push(file.slice(srcDir.length + 1))
      }
    }
    expect(offenders).toEqual([])
  })
})
