import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()
const srcDir = join(root, 'src')

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
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

describe('FORENSIC_BENCH step 5 — type + density lock', () => {
  it('keeps app shell density always compact', () => {
    const shell = read('src/features/workspace/AppShell.tsx')
    expect(shell).toMatch(/const density = 'compact'/)
    expect(shell).not.toMatch(/comfortable/)
    expect(read('src/design-system/gallery/main.tsx')).toMatch(/data-density="comfortable"/)
  })

  it('forbids type-display in features/ and pcap/', () => {
    const offenders: string[] = []
    for (const dir of ['features', 'pcap']) {
      for (const file of walkTs(join(srcDir, dir))) {
        const text = readFileSync(file, 'utf8')
        if (/\btype-display\b/.test(text)) {
          offenders.push(file.slice(srcDir.length + 1))
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('locks workspace / overview titles to section tokens', () => {
    const css = read('src/styles/corr-workspace.css')
    const workspaceTitle = css.match(/\.corr-workspace__title\s*\{[^}]+\}/)?.[0] ?? ''
    const overviewTitle = css.match(/\.corr-overview__title\s*\{[^}]+\}/)?.[0] ?? ''
    expect(workspaceTitle).toContain('--text-section-title')
    expect(overviewTitle).toContain('--text-section-title')
    expect(workspaceTitle).not.toContain('--text-body')
    expect(overviewTitle).not.toContain('--text-body')
    expect(workspaceTitle).not.toContain('--text-display')
  })

  it('keeps dual-log / PCAP data on mono stack', () => {
    const layout = read('src/styles/workspace-layout.css')
    expect(layout).toMatch(/font-family:\s*var\(--font-mono\)/)
    const tokens = read('src/styles/tokens.css')
    expect(tokens).toMatch(/--pcap-font-data:\s*var\(--font-mono\)/)
  })

  it('flattens staging + completion (no zone-card shadows / soft pop)', () => {
    const staging = read('src/styles/staging.css')
    expect(staging).toMatch(/\.staging-view \{[\s\S]*?max-width:\s*var\(--space-content-max\)/)
    const row = staging.match(/\.staging-row \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(row).toMatch(/box-shadow:\s*none/)
    expect(row).toMatch(/border:\s*1px solid/)
    expect(row).not.toMatch(/var\(--shadow-sm\)/)

    const completion = read('src/styles/corr-export-completion.css')
    expect(completion).toMatch(/\.corr-completion \{[\s\S]*?max-width:\s*var\(--space-content-max\)/)
    expect(completion).toMatch(/\.corr-completion__block \{[\s\S]*?border-top:\s*1px solid/)
    expect(completion).toMatch(/\.corr-completion__block--ok \{[\s\S]*?animation:\s*none/)
    expect(completion).not.toMatch(/zone-card/)
  })

  it('aligns reference landing density with compact bench', () => {
    const ref = read('src/styles/referenceCompositions.ts')
    expect(ref).toMatch(/id: 'landing'[\s\S]*?density: 'compact'/)
  })
})
