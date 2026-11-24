import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('DESIGN_MOVES step 7 / Forensic Bench — hero dropzone raised opaque', () => {
  it('defines dropzone--hero once in foundations as raised opaque', () => {
    const foundations = read('src/styles/foundations.css')
    expect(foundations).toMatch(/\.dropzone--hero\s*\{/)
    expect(foundations).toMatch(/background:\s*var\(--surface-raised\)/)
    expect(foundations).toMatch(/backdrop-filter:\s*none/)
    expect(foundations).not.toMatch(/\.dropzone--glass/)

    const heroBlock = foundations.match(/\/\* Forensic Bench step 3[\s\S]*?\/\* Command strip/)?.[0] ?? ''
    expect(heroBlock).toContain('.dropzone--hero')
    expect(heroBlock).toContain('--surface-raised')
    expect(heroBlock).toContain('border-subtle')
    expect(heroBlock).not.toContain('--glass-fill')
    expect(heroBlock).not.toContain('glass-backdrop')
    expect(heroBlock).not.toMatch(/border:\s*1px dashed/)
  })

  it('does not redefine hero or ship dropzone--glass in patterns.css', () => {
    const patterns = read('src/styles/patterns.css')
    expect(patterns).not.toMatch(/^\.dropzone--hero\s*\{/m)
    expect(patterns).not.toMatch(/\.dropzone--hero\.dropzone--active/)
    expect(patterns).not.toMatch(/\.dropzone--glass/)
    expect(patterns).toContain('lives only in foundations.css')
  })

  it('landing hero uses dropzone--hero without glass or raised-panel double wrap', () => {
    const landing = read('src/features/correlation-staging/MultiSourceDropzone.tsx')
    expect(landing).toMatch(/dropzone dropzone--hero/)
    expect(landing).not.toContain('dropzone--glass')
    expect(landing).not.toContain('ds-raised-panel')
  })
})
