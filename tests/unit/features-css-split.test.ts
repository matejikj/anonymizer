import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

const PARTIALS = [
  'src/styles/pcap-features.css',
  'src/styles/staging.css',
  'src/styles/corr-workspace.css',
  'src/styles/corr-export-completion.css',
  'src/styles/resolve-features.css',
  'src/styles/features.css',
] as const

describe('DESIGN_MOVES step 9 — features.css domain split', () => {
  it('ships domain partials and a short features leftover', () => {
    for (const rel of PARTIALS) {
      expect(() => statSync(join(root, rel))).not.toThrow()
    }
    const leftover = read('src/styles/features.css').split('\n').length
    expect(leftover).toBeLessThan(500)
    expect(read('src/styles/pcap-features.css').split('\n').length).toBeGreaterThan(1000)
    expect(read('src/styles/corr-workspace.css')).toContain('.corr-workspace')
    expect(read('src/styles/corr-export-completion.css')).toContain('.corr-completion')
    expect(read('src/styles/staging.css')).toContain('.staging-view')
  })

  it('imports domain partials from app.css in cascade order', () => {
    const app = read('src/styles/app.css')
    const order = PARTIALS.map((rel) => rel.replace('src/styles/', './'))
    let last = -1
    for (const path of order) {
      const idx = app.indexOf(`@import '${path}'`)
      expect(idx, path).toBeGreaterThan(last)
      last = idx
    }
  })

  it('keeps domain selectors out of the wrong partials', () => {
    expect(read('src/styles/staging.css')).not.toContain('.pcap-workspace')
    expect(read('src/styles/corr-export-completion.css')).not.toContain('.pcap-main-toolbar')
    expect(read('src/styles/pcap-features.css')).not.toContain('.corr-workspace__set-row')
  })
})
