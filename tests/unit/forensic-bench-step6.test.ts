import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('FORENSIC_BENCH step 6 — forensic selection rail', () => {
  const tokens = read('src/styles/tokens.css')
  const dataView = read('src/styles/data-view.css')
  const pcap = read('src/styles/pcap-features.css')
  const theme = read('src/features/workspace/codemirrorEditorTheme.ts')
  const corr = read('src/styles/corr-workspace.css')

  it('defines 2px selection rail tokens', () => {
    expect(tokens).toMatch(/--selection-rail-width:\s*2px/)
    expect(tokens).toMatch(/--selection-rail-color:\s*var\(--color-accent\)/)
    expect(tokens).toMatch(/--selection-rail:\s*inset var\(--selection-rail-width\)/)
    expect(tokens).toMatch(/--pcap-selection-bg:\s*color-mix\(in srgb, var\(--color-accent\) 8%/)
  })

  it('applies rail to CodeMirror active line and occurrence matches', () => {
    expect(dataView).toMatch(/\.cm-editor \.cm-activeLine \{[\s\S]*?box-shadow:\s*var\(--selection-rail\)/)
    expect(dataView).toMatch(/\.cm-sync-match[\s\S]*?box-shadow:\s*var\(--selection-rail\)/)
    expect(dataView).toMatch(/animation:\s*none/)
    expect(theme).toMatch(/boxShadow:\s*'var\(--selection-rail\)'/)
    expect(theme).not.toMatch(/match-pulse/)
  })

  it('applies rail to PCAP selected row (not full inset outline glow)', () => {
    const selected = pcap.match(/\.pcap-row--selected \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(selected).toMatch(/box-shadow:\s*var\(--selection-rail\)/)
    expect(selected).not.toMatch(/inset 0 0 0 1px/)
    expect(pcap).toMatch(/\.pcap-tree__node--selected \{[\s\S]*?box-shadow:\s*var\(--selection-rail\)/)
    expect(pcap).toMatch(/\.pcap-row:hover:not\(\.pcap-row--selected\) \{[\s\S]*?filter:\s*none/)
  })

  it('applies rail to correlation source rail active item', () => {
    const active = corr.match(/\.corr-rail__item--active \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(active).toMatch(/box-shadow:\s*var\(--selection-rail\)/)
    expect(active).not.toMatch(/var\(--shadow-sm\)/)
  })

  it('keeps hover as quiet ink wash (not thick accent fill)', () => {
    expect(dataView).toMatch(/--data-hover-bg:\s*color-mix\(in srgb, var\(--color-ink\) 4%/)
    expect(dataView).toMatch(/--data-selection-bg:\s*color-mix\(in srgb, var\(--color-accent\) 8%/)
  })
})
