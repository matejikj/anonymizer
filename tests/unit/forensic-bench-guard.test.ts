/**
 * FORENSIC_BENCH anti-AI / drift guard (T46).
 * Invariants live in code tokens — not a deleted design.md / construction doc.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

function walkTsx(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      walkTsx(full, out)
    } else if (/\.(tsx|ts)$/.test(name)) {
      out.push(full)
    }
  }
  return out
}

describe('FORENSIC_BENCH step 8 — anti-AI / drift guard', () => {
  const tokens = read('src/styles/tokens.css')
  const foundations = read('src/styles/foundations.css')
  const shell = read('src/styles/shell.css')
  const primitives = read('src/styles/primitives.css')
  const gallery = read('src/design-system/gallery/main.tsx')

  it('locks Bench radii and motion clamp', () => {
    expect(tokens).toMatch(/--radius-control:\s*6px/)
    expect(tokens).toMatch(/--radius-panel:\s*8px/)
    expect(tokens).toMatch(/--radius-overlay:\s*10px/)
    expect(tokens).toMatch(/--motion-fast:\s*120ms/)
    expect(tokens).toMatch(/--motion-default:\s*140ms/)
    expect(tokens).toMatch(/--motion-slow:\s*160ms/)
    expect(tokens).not.toMatch(/--motion-slow:\s*240ms/)
  })

  it('keeps chrome matte (no soft glass blur / shell glow)', () => {
    expect(tokens).toMatch(/--glass-blur:\s*0px/)
    expect(tokens).toMatch(/--glass-backdrop:\s*none/)
    expect(tokens).toMatch(/--glass-shadow:\s*none/)
    expect(tokens).toMatch(/--shadow-shell:\s*none/)
    expect(foundations).toMatch(/\.app-header \{[\s\S]*?backdrop-filter:\s*none/)
    expect(shell).toMatch(/\.app-header \{[\s\S]*?box-shadow:\s*none/)
    const primary = primitives.match(/\.btn--primary \{[\s\S]*?\n\}/)?.[0] ?? ''
    expect(primary).toMatch(/box-shadow:\s*none/)
    expect(primary).not.toMatch(/0\s+8px\s+24px/)
    expect(primary).not.toMatch(/0\s+4px\s+12px/)
  })

  it('defines 2px selection rail and uses it in data chrome', () => {
    expect(tokens).toMatch(/--selection-rail-width:\s*2px/)
    expect(tokens).toMatch(/--selection-rail:\s*inset var\(--selection-rail-width\)/)
    expect(read('src/styles/data-view.css')).toMatch(/box-shadow:\s*var\(--selection-rail\)/)
    expect(read('src/styles/design-system.css')).toMatch(
      /\.gallery-bench-row--selected[\s\S]*?box-shadow:\s*var\(--selection-rail\)/,
    )
  })

  it('forbids type-display in product UI sources', () => {
    const roots = ['src/features', 'src/pcap', 'src/design-system']
    const hits: string[] = []
    for (const rel of roots) {
      for (const file of walkTsx(join(root, rel))) {
        if (file.includes(`${join('design-system', 'gallery')}`)) continue
        const text = readFileSync(file, 'utf8')
        if (/\btype-display\b/.test(text)) {
          hits.push(file.replace(root + '/', ''))
        }
      }
    }
    expect(hits).toEqual([])
  })

  it('keeps gallery Bench chrome section and data-design', () => {
    expect(gallery).toMatch(/data-design="forensic-bench"/)
    expect(gallery).toMatch(/data-testid="gallery-bench-chrome"/)
    expect(gallery).toMatch(/gallery-bench-menubar/)
    expect(gallery).toMatch(/gallery-bench-row--selected/)
    expect(gallery).not.toMatch(/type-display/)
  })

  it('keeps Forensic Bench tokens as the anti-AI checklist source of truth', () => {
    expect(tokens).toMatch(/--glass-blur:\s*0px/)
    expect(tokens).toMatch(/--color-accent:\s*#0e5860/)
    expect(gallery).toMatch(/data-design="forensic-bench"/)
  })

  it('rejects purple / candy AI palette anchors in tokens', () => {
    expect(tokens).not.toMatch(/#7[cC]3[aA][eE][dD]/)
    expect(tokens).not.toMatch(/#8[bB]5[cC][fF]/)
    expect(tokens).not.toMatch(/#[aA]855[fF]7/)
    expect(tokens).toMatch(/--color-accent:\s*#0e5860/)
  })
})
