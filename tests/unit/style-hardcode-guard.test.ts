import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  GLASS_FORBIDDEN_SURFACES,
  GLASS_ALLOWED_SURFACES,
} from '../../src/styles/stateMatrix.ts'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

const FOUNDATION_STYLE_FILES = new Set([
  'src/styles/tokens.css',
  'src/styles/foundations.css',
  'src/styles/base.css',
  'src/styles/shell.css',
  'src/styles/primitives.css',
  'src/styles/patterns.css',
  'src/styles/design-system.css',
  'src/styles/data-view.css',
  'src/styles/workspace-layout.css',
  'src/styles/progress-splash.css',
  'src/styles/pcap-features.css',
  'src/styles/staging.css',
  'src/styles/corr-workspace.css',
  'src/styles/corr-export-completion.css',
  'src/styles/resolve-features.css',
  'src/styles/features.css',
  'src/styles/app.css',
])

const APPROVED_HARDCODE_FILES = new Set([
  ...FOUNDATION_STYLE_FILES,
  'src/features/workspace/codemirrorEditorTheme.ts',
])

const HEX_RE = /#[0-9a-fA-F]{3,8}\b/
const RGB_RE = /\brgba?\(/
const HARD_SHADOW_RE = /box-shadow:\s*[^;]*\d+px/
const HARD_RADIUS_RE = /border-radius:\s*\d+px/
const HARD_Z_RE = /z-index:\s*\d+/

function walkSrcCssAndTs(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) {
      if (name === 'gallery') continue
      walkSrcCssAndTs(full, out)
    } else if (/\.(css|tsx|ts)$/.test(name) && !name.endsWith('.d.ts')) {
      out.push(full)
    }
  }
  return out
}

describe('Style architecture and hard-code guard', () => {
  it('app.css is an import-only cascade barrel', () => {
    const app = read('src/styles/app.css')
    expect(app).toMatch(/@import '\.\/tokens\.css'/)
    expect(app).toMatch(/@import '\.\/foundations\.css'/)
    expect(app).toMatch(/@import '\.\/primitives\.css'/)
    expect(app).toMatch(/@import '\.\/patterns\.css'/)
    expect(app).toMatch(/@import '\.\/shell\.css'/)
    expect(app).toMatch(/@import '\.\/design-system\.css'/)
    expect(app).toMatch(/@import '\.\/data-view\.css'/)
    expect(app).toMatch(/@import '\.\/features\.css'/)
    const withoutImports = app
      .split('\n')
      .filter((l) => !l.trim().startsWith('@import') && !l.trim().startsWith('/*') && !l.trim().startsWith('*') && l.trim() !== '' && !l.trim().startsWith('*/'))
    expect(withoutImports).toEqual([])
  })

  it('exposes semantic token aliases', () => {
    const tokens = read('src/styles/tokens.css')
    for (const key of [
      '--text-primary',
      '--text-muted',
      '--border-interactive',
      '--surface-data',
      '--surface-raised',
      '--surface-glass',
      '--status-safe',
    ]) {
      expect(tokens).toContain(key)
    }
    expect(tokens).toMatch(/backdrop-filter is unavailable/)
    expect(tokens).toMatch(/forced-colors/)
  })

  it('forbids hard-coded colors/shadows/radius/z-index outside approved foundation files', () => {
    const srcRoot = join(root, 'src')
    const offenders: string[] = []
    for (const full of walkSrcCssAndTs(srcRoot)) {
      const rel = relative(root, full).replaceAll('\\', '/')
      if (APPROVED_HARDCODE_FILES.has(rel)) continue
      if (rel.startsWith('src/styles/')) continue
      if (rel.startsWith('src/design-system/gallery/')) continue
      if (!rel.endsWith('.css') && !rel.endsWith('.tsx')) continue
      // Only style modules and inline style strings in non-approved TSX
      const text = readFileSync(full, 'utf8')
      if (rel.endsWith('.tsx')) {
        // Flag only style={{ ... }} blocks with raw hex
        const styleBlocks = text.match(/style=\{\{[\s\S]*?\}\}/g) ?? []
        for (const block of styleBlocks) {
          if (HEX_RE.test(block) || RGB_RE.test(block)) {
            offenders.push(`${rel} inline style hard-code`)
          }
        }
        continue
      }
      if (HEX_RE.test(text) || RGB_RE.test(text) || HARD_SHADOW_RE.test(text) || HARD_RADIUS_RE.test(text) || HARD_Z_RE.test(text)) {
        offenders.push(rel)
      }
    }
    expect(offenders).toEqual([])
  })

  it('keeps glass allow/deny lists aligned with DataSurface contract', () => {
    expect([...GLASS_FORBIDDEN_SURFACES]).toEqual(
      expect.arrayContaining(['editor', 'packet-grid', 'data-plane']),
    )
    expect([...GLASS_ALLOWED_SURFACES]).toEqual(
      expect.arrayContaining(['header', 'command-bar', 'toast']),
    )
    const ds = read('src/styles/design-system.css')
    expect(ds).toMatch(/\.ds-data-surface[\s\S]*backdrop-filter:\s*none/)
    expect(ds).toMatch(/\.ds-glass-panel/)
    expect(ds).toMatch(/prefers-reduced-transparency/)
  })

  it('ships design-system module exports', () => {
    const index = read('src/design-system/index.ts')
    for (const name of [
      'Button',
      'IconButton',
      'SearchField',
      'SegmentedControl',
      'Tabs',
      'Badge',
      'Progress',
      'Tooltip',
      'DataSurface',
      'GlassPanel',
      'CommandBar',
      'WorkspaceChrome',
      'EmptyState',
      'ExportSummary',
      'AccessibleModal',
      'AccessibleDrawer',
      'StatusChip',
      'ProgressSplash',
      'StatusGlyph',
    ]) {
      expect(index).toContain(name)
    }
  })

  it('production rollup input excludes gallery.html', () => {
    const vite = read('vite.config.ts')
    expect(vite).toMatch(/main:\s*'index\.html'/)
    expect(vite).toMatch(/never shipped in dist/)
    expect(vite).not.toMatch(/gallery:\s*['"]gallery\.html['"]/)
  })
})
