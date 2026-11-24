import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()
const srcDir = join(root, 'src')

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

/** Packet-grid internals allowed to keep raw btn classes (DESIGN_MOVES step 10). */
const ALLOWED_RAW_BTN = new Set([
  join(srcDir, 'pcap/ui/PcapPacketDetails.tsx'),
])

describe('DESIGN_MOVES step 10 — Button / CommandBar chrome migration', () => {
  it('clears raw btn btn-- from features/ and pcap chrome (except packet details)', () => {
    const offenders: string[] = []
    const roots = [join(srcDir, 'features'), join(srcDir, 'pcap/ui'), join(srcDir, 'components/ui')]
    for (const rootDir of roots) {
      for (const file of walkTs(rootDir)) {
        if (ALLOWED_RAW_BTN.has(file)) continue
        const text = readFileSync(file, 'utf8')
        if (/className=\{?["'`][^"'`]*\bbtn btn--/.test(text) || /className=["'][^"']*\bbtn btn--/.test(text)) {
          offenders.push(file.slice(srcDir.length + 1))
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('keeps priority chrome on design-system Button/IconButton', () => {
    const files = [
      'pcap/ui/PcapEmptyDropzone.tsx',
      'features/correlation-workspace/CorrelationOccurrenceNav.tsx',
      'components/ui/ThemeToggle.tsx',
      'features/mapping-bundle/MappingBundleActions.tsx',
      'features/resolve-only/ResolveOpenButton.tsx',
    ]
    for (const rel of files) {
      const text = readFileSync(join(srcDir, rel), 'utf8')
      expect(text, rel).toMatch(/from ['"].*design-system/)
      expect(text, rel).toMatch(/\b(Button|IconButton)\b/)
      expect(text, rel).not.toMatch(/className=["']btn btn--/)
    }
  })
})
