/**
 * T46 — capacity evidence, release scripts, and no hardcoded /tmp probes.
 * Construction-time RELEASE_CHECKLIST.md / CI path under anonymizer/ were removed.
 */
import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const anonymizerRoot = join(fileURLToPath(new URL('../..', import.meta.url)))

describe('T46 release baseline artifacts', () => {
  it('does not ship obsolete release checklist markdown', () => {
    expect(existsSync(join(anonymizerRoot, 'docs/RELEASE_CHECKLIST.md'))).toBe(false)
    expect(existsSync(join(anonymizerRoot, 'docs/CAPACITY_EVIDENCE.md'))).toBe(false)
  })

  it('documents capacity evidence and tri-browser baseline budgets in JSON', () => {
    const evidence = JSON.parse(
      readFileSync(join(anonymizerRoot, 'tests/performance/results/capacity-evidence.json'), 'utf8'),
    ) as { version?: number; environment?: { browsers?: string[] }; browserBudgetBaseline?: { file?: string } }
    expect(evidence.version).toBe(1)
    expect(evidence.environment?.browsers).toEqual(['chromium', 'firefox', 'webkit'])
    const baseline = JSON.parse(
      readFileSync(join(anonymizerRoot, 'tests/performance/results/max-size-baseline.json'), 'utf8'),
    ) as { scenarios?: Record<string, unknown> }
    const keys = Object.keys(baseline.scenarios ?? {})
    expect(keys.some((k) => k.includes('::chromium'))).toBe(true)
    expect(keys.some((k) => k.includes('::firefox'))).toBe(true)
    expect(keys.some((k) => k.includes('::webkit'))).toBe(true)
    expect(keys.some((k) => k.startsWith('text-90mib-lf'))).toBe(true)
    expect(keys.some((k) => k.startsWith('pcap-100mib'))).toBe(true)
  })

  it('ships SBOM / release-manifest generators', () => {
    expect(existsSync(join(anonymizerRoot, 'scripts/generate-sbom.mjs'))).toBe(true)
    expect(existsSync(join(anonymizerRoot, 'scripts/generate-release-manifest.mjs'))).toBe(true)
  })

  it('does not keep hardcoded agent-scratch temp corpus paths in the suite', () => {
    const unitDir = join(anonymizerRoot, 'tests/unit')
    for (const name of readdirSync(unitDir)) {
      if (!name.endsWith('.test.ts') && !name.endsWith('.test.tsx')) continue
      const text = readFileSync(join(unitDir, name), 'utf8')
      // Concrete path literals only — comments saying "do not use …" are fine.
      expect(text, name).not.toMatch(/['"`]\/tmp\/claude-\d+/)
    }
  })

  it('marks recovery decrypt helpers as legacy plaintext aliases', () => {
    const src = readFileSync(
      join(anonymizerRoot, 'src/pcap/recovery/restore/dataFrameDecrypt.ts'),
      'utf8',
    )
    expect(src).toMatch(/readPlaintextDataFrameAt/)
    expect(src).toMatch(/createPlaintextFrameCache/)
    expect(src).toMatch(/Legacy name/)
    expect(src).toMatch(/Not cryptographic/)
  })
})
