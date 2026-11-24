/**
 * T46 — release checklist, CI workflow, capacity evidence, and no hardcoded /tmp probes.
 */
import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const anonymizerRoot = join(fileURLToPath(new URL('../..', import.meta.url)))
const repoRoot = join(anonymizerRoot, '..')

describe('T46 release baseline artifacts', () => {
  it('ships RELEASE_CHECKLIST with plaintext product gates', () => {
    const text = readFileSync(join(anonymizerRoot, 'docs/RELEASE_CHECKLIST.md'), 'utf8')
    expect(text).toMatch(/GPG_SIGN_RELEASE/)
    expect(text).toMatch(/sbom/i)
    expect(text).toMatch(/connect-src 'none'/)
    expect(text).toMatch(/pcap:diagnostic-gate|pcap:voip-gate/)
    expect(text).toMatch(/plaintext|nešifrovan/i)
    expect(text).toMatch(/T47/)
  })

  it('documents capacity evidence and tri-browser baseline budgets', () => {
    expect(existsSync(join(anonymizerRoot, 'docs/CAPACITY_EVIDENCE.md'))).toBe(true)
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

  // No CI stage yet for this package; the release gate is local:
  // `npm run verify` + the browser gates listed in RELEASE_CHECKLIST.md.
  it('defines the local release gate (verify script + checklist browser gates)', () => {
    const pkg = JSON.parse(readFileSync(join(anonymizerRoot, 'package.json'), 'utf8')) as {
      scripts?: Record<string, string>
    }
    const verify = pkg.scripts?.verify ?? ''
    expect(verify).toMatch(/check:architecture/)
    expect(verify).toMatch(/pcap:diagnostic-gate/)
    expect(verify).toMatch(/pcap:recovery-gate/)
    const checklist = readFileSync(join(anonymizerRoot, 'docs/RELEASE_CHECKLIST.md'), 'utf8')
    expect(checklist).toMatch(/npm run verify/)
    expect(checklist).toMatch(/test:e2e/)
    expect(checklist).toMatch(/test:a11y/)
    expect(checklist).toMatch(/release:max-size:ui/)
  })

  it('does not ship a GitHub Actions workflow for this package', () => {
    expect(existsSync(join(repoRoot, '.github/workflows/anonymizer.yml'))).toBe(false)
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
