import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

describe('Max-size release gate wiring', () => {
  it('playwright.max-size-release.config exists with tri-browser projects', () => {
    const cfg = readFileSync(join(root, 'playwright.max-size-release.config.ts'), 'utf8')
    expect(cfg).toContain('Max-size release gate')
    expect(cfg).toContain('releaseBrowserProjects')
    expect(cfg).toContain('max-size-')
  })

  it('playwright.browserProjects defines chromium, firefox, webkit', () => {
    const src = readFileSync(join(root, 'playwright.browserProjects.ts'), 'utf8')
    expect(src).toContain("name: 'chromium'")
    expect(src).toContain("name: 'firefox'")
    expect(src).toContain("name: 'webkit'")
  })

  it('max-size baseline file is committed', () => {
    const baseline = join(root, 'tests/performance/results/max-size-baseline.json')
    expect(existsSync(baseline)).toBe(true)
    const json = JSON.parse(readFileSync(baseline, 'utf8'))
    expect(json.scenarios).toBeDefined()
    expect(Object.keys(json.scenarios).length).toBeGreaterThan(5)
  })

  it('check-max-size-baseline script validates regression ratio', () => {
    const script = readFileSync(join(root, 'scripts/check-max-size-baseline.mjs'), 'utf8')
    expect(script).toContain('REGRESSION_RATIO')
    expect(script).toContain('max-size-baseline.json')
  })

  it('release gate helpers define cancel and heap budgets', () => {
    const helpers = readFileSync(
      join(root, 'tests/performance/e2e/helpers/releaseGate.ts'),
      'utf8',
    )
    expect(helpers).toContain('CANCEL_VISUAL_MS = 250')
    expect(helpers).toContain('CANCEL_COMPLETE_MS = 1_000')
    expect(helpers).toContain('HEAP_BUDGET_TEXT = 3.5')
    expect(helpers).toContain('HEAP_BUDGET_PCAP_BLOB = 3.5')
  })

  it('max-size e2e specs cover text, pcap and a11y', () => {
    for (const file of [
      'tests/performance/e2e/max-size-text-release.spec.ts',
      'tests/performance/e2e/max-size-pcap-release.spec.ts',
      'tests/performance/e2e/max-size-a11y-release.spec.ts',
    ]) {
      expect(existsSync(join(root, file))).toBe(true)
    }
  })

  it('package.json exposes max-size release scripts', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
    expect(pkg.scripts['release:max-size']).toBeDefined()
    expect(pkg.scripts['release:max-size:ui']).toBeDefined()
    expect(pkg.scripts['fixtures:max-size']).toBeDefined()
    expect(pkg.scripts['release:max-size:baseline']).toBeDefined()
  })
})
