/**
 * Correlation release gate wiring (scripts, playwright, artifact packer).
 */
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

describe('Correlation release gate wiring', () => {
  it('playwright.correlation-release.config exists with tri-browser projects', () => {
    const cfg = readFileSync(join(root, 'playwright.correlation-release.config.ts'), 'utf8')
    expect(cfg).toContain('Correlation release gate')
    expect(cfg).toContain('releaseBrowserProjects')
    expect(cfg).toContain('correlation-')
  })

  it('correlation e2e spec exists', () => {
    expect(existsSync(join(root, 'tests/performance/e2e/correlation-release.spec.ts'))).toBe(
      true,
    )
  })

  it('correlation release + artifact scripts exist', () => {
    expect(existsSync(join(root, 'scripts/release-correlation.mjs'))).toBe(true)
    expect(existsSync(join(root, 'scripts/release-pack-artifact.mjs'))).toBe(true)
  })

  it('package.json exposes correlation release scripts', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
    expect(pkg.scripts['release:correlation']).toBeDefined()
    expect(pkg.scripts['release:correlation:ui']).toBeDefined()
    expect(pkg.scripts['release:pack-artifact']).toBeDefined()
    expect(pkg.scripts['test:a11y']).toBeDefined()
    expect(pkg.scripts['test:visual']).toBeDefined()
  })

  it('release:correlation runs a11y and visual gates', () => {
    const script = readFileSync(join(root, 'scripts/release-correlation.mjs'), 'utf8')
    expect(script).toContain('test:a11y')
    expect(script).toContain('test:visual')
  })

  it('artifact packer forbids secrets and large fixtures', () => {
    const script = readFileSync(join(root, 'scripts/release-pack-artifact.mjs'), 'utf8')
    expect(script).toContain('rnd-mapping-bundle')
    expect(script).toContain('passphrase')
    expect(script).toContain('maximum-90mib')
    expect(script).toContain('FORBIDDEN')
  })
})
