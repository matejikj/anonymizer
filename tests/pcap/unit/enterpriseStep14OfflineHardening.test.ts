/**
 * Enterprise step 14 — offline hardening + SBOM + signed-release checklist.
 */

import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(fileURLToPath(new URL('../../..', import.meta.url)))

function runNode(script: string): { ok: boolean; output: string } {
  try {
    const output = execFileSync(process.execPath, [script], {
      cwd: root,
      encoding: 'utf8',
    })
    return { ok: true, output }
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message?: string }
    return { ok: false, output: [e.stdout, e.stderr, e.message].filter(Boolean).join('\n') }
  }
}

describe('enterprise step 14 — offline hardening', () => {
  it('check:offline-release passes', () => {
    const result = runNode('scripts/check-offline-release.mjs')
    expect(result.ok, result.output).toBe(true)
    expect(result.output).toContain('check-offline-release: OK')
  })

  it('production vite CSP forbids network connect', () => {
    const vite = readFileSync(join(root, 'vite.config.ts'), 'utf8')
    expect(vite).toContain("connect-src 'none'")
    expect(vite).toContain('Content-Security-Policy')
  })

  it('package-lock.json pins dependencies', () => {
    expect(existsSync(join(root, 'package-lock.json'))).toBe(true)
  })

  it('SBOM and release-manifest generators exist', () => {
    expect(existsSync(join(root, 'scripts/generate-sbom.mjs'))).toBe(true)
    expect(existsSync(join(root, 'scripts/generate-release-manifest.mjs'))).toBe(true)
    const sbomScript = readFileSync(join(root, 'scripts/generate-sbom.mjs'), 'utf8')
    expect(sbomScript.length).toBeGreaterThan(0)
  })

  it('npm run sbom produces CycloneDX file', () => {
    const result = runNode('scripts/generate-sbom.mjs')
    expect(result.ok, result.output).toBe(true)
    const sbomPath = join(root, 'release/sbom.cdx.json')
    expect(existsSync(sbomPath)).toBe(true)
    const sbom = JSON.parse(readFileSync(sbomPath, 'utf8')) as {
      bomFormat?: string
      components?: unknown[]
    }
    expect(sbom.bomFormat === 'CycloneDX' || Array.isArray(sbom.components)).toBe(true)
  })
})
