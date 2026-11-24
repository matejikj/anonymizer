#!/usr/bin/env node
/**
 * Enterprise step 14 — generate CycloneDX SBOM from package-lock (offline-capable).
 * Output: release/sbom.cdx.json
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const outDir = path.join(root, 'release')
const outFile = path.join(outDir, 'sbom.cdx.json')
const lock = path.join(root, 'package-lock.json')

function die(msg) {
  console.error(`generate-sbom: ${msg}`)
  process.exit(1)
}

if (!existsSync(lock)) {
  die('package-lock.json missing — commit the lockfile for reproducible installs')
}

mkdirSync(outDir, { recursive: true })

let json
try {
  json = execFileSync(
    'npm',
    ['sbom', '--sbom-format', 'cyclonedx', '--package-lock-only', '--sbom-type', 'application'],
    { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  )
} catch (err) {
  die(`npm sbom failed: ${err instanceof Error ? err.message : String(err)}`)
}

const trimmed = json.trim()
if (!trimmed.startsWith('{')) {
  die('npm sbom did not return JSON')
}

let parsed
try {
  parsed = JSON.parse(trimmed)
} catch {
  die('npm sbom returned invalid JSON')
}

if (!parsed.bomFormat && !parsed.$schema && !parsed.components) {
  die('SBOM missing CycloneDX markers (bomFormat / components)')
}

writeFileSync(outFile, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8')
console.log(`generate-sbom: OK → ${path.relative(root, outFile)}`)
console.log(`  components: ${Array.isArray(parsed.components) ? parsed.components.length : '?'}`)
