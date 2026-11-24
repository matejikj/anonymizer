#!/usr/bin/env node
/**
 * Compare max-size browser perf reports against approved baseline.
 * Fails when total wall time regresses more than 25% without MAX_SIZE_BASELINE_ALLOW_REGRESSION=1.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const resultsDir = path.join(root, 'tests/performance/results')
const baselinePath = path.join(resultsDir, 'max-size-baseline.json')

const REGRESSION_RATIO = 1.25

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

if (!fs.existsSync(baselinePath)) {
  console.error(`Missing baseline: ${path.relative(root, baselinePath)}`)
  process.exit(1)
}

const baseline = readJson(baselinePath)
const reports = fs
  .readdirSync(resultsDir)
  .filter((f) => f.startsWith('max-size-') && f.endsWith('.json') && f !== 'max-size-baseline.json' && f !== 'max-size-ui-report.json')

if (reports.length === 0) {
  console.error('No max-size-*.json reports found — run release:max-size:ui first')
  process.exit(1)
}

const violations = []
const compared = []

for (const file of reports) {
  const row = readJson(path.join(resultsDir, file))
  const key = `${row.scenario}::${row.browser}`
  const base = baseline.scenarios?.[key]
  if (!base) {
    console.warn(`  (no baseline entry for ${key}, skipping)`)
    continue
  }
  const wallMs = row.wallMs ?? row.exportMs ?? 0
  const baseMs = base.wallMs ?? base.exportMs ?? 0
  if (baseMs <= 0) continue
  const ratio = wallMs / baseMs
  compared.push({ key, wallMs, baseMs, ratio })
  if (ratio > REGRESSION_RATIO && process.env.MAX_SIZE_BASELINE_ALLOW_REGRESSION !== '1') {
    violations.push(`${key}: ${wallMs}ms vs baseline ${baseMs}ms (${(ratio * 100).toFixed(0)}%)`)
  }
}

if (violations.length > 0) {
  console.error('Max-size baseline regression (>25%):\n')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

console.log(`check-max-size-baseline: OK (${compared.length} scenarios compared)`)
