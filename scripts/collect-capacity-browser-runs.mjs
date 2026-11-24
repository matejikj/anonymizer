#!/usr/bin/env node
/**
 * Merge sanitized max-size Playwright row files into capacity-evidence.json browserRuns.
 * Never copies paths, canaries, or diagnostics blobs.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const resultsDir = path.join(root, 'tests/performance/results')
const evidencePath = path.join(resultsDir, 'capacity-evidence.json')

const SKIP = new Set(['max-size-baseline.json', 'max-size-ui-report.json'])

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

const evidence = readJson(evidencePath)
const existing = new Map(
  (evidence.browserRuns ?? []).map((r) => [`${r.scenario}::${r.browser}`, r]),
)

const osName = `${os.type()} ${os.release()}`
const nodeVersion = process.version

for (const name of fs.readdirSync(resultsDir)) {
  if (!name.startsWith('max-size-') || !name.endsWith('.json')) continue
  if (SKIP.has(name)) continue
  const row = readJson(path.join(resultsDir, name))
  if (!row.scenario || !row.browser || typeof row.wallMs !== 'number') continue
  if (row.fullGate !== true) continue
  const entry = {
    scenario: row.scenario,
    browser: row.browser,
    wallMs: Math.round(row.wallMs),
    ...(typeof row.exportMs === 'number' ? { exportMs: Math.round(row.exportMs) } : {}),
    os: osName,
  }
  existing.set(`${entry.scenario}::${entry.browser}`, entry)
}

evidence.browserRuns = [...existing.values()].sort((a, b) =>
  a.scenario.localeCompare(b.scenario) || a.browser.localeCompare(b.browser),
)
evidence.measuredAt = new Date().toISOString().slice(0, 10)
evidence.environment = {
  ...evidence.environment,
  nodeVersion,
  os: osName,
}

const baselineBench = path.join(resultsDir, 'baseline-bench.json')
if (fs.existsSync(baselineBench)) {
  const bench = readJson(baselineBench)
  evidence.nodeEngine = {
    ...evidence.nodeEngine,
    benchBaselineGeneratedAt: bench.generatedAt,
    benchBaselineMicroRows: (bench.rows ?? []).length,
  }
}

const scenarioAliases = {
  'pcap-100mib-classic-safe': 'pcap-100mib-classic-diagnostic',
}

function hasRun(scenario, browser) {
  const alt = scenarioAliases[scenario]
  const keys = [`${scenario}::${browser}`]
  if (alt) keys.push(`${alt}::${browser}`)
  return keys.some((k) => existing.has(k))
}

const blockers = []
for (const spec of evidence.browserBudgetBaseline?.scenariosCovered ?? []) {
  const brace = spec.indexOf('::{')
  const single = spec.lastIndexOf('::')
  if (brace !== -1) {
    const scenario = spec.slice(0, brace)
    const browsers = spec.slice(brace + 3, -1).split(',')
    for (const browser of browsers) {
      if (!hasRun(scenario, browser.trim())) {
        blockers.push({ scenario, browser: browser.trim(), status: 'not_measured' })
      }
    }
  } else if (single !== -1) {
    const scenario = spec.slice(0, single)
    const browser = spec.slice(single + 2)
    if (!hasRun(scenario, browser)) {
      blockers.push({ scenario, browser, status: 'not_measured' })
    }
  }
}
evidence.browserRunBlockers = blockers

fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`)
console.log(
  `capacity-evidence.json: ${evidence.browserRuns.length} browserRuns, ${blockers.length} blockers`,
)
