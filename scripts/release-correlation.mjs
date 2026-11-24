#!/usr/bin/env node
/**
 * Correlation release orchestrator.
 * Re-runs max-size gate pieces + correlation checklist / UI / artifact.
 *
 * Usage: npm run release:correlation
 * Optional: CORRELATION_SKIP_BROWSER=1 to skip Playwright gates
 */
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function run(label, cmd, args, env = {}) {
  console.log(`\n▶ ${label}`)
  const result = spawnSync(cmd, args, {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, ...env },
  })
  if (result.status !== 0) {
    process.exit(result.status ?? 1)
  }
}

run('check:network', 'npm', ['run', 'check:network'])
run('check:audit', 'npm', ['run', 'check:audit'])
run('check:architecture', 'npm', ['run', 'check:architecture'])
run('lint', 'npm', ['run', 'lint'])
run('unit tests (includes correlation release checklist)', 'npm', ['test'])
run('build', 'npm', ['run', 'build'])
run('check:anonym-subpath', 'npm', ['run', 'check:anonym-subpath'])
run('check:dist-artifacts', 'npm', ['run', 'check:dist-artifacts'])
run('pcap:hardening', 'npm', ['run', 'pcap:hardening'])
run('bench:text-pipeline (Node)', 'npm', ['run', 'bench:text-pipeline'])
run('bench:pcap-capacity (Node)', 'npm', ['run', 'bench:pcap-capacity'])

if (process.env.CORRELATION_SKIP_BROWSER === '1' || process.env.MAX_SIZE_SKIP_BROWSER === '1') {
  console.log('\n(correlation browser gate skipped — CORRELATION_SKIP_BROWSER / MAX_SIZE_SKIP_BROWSER=1)')
} else {
  // RELEASE_BROWSER=chromium|firefox|webkit — default all projects (tri-browser).
  const browserProject = process.env.RELEASE_BROWSER?.trim()
  const projectArgs = browserProject ? ['--', `--project=${browserProject}`] : []
  const browserLabel = browserProject ?? 'tri-browser'
  console.log(`\n(browser project scope: ${browserLabel})`)
  run(`test:e2e (${browserLabel} product)`, 'npm', ['run', 'test:e2e', ...projectArgs])
  run(`test:a11y (${browserLabel} axe/keyboard)`, 'npm', ['run', 'test:a11y', ...projectArgs])
  run(`test:visual (${browserLabel} screenshots + hierarchy)`, 'npm', ['run', 'test:visual', ...projectArgs])
  run(`release:max-size:ui (${browserLabel} micro fixtures)`, 'npm', ['run', 'release:max-size:ui', ...projectArgs])
  run(`release:correlation:ui (${browserLabel})`, 'npm', ['run', 'release:correlation:ui', ...projectArgs])
}

run('release:pack-artifact', 'npm', ['run', 'release:pack-artifact'])

console.log('\nCorrelation release gate finished OK.')
