#!/usr/bin/env node
/**
 * Max-size release orchestrator — Node benches + optional browser gate.
 * Usage: npm run release:max-size
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
run('unit tests', 'npm', ['test'])
run('build', 'npm', ['run', 'build'])
run('check:anonym-subpath', 'npm', ['run', 'check:anonym-subpath'])
run('pcap:hardening', 'npm', ['run', 'pcap:hardening'])
run('bench:text-pipeline (Node)', 'npm', ['run', 'bench:text-pipeline'])
run('bench:pcap-capacity (Node)', 'npm', ['run', 'bench:pcap-capacity'])

if (process.env.MAX_SIZE_SKIP_BROWSER === '1') {
  console.log('\n(max-size browser gate skipped — MAX_SIZE_SKIP_BROWSER=1)')
} else {
  run('test:e2e', 'npm', ['run', 'test:e2e'])
  run('release:max-size:ui (micro fixtures)', 'npm', ['run', 'release:max-size:ui'])
}

console.log('\nMax-size release orchestrator finished OK.')
