#!/usr/bin/env node
/**
 * F1 — zero-review gate (T62–T74 invariants).
 * Runs focused vitest suites; exit non-zero on failure.
 */

import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const suites = [
  'tests/unit/zeroReviewInvariants.test.ts',
  'tests/unit/t72T73ImportSplit.test.ts',
  'tests/pcap/unit/t74ProprietaryLight.test.ts',
  'tests/pcap/unit/canaryConformance.test.ts',
  'tests/pcap/unit/anonymizationOutcome.test.ts',
  'tests/pcap/unit/t08ThreeStateExportGate.test.ts',
  'tests/pcap/unit/pcapProfile.test.ts',
  'tests/unit/textAnonymizationOutcome.test.ts',
  'tests/unit/entityState.test.ts',
]

const result = spawnSync(
  'npx',
  ['vitest', 'run', ...suites],
  { cwd: root, stdio: 'inherit', env: process.env },
)

if (result.status !== 0) {
  console.error('zero-review-gate: FAILED')
  process.exit(result.status ?? 1)
}

console.log('zero-review-gate: OK')
