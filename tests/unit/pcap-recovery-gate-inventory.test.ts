/**
 * Step 10 — recovery release-gate inventory: no skips, wired into verify.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(dirname(fileURLToPath(import.meta.url)), '../..')
const unitDir = join(root, 'tests/unit')
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>
}

export const RECOVERY_GATE_FILES = [
  'pcap-recovery-gate-inventory.test.ts',
  'pcap-recovery-contract.test.ts',
  'pcap-recovery-codec.test.ts',
  'pcap-recovery-literal-export.test.ts',
  'pcap-recovery-compact-index.test.ts',
  'pcap-recovery-dual-export.test.ts',
  'pcap-recovery-unlock.test.ts',
  'pcap-recovery-search.test.ts',
  'pcap-recovery-packet-restore.test.ts',
  'pcap-recovery-copy-anon.test.ts',
  'pcap-recovery-golden.test.ts',
  'pcap-recovery-tamper-fuzz.test.ts',
  'pcap-recovery-lifecycle.test.ts',
  'pcap-recovery-bench.test.ts',
] as const

describe('Step 10 — pcap:recovery-gate inventory', () => {
  it('lists every recovery gate file on disk', () => {
    for (const file of RECOVERY_GATE_FILES) {
      expect(existsSync(join(unitDir, file)), `missing ${file}`).toBe(true)
    }
  })

  it('includes every recovery file in npm run pcap:recovery-gate', () => {
    const gate = packageJson.scripts['pcap:recovery-gate'] ?? ''
    expect(gate.length).toBeGreaterThan(0)
    expect(gate).not.toMatch(/\b--bail\b/)
    for (const file of RECOVERY_GATE_FILES) {
      expect(gate, `pcap:recovery-gate must include ${file}`).toContain(file)
    }
  })

  it('wires pcap:recovery-gate into npm run verify without skip flags', () => {
    const verify = packageJson.scripts.verify ?? ''
    expect(verify).toMatch(/pcap:recovery-gate/)
    expect(verify).toMatch(/pcap:wireshark-gate/)
    expect(verify).not.toMatch(/pcap:recovery-gate[^\n]*--skip/)
    expect(packageJson.scripts['pcap:recovery-gate'] ?? '').not.toMatch(/\bskip\b/i)
  })

  it('keeps existing PCAP gates declared', () => {
    expect(packageJson.scripts['pcap:voip-gate'] ?? '').toContain('voipReleaseGate')
    expect(packageJson.scripts['pcap:diagnostic-gate'] ?? '').toContain('diagnosticEquivalenceGate')
    expect(packageJson.scripts['pcap:wireshark-gate'] ?? '').toContain('pcapWiresharkLayout')
  })
})
