/**
 * CF-07 — release-gate inventory: every CF-01…CF-15 regression must stay mandatory.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..')
const unitDir = join(root, 'tests/pcap/unit')
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>
}

/** Finding ID → regression file(s) that must remain in `pcap:voip-gate`. */
export const CF_RELEASE_GATE_REGRESSIONS: Readonly<Record<string, readonly string[]>> = {
  'CF-01': ['cf01SipSdpLeaks.test.ts'],
  'CF-02': ['cf02MappingContract.test.ts'],
  'CF-03': ['cf03MediaClassification.test.ts'],
  'CF-04': ['cf04Cf05Reassembly.test.ts'],
  'CF-05': ['cf04Cf05Reassembly.test.ts'],
  'CF-06': ['cf08BodyCf06Ipv6.test.ts'],
  'CF-07': ['cf07ReleaseGateInventory.test.ts', 'voipReleaseGate.test.ts'],
  // CF-08 body fail-closed + T02 discovery↔plan parity for multipart/SIPREC bodies.
  'CF-08': ['cf08BodyCf06Ipv6.test.ts', 'sipBodyDiscoveryPlanParity.test.ts', 'sipBodyRevisedCorpus.test.ts'],
  'CF-09': ['cf09ExportBoundary.test.ts'],
  'CF-10': ['cf10TlsPath.test.ts', 't47TlsServerHelloPrivacy.test.ts', 'privacyGateParserIndependent.test.ts'],
  'CF-11': ['cf11Cf12Cf14FingerprintTimingPorts.test.ts'],
  'CF-12': ['cf11Cf12Cf14FingerprintTimingPorts.test.ts'],
  'CF-13': ['cf13TunnelsIcmpNdp.test.ts'],
  'CF-14': [
    'cf11Cf12Cf14FingerprintTimingPorts.test.ts',
    'portCatalogAndRtpRtcpPairing.test.ts',
  ],
  'CF-15': ['cf15PrivacyThreatModel.test.ts'],
}

describe('CF-07 release gate inventory', () => {
  it('lists every CF-01…CF-15 regression file on disk', () => {
    for (const [cf, files] of Object.entries(CF_RELEASE_GATE_REGRESSIONS)) {
      for (const file of files) {
        expect(existsSync(join(unitDir, file)), `${cf} missing ${file}`).toBe(true)
      }
    }
  })

  it('includes every CF regression in npm run pcap:voip-gate', () => {
    const gate = packageJson.scripts['pcap:voip-gate'] ?? ''
    expect(gate.length).toBeGreaterThan(0)
    const required = new Set<string>()
    for (const files of Object.values(CF_RELEASE_GATE_REGRESSIONS)) {
      for (const file of files) required.add(file)
    }
    for (const file of required) {
      expect(gate, `pcap:voip-gate must include ${file}`).toContain(file)
    }
  })

  it('wires pcap:voip-gate into npm run verify (no false-green release)', () => {
    const verify = packageJson.scripts.verify ?? ''
    expect(verify).toMatch(/pcap:voip-gate/)
  })

  it('wires pcap:diagnostic-gate into npm run verify', () => {
    const verify = packageJson.scripts.verify ?? ''
    expect(verify).toMatch(/pcap:diagnostic-gate/)
    expect(packageJson.scripts['pcap:diagnostic-gate'] ?? '').toContain('diagnosticEquivalenceGate')
  })
})
