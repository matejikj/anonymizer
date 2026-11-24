/**
 * Step 5 acceptance — cleanup UI/i18n/docs; no editable PCAP profiles remain.
 */

import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { cs } from '../../src/i18n/cs'
import { compileAndEvaluateSessionPolicy } from '../../src/correlation/profileCompatibility/sessionPolicy'
import { getActiveProfile } from '../../src/features/rules/activeProfile'
import { getActivePcapProfile } from '../../src/pcap/profile/activePcapProfile'
import { SourceKind } from '../../src/domain/sourceArtifact'
import { presetToSanitizationPolicy } from '../../src/pcap/profile/presets'

const root = join(dirname(fileURLToPath(import.meta.url)), '../..')
const srcDir = join(root, 'src')
const profilesDir = join(root, 'profiles')

function readSrc(rel: string): string {
  return readFileSync(join(srcDir, rel), 'utf8')
}

describe('Step 5 — cleanup and definition of done', () => {
  it('i18n has no PCAP profile CRUD or removed preset labels', () => {
    const raw = readFileSync(join(srcDir, 'i18n/cs.ts'), 'utf8')
    expect(raw).not.toMatch(/pcapProfiles:\s*\{/)
    expect(raw).not.toMatch(/addressesName|addressesImpact|addressesWarn|safeName|safeImpact|customPreset/)
    expect(cs.pcap.presets.diagnosticName).toBeTruthy()
    expect(cs.pcap.presets.highPrivacyName).toBeTruthy()
    expect(cs.correlationExport.exposedPcap).toBeTruthy()
    expect('exposedAddressesOnly' in cs.correlationExport).toBe(false)
  })

  it('no sample PCAP ruleset fixtures remain in profiles/', () => {
    const jsonFiles = readdirSync(profilesDir).filter((f) => f.endsWith('.json'))
    for (const file of jsonFiles) {
      expect(file).not.toMatch(/pcap-.*-example/)
      const content = readFileSync(join(profilesDir, file), 'utf8')
      expect(content).not.toMatch(/"pcapProfile"/)
      expect(content).not.toMatch(/addresses-only|"safe"/)
    }
  })

  it('pcapAnonymizationLevel and README document two runtime levels, not editable PCAP profiles', () => {
    const level = readSrc('pcap/profile/pcapAnonymizationLevel.ts')
    const readme = readFileSync(join(root, 'README.md'), 'utf8')
    expect(level).toMatch(/PcapAnonymizationLevel/)
    expect(level).toMatch(/diagnostic.*high-privacy|high-privacy.*diagnostic/)
    expect(readme).toMatch(/diagnostic.*high-privacy|high-privacy.*diagnostic/i)
    expect(readme).not.toMatch(/PcapProfileEditor/)
    expect(readme).not.toMatch(/pcapProfiles store/)
    expect(readme).not.toMatch(/addresses-only preset/)
    expect(readme).not.toMatch(/pcap-safe-example/)
  })

  it('README describes text profile and PCAP level separately', () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8')
    expect(readme).toMatch(/text profile|text rules/i)
    expect(readme).not.toMatch(/embedded PCAP/)
    expect(readme).not.toMatch(/pcap-\*-example/)
  })

  it('removed PCAP profile UI components do not exist', () => {
    for (const removed of [
      'features/profiles/PcapProfileSelector.tsx',
      'features/profiles/PcapProfileEditor.tsx',
      'features/profiles/ImportPcapProfileDialog.tsx',
      'features/profiles/PcapDirtySwitchDialog.tsx',
      'persistence/pcapProfileRepository.ts',
      'pcap/profile/migration.ts',
      'pcap/profile/pcapProfileController.ts',
    ]) {
      expect(() => readFileSync(join(srcDir, removed), 'utf8')).toThrow()
    }
  })

  it('correlation uses independent text profile and PCAP runtime level', () => {
    const report = compileAndEvaluateSessionPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: getActiveProfile(),
      pcapProfile: getActivePcapProfile(),
    })
    expect(report.policy.text).toBeDefined()
    expect(report.policy.pcap).toBeDefined()
    expect(getActivePcapProfile().preset).toMatch(/diagnostic|high-privacy/)
  })

  it('worker rebuild port documents generation guard for race safety', () => {
    const src = readSrc('pcap/profile/workerPcapPlanRebuildPort.ts')
    expect(src).toMatch(/shouldApply/)
    expect(src).toMatch(/latestGeneration/)
    expect(src).toMatch(/applied: false/)
  })

  it('production sanitize barrel has no SAFE_POLICY or ADDRESSES_ONLY_POLICY aliases', () => {
    const src = readSrc('pcap/sanitize/index.ts')
    expect(src).not.toMatch(/SAFE_POLICY/)
    expect(src).not.toMatch(/ADDRESSES_ONLY_POLICY/)
  })

  it('both PCAP levels expose immutable sanitization policies', () => {
    expect(presetToSanitizationPolicy('diagnostic').preset).toBe('diagnostic')
    expect(presetToSanitizationPolicy('high-privacy').preset).toBe('high-privacy')
    expect(presetToSanitizationPolicy('diagnostic').unsupportedPayloadPolicy).toBe('mask-in-place')
    expect(presetToSanitizationPolicy('high-privacy').unsupportedPayloadPolicy).toBe('truncate')
  })
})
