import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import {
  createDefaultPcapProfile,
  createPresetProfile,
  profileToSanitizationPolicy,
  presetToSanitizationPolicy,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  BUILTIN_PCAP_PRESETS,
  DEFAULT_PCAP_PRESET,
  DEFAULT_PCAP_LEVEL,
  PCAP_ANONYMIZATION_LEVELS,
  getPresetDefinition,
  derivedPolicyView,
} from '../../../src/pcap/profile/presets'
import { cs } from '../../../src/i18n/cs'

const profilesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../profiles')
const srcDir = join(dirname(fileURLToPath(import.meta.url)), '../../../src')

describe('PCAP anonymization levels (step 2)', () => {
  it('exposes exactly two built-in levels', () => {
    expect(PCAP_ANONYMIZATION_LEVELS).toEqual(['diagnostic', 'high-privacy'])
    expect(BUILTIN_PCAP_PRESETS).toEqual(['diagnostic', 'high-privacy'])
    expect(DEFAULT_PCAP_LEVEL).toBe('diagnostic')
    expect(DEFAULT_PCAP_PRESET).toBe('diagnostic')
  })

  it('presetToSanitizationPolicy is the sole factory for immutable policies', () => {
    const expected = {
      diagnostic: DIAGNOSTIC_POLICY,
      'high-privacy': HIGH_PRIVACY_POLICY,
    }
    for (const level of PCAP_ANONYMIZATION_LEVELS) {
      const view = createPresetProfile(level)
      expect(profileToSanitizationPolicy(view)).toEqual(expected[level])
      expect(presetToSanitizationPolicy(level)).toEqual(expected[level])
    }
  })

  it('derived policy views are not editable profiles — ids follow pcap-{level}', () => {
    expect(derivedPolicyView('diagnostic').id).toBe('pcap-diagnostic')
    expect(derivedPolicyView('high-privacy').id).toBe('pcap-high-privacy')
  })

  it('uses diagnostic as documented default across factory and bundled text profile', () => {
    const profile = createDefaultPcapProfile().profile
    const bundled = JSON.parse(
      readFileSync(join(profilesDir, 'rnd-team-production.json'), 'utf8'),
    )
    const overview = readFileSync(
      join(profilesDir, '..', 'docs/PCAP_ANONYMIZATION_OVERVIEW.md'),
      'utf8',
    )
    const levelModule = readFileSync(join(srcDir, 'pcap/profile/pcapAnonymizationLevel.ts'), 'utf8')

    expect(profile.preset).toBe('diagnostic')
    expect(profile.name).toBe(getPresetDefinition('diagnostic').defaultName)
    expect(profile.name).toBe(cs.pcap.presets.diagnosticName)
    expect(bundled).not.toHaveProperty('pcapProfile')
    expect(JSON.stringify(bundled)).not.toMatch(/"pcapProfile"/)
    expect(overview).toMatch(/Diagnostické pro AI|diagnostic/)
    expect(levelModule).toContain('PcapAnonymizationLevel')
    expect(overview).not.toContain('PcapProfileEditor')
    expect(profile.protocols.dns).toBe(true)
    expect(cs.pcap.presets.diagnosticImpact).toMatch(/Zachová pakety, timing a protokolové chyby/)
    expect(profileToSanitizationPolicy(profile)).toEqual(DIAGNOSTIC_POLICY)
  })

  it('production UI uses top-bar select for level changes, no inline preset cards', () => {
    for (const rel of ['pcap/ui/PcapEmptyDropzone.tsx', 'pcap/ui/pcapSession.ts']) {
      const src = readFileSync(join(srcDir, rel), 'utf8')
      expect(src).not.toMatch(/metadataPolicy/)
      expect(src).not.toMatch(/unsupportedPolicy/)
      expect(src).not.toMatch(/payloadPolicy:\s*'truncate-unsupported'/)
    }
    const dropzone = readFileSync(join(srcDir, 'pcap/ui/PcapEmptyDropzone.tsx'), 'utf8')
    expect(dropzone).not.toMatch(/pcap-preset-card/)
    expect(dropzone).not.toMatch(/applyBuiltinPcapPreset/)
    expect(dropzone).not.toMatch(/['"]safe['"]/)
    expect(dropzone).not.toMatch(/addresses-only/)

    const levelSelect = readFileSync(join(srcDir, 'pcap/ui/PcapAnonymizationLevelSelect.tsx'), 'utf8')
    expect(levelSelect).toMatch(/setPcapAnonymizationLevel/)
    expect(levelSelect).toMatch(/aria-busy/)
    expect(levelSelect).toMatch(/aria-live/)

    const inspector = readFileSync(join(srcDir, 'pcap/ui/PcapInspector.tsx'), 'utf8')
    expect(inspector).not.toMatch(/applyBuiltinPcapPreset/)
    expect(inspector).not.toMatch(/['"]safe['"]/)
    expect(inspector).not.toMatch(/addresses-only/)

    const settings = readFileSync(join(srcDir, 'components/ui/DetectionSettingsPopover.tsx'), 'utf8')
    expect(settings).toMatch(/PcapAnonymizationLevelSelect/)
    expect(settings).toMatch(/TextProfileSelector/)
  })

  it('no CRUD PCAP profile UI remains in features/profiles', () => {
    for (const removed of [
      'PcapProfileSelector.tsx',
      'PcapProfileEditor.tsx',
      'ImportPcapProfileDialog.tsx',
      'PcapDirtySwitchDialog.tsx',
    ]) {
      expect(() => readFileSync(join(srcDir, 'features/profiles', removed), 'utf8')).toThrow()
    }
  })
})
