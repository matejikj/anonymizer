/**
 * Step 1 acceptance: text ruleset is independent of PCAP runtime policy.
 */
import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import {
  parseRulesetConfig,
  serializeRulesetConfig,
} from '../../src/domain/rulesetValidate.ts'
import {
  activateProfile,
  bootstrapProfiles,
  prepareExport,
  resetProfileBootstrapForTests,
} from '../../src/features/profiles/profileController.ts'
import { putStoredProfile } from '../../src/persistence/profileRepository.ts'
import { closeRndLogAnonymizerDb, deleteRndLogAnonymizerDatabase } from '../../src/persistence/idb.ts'
import {
  bootstrapPcapLevel,
  resetPcapLevelBootstrapForTests,
  resetPcapLevelControllerState,
} from '../../src/pcap/profile/pcapLevelController.ts'
import {
  getActivePcapLevel,
  setActivePcapLevel,
} from '../../src/pcap/profile/activePcapProfile.ts'
import {
  resetPcapPlanRebuildPort,
  setPcapPlanRebuildPort,
} from '../../src/pcap/profile/workerPcapPlanRebuildPort.ts'
import type { PcapPlanRebuildPort } from '../../src/pcap/profile/PcapPlanRebuildPort.ts'
import { useAppStore } from '../../src/app/store.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'

describe('text config separated from PCAP (step 1)', () => {
  beforeEach(async () => {
    await closeRndLogAnonymizerDb()
    await deleteRndLogAnonymizerDatabase()
    resetProfileBootstrapForTests()
    resetPcapLevelBootstrapForTests()
    resetPcapLevelControllerState()
    resetPcapPlanRebuildPort()
    useAppStore.getState().resetSession()
    usePcapStore.getState().resetToEmpty()
  })

  it('prepareExport omits all PCAP fields', async () => {
    await bootstrapProfiles()
    const { json } = prepareExport()
    expect(json).not.toMatch(/pcapProfile|mediaPolicy|preservePacketLengths|protocols/)
    expect(JSON.parse(json)).not.toHaveProperty('pcapProfile')
  })

  it('import with pcapProfile is rejected', () => {
    const raw = {
      ...createDefaultRulesetConfig(),
      pcapProfile: { id: 'x', preset: 'diagnostic' },
    }
    const result = parseRulesetConfig(raw)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.issues[0]?.code).toBe('pcap-config-not-allowed')
    }
  })

  it('switching text profile does not rebuild PCAP plan or change active PCAP level', async () => {
    const rebuildPlan = vi.fn(async () => ({ generation: 1, applied: true }))
    setPcapPlanRebuildPort({ rebuildPlan } as unknown as PcapPlanRebuildPort)

    setActivePcapLevel('high-privacy')
    usePcapStore.getState().setActivePcapLevel('high-privacy')
    rebuildPlan.mockClear()

    const textA = createDefaultRulesetConfig()
    textA.profile.id = 'text-a'
    textA.profile.name = 'Text A'
    const textB = createDefaultRulesetConfig()
    textB.profile.id = 'text-b'
    textB.profile.name = 'Text B'
    await putStoredProfile(textA)
    await putStoredProfile(textB)
    await bootstrapProfiles()
    await activateProfile('text-a', { force: true })
    await activateProfile('text-b', { force: true })

    expect(rebuildPlan).not.toHaveBeenCalled()
    expect(getActivePcapLevel()).toBe('high-privacy')
    expect(serializeRulesetConfig(textB)).not.toMatch(/pcapProfile/)
  })
})
