import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  bootstrapPcapLevel,
  resetPcapLevelBootstrapForTests,
  resetPcapLevelControllerState,
  setPcapAnonymizationLevel,
} from '../../src/pcap/profile/pcapLevelController.ts'
import {
  DEFAULT_PCAP_LEVEL,
  presetToSanitizationPolicy,
} from '../../src/pcap/profile/presets.ts'
import {
  getActivePcapLevel,
  resetActivePcapLevel,
} from '../../src/pcap/profile/activePcapProfile.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'
import {
  resetPcapPlanRebuildPort,
  setPcapPlanRebuildPort,
} from '../../src/pcap/profile/workerPcapPlanRebuildPort.ts'
import type { PcapPlanRebuildPort } from '../../src/pcap/profile/PcapPlanRebuildPort.ts'
import {
  clearPcapSession,
  createMinimalPcapSession,
} from '../../src/pcap/ui/pcapSession.ts'
import { CaptureFormat } from '../../src/pcap/domain/types'
import { derivedPolicyView } from '../../src/pcap/profile/presets.ts'

describe('pcapLevelController (step 2)', () => {
  beforeEach(() => {
    resetPcapLevelBootstrapForTests()
    resetActivePcapLevel()
    resetPcapLevelControllerState()
    resetPcapPlanRebuildPort()
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
  })

  it('bootstraps to diagnostic every session', async () => {
    await bootstrapPcapLevel()
    expect(getActivePcapLevel()).toBe(DEFAULT_PCAP_LEVEL)
    expect(usePcapStore.getState().activePcapLevel).toBe('diagnostic')
    expect(usePcapStore.getState().activePolicy).toEqual(presetToSanitizationPolicy('diagnostic'))
  })

  it('bootstrap does not wipe a level already chosen in this session', async () => {
    await setPcapAnonymizationLevel('high-privacy', { rebuild: false })
    resetPcapLevelBootstrapForTests()
    await bootstrapPcapLevel()
    expect(getActivePcapLevel()).toBe('high-privacy')
    expect(usePcapStore.getState().activePcapLevel).toBe('high-privacy')
  })

  it('setPcapAnonymizationLevel switches level and triggers rebuild when session open', async () => {
    const rebuildPlan = vi.fn(async () => ({ generation: 1, applied: true }))
    setPcapPlanRebuildPort({ rebuildPlan } as unknown as PcapPlanRebuildPort)

    createMinimalPcapSession({
      fileName: 't.pcap',
      fileSize: 60,
      format: CaptureFormat.ClassicPcap,
      profile: derivedPolicyView('diagnostic'),
    })

    await bootstrapPcapLevel()
    await setPcapAnonymizationLevel('high-privacy')

    expect(getActivePcapLevel()).toBe('high-privacy')
    expect(usePcapStore.getState().activePcapLevel).toBe('high-privacy')
    expect(rebuildPlan).toHaveBeenCalledWith('high-privacy')
    expect(usePcapStore.getState().requestedPcapLevel).toBeNull()
  })

  it('only two levels are valid runtime policies', () => {
    expect(presetToSanitizationPolicy('diagnostic').preset).toBe('diagnostic')
    expect(presetToSanitizationPolicy('high-privacy').preset).toBe('high-privacy')
  })
})
