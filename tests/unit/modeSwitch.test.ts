import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it } from 'vitest'
import { useAppStore } from '../../src/app/store.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'
import { isCurrentModeProfileDirty, requestModeSwitch } from '../../src/app/modeSwitch.ts'
import { bootstrapProfiles } from '../../src/features/profiles/profileController.ts'
import { bootstrapPcapLevel } from '../../src/pcap/profile/pcapLevelController.ts'
import { closeRndLogAnonymizerDb, deleteRndLogAnonymizerDatabase } from '../../src/persistence/idb.ts'

describe('modeSwitch', () => {
  beforeEach(async () => {
    await deleteRndLogAnonymizerDatabase()
    await closeRndLogAnonymizerDb()
    useAppStore.setState({
      activeMode: 'text',
      profileDirty: false,
      profileDialog: 'none',
      pendingSwitchMode: null,
      pendingSwitchProfileId: null,
    })
    usePcapStore.getState().resetToEmpty()
    await bootstrapProfiles()
    await bootstrapPcapLevel()
  })

  it('switches mode immediately when text profile is clean', () => {
    requestModeSwitch('pcap')
    expect(useAppStore.getState().activeMode).toBe('pcap')
    expect(useAppStore.getState().profileDialog).toBe('none')
  })

  it('blocks mode switch when text profile is dirty', () => {
    useAppStore.getState().setProfileDirty(true)
    requestModeSwitch('pcap')
    expect(useAppStore.getState().activeMode).toBe('text')
    expect(useAppStore.getState().profileDialog).toBe('mode-switch-dirty')
    expect(useAppStore.getState().pendingSwitchMode).toBe('pcap')
  })

  it('does not treat PCAP level as a dirty editable profile', () => {
    useAppStore.getState().setActiveMode('pcap')
    expect(isCurrentModeProfileDirty()).toBe(false)
    requestModeSwitch('text')
    expect(useAppStore.getState().activeMode).toBe('text')
  })

  it('does not change PCAP level when switching text profile context', async () => {
    const pcapBefore = usePcapStore.getState().activePcapLevel
    requestModeSwitch('pcap')
    requestModeSwitch('text')
    expect(usePcapStore.getState().activePcapLevel).toBe(pcapBefore)
  })
})
