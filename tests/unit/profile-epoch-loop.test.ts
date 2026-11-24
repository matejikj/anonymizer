/**
 * Regression: refreshProfileList() must be a pure read. It used to bump the app store's
 * profileEpoch on every call, and TextProfileSelector re-invokes refreshProfileList() on every
 * profileEpoch change — together that formed a self-triggering infinite loop (continuous
 * IndexedDB reads + re-renders for as long as the tab stayed open, with heap climbing
 * unboundedly and never settling, discovered while re-verifying PCAP performance fixes against
 * a real 45MB capture left open in the browser).
 */
import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  bootstrapProfiles,
  refreshProfileList,
  resetProfileBootstrapForTests,
} from '../../src/features/profiles/profileController.ts'
import { closeRndLogAnonymizerDb, deleteRndLogAnonymizerDatabase } from '../../src/persistence/idb.ts'
import { useAppStore } from '../../src/app/store.ts'

describe('refreshProfileList does not self-trigger via profileEpoch', () => {
  beforeEach(async () => {
    await closeRndLogAnonymizerDb()
    await deleteRndLogAnonymizerDatabase()
    resetProfileBootstrapForTests()
    useAppStore.getState().resetSession()
  })

  it('does not bump profileEpoch on a plain read', async () => {
    await bootstrapProfiles()
    const before = useAppStore.getState().profileEpoch
    await refreshProfileList()
    expect(useAppStore.getState().profileEpoch).toBe(before)
  })

  it('repeated calls never advance profileEpoch (the actual infinite-loop trigger)', async () => {
    await bootstrapProfiles()
    const before = useAppStore.getState().profileEpoch
    for (let i = 0; i < 25; i++) {
      await refreshProfileList()
    }
    // If this ever bumps the epoch again, TextProfileSelector's `useEffect(..., [profileEpoch])`
    // would re-fire and call refreshProfileList() again — forever.
    expect(useAppStore.getState().profileEpoch).toBe(before)
  })
})
