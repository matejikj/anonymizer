/**
 * PCAP anonymization level runtime — session-scoped, not persisted.
 * Two built-in levels only; no CRUD, import, export, or IndexedDB profile store.
 */

import type { PcapAnonymizationLevel } from './pcapAnonymizationLevel'
import {
  DEFAULT_PCAP_LEVEL,
  levelDisplayName,
} from './pcapAnonymizationLevel'
import {
  getActivePcapLevel,
  setActivePcapLevel,
  resetActivePcapLevel,
  getActivePcapProfile,
} from './activePcapProfile'
import { getPcapPlanRebuildPort } from './workerPcapPlanRebuildPort.ts'
import { usePcapStore } from '../ui/pcapStore.ts'

let bootstrapped = false

function syncStoreFromLevel(level: PcapAnonymizationLevel): void {
  usePcapStore.getState().setActivePcapLevel(level)
  usePcapStore.getState().bumpProfileEpoch()
}

export function pcapLevelLabel(level: PcapAnonymizationLevel): string {
  return levelDisplayName(level)
}

/**
 * Sync store with the in-memory session level.
 * Does not reset an already chosen level — the top-bar select may run before PCAP mode mounts.
 */
export async function bootstrapPcapLevel(): Promise<void> {
  if (bootstrapped) return
  bootstrapped = true
  syncStoreFromLevel(getActivePcapLevel())
}

/** @deprecated Use bootstrapPcapLevel. */
export const bootstrapPcapProfiles = bootstrapPcapLevel

export async function setPcapAnonymizationLevel(
  level: PcapAnonymizationLevel,
  options: { rebuild?: boolean } = {},
): Promise<void> {
  const rebuild = options.rebuild !== false
  setActivePcapLevel(level)
  syncStoreFromLevel(level)
  if (rebuild) {
    usePcapStore.getState().setRequestedPcapLevel(level)
    try {
      await getPcapPlanRebuildPort().rebuildPlan(level)
    } finally {
      usePcapStore.getState().setRequestedPcapLevel(null)
    }
  }
}

/** @deprecated Use setPcapAnonymizationLevel. */
export async function applyBuiltinPcapPreset(level: PcapAnonymizationLevel): Promise<void> {
  await setPcapAnonymizationLevel(level)
}

export function resetPcapLevelControllerState(): void {
  resetActivePcapLevel()
  syncStoreFromLevel(DEFAULT_PCAP_LEVEL)
}

/** @deprecated Use resetPcapLevelControllerState. */
export const resetPcapControllerState = resetPcapLevelControllerState

export async function wipePcapLevelAndResync(): Promise<void> {
  bootstrapped = false
  resetPcapLevelControllerState()
  await bootstrapPcapLevel()
}

/** @deprecated Use wipePcapLevelAndResync. */
export const wipePcapProfilesAndResync = wipePcapLevelAndResync

/** Test-only: allow re-running bootstrap. */
export function resetPcapLevelBootstrapForTests(): void {
  bootstrapped = false
}

/** @deprecated Use resetPcapLevelBootstrapForTests. */
export const resetPcapProfileBootstrapForTests = resetPcapLevelBootstrapForTests

export { getActivePcapLevel, getActivePcapProfile, setActivePcapLevel }
