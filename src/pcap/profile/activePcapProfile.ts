/**
 * In-memory active PCAP anonymization level for the browser session.
 * Not persisted — each app session starts at DEFAULT_PCAP_LEVEL.
 */

import {
  DEFAULT_PCAP_LEVEL,
  type PcapAnonymizationLevel,
  presetToSanitizationPolicy,
  levelToMapping,
  derivedPolicyView,
  type DerivedPcapPolicyView,
} from './presets'
import type { SanitizationPolicy } from '../sanitize/types'
import type { PcapMapping } from './pcapAnonymizationLevel'

let activeLevel: PcapAnonymizationLevel = DEFAULT_PCAP_LEVEL
let revision = 0

export function getActivePcapLevel(): PcapAnonymizationLevel {
  return activeLevel
}

export function getActivePcapLevelRevision(): number {
  return revision
}

export function setActivePcapLevel(next: PcapAnonymizationLevel): void {
  if (next === activeLevel) return
  activeLevel = next
  revision += 1
}

export function resetActivePcapLevel(): void {
  activeLevel = DEFAULT_PCAP_LEVEL
  revision += 1
}

export function getActiveSanitizationPolicy(): SanitizationPolicy {
  return presetToSanitizationPolicy(activeLevel)
}

export function getActivePcapMapping(): PcapMapping {
  return levelToMapping(activeLevel)
}

/** @deprecated Prefer getActivePcapLevel. */
export function getActivePcapProfile(): DerivedPcapPolicyView {
  return derivedPolicyView(activeLevel)
}

/** @deprecated Prefer setActivePcapLevel. */
export function setActivePcapProfile(next: DerivedPcapPolicyView | { preset: PcapAnonymizationLevel }): void {
  setActivePcapLevel(next.preset)
}

/** @deprecated Prefer getActivePcapLevelRevision. */
export function getActivePcapProfileRevision(): number {
  return revision
}

/** @deprecated Prefer resetActivePcapLevel. */
export function resetActivePcapProfile(): void {
  resetActivePcapLevel()
}
