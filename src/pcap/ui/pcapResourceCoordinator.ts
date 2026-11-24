/**
 * Cross-mode resource coordinator (Stage 9).
 * Prevents silently holding two large materialized relations (text + PCAP).
 */

import { getSessionModel, clearSessionModel } from '../../features/workspace/sessionModel'
import { getPcapSession } from './pcapSession'
import { onPcapSessionClosed } from './pcapSessionLifecycle'
import { usePcapStore } from './pcapStore'
import { MAX_PCAP_FILE_BYTES, MAX_TEXT_FILE_BYTES } from '../../domain/capabilityContract'

export type ResourceConflictKind = 'text-over-pcap' | 'pcap-over-text'

export interface ResourceConflict {
  kind: ResourceConflictKind
}

const LARGE_TEXT_THRESHOLD = MAX_TEXT_FILE_BYTES / 4
const LARGE_PCAP_THRESHOLD = MAX_PCAP_FILE_BYTES / 4

export function detectResourceConflict(kind: 'pcap' | 'text', incomingBytes: number): ResourceConflict | null {
  if (kind === 'pcap') {
    const text = getSessionModel()
    if (text && text.meta.byteLength >= LARGE_TEXT_THRESHOLD && incomingBytes >= LARGE_PCAP_THRESHOLD) {
      return { kind: 'pcap-over-text' }
    }
  } else {
    const pcap = getPcapSession()
    if (pcap && pcap.fileSize >= LARGE_PCAP_THRESHOLD && incomingBytes >= LARGE_TEXT_THRESHOLD) {
      return { kind: 'text-over-pcap' }
    }
  }
  return null
}

export function releaseTextSessionForPcap(): void {
  clearSessionModel()
}

export function releasePcapSessionForText(): void {
  onPcapSessionClosed()
  usePcapStore.getState().resetToEmpty()
}
