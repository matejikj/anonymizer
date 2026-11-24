/**
 * Recovery restore session — FSM + idle timeout + wipe on lock.
 */

import { bytesToHex } from '../../../crypto/incrementalSha256'
import { randomBytes } from '../../../crypto/randomBytes'
import {
  canTransitionRecoverySession,
  isRecoverySessionTerminal,
  type RecoverySessionState,
} from '../domain/sessionState'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { PcapRecoveryManifestV1, UnlockedRecoverySummary } from '../domain/types'
import type { UnlockedLookupIndex } from './unlockedLookupIndex'
import type { RecoveryBundleBounds } from './recoveryBundleReader'
import { createDecryptedFrameCache } from './dataFrameDecrypt'

export class RecoverySession {
  private state: RecoverySessionState = 'idle'
  private sessionId: string | null = null
  private generationId: string | null = null
  private idleTimer: ReturnType<typeof setTimeout> | null = null
  private lastActivityAt = 0

  anonymizedBlob: Blob | null = null
  recoveryBlob: Blob | null = null
  bounds: RecoveryBundleBounds | null = null
  anonymizedSha256: Uint8Array | null = null
  pairLooksCompatible = false

  private manifest: PcapRecoveryManifestV1 | null = null
  private index: UnlockedLookupIndex | null = null
  private frameCache: import('./dataFrameDecrypt').DecryptedFrameCache | null = null
  dataDirectory: import('./dataFrameDirectory').DataFrameLocation[] | null = null

  onIdleTimeout: (() => void) | null = null

  get currentState(): RecoverySessionState {
    return this.state
  }

  get currentSessionId(): string | null {
    return this.sessionId
  }

  get currentGenerationId(): string | null {
    return this.generationId
  }

  get lookup(): UnlockedLookupIndex | null {
    return this.index
  }

  get recoveryManifest(): PcapRecoveryManifestV1 | null {
    return this.manifest
  }

  get decryptedFrameCache(): import('./dataFrameDecrypt').DecryptedFrameCache | null {
    return this.frameCache
  }

  transition(to: RecoverySessionState): boolean {
    if (!canTransitionRecoverySession(this.state, to)) return false
    this.state = to
    return true
  }

  beginGeneration(generationId: string): void {
    this.wipeSensitive()
    this.generationId = generationId
    this.sessionId = null
    this.bounds = null
    this.anonymizedBlob = null
    this.recoveryBlob = null
    this.pairLooksCompatible = false
    this.state = 'idle'
  }

  touch(): void {
    this.lastActivityAt = Date.now()
    this.resetIdleTimer()
  }

  private resetIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer)
      this.idleTimer = null
    }
    if (this.state !== 'unlocked' && this.state !== 'searching'
      && this.state !== 'restoring-packet' && this.state !== 'restoring-all') {
      return
    }
    this.idleTimer = setTimeout(() => {
      this.onIdleTimeout?.()
    }, PCAP_RECOVERY_LIMITS.sessionIdleTimeoutMs)
  }

  markUnlocked(input: {
    manifest: PcapRecoveryManifestV1
    index: UnlockedLookupIndex
    summary: Omit<UnlockedRecoverySummary, 'sessionId' | 'generationId'>
  }): UnlockedRecoverySummary {
    this.manifest = input.manifest
    this.index = input.index
    this.frameCache = createDecryptedFrameCache()
    this.dataDirectory = null
    this.sessionId = bytesToHex(randomBytes(16))
    this.state = 'unlocked'
    this.touch()
    return {
      sessionId: this.sessionId,
      generationId: this.generationId ?? '',
      ...input.summary,
    }
  }

  assertSession(generationId: string, sessionId?: string): boolean {
    if (this.generationId !== generationId) return false
    if (sessionId !== undefined && this.sessionId !== sessionId) return false
    if (isRecoverySessionTerminal(this.state)) return false
    return true
  }

  wipeSensitive(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer)
      this.idleTimer = null
    }
    this.manifest = null
    this.index?.wipe()
    this.index = null
    this.frameCache?.wipe()
    this.frameCache = null
    this.dataDirectory = null
    this.sessionId = null
    if (this.anonymizedSha256) {
      this.anonymizedSha256.fill(0)
      this.anonymizedSha256 = null
    }
  }

  failUnlockKeepPair(): void {
    // Wipe any partial unlock material but keep blobs/bounds/hash for retry.
    if (this.idleTimer) {
      clearTimeout(this.idleTimer)
      this.idleTimer = null
    }
    this.manifest = null
    this.index?.wipe()
    this.index = null
    this.frameCache?.wipe()
    this.frameCache = null
    this.dataDirectory = null
    this.sessionId = null
    // Allowed escape from unlocking/failed back to locked for retry.
    this.state = 'locked'
  }

  lock(): void {
    if (canTransitionRecoverySession(this.state, 'locking')) {
      this.state = 'locking'
    }
    this.wipeSensitive()
    this.bounds = null
    this.anonymizedBlob = null
    this.recoveryBlob = null
    this.state = 'terminated'
  }

  get lastActivityMs(): number {
    return this.lastActivityAt
  }
}
