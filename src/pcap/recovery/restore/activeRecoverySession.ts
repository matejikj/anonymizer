/**
 * Reference to the currently-unlocked recovery worker session (if any), shared between the
 * workspace bootstrap (which unlocks it), the toolbar search dialog (which reuses it), and the
 * PCAP session lifecycle (which disposes it on close) — without those modules depending on each
 * other directly.
 */
import { disposePcapRestoreWorker, lockRecoverySessionViaWorker } from '../worker/client'

export interface ActiveRecoverySessionRef {
  readonly generationId: string
  readonly sessionId: string
}

let activeRef: ActiveRecoverySessionRef | null = null

export function setActiveRecoverySessionRef(ref: ActiveRecoverySessionRef | null): void {
  activeRef = ref
}

export function getActiveRecoverySessionRef(): ActiveRecoverySessionRef | null {
  return activeRef
}

export async function disposeActiveRecoverySession(): Promise<void> {
  const ref = activeRef
  activeRef = null
  if (!ref) return
  try {
    await lockRecoverySessionViaWorker({ generationId: ref.generationId, sessionId: ref.sessionId })
  } catch {
    disposePcapRestoreWorker()
  }
}
