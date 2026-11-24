/**
 * Mapping session lifecycle — worker termination and registry release (Stage 19).
 * Registry and reverse index live outside Zustand; terminate workers on session close.
 * JavaScript cannot forensically wipe heap memory — callers must not claim otherwise.
 */

import { resetSharedMappingClient } from './sharedMappingClient'

/** Release mapping worker, reverse index references, and published snapshots. */
export function releaseMappingSession(): void {
  resetSharedMappingClient()
}
