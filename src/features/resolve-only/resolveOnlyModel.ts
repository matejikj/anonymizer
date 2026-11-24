/**
 * Resolve-only imported mapping — module scope, never Zustand (Stage 21).
 * Import does not restore log/capture or start anonymization session.
 *
 * Exposes a subscribe/getSnapshot pair for useSyncExternalStore: reading
 * payload/meta directly via plain getters during render is unsafe under
 * React's concurrent rendering / StrictMode double-invoke — a component
 * can observe payload and meta from different points in time even though
 * setResolveOnlyPayload sets them atomically, since each getter call
 * independently samples "current" mutable state rather than one snapshot.
 */

import type { MappingBundlePayload } from '../../mapping/bundle/types'

export interface ResolveOnlyMeta {
  readonly fileName: string
  readonly importedAt: number
  readonly entryCount: number
  readonly sourceCount: number
}

export interface ResolveOnlySnapshot {
  readonly payload: MappingBundlePayload | null
  readonly meta: ResolveOnlyMeta | null
}

const EMPTY_SNAPSHOT: ResolveOnlySnapshot = { payload: null, meta: null }

let snapshot: ResolveOnlySnapshot = EMPTY_SNAPSHOT
const listeners = new Set<() => void>()

function notify(): void {
  for (const listener of listeners) listener()
}

export function subscribeResolveOnlyModel(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getResolveOnlySnapshot(): ResolveOnlySnapshot {
  return snapshot
}

export function getResolveOnlyPayload(): MappingBundlePayload | null {
  return snapshot.payload
}

export function getResolveOnlyMeta(): ResolveOnlyMeta | null {
  return snapshot.meta
}

export function isResolveOnlyActive(): boolean {
  return snapshot.payload !== null
}

export function setResolveOnlyPayload(payload: MappingBundlePayload, fileName: string): void {
  snapshot = {
    payload,
    meta: {
      fileName,
      importedAt: Date.now(),
      entryCount: payload.entries.length,
      sourceCount: payload.sources.length,
    },
  }
  notify()
}

export function clearResolveOnlyModel(): void {
  if (snapshot === EMPTY_SNAPSHOT) return
  snapshot = EMPTY_SNAPSHOT
  notify()
}
