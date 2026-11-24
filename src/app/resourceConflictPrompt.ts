/**
 * Cross-mode resource conflict confirmation (Stage 14).
 * Replaces window.confirm with an accessible application dialog.
 */

import type { ResourceConflict } from '../pcap/ui/pcapResourceCoordinator.ts'
import { useAppStore } from './store.ts'

let pendingResolve: ((confirmed: boolean) => void) | null = null

export function promptResourceConflict(conflict: ResourceConflict): Promise<boolean> {
  return new Promise((resolve) => {
    pendingResolve = resolve
    useAppStore.getState().setResourceConflict(conflict)
  })
}

export function resolveResourceConflict(confirmed: boolean): void {
  pendingResolve?.(confirmed)
  pendingResolve = null
  useAppStore.getState().setResourceConflict(null)
}

export function cancelResourceConflict(): void {
  resolveResourceConflict(false)
}

export function confirmResourceConflictChoice(): void {
  resolveResourceConflict(true)
}
