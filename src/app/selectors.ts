import type { AppShellState } from './store.ts'

export const selectPhase = (s: AppShellState) => s.phase
export const selectStatusMessage = (s: AppShellState) => s.statusMessage
export const selectLastError = (s: AppShellState) => s.lastError
