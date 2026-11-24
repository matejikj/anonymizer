/**
 * Recovery session state machine (restore worker).
 * Terminal states are failed / cancelled / terminated after lock.
 */

export const RECOVERY_SESSION_STATES = [
  'idle',
  'preflighting',
  'locked',
  'unlocking',
  'unlocked',
  'searching',
  'restoring-packet',
  'restoring-all',
  'locking',
  'failed',
  'cancelled',
  'terminated',
] as const

export type RecoverySessionState = (typeof RECOVERY_SESSION_STATES)[number]

export const RECOVERY_SESSION_TERMINAL: ReadonlySet<RecoverySessionState> = new Set([
  'failed',
  'cancelled',
  'terminated',
])

export function isRecoverySessionTerminal(state: RecoverySessionState): boolean {
  return RECOVERY_SESSION_TERMINAL.has(state)
}

/** Allowed transitions — fail-closed; unknown edges are rejected by the worker. */
const TRANSITIONS: Readonly<Record<RecoverySessionState, readonly RecoverySessionState[]>> = {
  idle: ['preflighting', 'failed', 'cancelled', 'terminated'],
  preflighting: ['locked', 'failed', 'cancelled', 'terminated'],
  locked: ['unlocking', 'failed', 'cancelled', 'terminated'],
  unlocking: ['unlocked', 'failed', 'cancelled', 'terminated'],
  unlocked: [
    'searching',
    'restoring-packet',
    'restoring-all',
    'locking',
    'failed',
    'cancelled',
    'terminated',
  ],
  searching: ['unlocked', 'failed', 'cancelled', 'terminated'],
  'restoring-packet': ['unlocked', 'failed', 'cancelled', 'terminated'],
  'restoring-all': ['unlocked', 'failed', 'cancelled', 'terminated'],
  locking: ['terminated', 'failed'],
  failed: ['terminated'],
  cancelled: ['terminated'],
  terminated: [],
}

export function canTransitionRecoverySession(
  from: RecoverySessionState,
  to: RecoverySessionState,
): boolean {
  return TRANSITIONS[from].includes(to)
}
