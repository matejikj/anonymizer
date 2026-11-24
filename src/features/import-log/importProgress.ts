/** Import / analysis progress phases (ARCHITECTURE §3.1). */

export type ImportPhase =
  | 'idle'
  | 'checking'
  | 'loading'
  | 'analyzing'
  | 'preparing'
  | 'cancelled'
  | 'error'
  | 'done'

export interface ImportProgress {
  phase: ImportPhase
  requestId: string
  processedBytes: number
  processedLines: number
  totalBytes?: number
  message: string
  fileName?: string | null
  startedAt: number
  /** Rule currently under watchdog (custom regex). */
  activeRuleId?: string
  failedRuleIds: string[]
}

export function createIdleProgress(): ImportProgress {
  return {
    phase: 'idle',
    requestId: '',
    processedBytes: 0,
    processedLines: 0,
    message: '',
    fileName: null,
    startedAt: 0,
    failedRuleIds: [],
  }
}

export function phaseMessage(phase: ImportPhase): string {
  switch (phase) {
    case 'checking':
      return 'Kontroluji soubor…'
    case 'loading':
      return 'Načítám…'
    case 'analyzing':
      return 'Analyzuji…'
    case 'preparing':
      return 'Připravuji náhled…'
    case 'cancelled':
      return 'Analýza zrušena'
    case 'error':
      return 'Analýza selhala'
    case 'done':
      return 'Hotovo'
    case 'idle':
      return ''
  }
}
