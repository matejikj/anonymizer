import type { AppPhase } from './store.ts'
import type { PcapPhase } from '../pcap/ui/pcapSession.ts'

export type SessionStepId = 'files' | 'analysis' | 'review' | 'export'

export interface SessionStepView {
  readonly visible: boolean
  readonly activeStep: SessionStepId | null
  readonly completedBefore: ReadonlySet<SessionStepId>
}

const ORDER: readonly SessionStepId[] = ['files', 'analysis', 'review', 'export']

function completedBefore(active: SessionStepId): ReadonlySet<SessionStepId> {
  const idx = ORDER.indexOf(active)
  const done = new Set<SessionStepId>()
  for (let i = 0; i < idx; i++) done.add(ORDER[i]!)
  return done
}

function view(active: SessionStepId): SessionStepView {
  return { visible: true, activeStep: active, completedBefore: completedBefore(active) }
}

const hidden: SessionStepView = { visible: false, activeStep: null, completedBefore: new Set() }

/**
 * Four-step strip in the app header.
 * Mixed-set phases win over PCAP shell mode so a PCAP file inside a set
 * still shows Soubory → … → Kontrola.
 */
export function resolveSessionStepView(
  appPhase: AppPhase,
  pcapPhase: PcapPhase,
  inPcapShell: boolean,
): SessionStepView {
  if (appPhase === 'resolve-only') return hidden

  switch (appPhase) {
    case 'correlation-staging':
      return view('files')
    case 'correlation-processing':
      return view('analysis')
    case 'correlation-review':
      return view('review')
    case 'correlation-exporting':
    case 'correlation-completed':
      return view('export')
    default:
      break
  }

  // Standalone PCAP editor — progress lives in-header, not only in the toolbar.
  if (inPcapShell) {
    switch (pcapPhase) {
      case 'preflight':
      case 'analyzing':
        return view('analysis')
      case 'workspace':
      case 'error':
        return view('review')
      default:
        return hidden
    }
  }

  switch (appPhase) {
    case 'empty':
      return hidden
    case 'importing':
      return view('analysis')
    case 'workspace':
      return view('review')
    default:
      return hidden
  }
}

export const SESSION_STEP_ORDER = ORDER
