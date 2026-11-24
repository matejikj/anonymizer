/**
 * Authoritative multi-source correlation phase (Stage 31).
 * Mutually exclusive — never represent as overlapping booleans.
 */

import { useAppStore } from '../app/store'

export type CorrelationUiPhase =
  | { readonly kind: 'idle' }
  | { readonly kind: 'staging' }
  | { readonly kind: 'processing'; readonly generationId: string }
  | { readonly kind: 'review'; readonly generationId: string }
  | { readonly kind: 'exporting'; readonly generationId: string }
  | { readonly kind: 'completed'; readonly generationId: string }
  | { readonly kind: 'failed'; readonly recoverTo: 'staging' | 'review'; readonly generationId: string | null }

let phase: CorrelationUiPhase = { kind: 'idle' }

function bump(): void {
  useAppStore.getState().bumpCorrelationEpoch()
}

export function getCorrelationUiPhase(): CorrelationUiPhase {
  return phase
}

export function setCorrelationUiPhase(next: CorrelationUiPhase): void {
  phase = next
  const store = useAppStore.getState()
  switch (next.kind) {
    case 'idle':
      if (store.phase.startsWith('correlation-')) store.setPhase('empty')
      store.setCorrelationView({ phase: 'empty', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
    case 'staging':
      store.setPhase('correlation-staging')
      store.setCorrelationView({ phase: 'staged', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
    case 'processing':
      store.setPhase('correlation-processing')
      store.setCorrelationView({ phase: 'processing', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
    case 'review':
      store.setPhase('correlation-review')
      store.setCorrelationView({ phase: 'ready', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
    case 'exporting':
      store.setPhase('correlation-exporting')
      store.setCorrelationView({ phase: 'ready', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
    case 'completed':
      store.setPhase('correlation-completed')
      store.setCorrelationView({ phase: 'ready', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
    case 'failed':
      // Stay on processing UI so the user can decide (remove+continue / cancel).
      // recoverTo records where cancelInitialCorrelationProcessing should land.
      store.setPhase(next.recoverTo === 'staging' ? 'correlation-processing' : 'correlation-review')
      store.setCorrelationView({ phase: 'failed', sourceCount: store.correlationSourceCount, mappingRevision: store.correlationMappingRevision })
      break
  }
  bump()
}

export function resetCorrelationUiPhase(): void {
  phase = { kind: 'idle' }
}

export function correlationUiPhaseKind(): CorrelationUiPhase['kind'] {
  return phase.kind
}

/** Sync from AppPhase when shell navigation happens outside this model. */
export function syncCorrelationUiPhaseFromAppPhase(
  appPhase: string,
  generationId: string | null,
): void {
  switch (appPhase) {
    case 'correlation-staging':
      phase = { kind: 'staging' }
      break
    case 'correlation-processing':
      phase = { kind: 'processing', generationId: generationId ?? '' }
      break
    case 'correlation-review':
      phase = { kind: 'review', generationId: generationId ?? '' }
      break
    case 'correlation-exporting':
      phase = { kind: 'exporting', generationId: generationId ?? '' }
      break
    case 'correlation-completed':
      phase = { kind: 'completed', generationId: generationId ?? '' }
      break
    default:
      if (phase.kind !== 'idle') phase = { kind: 'idle' }
  }
}
