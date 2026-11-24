import { useEffect } from 'react'
import { useAppStore } from '../../app/store.ts'
import { getResolveOnlyPayload } from './resolveOnlyModel.ts'
import { MappingResolveWorkspace } from './MappingResolveWorkspace.tsx'
import {
  forceResolveReturnLookupStep,
  getResolveReturnStep,
} from './resolveReturnController.ts'

/**
 * Resolve-only app phase host (Stage 21 / Stage 30).
 * Always renders MappingResolveWorkspace three-step return flow.
 */
export function ResolveOnlyView() {
  const resolveOnlyEpoch = useAppStore((s) => s.resolveOnlyEpoch)
  void resolveOnlyEpoch

  useEffect(() => {
    if (getResolveOnlyPayload() && getResolveReturnStep() !== 'lookup') {
      forceResolveReturnLookupStep()
    }
  }, [resolveOnlyEpoch])

  return <MappingResolveWorkspace />
}
