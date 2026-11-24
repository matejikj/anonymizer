/**
 * Resolve-only return flow from empty state (Stage 30).
 * Two steps: pick bundle → lookup/report.
 * Failures use a single generic local error — no plaintext leakage into messages.
 */

import { useAppStore } from '../../app/store.ts'
import { MAPPING_CAPABILITY_LIMITS } from '../../domain/capabilityContract.ts'
import { BUNDLE_CODEC_ERROR } from '../../mapping/bundle/errors.ts'
import { cs } from '../../i18n/cs.ts'
import {
  BundleCancelledError,
  BundleLifecycleError,
  cancelBundleJob,
  importMappingBundleFile,
  releaseBundleCryptoSession,
} from '../mapping-bundle/bundleController.ts'
import { clearResolveOnlyModel, getResolveOnlyMeta, isResolveOnlyActive } from './resolveOnlyModel.ts'

export type ResolveReturnStep = 'pick-bundle' | 'lookup'

let step: ResolveReturnStep = 'pick-bundle'
let pendingFile: File | null = null
let wizardError: string | null = null
let busy = false

function bump(): void {
  useAppStore.setState((s) => ({ resolveOnlyEpoch: s.resolveOnlyEpoch + 1 }))
}

export function getResolveReturnStep(): ResolveReturnStep {
  return step
}

export function getResolveReturnPendingFile(): File | null {
  return pendingFile
}

export function getResolveReturnError(): string | null {
  return wizardError
}

export function isResolveReturnBusy(): boolean {
  return busy
}

export function resetResolveReturnWizard(): void {
  step = 'pick-bundle'
  pendingFile = null
  wizardError = null
  if (busy) {
    cancelBundleJob()
  }
  busy = false
}

/** Generic local error — never distinguishes corruption vs plaintext. */
export function resolveReturnGenericError(err: unknown): string {
  if (err instanceof BundleCancelledError) return cs.bundle.cancelled
  if (err instanceof BundleLifecycleError) {
    if (err.code === BUNDLE_CODEC_ERROR.oversize || err.code === 'bundle-oversize') {
      return cs.resolveReturn.errorOversize
    }
    return cs.resolveReturn.errorGeneric
  }
  if (err instanceof Error && /oversize|too large|exceeds/i.test(err.message)) {
    return cs.resolveReturn.errorOversize
  }
  return cs.resolveReturn.errorGeneric
}

export function openResolveReturnFromEmpty(): void {
  resetResolveReturnWizard()
  clearResolveOnlyModel()
  useAppStore.getState().enterResolveOnly()
  useAppStore.getState().setStatusMessage(cs.resolveReturn.statusOpen)
  bump()
}

export async function selectResolveReturnBundle(file: File, signal?: AbortSignal): Promise<void> {
  wizardError = null
  if (file.size > MAPPING_CAPABILITY_LIMITS.maxBundleImportBytes) {
    wizardError = cs.resolveReturn.errorOversize
    pendingFile = null
    bump()
    return
  }
  pendingFile = file
  busy = true
  bump()
  try {
    await importMappingBundleFile({ file, signal })
    if (!isResolveOnlyActive()) {
      wizardError = cs.resolveReturn.errorGeneric
      return
    }
    const meta = getResolveOnlyMeta()
    pendingFile = null
    step = 'lookup'
    useAppStore.getState().setToast({
      message: cs.bundle.imported.replace('{n}', String(meta?.entryCount ?? 0)),
    })
  } catch (err) {
    wizardError = resolveReturnGenericError(err)
    pendingFile = null
  } finally {
    busy = false
    bump()
  }
}

export function closeResolveReturnAndClear(): void {
  releaseBundleCryptoSession()
  resetResolveReturnWizard()
  clearResolveOnlyModel()
  useAppStore.getState().exitResolveOnly()
  useAppStore.getState().setStatusMessage(cs.status.ready)
  bump()
}

export function resetResolveReturnForTests(): void {
  resetResolveReturnWizard()
  clearResolveOnlyModel()
}

/** When payload already unlocked (e.g. MappingBundleActions), sync wizard to lookup. */
export function forceResolveReturnLookupStep(): void {
  if (!isResolveOnlyActive()) return
  pendingFile = null
  wizardError = null
  busy = false
  step = 'lookup'
  bump()
}
