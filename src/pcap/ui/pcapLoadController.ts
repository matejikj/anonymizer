/**
 * PCAP file load pipeline (Stage 9): preflight → worker discover/resolve/plan → slim session.
 */

import { CaptureFormat, IssueSeverity } from '../domain/types'
import { CancellationToken, CancellationError } from '../capture/cancellation'
import {
  preflightPcapFile,
  type PcapPreflightOk,
} from '../capture/preflight'
import {
  filterPacketIndices,
  createSlimPcapSession,
  getPcapSession,
  analysisFromWire,
} from './pcapSession'
import { mergeCoverageRollup } from '../processing/packedCaptureWire'
import { buildSessionCoverage } from '../coverage'
import { getActivePcapLevel, getActivePcapProfile } from '../profile/activePcapProfile'
import { createIdlePcapProgress, usePcapStore, type PcapProgress } from './pcapStore'
import { getPcapPlanRebuildPort } from '../profile/workerPcapPlanRebuildPort'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import { formatUnknownPlanErrorForUser } from './formatPlanError.ts'
import { orchestrateViaWorkers, cancelActiveProcessing } from '../processing/processingOrchestrator'
import { containerFromWire } from '../processing/containerWireAdapter'
import { planFromWire } from '../processing/planWireAdapter'
import type { PcapSourceDescriptor } from './pcapSourceDescriptor'
import {
  detectResourceConflict,
  releaseTextSessionForPcap,
} from './pcapResourceCoordinator'
import { promptResourceConflict } from '../../app/resourceConflictPrompt.ts'
import {
  onPcapSessionClosed,
  prepareNewPcapSession,
  setActiveWorkerGenerationId,
  teardownPcapSession,
} from './pcapSessionLifecycle'

let activeCancel: CancellationToken | null = null
let pendingReplaceFile: File | null = null

function nextGenerationId(): string {
  return `pcap-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
}

export function cancelPcapLoad(): void {
  const gen = activeCancel?.generationId
  activeCancel?.cancel()
  if (gen) cancelActiveProcessing(gen)
  activeCancel = null
}

export function cancelPcapReplace(): void {
  pendingReplaceFile = null
  usePcapStore.getState().setReplaceDialog('none')
  usePcapStore.getState().setPendingReplaceFileName(null)
}

export async function confirmPcapReplace(): Promise<void> {
  const file = pendingReplaceFile
  pendingReplaceFile = null
  usePcapStore.getState().setReplaceDialog('none')
  usePcapStore.getState().setPendingReplaceFileName(null)
  if (!file) return
  await loadPcapFile(file, { replaceConfirmed: true })
}

function showPreflightError(message: string, hadSession: boolean): void {
  if (hadSession) {
    useAppStore.getState().setToast({ message, kind: 'error' })
    return
  }
  const store = usePcapStore.getState()
  store.setErrorMessage(message)
  store.setPhase('error')
}

function beginPcapLoadProgress(file: File, phase: PcapProgress['phase'] = 'checking'): void {
  const store = usePcapStore.getState()
  store.setErrorMessage(null)
  store.setPhase('preflight')
  store.setProgress({
    phase,
    packetsDone: 0,
    packetsTotal: 0,
    bytesDone: 0,
    bytesTotal: file.size,
    startedAt: Date.now(),
    cancellable: true,
    fileName: file.name,
  })
}

export async function loadPcapFile(
  file: File,
  options: { replaceConfirmed?: boolean; resourceConfirmed?: boolean } = {},
): Promise<void> {
  const hadSession = getPcapSession() !== null

  if (!hadSession || options.replaceConfirmed) {
    beginPcapLoadProgress(file)
  }

  let pre: Awaited<ReturnType<typeof preflightPcapFile>>
  try {
    pre = await preflightPcapFile(file)
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') return
    showPreflightError(cs.pcap.errors.loadFailed, hadSession)
    return
  }

  if (!pre.ok) {
    showPreflightError(pre.message, hadSession)
    return
  }

  const resourceConflict = detectResourceConflict('pcap', file.size)
  if (resourceConflict && !options.resourceConfirmed) {
    const ok = await promptResourceConflict(resourceConflict)
    if (!ok) return
    releaseTextSessionForPcap()
    return loadPcapFile(file, { ...options, resourceConfirmed: true })
  }

  if (hadSession && !options.replaceConfirmed) {
    pendingReplaceFile = file
    usePcapStore.getState().setPendingReplaceFileName(file.name)
    usePcapStore.getState().setReplaceDialog('open')
    return
  }

  cancelPcapLoad()
  await loadPcapFileAfterPreflight(file, pre)
}

async function loadPcapFileAfterPreflight(file: File, pre: PcapPreflightOk): Promise<void> {
  releaseTextSessionForPcap()
  const generationId = nextGenerationId()
  const token = new CancellationToken(generationId)
  activeCancel = token

  const store = usePcapStore.getState()
  store.setErrorMessage(null)
  store.setPhase('preflight')
  store.setProgress({
    phase: 'checking',
    packetsDone: 0,
    packetsTotal: 0,
    bytesDone: 0,
    bytesTotal: pre.byteLength,
    startedAt: Date.now(),
    cancellable: true,
    fileName: file.name,
  })

  try {
    token.throwIfCancelled()

    // Packet indices, marks and navigation history belong to the outgoing capture.
    // Clear them only after replacement is confirmed and preflight has succeeded.
    store.resetPacketSelection()
    teardownPcapSession()
    prepareNewPcapSession(0, generationId)
    setActiveWorkerGenerationId(generationId)

    store.patchProgress({ phase: 'analyzing' })
    store.setPhase('analyzing')

    const profile = getActivePcapProfile()
    const { profileToSanitizationPolicy } = await import('../profile/presets')
    const policy = profileToSanitizationPolicy(profile)

    const result = await orchestrateViaWorkers({
      blob: file,
      fileName: file.name,
      format: pre.format,
      policy,
      profile,
      generationId,
      sourceId: file.name,
      onProgress: (phase, done, total) => {
        token.throwIfCancelled()
        if (phase === 'parsing') {
          // `done`/`total` are byte counts here, not packet counts — route them to
          // bytesDone/bytesTotal so the splash keeps showing byte progress (packetsTotal
          // stays 0 until the analyzing/discovering phase reports real packet counts).
          store.patchProgress({
            phase: 'analyzing',
            bytesDone: done,
            bytesTotal: total,
          })
          return
        }
        store.patchProgress({
          phase: phase === 'plan-build' ? 'building' : 'analyzing',
          packetsDone: done,
          packetsTotal: total,
          bytesDone: pre.byteLength,
        })
      },
    })
    token.throwIfCancelled()

    const container = containerFromWire(result.containerWire)
    const fatal = container.issues.filter((i) => i.severity === IssueSeverity.Fatal)
    if (container.descriptors.length === 0 && fatal.length > 0) {
      throw new Error(fatal[0]!.message)
    }

    const analysis = analysisFromWire(result.discoveryWire)

    const { unifiedCoverage, entityOccurrenceIndex } = buildSessionCoverage({
      packetCount: container.descriptors.length,
      analysis,
      packetDiscovery: container.packetDiscovery,
      entityOccurrences: result.discoveryWire.entityOccurrences,
      entityIntents: result.discoveryWire.intents.map((i) => ({
        category: i.category,
        canonical: i.canonical,
        packetIndex: i.packetIndex,
      })),
    })
    const unifiedWithRollup = mergeCoverageRollup(unifiedCoverage, container.coverageRollup)

    const descriptor: PcapSourceDescriptor = {
      fileName: file.name,
      fileSize: file.size,
      format: pre.format,
      sourceFile: file,
      descriptors: container.descriptors,
      checkpoints: container.checkpoints,
      issues: container.issues,
      classicHeader: container.classicHeader,
      pcapngSections: container.pcapngSections as PcapSourceDescriptor['pcapngSections'],
      pcapngInterfaces: container.pcapngInterfaces as PcapSourceDescriptor['pcapngInterfaces'],
    }

    const plan = planFromWire(result.planWire, profile.id)
    const session = createSlimPcapSession({
      descriptor,
      generationId,
      analysis,
      packetDiscovery: container.packetDiscovery,
      unifiedCoverage: unifiedWithRollup,
      entityOccurrenceIndex,
      coverageRollup: container.coverageRollup,
      plan,
      mappingRevision: result.snapshot.revision,
      profile,
    })

    prepareNewPcapSession(session.generation, generationId)

    const indicesOriginal = filterPacketIndices(store.filter, '', { dataView: 'original' })
    const indicesAnonymized = filterPacketIndices(store.filter, '', { dataView: 'anonymized' })
    store.setFilteredIndicesForViews(indicesOriginal, indicesAnonymized)
    store.setFocusedPane('anonymized')
    store.setDataView('anonymized')
    const pick = indicesAnonymized[0] ?? indicesOriginal[0] ?? (container.descriptors.length > 0 ? 0 : -1)
    store.setSelectedPacketIndex(pick)
    store.bumpSessionEpoch()
    store.setProgress(createIdlePcapProgress())
    store.setPhase('workspace')
    // T10 — show outcome immediately; dual editors remain on the workspace behind the dialog.
    store.setOutcomeDialogOpen(true)
    store.setExportHint(
      session.statuses.anonymization === 'exposed'
        ? cs.pcap.export.exposedHint
        : session.statuses.anonymization === 'blocked'
          ? cs.pcap.export.blockedHint
          : null,
    )
  } catch (err) {
    if (err instanceof CancellationError) {
      store.setProgress(createIdlePcapProgress())
      store.setPhase(getPcapSession() ? 'workspace' : 'empty')
      return
    }
    const message = formatUnknownPlanErrorForUser(err)
    onPcapSessionClosed()
    store.setProgress(createIdlePcapProgress())
    store.setErrorMessage(message)
    store.setPhase('error')
  } finally {
    if (activeCancel === token) activeCancel = null
  }
}

export function reapplyPcapPolicy(): void {
  void getPcapPlanRebuildPort().rebuildPlan(getActivePcapLevel())
}

export function refreshPcapFilter(): void {
  const store = usePcapStore.getState()
  const expr = store.displayFilterApplied
  const indicesOriginal = filterPacketIndices(store.filter, expr, { dataView: 'original' })
  const indicesAnonymized = filterPacketIndices(store.filter, expr, { dataView: 'anonymized' })
  store.setFilteredIndicesForViews(indicesOriginal, indicesAnonymized)
  const active = store.dataView === 'original' ? indicesOriginal : indicesAnonymized
  if (active.length === 0) {
    // Keep selection for dual-pane counterpart messaging when the other side still has rows.
    if (indicesOriginal.length === 0 && indicesAnonymized.length === 0) {
      store.setSelectedPacketIndex(-1)
    }
  } else if (!active.includes(store.selectedPacketIndex)) {
    const stillPresent =
      indicesOriginal.includes(store.selectedPacketIndex) ||
      indicesAnonymized.includes(store.selectedPacketIndex)
    if (!stillPresent) store.setSelectedPacketIndex(active[0]!)
  }
}

export function closePcapWorkspace(): void {
  onPcapSessionClosed()
  usePcapStore.getState().resetToEmpty()
}

export { CaptureFormat }
