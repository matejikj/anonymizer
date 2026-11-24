/**
 * UI export controller — wires session plan to export coordinator.
 */

import { runPcapExport, cancelPcapExport, PcapExportCancelledError, PcapExportValidationError } from '../export/coordinator'
import { triggerBlobDownload } from '../export/sinks'
import { anonymizedPcapFileName } from '../export/fileName'
import { buildAiDiagnosticsManifest, aiDiagnosticsFileName } from '../export/aiDiagnostics'
import { assertReportHasNoOriginalIdentifiers } from '../export/report'
import { buildSessionPlanSnapshot, countUnsupportedLayers, getPcapSession } from './pcapSession'
import { usePcapStore } from './pcapStore'
import { cs } from '../../i18n/cs.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import type { LayerCoverage } from '../sanitize/types'
import { discoveryIssuesForExport, sanitizerCoverageForExport } from '../processing/packedCaptureWire'
import { formatUnknownPlanErrorForUser } from './formatPlanError.ts'
import { useAppStore } from '../../app/store.ts'
import { DualExportCoordinator } from '../recovery/export/dualExportCoordinator'

const EXPORT_TOAST_DURATION_MS = 10_000
let exportToastTimer: ReturnType<typeof setTimeout> | null = null

function showExportToast(message: string): void {
  if (exportToastTimer) clearTimeout(exportToastTimer)
  useAppStore.getState().setToast({ message })
  exportToastTimer = setTimeout(() => {
    useAppStore.getState().setToast(null)
    exportToastTimer = null
  }, EXPORT_TOAST_DURATION_MS)
}

type PendingExportOptions = {
  preferFileSystemAccess?: boolean
  unsafeExportAcknowledged?: boolean
}

function flattenSessionCoverage(): readonly LayerCoverage[] {
  const session = getPcapSession()
  if (!session) return []
  // R10 packed discover: per-packet spans stay in the worker; use the weighted rollup kinds.
  return sanitizerCoverageForExport(session.packetDiscovery, session.coverageRollup)
}

/** Safe issue tokens from discovery (tls-branch:*, …) — no original identities. */
function flattenSessionIssues(): readonly string[] {
  const session = getPcapSession()
  if (!session) return []
  return discoveryIssuesForExport(session.packetDiscovery, session.coverageRollup)
}

function sessionLeakOriginals(): readonly import('../trust').LeakScanOriginal[] {
  const session = getPcapSession()
  if (!session?.analysis?.entities?.length) return []
  // Cap canaries — enough for gate signal without scanning huge entity tables twice.
  return session.analysis.entities.slice(0, 2_000).map((e) => ({
    category: e.category,
    value: e.value,
    packetNumber: e.firstPacket,
  }))
}

function checkExportEligibility(): { ok: true; unsafeExportAcknowledged: boolean } | { ok: false } {
  const session = getPcapSession()
  const plan = buildSessionPlanSnapshot()
  if (!session || !plan) return { ok: false }

  const store = usePcapStore.getState()

  if (store.requestedPcapLevel !== null || store.planStale) {
    store.setExportHint(cs.pcap.export.rebuildPendingHint)
    return { ok: false }
  }
  if (plan.pcapLevel !== store.activePcapLevel) {
    store.setExportHint(cs.pcap.export.levelMismatchHint)
    return { ok: false }
  }

  const vm = getPcapCoverageViewModel()
  const anonymization = vm?.summary.anonymization ?? session.statuses.anonymization
  const compatibility = vm?.summary.compatibility ?? session.statuses.compatibility
  const mediaUnsafe = session.profile.mediaPolicy === 'preserve-unsafe'
  const exportLooksSafe =
    vm?.summary.exportLooksSafe ?? (anonymization === 'covered' && !mediaUnsafe)

  if (compatibility === 'blocked' || anonymization === 'blocked') {
    store.setExportHint(cs.pcap.export.blockedHint)
    return { ok: false }
  }

  return { ok: true, unsafeExportAcknowledged: !exportLooksSafe }
}

/** Starts export immediately — no confirmation dialog. */
export async function startPcapExport(options?: { preferFileSystemAccess?: boolean }): Promise<void> {
  const eligibility = checkExportEligibility()
  if (!eligibility.ok) return
  await runPcapExportInternal({
    ...options,
    unsafeExportAcknowledged: eligibility.unsafeExportAcknowledged,
  })
}

/** Exports the anonymized PCAP together with its recovery (deanonymization) file. */
export async function startPcapExportWithRecovery(options?: {
  preferFileSystemAccess?: boolean
}): Promise<void> {
  const eligibility = checkExportEligibility()
  if (!eligibility.ok) return
  await runPcapExportWithRecoveryInternal({
    unsafeExportAcknowledged: eligibility.unsafeExportAcknowledged,
    preferFileSystemAccess: options?.preferFileSystemAccess,
  })
}

async function runPcapExportInternal(options?: PendingExportOptions): Promise<void> {
  const session = getPcapSession()
  const plan = buildSessionPlanSnapshot()
  if (!session || !plan) return

  const store = usePcapStore.getState()
  store.setExportBusy(true)
  store.setExportPhase('exporting')
  store.setExportMessage(cs.pcap.export.progressAnonymizing)
  store.setExportHint(null)
  store.setExportProgress(0, 0)
  store.setExportStartedAt(Date.now())

  try {
    const result = await runPcapExport({
      plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      baselineIssues: session.issues,
      unsupportedLayers: countUnsupportedLayers(),
      protocolCoverage: session.unifiedCoverage.byProtocol,
      preferFileSystemAccess: false,
      skipAutoDownload: true,
      profile: session.profile,
      policy: session.policy,
      coverage: flattenSessionCoverage(),
      issues: flattenSessionIssues(),
      leakOriginals: sessionLeakOriginals(),
      unsafeExportAcknowledged: options?.unsafeExportAcknowledged === true,
      onProgress: (p) => {
        if (p.phase === 'cancelled') {
          store.setExportMessage(p.message)
          return
        }
        const msg =
          p.phase === 'rewriting' ? cs.pcap.export.progressAnonymizing
          : p.phase === 'checksums' ? cs.pcap.export.progressChecksums
          : p.phase === 'assembling' ? cs.pcap.export.progressAssembling
          : p.phase === 'validating' ? cs.pcap.export.progressValidating
          : p.phase === 'done' ? cs.pcap.export.progressDone
          : p.message
        store.setExportMessage(msg)
        store.setExportProgress(p.packetsDone, p.packetsTotal)
      },
    })

    const pcapBlob =
      result.blob
      ?? new Blob([], { type: 'application/octet-stream' })

    if (pcapBlob.size > 0) {
      triggerBlobDownload(pcapBlob, result.fileName)
    }

    store.setExportPhase('done')
    store.setExportMessage(null)
    showExportToast(cs.pcap.export.toastSuccess)
  } catch (err) {
    store.setExportMessage(null)
    if (err instanceof PcapExportCancelledError) {
      store.setExportPhase('cancelled')
      showExportToast(cs.pcap.export.cancelled)
    } else if (err instanceof PcapExportValidationError) {
      store.setExportPhase('error')
      showExportToast(cs.pcap.export.validationFailed)
    } else {
      store.setExportPhase('error')
      showExportToast(formatUnknownPlanErrorForUser(err))
    }
  } finally {
    store.setExportBusy(false)
    store.setExportStartedAt(0)
    store.setExportProgress(0, 0)
  }
}

async function runPcapExportWithRecoveryInternal(options?: PendingExportOptions): Promise<void> {
  const session = getPcapSession()
  const plan = buildSessionPlanSnapshot()
  if (!session || !plan) return

  const store = usePcapStore.getState()
  store.setExportBusy(true)
  store.setExportPhase('exporting')
  store.setExportMessage(cs.pcap.export.progressAnonymizing)
  store.setExportHint(null)
  store.setExportProgress(0, 0)
  store.setExportStartedAt(Date.now())

  try {
    const format = plan.format === 1 ? 'pcapng' : 'pcap'
    // Recovery briefly holds a second, roughly file-sized copy of the output in memory (the
    // anonymized bytes + the full-literal encrypted original) before both download as Blobs —
    // same as the plain Export button, no folder picker. This used to risk exceeding available
    // heap on very large captures on top of everything the loaded session itself retains; now
    // that the session's own footprint is ~3x smaller (see pcapSession.ts /
    // containerWireAdapter.ts), the combined peak is comfortably within budget again — verified
    // against a real 225k-packet/47MB capture end to end without the picker.
    const dualSink = await DualExportCoordinator.open({
      generationId: plan.generationId,
      anonymizedFileName: anonymizedPcapFileName(plan.fileName, format),
      recoveryEnabled: true,
    })

    const result = await runPcapExport({
      plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      baselineIssues: session.issues,
      unsupportedLayers: countUnsupportedLayers(),
      protocolCoverage: session.unifiedCoverage.byProtocol,
      dualSink,
      recovery: { enabled: true },
      skipAutoDownload: true,
      profile: session.profile,
      policy: session.policy,
      coverage: flattenSessionCoverage(),
      issues: flattenSessionIssues(),
      leakOriginals: sessionLeakOriginals(),
      unsafeExportAcknowledged: options?.unsafeExportAcknowledged === true,
      onProgress: (p) => {
        if (p.phase === 'cancelled') {
          store.setExportMessage(p.message)
          return
        }
        const msg =
          p.phase === 'rewriting' ? cs.pcap.export.progressAnonymizing
          : p.phase === 'checksums' ? cs.pcap.export.progressChecksums
          : p.phase === 'assembling' ? cs.pcap.export.progressAssembling
          : p.phase === 'validating' ? cs.pcap.export.progressValidating
          : p.phase === 'writing-recovery' ? cs.pcap.export.progressWritingRecovery
          : p.phase === 'done' ? cs.pcap.export.progressDone
          : p.message
        store.setExportMessage(msg)
        store.setExportProgress(p.packetsDone, p.packetsTotal)
      },
    })

    if (!result.recoveryCreated) {
      throw new Error('Recovery export failed')
    }

    // This button downloads ONLY the recovery sidecar (the anonymized PCAP itself is what the
    // separate "Export" button is for). Downloading exactly one file here also sidesteps
    // Chrome's (and other browsers') "block a second automatic download from one page action"
    // protection — triggering two synthetic downloads from a single click silently drops the
    // second one with no error and no visible dialog, which is what used to happen here.
    if (result.recoveryBlob) {
      triggerBlobDownload(
        result.recoveryBlob,
        result.recoveryFileName ?? `${result.fileName}.rnd-pcap-recovery.bin`,
      )
    }

    store.setExportPhase('done')
    store.setExportMessage(null)
    showExportToast(cs.pcap.export.toastSuccessRecovery)
  } catch (err) {
    store.setExportMessage(null)
    if (err instanceof PcapExportCancelledError) {
      store.setExportPhase('cancelled')
      showExportToast(cs.pcap.export.cancelled)
    } else if (err instanceof PcapExportValidationError) {
      store.setExportPhase('error')
      showExportToast(cs.pcap.export.validationFailed)
    } else {
      store.setExportPhase('error')
      showExportToast(cs.pcap.recovery.exportRecoveryFailed)
    }
  } finally {
    store.setExportBusy(false)
    store.setExportStartedAt(0)
    store.setExportProgress(0, 0)
  }
}

/**
 * Downloads just the AI-diagnostics sidecar. Its content only depends on the plan/coverage
 * already held in the session — not on the incremental export rewrite — so this runs instantly,
 * without spinning up the export worker.
 */
export function startPcapExportDiagnostics(): void {
  const session = getPcapSession()
  const plan = buildSessionPlanSnapshot()
  if (!session || !plan) return

  try {
    const format = plan.format === 1 ? 'pcapng' : 'pcap'
    const exportFileName = anonymizedPcapFileName(plan.fileName, format)
    const manifest = buildAiDiagnosticsManifest({
      plan,
      protocolCoverage: session.unifiedCoverage.byProtocol,
    })
    const json = JSON.stringify(manifest, null, 2)
    assertReportHasNoOriginalIdentifiers(json)
    triggerBlobDownload(
      new Blob([json], { type: 'application/json' }),
      aiDiagnosticsFileName(exportFileName),
    )
    showExportToast(cs.pcap.export.toastSuccessDiagnostics)
  } catch (err) {
    showExportToast(formatUnknownPlanErrorForUser(err))
  }
}

/** Re-offers the already-computed restored blob from a recovery session — no re-export needed. */
export function downloadDeanonymizedPcap(): void {
  const session = getPcapSession()
  if (!session?.counterpartSource) return
  triggerBlobDownload(session.counterpartSource.blob, `deanonymized-${session.fileName}`)
}

export function cancelPcapExportUi(): void {
  cancelPcapExport()
}
