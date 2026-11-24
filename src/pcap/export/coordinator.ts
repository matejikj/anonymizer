/**
 * PCAP export coordinator — streaming incremental export, validation gate, hard-cancel (Stage 12–13).
 * Step 5: optional DualSinkExportBridge for atomic anonymized + recovery sinks.
 */

import type { PacketRecordDescriptor, ParseIssue } from '../domain/types'
import type { PcapPlanSnapshot } from './planSnapshot'
import { buildSafeReport } from './engine'
import { anonymizedPcapFileName } from './fileName'
import {
  BlobExportSink,
  type ExportSink,
  pickExportFile,
  triggerBlobDownload,
  supportsFileSystemAccess,
} from './sinks'
import { ExportSinkCoordinator } from './sinkCoordinator'
import type { DualSinkExportBridge, DualSinkFinalizeResult } from './dualSinkBridge'
import { reportFileName, assertReportHasNoOriginalIdentifiers } from './report'
import {
  aiDiagnosticsFileName,
  buildAiDiagnosticsManifest,
} from './aiDiagnostics'
import { CancellationToken, CancellationError } from '../capture/cancellation'
import type { UnifiedProtocolSummary } from '../coverage/types'
import { runIncrementalExport } from './incremental'
import type { IncrementalExportInput, IncrementalExportProgress } from './incremental'
import { buildIncrementalExportViaWorker } from './incrementalExportWorkerClient'
import { disposePcapExportWorker } from './pcapExportWorkerClient'
import type { PcapProfile } from '../profile/schema'
import type { LayerCoverage, SanitizationPolicy } from '../sanitize/types'
import type { BuildPrivacyReportInput } from '../privacy/privacyReport'
import { hydrateAndRemediatePlan } from './leakRemediation'
import { getSharedMappingClient } from '../../mapping/sharedMappingClient'

export type PcapExportPhase =
  | 'idle'
  | 'picking'
  | 'rewriting'
  | 'checksums'
  | 'assembling'
  | 'validating'
  | 'binding'
  | 'writing-recovery'
  | 'done'
  | 'cancelled'
  | 'error'

export type PcapExportProgress = {
  phase: PcapExportPhase
  packetsDone: number
  packetsTotal: number
  message: string
}

export type PcapExportResult = {
  fileName: string
  byteLength: number
  reportFileName: string
  reportJson: string
  aiDiagnosticsFileName?: string
  aiDiagnosticsJson?: string
  usedFileSystemAccess: boolean
  partialFilePossible: boolean
  blob?: Blob
  /** Step 5 — safe flag only; no secrets / hashes / recoveryId. */
  recoveryCreated: boolean
  recoveryFileName?: string
  recoveryBlob?: Blob
  recoveryByteLength?: number
}

export class PcapExportCancelledError extends Error {
  constructor() {
    super('PCAP export cancelled')
    this.name = 'PcapExportCancelledError'
  }
}

export class PcapExportValidationError extends Error {
  readonly newBlockingCount: number

  constructor(newBlockingCount: number) {
    super('Export validation failed — output introduced new structural errors')
    this.name = 'PcapExportValidationError'
    this.newBlockingCount = newBlockingCount
  }
}

let activeExportToken: CancellationToken | null = null
let activeSinkCoordinator: ExportSinkCoordinator | null = null
let activeDualBridge: DualSinkExportBridge | null = null

export function cancelPcapExport(): void {
  activeExportToken?.cancel()
  activeSinkCoordinator?.cancel()
  void activeSinkCoordinator?.abort()
  activeDualBridge?.cancel()
  void activeDualBridge?.abort()
  disposePcapExportWorker()
}

class SingleSinkBridge implements DualSinkExportBridge {
  readonly partialFilePossible: boolean
  private readonly coord: ExportSinkCoordinator

  constructor(coord: ExportSinkCoordinator, partialFilePossible: boolean) {
    this.coord = coord
    this.partialFilePossible = partialFilePossible
  }

  cancel(): void {
    this.coord.cancel()
  }

  isActive(generationId?: string): boolean {
    return this.coord.isActive(generationId)
  }

  async writeAnonymized(chunk: ArrayBuffer, generationId: string): Promise<boolean> {
    return this.coord.writeChunk(chunk, generationId)
  }

  async abort(): Promise<void> {
    await this.coord.abort()
  }

  async finalize(): Promise<DualSinkFinalizeResult> {
    const anonymized = await this.coord.finalize()
    return { anonymized, recoveryCreated: false }
  }
}

export async function runPcapExport(input: {
  plan: PcapPlanSnapshot
  descriptors: readonly PacketRecordDescriptor[]
  sourceBlob: Blob
  baselineIssues?: readonly ParseIssue[]
  unsupportedLayers: number
  protocolCoverage: readonly UnifiedProtocolSummary[]
  preferFileSystemAccess?: boolean
  /** Pre-selected sink (e.g. directory export in correlation session). */
  sink?: ExportSink
  /**
   * Optional dual-sink bridge (step 5). When provided, owns anonymized (+ recovery) sinks.
   * Must not carry hashes through Zustand — only ephemeral call args.
   */
  dualSink?: DualSinkExportBridge
  /** Step 5 — recovery sidecar options. */
  recovery?: {
    readonly enabled: boolean
    readonly indexSeed?: ArrayBuffer
    readonly copyAnon?: boolean
  }
  /** When true, skip anchor download even for blob sinks (caller delivers bytes). */
  skipAutoDownload?: boolean
  onProgress?: (p: PcapExportProgress) => void
  /** CF-15 — required for privacy report embedded in export manifest. */
  profile?: Pick<PcapProfile, 'preset' | 'mediaPolicy' | 'mapping'>
  policy?: SanitizationPolicy
  coverage?: readonly LayerCoverage[]
  /** Set when the operator confirmed a non-green / unsafe export. */
  unsafeExportAcknowledged?: boolean
  /** Step 5 — original entity canaries for in-memory leak scan (never written to report). */
  leakOriginals?: readonly import('../trust').LeakScanOriginal[]
  droppedMetadataBlocks?: number
  /** Safe sanitizer issue tokens (e.g. tls-branch:ech) for report tlsHandling. */
  issues?: readonly string[]
}): Promise<PcapExportResult & { blob?: Blob }> {
  const generationId = input.plan.generationId
  const token = new CancellationToken(generationId)
  activeExportToken = token

  const recoveryEnabled = input.recovery?.enabled === true

  let bridge: DualSinkExportBridge

  if (input.dualSink) {
    bridge = input.dualSink
    activeDualBridge = bridge
    activeSinkCoordinator = null
  } else {
    const sinkCoordinator = new ExportSinkCoordinator(generationId)
    activeSinkCoordinator = sinkCoordinator
    activeDualBridge = null

    const totalPick = input.plan.packets.filter((p) => !p.drop).length
    input.onProgress?.({
      phase: 'picking',
      packetsDone: 0,
      packetsTotal: totalPick,
      message: 'Připravuji export…',
    })

    const format = input.plan.format === 1 ? 'pcapng' : 'pcap'
    const outFileName = anonymizedPcapFileName(input.plan.fileName, format)

    let sink: ExportSink | null = input.sink ?? null
    let partial = false
    if (!sink && input.preferFileSystemAccess && supportsFileSystemAccess()) {
      const picked = await pickExportFile(outFileName, format)
      if (picked) {
        sink = picked
        partial = true
      }
    }
    token.throwIfCancelled()

    if (!sink) {
      sink = new BlobExportSink(outFileName)
    }
    sinkCoordinator.attachSink(sink)
    bridge = new SingleSinkBridge(sinkCoordinator, partial)
    activeDualBridge = bridge
  }

  const progress = (phase: PcapExportPhase, packetsDone: number, packetsTotal: number, message: string) => {
    input.onProgress?.({ phase, packetsDone, packetsTotal, message })
  }

  const partialFilePossible = bridge.partialFilePossible

  try {
    const total = input.plan.packets.filter((p) => !p.drop).length
    if (input.dualSink) {
      progress('picking', 0, total, 'Připravuji export…')
    }

    // T66/T65 — propagate known identities, then auto-remediate residual leaks.
    let plan = input.plan
    const published = getSharedMappingClient().getPublishedSnapshot() ?? undefined
    if (
      (input.leakOriginals && input.leakOriginals.length > 0)
      || (published && plan.identityPropagation === undefined)
    ) {
      progress('rewriting', 0, total, 'Doplňuji náhrady a kontroluji úniky…')
      const remediated = await hydrateAndRemediatePlan({
        plan,
        descriptors: input.descriptors,
        sourceBlob: input.sourceBlob,
        originals: input.leakOriginals ?? [],
        mappingSnapshot: published,
      })
      plan = remediated.plan
      token.throwIfCancelled()
    }

    const exportInput: IncrementalExportInput = {
      plan,
      descriptors: input.descriptors,
      sourceBlob: input.sourceBlob,
      baselineIssues: input.baselineIssues ?? [],
      expectedGenerationId: generationId,
      expectedProfileHash: plan.profileHash,
      isCancelled: () => token.cancelled || !bridge.isActive(generationId),
      onProgress: (p: IncrementalExportProgress) => {
        if (p.phase === 'rewriting') progress('rewriting', p.packetsDone, p.packetsTotal, 'Přepisuji pakety…')
        else if (p.phase === 'checksums') progress('checksums', p.packetsDone, p.packetsTotal, 'Počítám checksumy…')
        else if (p.phase === 'assembling') progress('assembling', p.packetsDone, p.packetsTotal, 'Sestavuji capture…')
        else if (p.phase === 'validating') progress('validating', p.packetsDone, p.packetsTotal, 'Ověřuji strukturu…')
        else if (p.phase === 'binding') progress('binding', p.packetsDone, p.packetsTotal, 'Vazba recovery…')
        else if (p.phase === 'writing-recovery') {
          progress('writing-recovery', p.packetsDone, p.packetsTotal, 'Vytvářím soubor pro obnovu…')
        }
      },
      deliverChunk: async (chunk: ArrayBuffer) => {
        token.throwIfCancelled()
        return bridge.writeAnonymized(chunk, generationId)
      },
      recovery: recoveryEnabled
        ? {
            enabled: true,
            indexSeed: input.recovery!.indexSeed,
            ...(input.recovery!.copyAnon === true ? { copyAnon: true } : {}),
          }
        : undefined,
      deliverRecoveryChunk:
        recoveryEnabled && bridge.writeRecovery
          ? async (chunk: ArrayBuffer) => {
              token.throwIfCancelled()
              return bridge.writeRecovery!(chunk, generationId)
            }
          : undefined,
    }

    progress('rewriting', 0, total, 'Přepisuji pakety…')
    if (recoveryEnabled && typeof Worker === 'undefined') {
      await bridge.abort()
      throw new Error('Recovery export requires Worker')
    }
    const built =
      typeof Worker !== 'undefined'
        ? await buildIncrementalExportViaWorker(exportInput)
        : await runIncrementalExport(exportInput)

    token.throwIfCancelled()
    if (!bridge.isActive(generationId)) {
      throw new CancellationError('PCAP export cancelled')
    }

    if (!built.validationValid) {
      await bridge.abort()
      throw new PcapExportValidationError(built.validation.newBlockingIssues.length)
    }

    const finalized = await bridge.finalize()
    token.throwIfCancelled()

    const safeRecoveryCreated =
      recoveryEnabled
      && finalized.recoveryCreated === true
      && built.recoveryCreated === true
      && (finalized.recovery?.byteLength ?? 0) > 0

    if (recoveryEnabled && !safeRecoveryCreated) {
      throw new Error('Recovery sidecar was not created')
    }

    const privacyInput: BuildPrivacyReportInput | undefined =
      input.profile && input.policy
        ? {
            plan,
            profile: input.profile,
            policy: input.policy,
            coverage: input.coverage,
            unsafeExportAcknowledged: input.unsafeExportAcknowledged === true,
          }
        : undefined

    const report = buildSafeReport(
      plan,
      {
        fileName: built.fileName,
        changedPackets: built.changedPackets,
        truncatedPayloads: built.truncatedPayloads,
        checksumReport: built.checksumReport,
        validation: built.validation,
        recoveryCreated: safeRecoveryCreated,
        leakOriginals: input.leakOriginals,
        anonymizedBytes:
          input.leakOriginals && input.leakOriginals.length > 0 && finalized.anonymized.blob
            ? new Uint8Array(await finalized.anonymized.blob.arrayBuffer())
            : undefined,
        droppedMetadataBlocks: input.droppedMetadataBlocks,
        issues: input.issues,
      },
      input.unsupportedLayers,
      input.protocolCoverage,
      privacyInput,
    )
    const reportJson = JSON.stringify(report, null, 2)
    assertReportHasNoOriginalIdentifiers(reportJson)
    const rptName = reportFileName(built.fileName)

    const aiManifest = buildAiDiagnosticsManifest({
      plan: input.plan,
      protocolCoverage: input.protocolCoverage,
      unsupportedLayers: input.unsupportedLayers,
      checksumCounts: built.checksumReport.counts,
      validationValid: built.validation.validationValid,
      newBlockingIssueCount: built.validation.newBlockingIssues.length,
      requiresUnsafeConfirmation: report.privacy?.requiresUnsafeConfirmation,
      unsafeExportAcknowledged: report.privacy?.unsafeExportAcknowledged,
      gate: report.gate,
      exportAllowed: report.exportAllowed,
      safeForAi: report.safeForAi,
      diagnosticResidualRisk: report.diagnosticResidualRisk,
      leakFindings: report.leakFindings,
      privacy: report.privacy,
    })
    const aiDiagnosticsJson = JSON.stringify(aiManifest, null, 2)
    assertReportHasNoOriginalIdentifiers(aiDiagnosticsJson)
    const aiName = aiDiagnosticsFileName(built.fileName)

    const outputBlob = finalized.anonymized.blob
    const recoveryBlob = finalized.recovery?.blob
    if (outputBlob && !input.skipAutoDownload) {
      triggerBlobDownload(outputBlob, finalized.anonymized.fileName)
      const reportBlob = new Blob([reportJson], { type: 'application/json' })
      triggerBlobDownload(reportBlob, rptName)
      const aiBlob = new Blob([aiDiagnosticsJson], { type: 'application/json' })
      triggerBlobDownload(aiBlob, aiName)
      if (recoveryBlob && finalized.recovery) {
        triggerBlobDownload(recoveryBlob, finalized.recovery.fileName)
      }
    }

    progress('done', total, total, 'Export dokončen')

    return {
      fileName: finalized.anonymized.fileName,
      byteLength: finalized.anonymized.byteLength,
      reportFileName: rptName,
      reportJson,
      aiDiagnosticsFileName: aiName,
      aiDiagnosticsJson,
      usedFileSystemAccess: partialFilePossible,
      partialFilePossible,
      blob: outputBlob,
      recoveryCreated: safeRecoveryCreated,
      recoveryFileName: finalized.recovery?.fileName,
      recoveryBlob,
      recoveryByteLength: finalized.recovery?.byteLength,
    }
  } catch (err) {
    await bridge.abort()
    if (err instanceof CancellationError) {
      progress(
        'cancelled',
        0,
        0,
        partialFilePossible
          ? 'Export zrušen — prohlížeč mohl zanechat neúplný soubor.'
          : 'Export zrušen.',
      )
      throw new PcapExportCancelledError()
    }
    if (err instanceof PcapExportValidationError) {
      progress('error', 0, 0, 'Export selhal — validace odhalila novou strukturální chybu. Zkuste export znovu.')
      throw err
    }
    progress('error', 0, 0, err instanceof Error ? err.message : 'Export selhal')
    throw err
  } finally {
    if (activeExportToken === token) activeExportToken = null
    if (activeSinkCoordinator) activeSinkCoordinator = null
    if (activeDualBridge === bridge) activeDualBridge = null
  }
}
