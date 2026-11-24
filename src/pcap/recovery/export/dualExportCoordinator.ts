/**
 * DualExportCoordinator — atomic anonymized + recovery sink lifecycle (step 5).
 *
 * Hashing and plaintext recovery framing stay inside the export worker (no React/Zustand).
 * This coordinator only owns sinks, cancel/abort pairing, and finalize atomicity.
 */

import { CancellationError } from '../../capture/cancellation'
import { ExportSinkCoordinator } from '../../export/sinkCoordinator'
import {
  BlobExportSink,
  createDirectoryFileSink,
  pickExportDirectory,
  type ExportSink,
} from '../../export/sinks'
import type {
  DualSinkExportBridge,
  DualSinkFinalizeResult,
  ExportFinalizeResult,
} from '../../export/dualSinkBridge'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'

export function recoverySidecarFileName(anonymizedFileName: string): string {
  return `${anonymizedFileName}${PCAP_RECOVERY_LIMITS.fileExtension}`
}

export type DualExportOpenOptions = {
  readonly generationId: string
  readonly anonymizedFileName: string
  readonly recoveryEnabled: boolean
  /** Pre-selected anonymized sink (correlation / tests). */
  readonly anonymizedSink?: ExportSink
  /** Prefer directory picker when both files are written (FS Access). */
  readonly preferDirectory?: boolean
}

export class DualExportCoordinator implements DualSinkExportBridge {
  readonly generationId: string
  readonly recoveryEnabled: boolean
  readonly recoveryFileName: string
  readonly partialFilePossible: boolean

  private readonly anonymized: ExportSinkCoordinator
  private readonly recovery: ExportSinkCoordinator | null
  private _pairComplete = false
  private _failed = false

  private constructor(input: {
    generationId: string
    recoveryEnabled: boolean
    recoveryFileName: string
    partialFilePossible: boolean
    anonymized: ExportSinkCoordinator
    recovery: ExportSinkCoordinator | null
  }) {
    this.generationId = input.generationId
    this.recoveryEnabled = input.recoveryEnabled
    this.recoveryFileName = input.recoveryFileName
    this.partialFilePossible = input.partialFilePossible
    this.anonymized = input.anonymized
    this.recovery = input.recovery
  }

  /** True only after both required sinks finalized without cancel/error. */
  get pairComplete(): boolean {
    return this._pairComplete && !this._failed
  }

  get failed(): boolean {
    return this._failed
  }

  static async open(options: DualExportOpenOptions): Promise<DualExportCoordinator> {
    const anonymizedCoord = new ExportSinkCoordinator(options.generationId)
    const recoveryFileName = recoverySidecarFileName(options.anonymizedFileName)
    let recoveryCoord: ExportSinkCoordinator | null = null
    let partialFilePossible = false

    if (options.anonymizedSink) {
      anonymizedCoord.attachSink(options.anonymizedSink)
      partialFilePossible = options.anonymizedSink.kind === 'file-system-access'
      if (options.recoveryEnabled) {
        recoveryCoord = new ExportSinkCoordinator(options.generationId)
        recoveryCoord.attachSink(new BlobExportSink(recoveryFileName))
      }
    } else if (options.recoveryEnabled && options.preferDirectory) {
      const dir = await pickExportDirectory()
      if (dir) {
        const anonSink = await createDirectoryFileSink(dir, options.anonymizedFileName)
        const recSink = await createDirectoryFileSink(dir, recoveryFileName)
        anonymizedCoord.attachSink(anonSink)
        recoveryCoord = new ExportSinkCoordinator(options.generationId)
        recoveryCoord.attachSink(recSink)
        partialFilePossible = true
      } else {
        anonymizedCoord.attachSink(new BlobExportSink(options.anonymizedFileName))
        recoveryCoord = new ExportSinkCoordinator(options.generationId)
        recoveryCoord.attachSink(new BlobExportSink(recoveryFileName))
      }
    } else {
      anonymizedCoord.attachSink(new BlobExportSink(options.anonymizedFileName))
      if (options.recoveryEnabled) {
        recoveryCoord = new ExportSinkCoordinator(options.generationId)
        recoveryCoord.attachSink(new BlobExportSink(recoveryFileName))
      }
    }

    return new DualExportCoordinator({
      generationId: options.generationId,
      recoveryEnabled: options.recoveryEnabled,
      recoveryFileName,
      partialFilePossible,
      anonymized: anonymizedCoord,
      recovery: recoveryCoord,
    })
  }

  cancel(): void {
    this._failed = true
    this.anonymized.cancel()
    this.recovery?.cancel()
  }

  isActive(generationId?: string): boolean {
    if (this._failed) return false
    if (!this.anonymized.isActive(generationId)) return false
    if (this.recovery && !this.recovery.isActive(generationId)) return false
    return true
  }

  async writeAnonymized(chunk: ArrayBuffer, generationId: string): Promise<boolean> {
    if (this._failed) return false
    return this.anonymized.writeChunk(chunk, generationId)
  }

  async writeRecovery(chunk: ArrayBuffer, generationId: string): Promise<boolean> {
    if (this._failed || !this.recovery) return false
    return this.recovery.writeChunk(chunk, generationId)
  }

  async abort(): Promise<void> {
    this._failed = true
    this._pairComplete = false
    await Promise.all([this.anonymized.abort(), this.recovery?.abort() ?? Promise.resolve()])
  }

  async finalize(): Promise<DualSinkFinalizeResult> {
    if (this._failed || this.anonymized.cancelled) {
      throw new CancellationError('Export cancelled')
    }
    let anonymized: ExportFinalizeResult
    try {
      anonymized = await this.anonymized.finalize()
    } catch (err) {
      this._failed = true
      await this.recovery?.abort()
      throw err
    }

    if (!this.recovery) {
      this._pairComplete = true
      return { anonymized, recoveryCreated: false }
    }

    try {
      if (this.recovery.cancelled || this._failed) {
        throw new CancellationError('Export cancelled')
      }
      const recovery = await this.recovery.finalize()
      this._pairComplete = true
      return { anonymized, recovery, recoveryCreated: true }
    } catch (err) {
      this._failed = true
      this._pairComplete = false
      // Anonymized may already be on disk (FS) — never advertise a completed pair.
      throw err
    }
  }
}
