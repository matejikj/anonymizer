/**
 * Export sink coordinator — generation/cancel gate for streaming writes (Stage 12).
 * UI must not ACK chunks or close writers directly; only this coordinator owns sink lifecycle.
 */

import { CancellationError } from '../capture/cancellation'
import type { ExportSink } from './sinks'

export class ExportSinkCoordinator {
  readonly generationId: string
  private _cancelled = false
  private _sink: ExportSink | null = null

  constructor(generationId: string) {
    this.generationId = generationId
  }

  attachSink(sink: ExportSink): void {
    this._sink = sink
  }

  get sink(): ExportSink | null {
    return this._sink
  }

  get cancelled(): boolean {
    return this._cancelled
  }

  get partialFilePossible(): boolean {
    return this._sink?.kind === 'file-system-access'
  }

  isActive(generationId?: string): boolean {
    if (this._cancelled) return false
    if (generationId !== undefined && generationId !== this.generationId) return false
    return true
  }

  cancel(): void {
    this._cancelled = true
  }

  /** Returns false when the write must be ignored (late chunk after cancel/generation change). */
  async writeChunk(chunk: ArrayBuffer, generationId: string): Promise<boolean> {
    if (!this.isActive(generationId)) return false
    const sink = this._sink
    if (!sink) throw new Error('Export sink not attached')
    await sink.write(chunk)
    return this.isActive(generationId)
  }

  async abort(): Promise<void> {
    this._cancelled = true
    const sink = this._sink
    if (!sink) return
    try {
      await sink.abort()
    } catch {
      // ignore abort errors on already-closed streams
    }
  }

  async finalize(): Promise<{ blob?: Blob; fileName: string; byteLength: number }> {
    if (this._cancelled) throw new CancellationError('Export cancelled')
    const sink = this._sink
    if (!sink) throw new Error('Export sink not attached')
    return sink.finalize()
  }
}
