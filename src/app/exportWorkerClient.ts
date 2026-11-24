/**
 * Export Worker client (ARCHITECTURE §8 / Krok 9).
 */

import type {
  ExportWorkerRequest,
  ExportWorkerResponse,
  ReplacementSnapshot,
  RequestId,
} from '../workers/protocol.ts'
import { EXPORT_PROTOCOL_VERSION } from '../workers/protocol.ts'

export type ExportWorkerLike = {
  postMessage(message: unknown, transfer?: Transferable[]): void
  terminate(): void
  addEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
}

export function createExportWorker(): ExportWorkerLike {
  return new Worker(new URL('../workers/export.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as ExportWorkerLike
}

export class ExportWorkerClient {
  private worker: ExportWorkerLike | null = null
  private requestId: RequestId | null = null

  ensure(): void {
    if (!this.worker) this.worker = createExportWorker()
  }

  start(requestId: RequestId, snapshot: ReplacementSnapshot): void {
    this.ensure()
    this.requestId = requestId
    const msg: ExportWorkerRequest = {
      type: 'start-export',
      protocolVersion: EXPORT_PROTOCOL_VERSION,
      requestId,
      replacementSnapshot: snapshot,
    }
    this.worker!.postMessage(msg)
  }

  postChunk(msg: ExportWorkerRequest, transfer?: Transferable[]): void {
    this.ensure()
    if (transfer && transfer.length > 0) {
      this.worker!.postMessage(msg, transfer)
    } else {
      this.worker!.postMessage(msg)
    }
  }

  cancel(): void {
    if (this.worker && this.requestId) {
      this.worker.postMessage({
        type: 'cancel',
        protocolVersion: EXPORT_PROTOCOL_VERSION,
        requestId: this.requestId,
      } satisfies ExportWorkerRequest)
    }
    this.dispose()
  }

  dispose(): void {
    this.worker?.terminate()
    this.worker = null
    this.requestId = null
  }

  onMessage(listener: (msg: ExportWorkerResponse) => void): () => void {
    this.ensure()
    const handler = (ev: MessageEvent) => listener(ev.data as ExportWorkerResponse)
    this.worker!.addEventListener('message', handler)
    return () => this.worker?.removeEventListener('message', handler)
  }
}
