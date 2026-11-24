/**
 * Shared conformance test primitives (Stage 16).
 * Reused by text/PCAP worker port tests; Stage 23 builds full SourceAdapter suite.
 */

import { expect } from 'vitest'
import type { WorkerLike } from '../../src/app/workerClient.ts'
import {
  DETECTION_PROTOCOL_VERSION,
  EXPORT_PROTOCOL_VERSION,
  type DetectionWorkerRequest,
  type DetectionWorkerResponse,
  type ExportWorkerRequest,
  type ExportWorkerResponse,
} from '../../src/workers/protocol.ts'
import { WORKER_ERROR } from '../../src/workers/protocol.ts'
import {
  MAPPING_PROTOCOL_VERSION,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from '../../src/mapping/protocol.ts'
import {
  PCAP_PROCESSING_PROTOCOL_VERSION,
  type PcapProcessingWorkerRequest,
} from '../../src/pcap/processing/workerProtocol.ts'
import { PCAP_EXPORT_PROTOCOL_VERSION } from '../../src/pcap/export/workerProtocol.ts'

export interface ConformanceMessageTap {
  readonly posted: unknown[]
  readonly responses: unknown[]
}

export function createMessageTap(worker: WorkerLike): ConformanceMessageTap {
  const posted: unknown[] = []
  const responses: unknown[] = []
  const original = worker.postMessage.bind(worker)
  worker.postMessage = (message: unknown, transfer?: Transferable[]) => {
    posted.push(message)
    original(message, transfer)
  }
  worker.addEventListener('message', (ev) => {
    responses.push(ev.data)
  })
  return { posted, responses }
}

export function expectStaleResponseIgnored<T extends { requestId: string }>(
  activeRequestId: string,
  response: T,
): void {
  expect(response.requestId).not.toBe(activeRequestId)
}

export function expectWorkerErrorCode(
  response: { code?: string },
  code: string,
): void {
  expect(response.code).toBe(code)
}

export function detectionStartMessage(requestId: string, profile: DetectionWorkerRequest extends { type: 'start-detection' } ? DetectionWorkerRequest['profile'] : never): DetectionWorkerRequest {
  return {
    type: 'start-detection',
    protocolVersion: DETECTION_PROTOCOL_VERSION,
    requestId,
    profile,
  }
}

export function exportStartMessage(
  requestId: string,
  replacementSnapshot: ExportWorkerRequest extends { type: 'start-export' } ? ExportWorkerRequest['replacementSnapshot'] : never,
): ExportWorkerRequest {
  return {
    type: 'start-export',
    protocolVersion: EXPORT_PROTOCOL_VERSION,
    requestId,
    replacementSnapshot,
  }
}

export function mappingPingMessage(requestId: string): MappingWorkerRequest {
  return {
    type: 'ping',
    protocolVersion: MAPPING_PROTOCOL_VERSION,
    requestId,
  }
}

export const WORKER_PROTOCOL_VERSIONS = {
  detection: DETECTION_PROTOCOL_VERSION,
  export: EXPORT_PROTOCOL_VERSION,
  mapping: MAPPING_PROTOCOL_VERSION,
  pcapProcessing: PCAP_PROCESSING_PROTOCOL_VERSION,
  pcapExport: PCAP_EXPORT_PROTOCOL_VERSION,
} as const

export function expectVersionedRequest(msg: Record<string, unknown>): void {
  expect(typeof msg.protocolVersion).toBe('number')
  expect(msg.protocolVersion).toBeGreaterThan(0)
}

export function expectCancelledError(response: DetectionWorkerResponse | ExportWorkerResponse): void {
  if (response.type !== 'error') {
    throw new Error(`Expected error response, got ${response.type}`)
  }
  expect(response.code).toBe(WORKER_ERROR.cancelled)
}

export function malformedDetectionChunk(requestId: string): DetectionWorkerRequest {
  return {
    type: 'input-chunk',
    protocolVersion: DETECTION_PROTOCOL_VERSION,
    requestId,
    sequence: 0,
    final: true,
  }
}

export function invalidProtocolVersion<T extends { protocolVersion: number }>(msg: T): T {
  return { ...msg, protocolVersion: 0 }
}

export type VersionedWorkerRequest =
  | DetectionWorkerRequest
  | ExportWorkerRequest
  | MappingWorkerRequest
  | PcapProcessingWorkerRequest

export function assertNoNetworkInConformance(): void {
  if (typeof fetch !== 'undefined') {
    const originalFetch = globalThis.fetch
    globalThis.fetch = (...args) => {
      throw new Error(`Unexpected network fetch in conformance test: ${String(args[0])}`)
    }
    return () => {
      globalThis.fetch = originalFetch
    }
  }
  return () => {}
}
