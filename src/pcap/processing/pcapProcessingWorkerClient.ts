/**
 * PCAP processing worker client (Stage 8).
 */

import { CaptureFormat } from '../domain/types'
import type { SanitizationPolicy } from '../sanitize/types'
import type { PcapProfile } from '../profile/schema'
import type { MappingSnapshot } from '../../mapping/types'
import { snapshotToWire } from '../../mapping/protocol'
import {
  PCAP_PROCESSING_PROTOCOL_VERSION,
  PCAP_PROCESSING_WORKER_ERROR,
  type PcapProcessingWorkerRequest,
  type PcapProcessingWorkerResponse,
  type WireSourceDiscoveryPayload,
} from './workerProtocol'
import type { WireContainerMetadata } from './containerWireAdapter'
import type { WireClassicHeader, WirePlanSnapshot } from '../export/workerProtocol'

export type ProcessingClientStatus = 'idle' | 'running' | 'cancelling' | 'unavailable'

export interface WorkerLike {
  postMessage(message: unknown, transfer?: Transferable[]): void
  terminate(): void
  addEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
}

export type WorkerFactory = () => WorkerLike

function defaultWorkerFactory(): WorkerLike {
  return new Worker(new URL('../../workers/pcap-processing.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as WorkerLike
}

let requestCounter = 0

export function nextProcessingRequestId(): string {
  requestCounter += 1
  return `pcap-proc-${requestCounter}-${Date.now().toString(36)}`
}

export class PcapProcessingWorkerClient {
  private worker: WorkerLike | null = null
  private status: ProcessingClientStatus = 'idle'
  private activeGenerationId: string | null = null
  private activeRequestId: string | null = null
  private readonly createWorker: WorkerFactory
  private onMessageBound: (ev: MessageEvent) => void
  private resolveDiscover: ((d: { discovery: WireSourceDiscoveryPayload; container: WireContainerMetadata }) => void) | null = null
  private rejectDiscover: ((e: Error) => void) | null = null
  private resolvePlan: ((p: WirePlanSnapshot) => void) | null = null
  private rejectPlan: ((e: Error) => void) | null = null
  private onProgress: ((phase: string, done: number, total: number) => void) | null = null

  constructor(createWorker: WorkerFactory = defaultWorkerFactory) {
    this.createWorker = createWorker
    this.onMessageBound = (ev) => this.onMessage(ev)
  }

  getStatus(): ProcessingClientStatus {
    return this.status
  }

  ensureWorker(): void {
    if (this.worker) return
    try {
      this.worker = this.createWorker()
      this.worker.addEventListener('message', this.onMessageBound)
      this.status = 'idle'
    } catch {
      this.status = 'unavailable'
    }
  }

  async processCapture(input: {
    generationId: string
    sourceId: string
    format: CaptureFormat
    policy: SanitizationPolicy
    blob: Blob
    batchSize?: number
    onProgress?: (phase: string, done: number, total: number) => void
  }): Promise<{ discovery: WireSourceDiscoveryPayload; container: WireContainerMetadata }> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Processing worker unavailable')

    const requestId = nextProcessingRequestId()
    this.activeGenerationId = input.generationId
    this.activeRequestId = requestId
    this.status = 'running'
    this.onProgress = input.onProgress ?? null

    return new Promise((resolve, reject) => {
      this.resolveDiscover = (d) => resolve(d)
      this.rejectDiscover = reject
      this.worker!.postMessage({
        type: 'process',
        protocolVersion: PCAP_PROCESSING_PROTOCOL_VERSION,
        requestId,
        generationId: input.generationId,
        sourceId: input.sourceId,
        format: input.format,
        policy: input.policy,
        blob: input.blob,
        batchSize: input.batchSize,
      } satisfies PcapProcessingWorkerRequest)
    })
  }

  async buildPlan(input: {
    generationId: string
    profile: PcapProfile
    format: CaptureFormat
    fileName: string
    snapshot: MappingSnapshot
    classicHeader?: WireClassicHeader
    pcapngSections?: WirePlanSnapshot['pcapngSections']
    pcapngInterfaces?: WirePlanSnapshot['pcapngInterfaces']
    unresolvedClosureFailures?: readonly import('./workerProtocol').WireClosureFailure[]
    onProgress?: (phase: string, done: number, total: number) => void
  }): Promise<WirePlanSnapshot> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Processing worker unavailable')

    const requestId = nextProcessingRequestId()
    this.activeGenerationId = input.generationId
    this.activeRequestId = requestId
    this.status = 'running'
    this.onProgress = input.onProgress ?? null

    return new Promise((resolve, reject) => {
      this.resolvePlan = resolve
      this.rejectPlan = reject
      this.worker!.postMessage({
        type: 'build-plan',
        protocolVersion: PCAP_PROCESSING_PROTOCOL_VERSION,
        requestId,
        generationId: input.generationId,
        profile: input.profile,
        format: input.format,
        fileName: input.fileName,
        snapshot: snapshotToWire(input.snapshot),
        classicHeader: input.classicHeader,
        pcapngSections: input.pcapngSections,
        pcapngInterfaces: input.pcapngInterfaces,
        unresolvedClosureFailures: input.unresolvedClosureFailures,
      } satisfies PcapProcessingWorkerRequest)
    })
  }

  cancel(generationId: string): void {
    if (!this.worker) return
    this.status = 'cancelling'
    this.worker.postMessage({
      type: 'cancel',
      protocolVersion: PCAP_PROCESSING_PROTOCOL_VERSION,
      requestId: nextProcessingRequestId(),
      generationId,
    } satisfies PcapProcessingWorkerRequest)
  }

  terminate(): void {
    const error = new Error('Processing worker terminated')
    this.rejectDiscover?.(error)
    this.rejectPlan?.(error)
    if (this.worker) {
      this.worker.removeEventListener('message', this.onMessageBound)
      this.worker.terminate()
    }
    this.worker = null
    this.status = 'idle'
    this.activeGenerationId = null
    this.activeRequestId = null
    this.resolveDiscover = null
    this.rejectDiscover = null
    this.resolvePlan = null
    this.rejectPlan = null
    this.onProgress = null
  }

  private onMessage(ev: MessageEvent<PcapProcessingWorkerResponse>): void {
    const msg = ev.data
    if (!msg) return

    if (msg.type === 'progress') {
      if (msg.requestId !== this.activeRequestId) return
      if (msg.generationId !== this.activeGenerationId) return
      this.onProgress?.(msg.phase, msg.packetsDone, msg.packetsTotal)
      return
    }

    if (msg.type === 'error') {
      if (msg.requestId !== this.activeRequestId) return
      this.status = 'idle'
      this.activeRequestId = null
      const err = new Error(msg.message)
      this.rejectDiscover?.(err)
      this.rejectPlan?.(err)
      this.resolveDiscover = null
      this.rejectDiscover = null
      this.resolvePlan = null
      this.rejectPlan = null
      this.onProgress = null
      return
    }

    if (msg.type === 'discovered') {
      if (msg.requestId !== this.activeRequestId) return
      if (msg.generationId !== this.activeGenerationId) return
      this.status = 'idle'
      this.activeRequestId = null
      this.resolveDiscover?.({ discovery: msg.discovery, container: msg.container })
      this.resolveDiscover = null
      this.rejectDiscover = null
      this.onProgress = null
      return
    }

    if (msg.type === 'plan-built') {
      if (msg.requestId !== this.activeRequestId) return
      if (msg.generationId !== this.activeGenerationId) return
      this.status = 'idle'
      this.activeRequestId = null
      this.resolvePlan?.(msg.plan)
      this.resolvePlan = null
      this.rejectPlan = null
      this.onProgress = null
      return
    }
  }
}

export { PCAP_PROCESSING_WORKER_ERROR }
