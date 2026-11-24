/**
 * MappingWorkerClient — main-thread client for worker-owned MappingAuthority (Stage 7).
 */

import type { CustomRule } from '../domain/types'
import {
  DEFAULT_MAPPING_CONFIG,
  type MappingConfig,
} from '../pcap/anonymization/mapping'
import {
  MAPPING_PROTOCOL_VERSION,
  MAPPING_WORKER_ERROR,
  snapshotFromWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
  type WireCanonicalIdentity,
  type WireReverseLookupCandidate,
} from './protocol'
import type { CanonicalIdentity, CorrelationResolveOptions, MappingSessionSnapshot, MappingSnapshot, OccurrenceRef, ReleaseOccurrenceResult } from './types'
import type { IdentityCategory } from './identityCategories'
import type { ReverseLookupCandidate } from './reverseIndex'

export type MappingClientStatus = 'idle' | 'running' | 'cancelling' | 'unavailable'

export interface WorkerLike {
  postMessage(message: unknown, transfer?: Transferable[]): void
  terminate(): void
  addEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
}

export type WorkerFactory = () => WorkerLike

function defaultWorkerFactory(): WorkerLike {
  return new Worker(new URL('../workers/mapping.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as WorkerLike
}

let requestCounter = 0

export function nextMappingRequestId(): string {
  requestCounter += 1
  return `map-${requestCounter}-${Date.now().toString(36)}`
}

export class MappingWorkerClient {
  private worker: WorkerLike | null = null
  private status: MappingClientStatus = 'idle'
  private activeGenerationId: string | null = null
  private activeRequestId: string | null = null
  private publishedSnapshot: MappingSessionSnapshot | null = null
  private publishedRevision = 0
  private resolvePending: ((snapshot: MappingSnapshot) => void) | null = null
  private rejectPending: ((err: Error) => void) | null = null
  /** When true, a successful `resolved` response publishes the session snapshot. */
  private pendingPublishesSession = false
  private readonly createWorker: WorkerFactory
  private onMessageBound: (ev: MessageEvent) => void

  constructor(createWorker: WorkerFactory = defaultWorkerFactory) {
    this.createWorker = createWorker
    this.onMessageBound = (ev) => this.onMessage(ev)
  }

  getStatus(): MappingClientStatus {
    return this.status
  }

  getPublishedSnapshot(): MappingSessionSnapshot | null {
    return this.publishedSnapshot
  }

  /** Test-only: publish a session snapshot without going through the worker. */
  setPublishedSnapshotForTests(snapshot: MappingSessionSnapshot | null): void {
    this.publishedSnapshot = snapshot
    this.publishedRevision = snapshot?.mappingRevision ?? 0
  }

  /**
   * Publishes a snapshot built outside the normal resolve() flow — used by the
   * PCAP recovery workspace to inject a reverse mapping (anonymized value →
   * true original) so existing snapshot-driven UI (packet list endpoints,
   * display filters) shows real originals without needing its own code path.
   */
  publishSyntheticSnapshot(snapshot: MappingSessionSnapshot): void {
    this.publishedSnapshot = snapshot
    this.publishedRevision = snapshot.mappingRevision
  }

  getPublishedRevision(): number {
    return this.publishedRevision
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

  async ping(): Promise<number> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')

    const requestId = nextMappingRequestId()
    return new Promise<number>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('ping timeout')), 5000)
      const handler = (ev: MessageEvent<MappingWorkerResponse>) => {
        const msg = ev.data
        if (!msg || msg.requestId !== requestId) return
        clearTimeout(timeout)
        this.worker?.removeEventListener('message', handler)
        if (msg.type === 'pong') resolve(msg.revision)
        else if (msg.type === 'error') reject(new Error(msg.message))
      }
      this.worker!.addEventListener('message', handler)
      this.worker!.postMessage({
        type: 'ping',
        protocolVersion: MAPPING_PROTOCOL_VERSION,
        requestId,
      } satisfies MappingWorkerRequest)
    })
  }

  async resolve(
    generationId: string,
    sourceId: string,
    identities: readonly CanonicalIdentity[],
    config: MappingConfig = DEFAULT_MAPPING_CONFIG,
    customRules: readonly CustomRule[] = [],
  ): Promise<MappingSnapshot> {
    return this.postResolve('resolve', generationId, sourceId, identities, config, customRules)
  }

  /** Stage resolve delta without publishing — commit via commitStaging() (Stage 24). */
  async resolveStaging(
    generationId: string,
    sourceId: string,
    identities: readonly CanonicalIdentity[],
    config: MappingConfig = DEFAULT_MAPPING_CONFIG,
    customRules: readonly CustomRule[] = [],
    correlationOptions?: CorrelationResolveOptions,
  ): Promise<MappingSnapshot> {
    return this.postResolve('resolve-staging', generationId, sourceId, identities, config, customRules, correlationOptions)
  }

  async commitStaging(): Promise<MappingSnapshot> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')

    const requestId = nextMappingRequestId()
    const msg = await this.postAndWait(requestId, {
      type: 'commit-staging',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
    }, (m) => m.type === 'staging-committed' || m.type === 'error')

    if (msg.type === 'error') throw new Error(msg.message)
    if (msg.type !== 'staging-committed') throw new Error('unexpected mapping worker response')

    const snapshot = snapshotFromWire(msg.snapshot)
    if (snapshot.scope !== 'session') {
      throw new Error('commitStaging must publish a session-scoped snapshot')
    }
    this.publishedSnapshot = snapshot
    this.publishedRevision = snapshot.revision
    return snapshot
  }

  async abortStaging(): Promise<void> {
    this.ensureWorker()
    if (!this.worker) return

    const requestId = nextMappingRequestId()
    await this.postAndWait(requestId, {
      type: 'abort-staging',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
    }, (m) => m.type === 'staging-aborted' || m.type === 'error')
  }

  private async postResolve(
    type: 'resolve' | 'resolve-staging',
    generationId: string,
    sourceId: string,
    identities: readonly CanonicalIdentity[],
    config: MappingConfig,
    customRules: readonly CustomRule[],
    correlationOptions?: CorrelationResolveOptions,
  ): Promise<MappingSnapshot> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')

    if (this.activeGenerationId && this.activeGenerationId !== generationId) {
      throw new Error(MAPPING_WORKER_ERROR.invalidMessage)
    }

    const requestId = nextMappingRequestId()
    this.activeGenerationId = generationId
    this.activeRequestId = requestId
    this.status = 'running'
    this.pendingPublishesSession = type === 'resolve'

    const wireIdentities: WireCanonicalIdentity[] = identities.map((id) => ({
      category: id.category,
      canonical: id.canonical,
      constraint: id.constraint as WireCanonicalIdentity['constraint'],
      originalSpelling: id.originalSpelling,
      source: id.source,
      occurrence: id.occurrence,
      portFlowHint: id.portFlowHint,
      mediaMateCanonical: id.mediaMateCanonical,
    }))

    return new Promise<MappingSnapshot>((resolve, reject) => {
      this.resolvePending = resolve
      this.rejectPending = reject
      this.worker!.postMessage({
        type,
        protocolVersion: MAPPING_PROTOCOL_VERSION,
        requestId,
        generationId,
        sourceId,
        config,
        identities: wireIdentities,
        customRules: customRules.length > 0 ? [...customRules] : undefined,
        correlationOptions,
      } satisfies MappingWorkerRequest)
    })
  }

  cancel(generationId: string): void {
    if (!this.worker || !this.activeGenerationId) return
    this.status = 'cancelling'
    const requestId = nextMappingRequestId()
    this.worker.postMessage({
      type: 'cancel',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
      generationId,
    } satisfies MappingWorkerRequest)
  }

  /** Hard terminate — releases worker and client-side snapshot references (Stage 19). */
  terminate(): void {
    if (!this.worker) {
      this.publishedSnapshot = null
      this.publishedRevision = 0
      return
    }
    this.worker.removeEventListener('message', this.onMessageBound)
    this.worker.terminate()
    this.worker = null
    this.status = 'idle'
    this.activeGenerationId = null
    this.activeRequestId = null
    this.resolvePending = null
    this.rejectPending = null
    this.publishedSnapshot = null
    this.publishedRevision = 0
  }

  async resetSession(): Promise<void> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')
    const requestId = nextMappingRequestId()
    await this.postAndWait(requestId, {
      type: 'reset-session',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
    }, (msg) => msg.type === 'session-reset')
    this.publishedSnapshot = null
    this.publishedRevision = 0
  }

  async lookupByOriginal(category: IdentityCategory, canonical: string): Promise<readonly ReverseLookupCandidate[]> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')
    const requestId = nextMappingRequestId()
    const msg = await this.postAndWait(requestId, {
      type: 'lookup-original',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
      category,
      canonical,
    }, (m) => m.type === 'lookup-result' || m.type === 'error')
    if (msg.type === 'error') throw new Error(msg.message)
    if (msg.type !== 'lookup-result') throw new Error('unexpected mapping worker response')
    return msg.candidates.map((c: WireReverseLookupCandidate) => ({
      identityId: c.identityId,
      category: c.category,
      canonical: c.canonical,
      alias: c.alias,
      fingerprint: c.fingerprint,
      disposition: c.disposition,
      occurrences: [],
    }))
  }

  async lookupByAlias(alias: string): Promise<readonly ReverseLookupCandidate[]> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')
    const requestId = nextMappingRequestId()
    const msg = await this.postAndWait(requestId, {
      type: 'lookup-alias',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
      alias,
    }, (m) => m.type === 'lookup-result' || m.type === 'error')
    if (msg.type === 'error') throw new Error(msg.message)
    if (msg.type !== 'lookup-result') throw new Error('unexpected mapping worker response')
    return msg.candidates.map((c: WireReverseLookupCandidate) => ({
      identityId: c.identityId,
      category: c.category,
      canonical: c.canonical,
      alias: c.alias,
      fingerprint: c.fingerprint,
      disposition: c.disposition,
      occurrences: [],
    }))
  }

  async releaseOccurrence(
    category: IdentityCategory,
    canonical: string,
    occurrence: OccurrenceRef,
  ): Promise<ReleaseOccurrenceResult> {
    this.ensureWorker()
    if (!this.worker) throw new Error('Mapping worker unavailable')
    const requestId = nextMappingRequestId()
    const wireOccurrence = occurrence.kind === 'text'
      ? { kind: 'text' as const, sourceId: occurrence.sourceId, line: occurrence.line, start: occurrence.start, end: occurrence.end }
      : { kind: 'packet' as const, sourceId: occurrence.sourceId, packetIndex: occurrence.packetIndex }
    const msg = await this.postAndWait(requestId, {
      type: 'release-occurrence',
      protocolVersion: MAPPING_PROTOCOL_VERSION,
      requestId,
      category,
      canonical,
      occurrence: wireOccurrence,
    }, (m) => m.type === 'occurrence-released' || m.type === 'error')
    if (msg.type === 'error') {
      return { ok: false, code: msg.code as ReleaseOccurrenceResult extends { ok: false; code: infer C } ? C : never, message: msg.message }
    }
    if (msg.type !== 'occurrence-released') throw new Error('unexpected mapping worker response')
    this.publishedRevision = msg.mappingRevision
    if (msg.snapshot) {
      const snap = snapshotFromWire(msg.snapshot)
      if (snap.scope === 'session') {
        this.publishedSnapshot = snap
      }
    }
    return { ok: true, mappingRevision: msg.mappingRevision, scrubbed: msg.scrubbed }
  }

  private postAndWait(
    requestId: string,
    request: MappingWorkerRequest,
    match: (msg: MappingWorkerResponse) => boolean,
  ): Promise<MappingWorkerResponse> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.worker?.removeEventListener('message', handler)
        reject(new Error('mapping worker request timeout'))
      }, 30_000)
      const handler = (ev: MessageEvent<MappingWorkerResponse>) => {
        const msg = ev.data
        if (!msg || msg.requestId !== requestId) return
        if (!match(msg)) return
        clearTimeout(timeout)
        this.worker?.removeEventListener('message', handler)
        resolve(msg)
      }
      this.worker!.addEventListener('message', handler)
      this.worker!.postMessage(request)
    })
  }

  private onMessage(ev: MessageEvent<MappingWorkerResponse>): void {
    const msg = ev.data
    if (!msg) return

    if (msg.type === 'error') {
      if (msg.requestId !== this.activeRequestId) return
      if (msg.generationId && msg.generationId !== this.activeGenerationId) return

      this.status = 'idle'
      this.activeRequestId = null
      this.activeGenerationId = null
      const reject = this.rejectPending
      this.rejectPending = null
      this.resolvePending = null
      reject?.(new Error(msg.message))
      return
    }

    if (msg.type === 'resolved' || msg.type === 'staging-preview') {
      if (msg.requestId !== this.activeRequestId) return
      if (msg.generationId !== this.activeGenerationId) return

      const snapshot = snapshotFromWire(msg.snapshot)
      if (msg.type === 'resolved' && this.pendingPublishesSession && snapshot.scope === 'session') {
        this.publishedSnapshot = snapshot
        this.publishedRevision = snapshot.revision
      }
      this.pendingPublishesSession = false
      this.status = 'idle'
      this.activeRequestId = null
      this.activeGenerationId = null

      const resolve = this.resolvePending
      this.resolvePending = null
      this.rejectPending = null
      resolve?.(snapshot)
      return
    }

    if (msg.type === 'pong') {
      // ping/cancel ack — no client state change beyond cancelling flag
      if (this.status === 'cancelling') {
        this.status = 'idle'
        this.activeRequestId = null
        this.activeGenerationId = null
        const reject = this.rejectPending
        this.rejectPending = null
        this.resolvePending = null
        reject?.(new Error('cancelled'))
      }
    }
  }
}
