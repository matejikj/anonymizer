/**
 * Detection Worker client — generation ID, backpressure, cancel, regex watchdog.
 * ARCHITECTURE §7.3 / §8 / Krok 3.
 */

import type { EntitySummary } from '../domain/types.ts'
import type { RulesetConfig } from '../domain/configSchema.ts'
import { createDefaultRulesetConfig } from '../domain/configSchema.ts'
import type {
  DetectionWorkerRequest,
  DetectionWorkerResponse,
  PackedMatchBuffers,
  RequestId,
} from '../workers/protocol.ts'
import { DETECTION_PROTOCOL_VERSION, WORKER_ERROR } from '../workers/protocol.ts'
import { getActivePerfDiagnostics } from '../diagnostics/perfDiagnostics.ts'

export const WATCHDOG_MS = 2_000
export const MAX_IN_FLIGHT_CHUNKS = 2
export const PROGRESS_MIN_INTERVAL_MS = 100 // ≤ ~10/s

export type WorkerClientStatus = 'idle' | 'running' | 'cancelling' | 'unavailable'

export interface DetectionProgressEvent {
  requestId: RequestId
  processedBytes: number
  processedLines: number
}

export interface DetectionResult {
  requestId: RequestId
  packedMatches: PackedMatchBuffers
  entities: EntitySummary[]
  lineCount: number
  failedRuleIds: string[]
  /** T07 — value-free line isolation incidents from detection. */
  incidents?: import('../domain/anonymizationIncident').IncidentLogSnapshot
}

export interface DetectionClientHooks {
  onProgress?: (ev: DetectionProgressEvent) => void
  onRuleStarted?: (ruleId: string) => void
  onStatus?: (status: WorkerClientStatus) => void
}

export interface WorkerLike {
  postMessage(message: unknown, transfer?: Transferable[]): void
  terminate(): void
  addEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (ev: MessageEvent) => void): void
}

export type WorkerFactory = () => WorkerLike

function defaultWorkerFactory(): WorkerLike {
  return new Worker(new URL('../workers/detection.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as WorkerLike
}

let generationCounter = 0

export function nextRequestId(): RequestId {
  generationCounter += 1
  return `det-${generationCounter}-${Date.now().toString(36)}`
}

export class DetectionWorkerClient {
  private worker: WorkerLike | null = null
  private status: WorkerClientStatus = 'idle'
  private activeRequestId: RequestId | null = null
  private inFlight = 0
  private waiters: Array<() => void> = []
  private lastProgressAt = 0
  private lastHeartbeatAt = 0
  private activeRuleId: string | undefined
  private watchdogTimer: ReturnType<typeof setInterval> | null = null
  private failedRuleIds = new Set<string>()
  private detectResolve: ((r: DetectionResult) => void) | null = null
  private detectReject: ((e: Error) => void) | null = null
  private planResolve: ((buffers: import('../workers/protocol.ts').ReplacementPlanBuffers) => void) | null =
    null
  private planReject: ((e: Error) => void) | null = null
  private pendingAccept = new Map<number, () => void>()
  private progressListeners = new Set<(ev: DetectionProgressEvent) => void>()
  private readonly createWorker: WorkerFactory
  private readonly hooks: DetectionClientHooks
  private onMessageBound: (ev: MessageEvent) => void

  constructor(hooks: DetectionClientHooks = {}, createWorker: WorkerFactory = defaultWorkerFactory) {
    this.hooks = hooks
    this.createWorker = createWorker
    this.onMessageBound = (ev) => this.onMessage(ev)
  }

  /** Extra progress subscribers (e.g. streamImport). */
  subscribeProgress(listener: (ev: DetectionProgressEvent) => void): () => void {
    this.progressListeners.add(listener)
    return () => this.progressListeners.delete(listener)
  }

  getStatus(): WorkerClientStatus {
    return this.status
  }

  getFailedRuleIds(): string[] {
    return [...this.failedRuleIds]
  }

  /** Clear isolated-rule state before a fresh import detection run. */
  clearFailedRuleIds(): void {
    this.failedRuleIds.clear()
  }

  /** Ensure a live worker exists. */
  ensureWorker(): void {
    if (this.worker) return
    try {
      this.worker = this.createWorker()
      this.worker.addEventListener('message', this.onMessageBound)
      this.setStatus('idle')
    } catch {
      this.setStatus('unavailable')
      throw new Error('Detection Worker nelze spustit')
    }
  }

  /**
   * Start a new detection generation. Previous in-flight results are ignored.
   */
  begin(profile: RulesetConfig = createDefaultRulesetConfig()): RequestId {
    this.ensureWorker()
    const requestId = nextRequestId()
    this.activeRequestId = requestId
    this.inFlight = 0
    this.waiters = []
    this.pendingAccept.clear()
    this.activeRuleId = undefined
    this.lastHeartbeatAt = Date.now()
    this.lastProgressAt = 0
    this.setStatus('running')
    this.post({ type: 'start-detection', protocolVersion: DETECTION_PROTOCOL_VERSION, requestId, profile })
    this.startWatchdog()
    return requestId
  }

  /**
   * Send an input chunk with backpressure (max 2 in flight).
   * Transfers ArrayBuffer ownership when bytes are provided.
   */
  async sendChunk(
    requestId: RequestId,
    chunk: {
      sequence: number
      bytes?: ArrayBuffer
      byteOffset?: number
      byteLength?: number
      text?: string
      final: boolean
    },
  ): Promise<void> {
    if (requestId !== this.activeRequestId) return
    await this.waitForSlot()
    if (requestId !== this.activeRequestId) return

    this.inFlight += 1
    this.recordInFlightBytes(chunk.bytes?.byteLength ?? chunk.text?.length ?? 0)
    const acceptPromise = new Promise<void>((resolve) => {
      this.pendingAccept.set(chunk.sequence, resolve)
    })

    const msg: DetectionWorkerRequest = {
      type: 'input-chunk',
      protocolVersion: DETECTION_PROTOCOL_VERSION,
      requestId,
      sequence: chunk.sequence,
      bytes: chunk.bytes,
      byteOffset: chunk.byteOffset,
      byteLength: chunk.byteLength,
      text: chunk.text,
      final: chunk.final,
    }
    const transfer: Transferable[] = []
    if (chunk.bytes) transfer.push(chunk.bytes)
    this.post(msg, transfer)

    await acceptPromise
  }

  /** Wait until `detected` for the active request (or error / cancel). */
  waitForResult(requestId: RequestId): Promise<DetectionResult> {
    if (requestId !== this.activeRequestId) {
      return Promise.reject(new Error('Stale requestId'))
    }
    return new Promise<DetectionResult>((resolve, reject) => {
      this.detectResolve = resolve
      this.detectReject = reject
    })
  }

  /**
   * Rebuild replacement plan from an effective entity bitset (ARCHITECTURE §8).
   * Requires the worker session from the last successful detection to still be alive.
   */
  buildPlan(
    requestId: RequestId,
    entityBitset: ArrayBuffer,
  ): Promise<import('../workers/protocol.ts').ReplacementPlanBuffers> {
    if (requestId !== this.activeRequestId || !this.worker) {
      return Promise.reject(new Error('Worker plán nelze sestavit (relace není aktivní)'))
    }
    return new Promise((resolve, reject) => {
      this.planResolve = resolve
      this.planReject = reject
      this.post({ type: 'build-plan', protocolVersion: DETECTION_PROTOCOL_VERSION, requestId, entityBitset }, [entityBitset])
    })
  }

  /** Push MappingAuthority aliases into the live detection session (Stage 18). */
  syncEntityReplacements(
    requestId: RequestId,
    replacements: Record<string, string>,
  ): Promise<void> {
    if (requestId !== this.activeRequestId || !this.worker) {
      return Promise.reject(new Error('Worker relace není aktivní'))
    }
    return new Promise((resolve, reject) => {
      const handler = (ev: MessageEvent) => {
        const msg = ev.data as import('../workers/protocol.ts').DetectionWorkerResponse
        if (!msg || msg.requestId !== requestId) return
        if (msg.type === 'replacements-synced') {
          this.worker?.removeEventListener('message', handler)
          resolve()
        } else if (msg.type === 'error') {
          this.worker?.removeEventListener('message', handler)
          reject(new Error(msg.message))
        }
      }
      this.worker!.addEventListener('message', handler)
      this.post({
        type: 'sync-replacements',
        protocolVersion: DETECTION_PROTOCOL_VERSION,
        requestId,
        replacements,
      })
    })
  }

  getActiveRequestId(): RequestId | null {
    return this.activeRequestId
  }

  /**
   * Hard-cancel: terminate worker, bump generation, spawn a fresh worker.
   * Stale responses from the old worker cannot arrive.
   */
  cancel(): void {
    const prev = this.activeRequestId
    this.activeRequestId = null
    this.setStatus('cancelling')
    this.stopWatchdog()
    this.teardownWorker()
    this.failPending(new Error('Analýza zrušena'))
    this.inFlight = 0
    this.waiters.forEach((w) => w())
    this.waiters = []
    this.pendingAccept.clear()
    try {
      this.ensureWorker()
      this.setStatus('idle')
    } catch {
      this.setStatus('unavailable')
    }
    void prev
  }

  /**
   * Mark a regex rule as failed, terminate, and restart analysis without it.
   */
  isolateRuleAndRestart(
    ruleId: string,
    profile: RulesetConfig,
  ): { requestId: RequestId; profile: RulesetConfig } {
    this.failedRuleIds.add(ruleId)
    this.cancel()
    const nextProfile = excludeRules(profile, this.failedRuleIds)
    const requestId = this.begin(nextProfile)
    return { requestId, profile: nextProfile }
  }

  dispose(): void {
    this.activeRequestId = null
    this.stopWatchdog()
    this.teardownWorker()
    this.setStatus('idle')
  }

  private onMessage(ev: MessageEvent): void {
    const msg = ev.data as DetectionWorkerResponse
    if (!msg || typeof msg !== 'object' || !('requestId' in msg)) return
    // Stale generation — ignore completely.
    if (msg.requestId !== this.activeRequestId) return

    switch (msg.type) {
      case 'chunk-accepted': {
        this.inFlight = Math.max(0, this.inFlight - 1)
        this.recordInFlightBytes(0)
        const resolve = this.pendingAccept.get(msg.sequence)
        if (resolve) {
          this.pendingAccept.delete(msg.sequence)
          resolve()
        }
        const next = this.waiters.shift()
        if (next) next()
        this.touchHeartbeat()
        break
      }
      case 'progress': {
        this.touchHeartbeat()
        const now = Date.now()
        if (now - this.lastProgressAt >= PROGRESS_MIN_INTERVAL_MS) {
          this.lastProgressAt = now
          const ev = {
            requestId: msg.requestId,
            processedBytes: msg.processedBytes,
            processedLines: msg.processedLines,
          }
          this.hooks.onProgress?.(ev)
          for (const listener of this.progressListeners) listener(ev)
        }
        break
      }
      case 'rule-started': {
        this.activeRuleId = msg.ruleId
        this.touchHeartbeat()
        this.hooks.onRuleStarted?.(msg.ruleId)
        break
      }
      case 'heartbeat': {
        this.touchHeartbeat()
        if (msg.ruleId) this.activeRuleId = msg.ruleId
        break
      }
      case 'detected': {
        this.stopWatchdog()
        this.setStatus('idle')
        const result: DetectionResult = {
          requestId: msg.requestId,
          packedMatches: msg.packedMatches,
          entities: msg.entities,
          lineCount: msg.lineCount,
          failedRuleIds: [...this.failedRuleIds],
          incidents: msg.incidents,
        }
        this.detectResolve?.(result)
        this.detectResolve = null
        this.detectReject = null
        break
      }
      case 'plan-built': {
        this.planResolve?.(msg.planBuffers)
        this.planResolve = null
        this.planReject = null
        break
      }
      case 'error': {
        this.stopWatchdog()
        if (msg.code === WORKER_ERROR.regexTimeout) {
          // Handled by watchdog path; ignore duplicate
          break
        }
        this.setStatus('idle')
        this.planReject?.(Object.assign(new Error(msg.message), { code: msg.code }))
        this.planResolve = null
        this.planReject = null
        this.failPending(
          Object.assign(new Error(msg.message), { code: msg.code, ruleId: msg.ruleId }),
        )
        break
      }
      default:
        break
    }
  }

  private touchHeartbeat(): void {
    this.lastHeartbeatAt = Date.now()
  }

  private startWatchdog(): void {
    this.stopWatchdog()
    this.watchdogTimer = setInterval(() => {
      if (this.status !== 'running' || !this.activeRequestId) return
      // Watchdog only bites while a custom rule is active (ARCHITECTURE §7.3).
      if (!this.activeRuleId) {
        this.touchHeartbeat()
        return
      }
      if (Date.now() - this.lastHeartbeatAt > WATCHDOG_MS) {
        const ruleId = this.activeRuleId
        const err = Object.assign(
          new Error(
            `Vlastní regex pravidlo „${ruleId}“ neodpovídá (timeout ${WATCHDOG_MS} ms). Pravidlo bude vypnuto.`,
          ),
          { code: WORKER_ERROR.regexTimeout, ruleId },
        )
        this.failedRuleIds.add(ruleId)
        this.activeRuleId = undefined
        this.stopWatchdog()
        this.teardownWorker()
        this.setStatus('idle')
        this.failPending(err)
        // Do not auto-spawn here — next begin()/ensureWorker creates a fresh worker.
      }
    }, 250)
  }

  private stopWatchdog(): void {
    if (this.watchdogTimer != null) {
      clearInterval(this.watchdogTimer)
      this.watchdogTimer = null
    }
  }

  private async waitForSlot(): Promise<void> {
    while (this.inFlight >= MAX_IN_FLIGHT_CHUNKS) {
      await new Promise<void>((resolve) => this.waiters.push(resolve))
    }
  }

  private recordInFlightBytes(lastChunkBytes: number): void {
    const hook = getActivePerfDiagnostics()
    if (!hook) return
    hook.setInFlightBytes(this.inFlight * Math.max(lastChunkBytes, 1))
    if (lastChunkBytes > 0) hook.recordTransfer(lastChunkBytes)
  }

  private post(message: DetectionWorkerRequest, transfer: Transferable[] = []): void {
    if (!this.worker) throw new Error('Worker není dostupný')
    if (transfer.length > 0) this.worker.postMessage(message, transfer)
    else this.worker.postMessage(message)
  }

  private teardownWorker(): void {
    if (!this.worker) return
    this.worker.removeEventListener('message', this.onMessageBound)
    this.worker.terminate()
    this.worker = null
  }

  private failPending(err: Error): void {
    this.detectReject?.(err)
    this.detectResolve = null
    this.detectReject = null
    for (const resolve of this.pendingAccept.values()) resolve()
    this.pendingAccept.clear()
  }

  private setStatus(status: WorkerClientStatus): void {
    this.status = status
    this.hooks.onStatus?.(status)
  }
}

function excludeRules(profile: RulesetConfig, failed: ReadonlySet<string>): RulesetConfig {
  return {
    ...profile,
    profile: {
      ...profile.profile,
      rules: profile.profile.rules.map((r) =>
        failed.has(r.id) ? { ...r, enabled: false } : r,
      ),
    },
  }
}

/** Convenience stub used by Krok 1 layout; prefer DetectionWorkerClient. */
export function createWorkerClientStub(): { status: WorkerClientStatus } {
  return { status: 'unavailable' }
}
