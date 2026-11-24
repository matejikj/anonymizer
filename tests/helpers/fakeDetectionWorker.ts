/**
 * In-process FakeWorker that drives DetectionSession (Vitest / Node).
 */

import type { WorkerLike } from '../../src/app/workerClient.ts'
import type {
  DetectionWorkerRequest,
  DetectionWorkerResponse,
} from '../../src/workers/protocol.ts'
import {
  validateDetectionProtocolVersion,
  WORKER_ERROR,
} from '../../src/workers/protocol.ts'
import { DetectionSession } from '../../src/workers/detectionSession.ts'

export interface FakeWorkerOptions {
  /** If set, on final chunk emit rule-started and stall (no heartbeat/detected). */
  hangOnRuleId?: string
  /** Artificial delay before chunk-accepted (ms). */
  acceptDelayMs?: number
  /** Observe worker input for streaming/backpressure assertions. */
  onInputChunk?: (chunk: Extract<DetectionWorkerRequest, { type: 'input-chunk' }>) => void
}

export class FakeDetectionWorker implements WorkerLike {
  private listeners = new Set<(ev: MessageEvent) => void>()
  private terminated = false
  private hangOnRuleId: string | undefined
  private acceptDelayMs: number
  private onInputChunk: FakeWorkerOptions['onInputChunk']
  private stalled = false

  private session: DetectionSession

  constructor(options: FakeWorkerOptions = {}) {
    this.hangOnRuleId = options.hangOnRuleId
    this.acceptDelayMs = options.acceptDelayMs ?? 0
    this.onInputChunk = options.onInputChunk
    this.session = new DetectionSession({
      onProgress: (processedBytes, processedLines) => {
        this.emit({
          type: 'progress',
          requestId: this.session.requestId,
          processedBytes,
          processedLines,
        })
      },
      onRuleStarted: (ruleId) => {
        if (this.hangOnRuleId && ruleId === this.hangOnRuleId) {
          // Still notify client, but suppress heartbeats for this rule.
          this.emit({ type: 'rule-started', requestId: this.session.requestId, ruleId })
          return
        }
        this.emit({ type: 'rule-started', requestId: this.session.requestId, ruleId })
        this.emit({ type: 'heartbeat', requestId: this.session.requestId, ruleId })
      },
      onHeartbeat: (ruleId) => {
        if (ruleId && this.hangOnRuleId === ruleId) return
        this.emit({ type: 'heartbeat', requestId: this.session.requestId, ruleId })
      },
    })
  }

  addEventListener(_type: 'message', listener: (ev: MessageEvent) => void): void {
    this.listeners.add(listener)
  }

  removeEventListener(_type: 'message', listener: (ev: MessageEvent) => void): void {
    this.listeners.delete(listener)
  }

  terminate(): void {
    this.terminated = true
    this.listeners.clear()
  }

  postMessage(message: unknown, _transfer?: Transferable[]): void {
    if (this.terminated) return
    const msg = message as DetectionWorkerRequest
    queueMicrotask(() => {
      void this.handle(msg)
    })
  }

  private async handle(msg: DetectionWorkerRequest): Promise<void> {
    if (this.terminated || this.stalled) return
    const versionErr = validateDetectionProtocolVersion(msg.protocolVersion)
    if (versionErr) {
      this.emit({
        type: 'error',
        requestId: 'requestId' in msg ? msg.requestId : '',
        code: versionErr,
        message: 'Neplatná verze worker protokolu',
      })
      return
    }
    try {
      switch (msg.type) {
        case 'start-detection':
          this.session.start(msg.requestId, msg.profile)
          return
        case 'cancel':
          this.emit({
            type: 'error',
            requestId: msg.requestId,
            code: WORKER_ERROR.cancelled,
            message: 'Zrušeno',
          })
          return
        case 'input-chunk': {
          if (msg.requestId !== this.session.requestId) return
          this.onInputChunk?.(msg)

          if (this.hangOnRuleId && msg.final) {
            if (this.acceptDelayMs > 0) {
              await new Promise((r) => setTimeout(r, this.acceptDelayMs))
            }
            if (this.terminated) return
            this.emit({
              type: 'chunk-accepted',
              requestId: msg.requestId,
              sequence: msg.sequence,
            })
            this.emit({
              type: 'rule-started',
              requestId: msg.requestId,
              ruleId: this.hangOnRuleId,
            })
            this.stalled = true
            return
          }

          if (msg.bytes) {
            this.session.pushByteChunk(
              msg.bytes,
              msg.byteOffset ?? 0,
              msg.byteLength ?? msg.bytes.byteLength,
              msg.final,
            )
          } else if (msg.text != null) {
            this.session.pushTextChunk(msg.text, msg.final)
          } else {
            this.emit({
              type: 'error',
              requestId: msg.requestId,
              code: WORKER_ERROR.invalidChunk,
              message: 'Chunk bez bytes i text',
            })
            return
          }

          if (this.acceptDelayMs > 0) {
            await new Promise((r) => setTimeout(r, this.acceptDelayMs))
          }
          if (this.terminated) return

          this.emit({
            type: 'chunk-accepted',
            requestId: msg.requestId,
            sequence: msg.sequence,
          })

          if (msg.final) {
            const result = this.session.finalizeDetection()
            this.emit({
              type: 'detected',
              requestId: msg.requestId,
              packedMatches: result.packedMatches,
              entities: result.entities,
              lineCount: result.lineCount,
              incidents: result.incidents,
            })
          }
          return
        }
        case 'build-plan': {
          if (msg.requestId !== this.session.requestId) return
          const result = this.session.buildPlan(msg.entityBitset)
          this.emit({
            type: 'plan-built',
            requestId: msg.requestId,
            planBuffers: result.planBuffers,
          })
          return
        }
        case 'sync-replacements': {
          if (msg.requestId !== this.session.requestId) return
          this.session.applyReplacements(msg.replacements)
          this.emit({ type: 'replacements-synced', requestId: msg.requestId })
          return
        }
      }
    } catch (err) {
      this.emit({
        type: 'error',
        requestId: msg.requestId,
        code: WORKER_ERROR.internal,
        message: err instanceof Error ? err.message : String(err),
      })
    }
  }

  private emit(msg: DetectionWorkerResponse): void {
    if (this.terminated) return
    const ev = { data: msg } as MessageEvent
    for (const listener of [...this.listeners]) listener(ev)
  }
}
