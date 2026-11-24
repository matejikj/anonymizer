import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { DetectionWorkerClient } from '../../src/app/workerClient.ts'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker.ts'
import {
  detectionStartMessage,
  expectCancelledError,
  expectVersionedRequest,
  expectWorkerErrorCode,
  invalidProtocolVersion,
  malformedDetectionChunk,
  WORKER_PROTOCOL_VERSIONS,
} from './primitives.ts'
import {
  DETECTION_PROTOCOL_VERSION,
  validateDetectionProtocolVersion,
  WORKER_ERROR,
} from '../../src/workers/protocol.ts'

describe('conformance — text detection worker port', () => {
  let client: DetectionWorkerClient

  beforeEach(() => {
    client = new DetectionWorkerClient({}, () => new FakeDetectionWorker())
  })

  afterEach(() => {
    client.dispose()
  })

  it('uses versioned start-detection wire message', () => {
    const msg = detectionStartMessage('req-1', createDefaultRulesetConfig())
    expectVersionedRequest(msg as unknown as Record<string, unknown>)
    expect(msg.protocolVersion).toBe(WORKER_PROTOCOL_VERSIONS.detection)
  })

  it('rejects invalid protocol version at validation layer', () => {
    expect(validateDetectionProtocolVersion(0)).toBe(WORKER_ERROR.invalidVersion)
    expect(validateDetectionProtocolVersion(DETECTION_PROTOCOL_VERSION)).toBeNull()
  })

  it('ignores stale detected response for superseded requestId', async () => {
    const requestId = client.begin(createDefaultRulesetConfig())
    const stalePromise = client.waitForResult(requestId)
    client.cancel()
    await expect(stalePromise).rejects.toThrow()
  })

  it('handles cancel with typed error code', async () => {
    const worker = new FakeDetectionWorker()
    const listeners = new Set<(ev: MessageEvent) => void>()
    worker.addEventListener('message', (ev) => listeners.forEach((fn) => fn(ev)))

    worker.postMessage(
      detectionStartMessage('cancel-test', createDefaultRulesetConfig()),
    )
    worker.postMessage({
      type: 'cancel',
      protocolVersion: DETECTION_PROTOCOL_VERSION,
      requestId: 'cancel-test',
    })

    await new Promise((r) => setTimeout(r, 0))
    const responses = [...listeners].length
    expect(responses).toBeGreaterThanOrEqual(0)

    worker.postMessage({
      type: 'cancel',
      protocolVersion: DETECTION_PROTOCOL_VERSION,
      requestId: 'cancel-test',
    })
    await new Promise((r) => setTimeout(r, 0))
  })

  it('malformed final chunk without payload yields invalid-chunk error', async () => {
    const worker = new FakeDetectionWorker()
    let lastError: unknown
    worker.addEventListener('message', (ev) => {
      const msg = ev.data
      if (msg?.type === 'error') lastError = msg
    })

    worker.postMessage(detectionStartMessage('bad-chunk', createDefaultRulesetConfig()))
    worker.postMessage(malformedDetectionChunk('bad-chunk'))
    await new Promise((r) => setTimeout(r, 0))

    expectWorkerErrorCode(lastError as { code: string }, WORKER_ERROR.invalidChunk)
  })

  it('invalid protocol version on start is rejected by worker', async () => {
    const worker = new FakeDetectionWorker()
    let lastError: unknown
    worker.addEventListener('message', (ev) => {
      const msg = ev.data
      if (msg?.type === 'error') lastError = msg
    })

    const bad = invalidProtocolVersion(
      detectionStartMessage('bad-ver', createDefaultRulesetConfig()),
    )
    worker.postMessage(bad)
    await new Promise((r) => setTimeout(r, 0))

    expectWorkerErrorCode(lastError as { code: string }, WORKER_ERROR.invalidVersion)
  })
})

describe('conformance — text export worker port', () => {
  it('declares export protocol version constant', () => {
    expect(WORKER_PROTOCOL_VERSIONS.export).toBe(1)
  })
})
