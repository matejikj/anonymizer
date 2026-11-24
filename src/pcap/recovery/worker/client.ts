/**
 * Main-thread client for the PCAP recovery restore worker (steps 6–7).
 * Generation/session guards; ignores stale replies.
 */

import type {
  PcapRestoreWorkerRequest,
  PcapRestoreWorkerResponse,
} from './protocol'
import { PCAP_RECOVERY_PROTOCOL_VERSION } from './protocol'
import type {
  RecoveryHitRef,
  RecoveryPairSummary,
  RecoveryResultPage,
  RestoredPacketView,
  RestoreSummary,
  UnlockedRecoverySummary,
} from '../domain/types'
import { PCAP_RECOVERY_ERROR } from '../domain/errors'

let worker: Worker | null = null
let activeGenerationId = ''

export function createPcapRestoreWorker(): Worker {
  return new Worker(new URL('../../../workers/pcap-restore.worker.ts', import.meta.url), {
    type: 'module',
  })
}

function getWorker(): Worker {
  if (!worker) worker = createPcapRestoreWorker()
  return worker
}

export function disposePcapRestoreWorker(): void {
  worker?.terminate()
  worker = null
  activeGenerationId = ''
}

function requestId(): string {
  return `rr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

function waitFor(
  w: Worker,
  generationId: string,
  rid: string,
  match: (msg: PcapRestoreWorkerResponse) => boolean,
): Promise<PcapRestoreWorkerResponse> {
  return new Promise((resolve, reject) => {
    const onMessage = (ev: MessageEvent<PcapRestoreWorkerResponse>) => {
      const msg = ev.data
      if ('generationId' in msg && msg.generationId !== generationId) return
      if ('requestId' in msg && msg.requestId !== rid && msg.requestId !== 'idle-timeout') return
      if (!match(msg)) return
      cleanup()
      resolve(msg)
    }
    const onError = (err: ErrorEvent) => {
      cleanup()
      reject(err.error ?? new Error(err.message || 'Restore worker failed'))
    }
    const cleanup = () => {
      w.removeEventListener('message', onMessage)
      w.removeEventListener('error', onError)
    }
    w.addEventListener('message', onMessage)
    w.addEventListener('error', onError)
  })
}

export async function preflightRecoveryPairViaWorker(input: {
  generationId: string
  anonymizedBlob: Blob
  recoveryBlob: Blob
}): Promise<RecoveryPairSummary> {
  activeGenerationId = input.generationId
  const w = getWorker()
  const rid = requestId()
  const req: PcapRestoreWorkerRequest = {
    type: 'preflight',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
    anonymizedBlob: input.anonymizedBlob,
    recoveryBlob: input.recoveryBlob,
  }
  const pending = waitFor(
    w,
    input.generationId,
    rid,
    (msg) => msg.type === 'preflight-ok' || msg.type === 'error',
  )
  w.postMessage(req)
  const msg = await pending
  if (msg.type === 'error') {
    throw Object.assign(new Error(msg.message), { code: msg.code })
  }
  if (msg.type !== 'preflight-ok') {
    throw new Error('Unexpected restore worker response')
  }
  return msg.summary
}

export async function unlockRecoveryPairViaWorker(input: {
  generationId: string
}): Promise<UnlockedRecoverySummary> {
  if (activeGenerationId !== input.generationId) {
    throw Object.assign(new Error('Stale generation'), { code: PCAP_RECOVERY_ERROR.sessionLocked })
  }
  const w = getWorker()
  const rid = requestId()
  const req: PcapRestoreWorkerRequest = {
    type: 'unlock',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
  }
  const pending = waitFor(
    w,
    input.generationId,
    rid,
    (msg) => msg.type === 'unlocked' || msg.type === 'error',
  )
  w.postMessage(req)
  const msg = await pending
  if (msg.type === 'error') {
    throw Object.assign(new Error(msg.message), { code: msg.code })
  }
  if (msg.type !== 'unlocked') {
    throw new Error('Unexpected restore worker response')
  }
  return {
    sessionId: msg.sessionId,
    generationId: msg.generationId,
    ...msg.summary,
  }
}

export async function searchRecoveryViaWorker(input: {
  generationId: string
  sessionId: string
  query: string
  offset?: number
  limit?: number
}): Promise<RecoveryResultPage> {
  if (activeGenerationId !== input.generationId) {
    throw Object.assign(new Error('Stale generation'), { code: PCAP_RECOVERY_ERROR.sessionLocked })
  }
  const w = getWorker()
  const rid = requestId()
  const req: PcapRestoreWorkerRequest = {
    type: 'search',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
    sessionId: input.sessionId,
    query: input.query,
    offset: input.offset,
    limit: input.limit,
  }
  const pending = waitFor(
    w,
    input.generationId,
    rid,
    (msg) => msg.type === 'search-result' || msg.type === 'error',
  )
  w.postMessage(req)
  const msg = await pending
  if (msg.type === 'error') {
    throw Object.assign(new Error(msg.message), { code: msg.code })
  }
  if (msg.type !== 'search-result') {
    throw new Error('Unexpected restore worker response')
  }
  return msg.page
}

export async function openPacketViaWorker(input: {
  generationId: string
  sessionId: string
  hitRef: RecoveryHitRef
}): Promise<RestoredPacketView> {
  if (activeGenerationId !== input.generationId) {
    throw Object.assign(new Error('Stale generation'), { code: PCAP_RECOVERY_ERROR.sessionLocked })
  }
  const w = getWorker()
  const rid = requestId()
  const req: PcapRestoreWorkerRequest = {
    type: 'open-packet',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
    sessionId: input.sessionId,
    hitRef: input.hitRef,
  }
  const pending = waitFor(
    w,
    input.generationId,
    rid,
    (msg) => msg.type === 'packet-opened' || msg.type === 'error',
  )
  w.postMessage(req)
  const msg = await pending
  if (msg.type === 'error') {
    throw Object.assign(new Error(msg.message), { code: msg.code })
  }
  if (msg.type !== 'packet-opened') {
    throw new Error('Unexpected restore worker response')
  }
  return msg.view
}

function collectVerifiedRestore(input: {
  worker: Worker
  generationId: string
  requestId: string
}): Promise<{ blob: Blob; summary: RestoreSummary }> {
  return new Promise((resolve, reject) => {
    const chunks: ArrayBuffer[] = []
    const onMessage = (ev: MessageEvent<PcapRestoreWorkerResponse>) => {
      const msg = ev.data
      if ('generationId' in msg && msg.generationId !== input.generationId) return
      if ('requestId' in msg && msg.requestId !== input.requestId && msg.requestId !== 'idle-timeout') return
      if (msg.type === 'chunk' && msg.streamId === 'restore') {
        chunks.push(msg.buffer)
        input.worker.postMessage({
          type: 'chunk-ack',
          protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
          requestId: input.requestId,
          streamId: 'restore',
          chunkIndex: msg.chunkIndex,
        } satisfies PcapRestoreWorkerRequest)
        return
      }
      if (msg.type === 'progress') return
      if (msg.type === 'error') {
        cleanup()
        chunks.length = 0
        reject(Object.assign(new Error(msg.message), { code: msg.code }))
        return
      }
      if (msg.type === 'restore-complete') {
        cleanup()
        if (!msg.summary.verified) {
          chunks.length = 0
          reject(Object.assign(new Error('Restore not verified'), { code: PCAP_RECOVERY_ERROR.outputHashMismatch }))
          return
        }
        resolve({
          blob: new Blob(chunks, { type: 'application/octet-stream' }),
          summary: msg.summary,
        })
      }
    }
    const onError = (err: ErrorEvent) => {
      cleanup()
      chunks.length = 0
      reject(err.error ?? new Error(err.message || 'Restore worker failed'))
    }
    const cleanup = () => {
      input.worker.removeEventListener('message', onMessage)
      input.worker.removeEventListener('error', onError)
    }
    input.worker.addEventListener('message', onMessage)
    input.worker.addEventListener('error', onError)
  })
}

export async function restorePacketViaWorker(input: {
  generationId: string
  sessionId: string
  hitRef: RecoveryHitRef
}): Promise<{ blob: Blob; summary: RestoreSummary }> {
  if (activeGenerationId !== input.generationId) {
    throw Object.assign(new Error('Stale generation'), { code: PCAP_RECOVERY_ERROR.sessionLocked })
  }
  const w = getWorker()
  const rid = requestId()
  const pending = collectVerifiedRestore({ worker: w, generationId: input.generationId, requestId: rid })
  w.postMessage({
    type: 'restore-packet',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
    sessionId: input.sessionId,
    hitRef: input.hitRef,
  } satisfies PcapRestoreWorkerRequest)
  return pending
}

export async function restoreAllViaWorker(input: {
  generationId: string
  sessionId: string
  onProgress?: (done: number, total: number) => void
}): Promise<{ blob: Blob; summary: RestoreSummary }> {
  if (activeGenerationId !== input.generationId) {
    throw Object.assign(new Error('Stale generation'), { code: PCAP_RECOVERY_ERROR.sessionLocked })
  }
  const w = getWorker()
  const rid = requestId()
  const onProgress = (ev: MessageEvent<PcapRestoreWorkerResponse>) => {
    const msg = ev.data
    if (msg.type === 'progress' && msg.requestId === rid && msg.generationId === input.generationId) {
      input.onProgress?.(msg.done, msg.total)
    }
  }
  if (input.onProgress) w.addEventListener('message', onProgress)
  try {
    const pending = collectVerifiedRestore({ worker: w, generationId: input.generationId, requestId: rid })
    w.postMessage({
      type: 'restore-all',
      protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
      requestId: rid,
      generationId: input.generationId,
      sessionId: input.sessionId,
    } satisfies PcapRestoreWorkerRequest)
    return await pending
  } finally {
    w.removeEventListener('message', onProgress)
  }
}

export async function getPacketNumberMapViaWorker(input: {
  generationId: string
  sessionId: string
}): Promise<readonly number[]> {
  if (activeGenerationId !== input.generationId) {
    throw Object.assign(new Error('Stale generation'), { code: PCAP_RECOVERY_ERROR.sessionLocked })
  }
  const w = getWorker()
  const rid = requestId()
  const req: PcapRestoreWorkerRequest = {
    type: 'packet-map',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
    sessionId: input.sessionId,
  }
  const pending = waitFor(
    w,
    input.generationId,
    rid,
    (msg) => msg.type === 'packet-map-result' || msg.type === 'error',
  )
  w.postMessage(req)
  const msg = await pending
  if (msg.type === 'error') {
    throw Object.assign(new Error(msg.message), { code: msg.code })
  }
  if (msg.type !== 'packet-map-result') {
    throw new Error('Unexpected restore worker response')
  }
  return msg.anonymizedToOriginal
}

export async function lockRecoverySessionViaWorker(input: {
  generationId: string
  sessionId?: string
}): Promise<void> {
  const w = getWorker()
  const rid = requestId()
  const req: PcapRestoreWorkerRequest = {
    type: 'lock',
    protocolVersion: PCAP_RECOVERY_PROTOCOL_VERSION,
    requestId: rid,
    generationId: input.generationId,
    sessionId: input.sessionId,
  }
  const pending = waitFor(
    w,
    input.generationId,
    rid,
    (msg) =>
      (msg.type === 'locked' && msg.requestId === rid)
      || msg.type === 'error'
      || msg.requestId === 'idle-timeout',
  )
  w.postMessage(req)
  await pending
  disposePcapRestoreWorker()
}
