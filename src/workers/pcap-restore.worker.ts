/// <reference lib="webworker" />
/**
 * PCAP recovery restore worker — preflight / open / search / packet+full restore / lock.
 * Holds blobs and index; never posts query text to logs.
 */

import type {
  PcapRestoreWorkerRequest,
  PcapRestoreWorkerResponse,
} from '../pcap/recovery/worker/protocol'
import {
  validateRecoveryProtocolVersion,
} from '../pcap/recovery/worker/protocol'
import { PCAP_RECOVERY_ERROR } from '../pcap/recovery/domain/errors'
import { RecoverySession } from '../pcap/recovery/restore/recoverySession'
import { preflightRecoveryPair } from '../pcap/recovery/restore/recoveryPairVerifier'
import { unlockRecoveryPair } from '../pcap/recovery/restore/unlockPipeline'
import { searchUnlockedIndex } from '../pcap/recovery/restore/recoverySearch'
import {
  openRestoredPacket,
  restorePacketMiniCapture,
  type PacketRestoreContext,
} from '../pcap/recovery/restore/packetRestore'
import { streamFullRestore } from '../pcap/recovery/restore/fullRestore'
import { PCAP_RECOVERY_LIMITS } from '../pcap/recovery/domain/limits'
import { wipeBytes } from '../crypto/wipe'
import { toSafeWorkerError } from '../domain/safeWorkerError'

const session = new RecoverySession()
session.onIdleTimeout = () => {
  const gen = session.currentGenerationId
  session.lock()
  if (gen) {
    post({ type: 'locked', requestId: 'idle-timeout', generationId: gen })
  }
}

function post(msg: PcapRestoreWorkerResponse): void {
  ;(self as DedicatedWorkerGlobalScope).postMessage(msg)
}

function postError(
  requestId: string,
  generationId: string,
  code: string,
  message: string,
  sessionId?: string,
): void {
  post({
    type: 'error',
    requestId,
    generationId,
    sessionId,
    code,
    message,
  })
}

self.onmessage = (ev: MessageEvent<PcapRestoreWorkerRequest>) => {
  void handle(ev.data)
}

async function handle(msg: PcapRestoreWorkerRequest): Promise<void> {
  const versionErr = validateRecoveryProtocolVersion(msg.protocolVersion)
  if (versionErr) {
    postError(msg.requestId, 'generationId' in msg ? msg.generationId : '', versionErr, 'Invalid recovery protocol version')
    return
  }

  try {
    switch (msg.type) {
      case 'preflight':
        await handlePreflight(msg)
        break
      case 'unlock':
        await handleUnlock(msg)
        break
      case 'lock':
        handleLock(msg)
        break
      case 'search':
        handleSearch(msg)
        break
      case 'open-packet':
        await handleOpenPacket(msg)
        break
      case 'restore-packet':
        await handleRestorePacket(msg)
        break
      case 'restore-all':
        await handleRestoreAll(msg)
        break
      case 'packet-map':
        handlePacketMap(msg)
        break
      case 'chunk-ack':
        restoreBackpressure.ack()
        break
      default:
        postError(
          (msg as { requestId: string }).requestId,
          '',
          PCAP_RECOVERY_ERROR.internal,
          'Unknown restore request',
        )
    }
  } catch (err) {
    const safe = toSafeWorkerError(err, 'pcap-restore', PCAP_RECOVERY_ERROR.internal)
    postError(
      msg.requestId,
      'generationId' in msg ? msg.generationId : '',
      safe.code,
      safe.safeMessage,
    )
  }
}

async function handlePreflight(
  msg: Extract<PcapRestoreWorkerRequest, { type: 'preflight' }>,
): Promise<void> {
  session.beginGeneration(msg.generationId)
  if (!session.transition('preflighting')) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.internal, 'Invalid session transition')
    return
  }

  session.anonymizedBlob = msg.anonymizedBlob
  session.recoveryBlob = msg.recoveryBlob

  const result = await preflightRecoveryPair({
    anonymizedBlob: msg.anonymizedBlob,
    recoveryBlob: msg.recoveryBlob,
  })

  if (!result.ok) {
    session.transition('failed')
    postError(msg.requestId, msg.generationId, result.code, result.message)
    return
  }

  session.bounds = result.value.bounds
  session.anonymizedSha256 = result.value.anonymizedSha256
  session.pairLooksCompatible = result.value.summary.pairLooksCompatible
  if (!session.transition('locked')) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.internal, 'Invalid session transition')
    return
  }

  post({
    type: 'preflight-ok',
    requestId: msg.requestId,
    generationId: msg.generationId,
    summary: result.value.summary,
  })
}

async function handleUnlock(
  msg: Extract<PcapRestoreWorkerRequest, { type: 'unlock' }>,
): Promise<void> {
  if (!session.assertSession(msg.generationId) || session.currentState !== 'locked') {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.sessionLocked, 'Unlock not allowed')
    return
  }

  if (!session.pairLooksCompatible || !session.bounds || !session.anonymizedSha256 || !session.recoveryBlob) {
    postError(
      msg.requestId,
      msg.generationId,
      PCAP_RECOVERY_ERROR.pairMismatch,
      'Soubory k sobě nepatří. Vyberte anonymizovaný PCAP a odpovídající soubor pro obnovu.',
    )
    return
  }

  if (!session.transition('unlocking')) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.internal, 'Invalid session transition')
    return
  }

  const unlocked = await unlockRecoveryPair({
    recoveryBlob: session.recoveryBlob,
    bounds: session.bounds,
    anonymizedSha256: session.anonymizedSha256,
  })

  if (!unlocked.ok) {
    const code =
      unlocked.code === PCAP_RECOVERY_ERROR.cancelled
        ? unlocked.code
        : PCAP_RECOVERY_ERROR.authFailed
    if (code === PCAP_RECOVERY_ERROR.authFailed) {
      session.failUnlockKeepPair()
    } else {
      session.transition('failed')
    }
    postError(
      msg.requestId,
      msg.generationId,
      code,
      code === PCAP_RECOVERY_ERROR.authFailed
        ? 'Soubor pro obnovu je poškozený nebo nepatří k tomuto anonymizovanému souboru.'
        : unlocked.message,
    )
    return
  }

  const summary = session.markUnlocked(unlocked.value)
  post({
    type: 'unlocked',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: summary.sessionId,
    summary: {
      pcapLevel: summary.pcapLevel,
      policyHash: summary.policyHash,
      engineVersion: summary.engineVersion,
      originalFormat: summary.originalFormat,
      originalByteLength: summary.originalByteLength,
      anonymizedByteLength: summary.anonymizedByteLength,
      lookupEntryCount: summary.lookupEntryCount,
      originalPacketCount: summary.originalPacketCount,
      anonymizedPacketCount: summary.anonymizedPacketCount,
      idleTimeoutMs: summary.idleTimeoutMs,
    },
  })
}

function handleLock(msg: Extract<PcapRestoreWorkerRequest, { type: 'lock' }>): void {
  if (msg.sessionId && !session.assertSession(msg.generationId, msg.sessionId)) {
    // Stale lock — still clear local state.
  }
  session.lock()
  post({ type: 'locked', requestId: msg.requestId, generationId: msg.generationId })
}

function handleSearch(msg: Extract<PcapRestoreWorkerRequest, { type: 'search' }>): void {
  if (!session.assertSession(msg.generationId, msg.sessionId)) {
    postError(
      msg.requestId,
      msg.generationId,
      PCAP_RECOVERY_ERROR.sessionLocked,
      'Session is not unlocked',
      msg.sessionId,
    )
    return
  }

  const index = session.lookup
  if (!index || (session.currentState !== 'unlocked' && session.currentState !== 'searching')) {
    postError(
      msg.requestId,
      msg.generationId,
      PCAP_RECOVERY_ERROR.sessionLocked,
      'Unlock required before search',
      msg.sessionId,
    )
    return
  }

  if (session.currentState === 'unlocked' && !session.transition('searching')) {
    postError(
      msg.requestId,
      msg.generationId,
      PCAP_RECOVERY_ERROR.internal,
      'Invalid session transition',
      msg.sessionId,
    )
    return
  }
  session.touch()

  const page = searchUnlockedIndex({
    index,
    query: msg.query,
    offset: msg.offset,
    limit: msg.limit,
  })

  if (session.currentState === 'searching') {
    session.transition('unlocked')
  }

  if (!page.ok) {
    postError(msg.requestId, msg.generationId, page.code, page.message, msg.sessionId)
    return
  }

  post({
    type: 'search-result',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: msg.sessionId,
    page: page.value,
  })
}

const restoreBackpressure = {
  inFlight: 0,
  waiters: [] as Array<() => void>,
  async acquire(): Promise<void> {
    while (this.inFlight >= PCAP_RECOVERY_LIMITS.maxUnackedChunks) {
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve)
      })
    }
    this.inFlight += 1
  },
  ack(): void {
    this.inFlight = Math.max(0, this.inFlight - 1)
    this.waiters.shift()?.()
  },
  reset(): void {
    this.inFlight = 0
    this.waiters.length = 0
  },
}

function requireUnlocked(
  msg: { requestId: string; generationId: string; sessionId: string },
): PacketRestoreContext | null {
  if (!session.assertSession(msg.generationId, msg.sessionId)) {
    postError(
      msg.requestId,
      msg.generationId,
      PCAP_RECOVERY_ERROR.sessionLocked,
      'Session is not unlocked',
      msg.sessionId,
    )
    return null
  }
  const index = session.lookup
  const manifest = session.recoveryManifest
  const bounds = session.bounds
  const recoveryBlob = session.recoveryBlob
  if (!index || !manifest || !bounds || !recoveryBlob) {
    postError(
      msg.requestId,
      msg.generationId,
      PCAP_RECOVERY_ERROR.sessionLocked,
      'Unlock required before restore',
      msg.sessionId,
    )
    return null
  }
  return {
    recoveryBlob,
    anonymizedBlob: session.anonymizedBlob,
    bounds,
    manifest,
    index,
    cache: session.decryptedFrameCache ?? undefined,
    dataDirectory: session.dataDirectory,
  }
}

function persistDirectory(ctx: PacketRestoreContext): void {
  if (ctx.dataDirectory) {
    session.dataDirectory = [...ctx.dataDirectory]
  }
}

async function handleOpenPacket(
  msg: Extract<PcapRestoreWorkerRequest, { type: 'open-packet' }>,
): Promise<void> {
  const ctx = requireUnlocked(msg)
  if (!ctx) return
  if (session.currentState !== 'unlocked' && session.currentState !== 'restoring-packet') {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.sessionLocked, 'Unlock required', msg.sessionId)
    return
  }
  if (session.currentState === 'unlocked' && !session.transition('restoring-packet')) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.internal, 'Invalid session transition', msg.sessionId)
    return
  }
  session.touch()
  const opened = await openRestoredPacket(ctx, msg.hitRef)
  persistDirectory(ctx)
  if (session.currentState === 'restoring-packet') session.transition('unlocked')
  if (!opened.ok) {
    postError(msg.requestId, msg.generationId, opened.code, opened.message, msg.sessionId)
    return
  }
  post({
    type: 'packet-opened',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: msg.sessionId,
    view: opened.value,
  })
}

async function handleRestorePacket(
  msg: Extract<PcapRestoreWorkerRequest, { type: 'restore-packet' }>,
): Promise<void> {
  const ctx = requireUnlocked(msg)
  if (!ctx) return
  if (session.currentState === 'unlocked' && !session.transition('restoring-packet')) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.internal, 'Invalid session transition', msg.sessionId)
    return
  }
  session.touch()
  const mini = await restorePacketMiniCapture(ctx, msg.hitRef)
  persistDirectory(ctx)
  if (session.currentState === 'restoring-packet') session.transition('unlocked')
  if (!mini.ok) {
    postError(msg.requestId, msg.generationId, mini.code, mini.message, msg.sessionId)
    return
  }
  const copy = mini.value.bytes.slice()
  wipeBytes(mini.value.bytes)
  restoreBackpressure.reset()
  await restoreBackpressure.acquire()
  post({
    type: 'chunk',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: msg.sessionId,
    streamId: 'restore',
    chunkIndex: 0,
    buffer: copy.buffer,
  })
  post({
    type: 'restore-complete',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: msg.sessionId,
    summary: mini.value.summary,
  })
}

async function handleRestoreAll(
  msg: Extract<PcapRestoreWorkerRequest, { type: 'restore-all' }>,
): Promise<void> {
  const ctx = requireUnlocked(msg)
  if (!ctx) return
  if (session.currentState === 'unlocked' && !session.transition('restoring-all')) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.internal, 'Invalid session transition', msg.sessionId)
    return
  }
  session.touch()
  restoreBackpressure.reset()

  const result = await streamFullRestore({
    recoveryBlob: ctx.recoveryBlob,
    bounds: ctx.bounds,
    manifest: ctx.manifest,
    cache: ctx.cache,
    anonymizedBlob: ctx.anonymizedBlob,
    handlers: {
      onChunk: async (chunk, chunkIndex) => {
        await restoreBackpressure.acquire()
        post({
          type: 'chunk',
          requestId: msg.requestId,
          generationId: msg.generationId,
          sessionId: msg.sessionId,
          streamId: 'restore',
          chunkIndex,
          buffer: chunk,
        })
      },
      onProgress: (done, total) => {
        post({
          type: 'progress',
          requestId: msg.requestId,
          generationId: msg.generationId,
          sessionId: msg.sessionId,
          phase: 'restoring-all',
          done,
          total,
        })
      },
    },
  })

  if (session.currentState === 'restoring-all') session.transition('unlocked')
  restoreBackpressure.reset()

  if (!result.ok) {
    postError(msg.requestId, msg.generationId, result.code, result.message, msg.sessionId)
    return
  }
  post({
    type: 'restore-complete',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: msg.sessionId,
    summary: result.value,
  })
}

function handlePacketMap(msg: Extract<PcapRestoreWorkerRequest, { type: 'packet-map' }>): void {
  if (!session.assertSession(msg.generationId, msg.sessionId)) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.sessionLocked, 'Session is not unlocked', msg.sessionId)
    return
  }
  const index = session.lookup
  if (!index) {
    postError(msg.requestId, msg.generationId, PCAP_RECOVERY_ERROR.sessionLocked, 'Unlock required', msg.sessionId)
    return
  }
  const anonymizedToOriginal = new Array<number>(index.anonymizedPacketCount + 1).fill(-1)
  for (let n = 1; n <= index.anonymizedPacketCount; n++) {
    anonymizedToOriginal[n] = index.packetMap.toOriginal(n) ?? -1
  }
  post({
    type: 'packet-map-result',
    requestId: msg.requestId,
    generationId: msg.generationId,
    sessionId: msg.sessionId,
    anonymizedToOriginal,
  })
}

export {}
