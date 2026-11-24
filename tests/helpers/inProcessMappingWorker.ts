import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { MappingWorkerClient, type WorkerLike } from '../../src/mapping/mappingWorkerClient'
import { resetSharedMappingClient, setSharedMappingClientForTests } from '../../src/mapping/sharedMappingClient'
import {
  validateMappingConfig,
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  lookupCandidatesToWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from '../../src/mapping/protocol'
import { canonicalizeIdentity } from '../../src/mapping/canonicalize'

/** In-process mapping worker for tests (Stage 7 / Stage 18 / Stage 19). */
export function createInProcessMappingWorkerFactory(): () => WorkerLike {
  const authority = new MappingAuthority()
  return () => {
    const listeners = new Set<(ev: MessageEvent) => void>()
    const emit = (response: MappingWorkerResponse) => {
      for (const fn of listeners) fn({ data: response } as MessageEvent)
    }

    const handle = (msg: MappingWorkerRequest) => {
      const versionErr = validateProtocolVersion(msg.protocolVersion)
      if (versionErr) {
        emit({
          type: 'error',
          requestId: 'requestId' in msg ? msg.requestId : 'unknown',
          code: versionErr.code,
          message: versionErr.message,
        })
        return
      }

      if (msg.type === 'ping') {
        emit({ type: 'pong', requestId: msg.requestId, revision: authority.getMappingRevision() })
        return
      }

      if (msg.type === 'cancel') {
        authority.requestCancel(msg.generationId)
        emit({ type: 'pong', requestId: msg.requestId, revision: authority.getMappingRevision() })
        return
      }

      if (msg.type === 'reset-session') {
        authority.resetSession()
        emit({ type: 'session-reset', requestId: msg.requestId })
        return
      }

      if (msg.type === 'lookup-original') {
        const canonical = canonicalizeIdentity(msg.category, msg.canonical)
        if (canonical === null) {
          emit({ type: 'error', requestId: msg.requestId, code: 'mapping-invalid-identity', message: 'bad canonical' })
          return
        }
        const result = authority.lookupByOriginal({ category: msg.category, canonical })
        if (!result.ok) {
          emit({ type: 'error', requestId: msg.requestId, code: result.code, message: result.message })
          return
        }
        emit({ type: 'lookup-result', requestId: msg.requestId, candidates: lookupCandidatesToWire(result.candidates) })
        return
      }

      if (msg.type === 'lookup-alias') {
        const result = authority.lookupByAlias({ alias: msg.alias })
        if (!result.ok) {
          emit({ type: 'error', requestId: msg.requestId, code: result.code, message: result.message })
          return
        }
        emit({ type: 'lookup-result', requestId: msg.requestId, candidates: lookupCandidatesToWire(result.candidates) })
        return
      }

      if (msg.type === 'release-occurrence') {
        const canonical = canonicalizeIdentity(msg.category, msg.canonical)
        if (canonical === null) {
          emit({ type: 'error', requestId: msg.requestId, code: 'mapping-invalid-identity', message: 'bad canonical' })
          return
        }
        const occurrence = msg.occurrence.kind === 'text'
          ? { kind: 'text' as const, sourceId: msg.occurrence.sourceId, line: msg.occurrence.line!, start: msg.occurrence.start!, end: msg.occurrence.end! }
          : { kind: 'packet' as const, sourceId: msg.occurrence.sourceId, packetIndex: msg.occurrence.packetIndex! }
        const result = authority.releaseOccurrence({ category: msg.category, canonical, occurrence })
        if (!result.ok) {
          emit({ type: 'error', requestId: msg.requestId, code: result.code, message: result.message })
          return
        }
        emit({
          type: 'occurrence-released',
          requestId: msg.requestId,
          mappingRevision: result.mappingRevision,
          scrubbed: result.scrubbed,
          snapshot: authority.getPublishedSnapshot()
            ? snapshotToWire(authority.getPublishedSnapshot()!)
            : null,
        })
        return
      }

      if (msg.type === 'resolve') {
        const configErr = validateMappingConfig(msg.config)
        if (configErr) {
          emit({ type: 'error', requestId: msg.requestId, generationId: msg.generationId, code: configErr.code, message: configErr.message })
          return
        }
        const validated = validateResolveIdentities(msg.identities)
        if (!validated.ok) {
          emit({
            type: 'error',
            requestId: msg.requestId,
            generationId: msg.generationId,
            code: validated.error.code,
            message: validated.error.message,
          })
          return
        }

        const result = authority.resolve({
          generationId: msg.generationId,
          sourceId: msg.sourceId,
          identities: validated.identities,
          customRules: msg.customRules,
          correlationOptions: msg.correlationOptions,
        }, msg.config)

        if (!result.ok) {
          emit({
            type: 'error',
            requestId: msg.requestId,
            generationId: msg.generationId,
            code: result.code,
            message: result.message,
          })
          return
        }

        emit({
          type: 'resolved',
          requestId: msg.requestId,
          generationId: msg.generationId,
          snapshot: snapshotToWire(result.snapshot),
        })
        return
      }

      if (msg.type === 'resolve-staging') {
        const configErr = validateMappingConfig(msg.config)
        if (configErr) {
          emit({ type: 'error', requestId: msg.requestId, generationId: msg.generationId, code: configErr.code, message: configErr.message })
          return
        }
        const validated = validateResolveIdentities(msg.identities)
        if (!validated.ok) {
          emit({
            type: 'error',
            requestId: msg.requestId,
            generationId: msg.generationId,
            code: validated.error.code,
            message: validated.error.message,
          })
          return
        }

        const result = authority.resolveStaging({
          generationId: msg.generationId,
          sourceId: msg.sourceId,
          identities: validated.identities,
          customRules: msg.customRules,
          correlationOptions: msg.correlationOptions,
        }, msg.config)

        if (!result.ok) {
          emit({
            type: 'error',
            requestId: msg.requestId,
            generationId: msg.generationId,
            code: result.code,
            message: result.message,
          })
          return
        }

        emit({
          type: 'staging-preview',
          requestId: msg.requestId,
          generationId: msg.generationId,
          snapshot: snapshotToWire(result.snapshot),
        })
        return
      }

      if (msg.type === 'commit-staging') {
        const result = authority.commitStaging()
        if (!result.ok) {
          emit({ type: 'error', requestId: msg.requestId, code: result.code, message: result.message })
          return
        }
        emit({
          type: 'staging-committed',
          requestId: msg.requestId,
          generationId: result.snapshot.generationId,
          snapshot: snapshotToWire(result.snapshot),
        })
        return
      }

      if (msg.type === 'abort-staging') {
        authority.abortStaging()
        emit({ type: 'staging-aborted', requestId: msg.requestId })
      }
    }

    return {
      postMessage(message: unknown) {
        queueMicrotask(() => handle(message as MappingWorkerRequest))
      },
      terminate() {
        listeners.clear()
      },
      addEventListener(_type: 'message', listener: (ev: MessageEvent) => void) {
        listeners.add(listener)
      },
      removeEventListener(_type: 'message', listener: (ev: MessageEvent) => void) {
        listeners.delete(listener)
      },
    }
  }
}

export function installInProcessMappingWorkerForTests(): void {
  setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
}

export function resetInProcessMappingWorkerForTests(): void {
  resetSharedMappingClient()
}
