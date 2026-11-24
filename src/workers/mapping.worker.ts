/**
 * Mapping worker entry (Stage 7 / Stage 19).
 */

import { MappingAuthority } from '../mapping/mappingAuthority'
import {
  MAPPING_WORKER_ERROR,
  validateMappingConfig,
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  lookupCandidatesToWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from '../mapping/protocol'
import { canonicalizeIdentity } from '../mapping/canonicalize'
import { DEFAULT_MAPPING_CONFIG } from '../pcap/anonymization/mapping'
import { toSafeWorkerError } from '../domain/safeWorkerError'

const authority = new MappingAuthority(DEFAULT_MAPPING_CONFIG)
let activeResolveGeneration: string | null = null

function post(response: MappingWorkerResponse): void {
  self.postMessage(response)
}

function onError(requestId: string, generationId: string | undefined, code: string, message: string): void {
  // T03: never forward caller message text over the wire — only code + safe Czech copy.
  const err = Object.assign(new Error(message), { code })
  const safe = toSafeWorkerError(err, 'mapping', code)
  post({
    type: 'error',
    requestId,
    generationId,
    code: safe.code,
    message: safe.safeMessage,
  })
}

self.addEventListener('message', (ev: MessageEvent<MappingWorkerRequest>) => {
  const msg = ev.data
  if (!msg || typeof msg !== 'object' || !('type' in msg)) {
    return
  }

  try {
  const versionErr = validateProtocolVersion(msg.protocolVersion)
  if (versionErr) {
    onError('requestId' in msg ? msg.requestId : 'unknown', undefined, versionErr.code, versionErr.message)
    return
  }

  switch (msg.type) {
    case 'ping':
      post({ type: 'pong', requestId: msg.requestId, revision: authority.getMappingRevision() })
      break

    case 'cancel':
      activeResolveGeneration = msg.generationId
      authority.requestCancel(msg.generationId)
      post({ type: 'pong', requestId: msg.requestId, revision: authority.getMappingRevision() })
      break

    case 'reset-session':
      authority.resetSession()
      activeResolveGeneration = null
      post({ type: 'session-reset', requestId: msg.requestId })
      break

    case 'lookup-original': {
      const canonical = canonicalizeIdentity(msg.category, msg.canonical)
      if (canonical === null) {
        onError(msg.requestId, undefined, MAPPING_WORKER_ERROR.invalidIdentity, 'Invalid canonical')
        break
      }
      const result = authority.lookupByOriginal({ category: msg.category, canonical })
      if (!result.ok) {
        onError(msg.requestId, undefined, result.code, result.message)
        break
      }
      post({
        type: 'lookup-result',
        requestId: msg.requestId,
        candidates: lookupCandidatesToWire(result.candidates),
      })
      break
    }

    case 'lookup-alias': {
      const result = authority.lookupByAlias({ alias: msg.alias })
      if (!result.ok) {
        onError(msg.requestId, undefined, result.code, result.message)
        break
      }
      post({
        type: 'lookup-result',
        requestId: msg.requestId,
        candidates: lookupCandidatesToWire(result.candidates),
      })
      break
    }

    case 'release-occurrence': {
      const canonical = canonicalizeIdentity(msg.category, msg.canonical)
      const occurrence = msg.occurrence.kind === 'text'
        ? {
            kind: 'text' as const,
            sourceId: msg.occurrence.sourceId,
            line: msg.occurrence.line!,
            start: msg.occurrence.start!,
            end: msg.occurrence.end!,
          }
        : {
            kind: 'packet' as const,
            sourceId: msg.occurrence.sourceId,
            packetIndex: msg.occurrence.packetIndex!,
          }
      if (canonical === null) {
        onError(msg.requestId, undefined, MAPPING_WORKER_ERROR.invalidIdentity, 'Invalid canonical')
        break
      }
      const result = authority.releaseOccurrence({
        category: msg.category,
        canonical,
        occurrence,
      })
      if (!result.ok) {
        onError(msg.requestId, undefined, result.code, result.message)
        break
      }
      post({
        type: 'occurrence-released',
        requestId: msg.requestId,
        mappingRevision: result.mappingRevision,
        scrubbed: result.scrubbed,
        snapshot: authority.getPublishedSnapshot()
          ? snapshotToWire(authority.getPublishedSnapshot()!)
          : null,
      })
      break
    }

    case 'resolve': {
      activeResolveGeneration = msg.generationId
      const configErr = validateMappingConfig(msg.config)
      if (configErr) {
        onError(msg.requestId, msg.generationId, configErr.code, configErr.message)
        activeResolveGeneration = null
        break
      }
      const validated = validateResolveIdentities(msg.identities)
      if (!validated.ok) {
        onError(msg.requestId, msg.generationId, validated.error.code, validated.error.message)
        activeResolveGeneration = null
        break
      }

      if (msg.generationId !== activeResolveGeneration) {
        onError(msg.requestId, msg.generationId, MAPPING_WORKER_ERROR.invalidMessage, 'Stale generation')
        break
      }

      const result = authority.resolve({
        generationId: msg.generationId,
        sourceId: msg.sourceId,
        identities: validated.identities,
        customRules: msg.customRules,
        correlationOptions: msg.correlationOptions,
      }, msg.config)

      if (!result.ok) {
        onError(msg.requestId, msg.generationId, result.code, result.message)
        activeResolveGeneration = null
        break
      }

      if (msg.generationId !== activeResolveGeneration) {
        onError(msg.requestId, msg.generationId, MAPPING_WORKER_ERROR.invalidMessage, 'Stale generation after resolve')
        activeResolveGeneration = null
        break
      }

      post({
        type: 'resolved',
        requestId: msg.requestId,
        generationId: msg.generationId,
        snapshot: snapshotToWire(result.snapshot),
      })
      activeResolveGeneration = null
      authority.clearCancel()
      break
    }

    case 'resolve-staging': {
      activeResolveGeneration = msg.generationId
      const configErr = validateMappingConfig(msg.config)
      if (configErr) {
        onError(msg.requestId, msg.generationId, configErr.code, configErr.message)
        activeResolveGeneration = null
        break
      }
      const validated = validateResolveIdentities(msg.identities)
      if (!validated.ok) {
        onError(msg.requestId, msg.generationId, validated.error.code, validated.error.message)
        activeResolveGeneration = null
        break
      }

      const result = authority.resolveStaging({
        generationId: msg.generationId,
        sourceId: msg.sourceId,
        identities: validated.identities,
        customRules: msg.customRules,
        correlationOptions: msg.correlationOptions,
      }, msg.config)

      if (!result.ok) {
        onError(msg.requestId, msg.generationId, result.code, result.message)
        activeResolveGeneration = null
        break
      }

      post({
        type: 'staging-preview',
        requestId: msg.requestId,
        generationId: msg.generationId,
        snapshot: snapshotToWire(result.snapshot),
      })
      activeResolveGeneration = null
      authority.clearCancel()
      break
    }

    case 'commit-staging': {
      const result = authority.commitStaging()
      if (!result.ok) {
        onError(msg.requestId, undefined, result.code, result.message)
        break
      }
      post({
        type: 'staging-committed',
        requestId: msg.requestId,
        generationId: result.snapshot.generationId,
        snapshot: snapshotToWire(result.snapshot),
      })
      break
    }

    case 'abort-staging': {
      authority.abortStaging()
      post({ type: 'staging-aborted', requestId: msg.requestId })
      break
    }

    default:
      break
  }
  } catch (err) {
    const safe = toSafeWorkerError(err, 'mapping', MAPPING_WORKER_ERROR.internal)
    onError(
      'requestId' in msg ? msg.requestId : 'unknown',
      'generationId' in msg ? msg.generationId : undefined,
      safe.code,
      safe.safeMessage,
    )
    activeResolveGeneration = null
  }
})

export {}
