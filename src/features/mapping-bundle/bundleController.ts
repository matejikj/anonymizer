/**
 * Mapping bundle export/import lifecycle (Stage 21).
 * Plain JSON only — no encryption, no passphrase.
 */

import { MAPPING_CAPABILITY_LIMITS } from '../../domain/capabilityContract'
import { getSharedMappingClient } from '../../mapping/sharedMappingClient'
import { BUNDLE_CODEC_ERROR } from '../../mapping/bundle/errors'
import { buildBundlePayloadFromSnapshot, bundleFileName } from '../../mapping/bundle/buildPayload'
import { serializeMappingBundleJson, parseMappingBundleJsonBytes } from '../../mapping/bundle'
import type { MappingBundleSource, MappingBundlePayload } from '../../mapping/bundle/types'
import { downloadBlob } from '../export-log/exportCoordinator.ts'
import {
  clearResolveOnlyModel,
  setResolveOnlyPayload,
} from '../resolve-only/resolveOnlyModel.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import { getPcapSession } from '../../pcap/ui/pcapSession.ts'
import { listCorrelationSources } from '../../correlation/correlationSessionModel.ts'
import { SourceKind as SK } from '../../domain/sourceArtifact.ts'

export class BundleCancelledError extends Error {
  override readonly name = 'BundleCancelledError'
}

export class BundleLifecycleError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

export type BundleJobPhase = 'idle' | 'encoding' | 'decoding'

let activeJob: BundleJobPhase = 'idle'
let activeAbort: AbortController | null = null

export function getBundleJobPhase(): BundleJobPhase {
  return activeJob
}

export function exportMappingBundlePayload(
  payload: MappingBundlePayload,
  label: string,
  input: { signal?: AbortSignal },
): { fileName: string; byteLength: number } {
  if (input.signal?.aborted) throw new BundleCancelledError()

  const json = serializeMappingBundleJson(payload)
  const bytes = new TextEncoder().encode(json)
  if (bytes.byteLength > MAPPING_CAPABILITY_LIMITS.maxBundleBytes) {
    throw new BundleLifecycleError(BUNDLE_CODEC_ERROR.oversize, 'Bundle exceeds export limit')
  }

  const fileName = bundleFileName(label)
  const blob = new Blob([json], { type: 'application/json;charset=utf-8' })
  downloadBlob(fileName, blob)
  return { fileName, byteLength: bytes.byteLength }
}

export function cancelBundleJob(): void {
  activeAbort?.abort()
  activeAbort = null
  activeJob = 'idle'
}

export function releaseBundleCryptoSession(): void {
  cancelBundleJob()
  clearResolveOnlyModel()
}

function textSourcesFromSession(): MappingBundleSource[] {
  const session = getSessionModel()
  if (!session) return []
  return [{
    id: session.meta.generation,
    kind: 'text',
    name: session.meta.fileName ?? 'text-log',
  }]
}

function pcapSourcesFromSession(): MappingBundleSource[] {
  const session = getPcapSession()
  if (!session) return []
  return [{
    id: session.generationId,
    kind: 'pcap',
    name: session.fileName,
  }]
}

export function collectActiveMappingSources(mode: 'text' | 'pcap'): MappingBundleSource[] {
  return mode === 'text' ? textSourcesFromSession() : pcapSourcesFromSession()
}

export function collectCorrelationMappingSources(): MappingBundleSource[] {
  const sources: MappingBundleSource[] = []
  for (const record of listCorrelationSources()) {
    if (record.phase !== 'planned') continue
    const kind = record.kind === SK.Pcap ? 'pcap' : 'text'
    sources.push({
      id: record.sourceId,
      kind,
      name: record.fileName,
    })
  }
  return sources
}

export function canExportCorrelationMappingBundle(): boolean {
  const sources = collectCorrelationMappingSources()
  if (sources.length === 0) return false
  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  return !!snapshot && snapshot.entries.length > 0
}

export async function exportCorrelationMappingBundle(input: {
  signal?: AbortSignal
}): Promise<{ fileName: string; byteLength: number }> {
  const sources = collectCorrelationMappingSources()
  if (sources.length === 0) {
    throw new BundleLifecycleError('bundle-no-source', 'No correlation sources for mapping export')
  }
  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  if (!snapshot || snapshot.entries.length === 0) {
    throw new BundleLifecycleError('bundle-empty', 'No mapping entries to export')
  }

  if (activeJob !== 'idle') {
    throw new BundleLifecycleError('bundle-busy', 'Mapping bundle job already running')
  }

  const payload = buildBundlePayloadFromSnapshot(snapshot, sources)
  const ac = new AbortController()
  activeAbort = ac
  activeJob = 'encoding'

  const onAbort = () => cancelBundleJob()
  input.signal?.addEventListener('abort', onAbort, { once: true })

  try {
    if (input.signal?.aborted) throw new BundleCancelledError()

    return exportMappingBundlePayload(payload, `correlation-${sources.length}-sources`, input)
  } finally {
    input.signal?.removeEventListener('abort', onAbort)
    activeAbort = null
    activeJob = 'idle'
  }
}

export async function exportActiveMappingBundle(input: {
  mode: 'text' | 'pcap'
  signal?: AbortSignal
}): Promise<{ fileName: string; byteLength: number }> {
  if (activeJob !== 'idle') {
    throw new BundleLifecycleError('bundle-busy', 'Mapping bundle job already running')
  }

  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  if (!snapshot || snapshot.entries.length === 0) {
    throw new BundleLifecycleError('bundle-empty', 'No mapping entries to export')
  }

  const sources = collectActiveMappingSources(input.mode)
  if (sources.length === 0) {
    throw new BundleLifecycleError('bundle-no-source', 'No active session source')
  }

  const payload = buildBundlePayloadFromSnapshot(snapshot, sources)
  const ac = new AbortController()
  activeAbort = ac
  activeJob = 'encoding'

  const onAbort = () => cancelBundleJob()
  input.signal?.addEventListener('abort', onAbort, { once: true })

  try {
    if (input.signal?.aborted) throw new BundleCancelledError()

    const label = sources[0]?.name ?? 'mapping'
    return exportMappingBundlePayload(payload, label, input)
  } finally {
    input.signal?.removeEventListener('abort', onAbort)
    activeAbort = null
    activeJob = 'idle'
  }
}

export async function importMappingBundleFile(input: {
  file: File
  signal?: AbortSignal
}): Promise<{ entryCount: number; fileName: string }> {
  if (activeJob !== 'idle') {
    throw new BundleLifecycleError('bundle-busy', 'Mapping bundle job already running')
  }

  if (input.file.size > MAPPING_CAPABILITY_LIMITS.maxBundleImportBytes) {
    throw new BundleLifecycleError(BUNDLE_CODEC_ERROR.oversize, 'Bundle file exceeds import limit')
  }

  activeJob = 'decoding'
  const ac = new AbortController()
  activeAbort = ac

  const onAbort = () => cancelBundleJob()
  input.signal?.addEventListener('abort', onAbort, { once: true })

  try {
    if (input.signal?.aborted) throw new BundleCancelledError()

    const bytes = new Uint8Array(await input.file.arrayBuffer())
    if (bytes.byteLength > MAPPING_CAPABILITY_LIMITS.maxBundleImportBytes) {
      throw new BundleLifecycleError(BUNDLE_CODEC_ERROR.oversize, 'Bundle exceeds import limit')
    }

    const decoded = parseMappingBundleJsonBytes(bytes)
    if (input.signal?.aborted) throw new BundleCancelledError()

    if (!decoded.ok) {
      throw new BundleLifecycleError(decoded.code, decoded.message)
    }

    clearResolveOnlyModel()
    setResolveOnlyPayload(decoded.value, input.file.name)

    return { entryCount: decoded.value.entries.length, fileName: input.file.name }
  } finally {
    input.signal?.removeEventListener('abort', onAbort)
    activeAbort = null
    activeJob = 'idle'
  }
}
