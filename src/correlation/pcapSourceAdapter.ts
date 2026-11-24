/**
 * PCAP source adapter — probe, preflight, discovery pipeline, deterministic plan (Stage 23).
 */

import { SourceKind as SK } from '../domain/sourceArtifact'
import { CaptureFormat } from '../pcap/domain/types'
import { probeFormat } from '../pcap/capture/probe'
import { preflightPcapFile } from '../pcap/capture/preflight'
import { identitiesFromDiscovery } from '../pcap/discovery/discoveryPipeline'
import { containerFromWire } from '../pcap/processing/containerWireAdapter'
import { sourceDiscoveryFromWire } from '../pcap/processing/discoveryWireAdapter'
import { PcapProcessingWorkerClient } from '../pcap/processing/pcapProcessingWorkerClient'
import { planFromWire } from '../pcap/processing/planWireAdapter'
import { validateMappingClosure } from '../pcap/plan/mappingClosureValidation'
import { getActivePcapProfile, getActivePcapProfileRevision } from '../pcap/profile/activePcapProfile'
import { profileToSanitizationPolicy } from '../pcap/profile/presets'
import type {
  BuildPlanRequest,
  DiscoveryRequest,
  PcapSourceDiscovery,
  PcapSourcePlan,
  ProbeResult,
  SourceAdapter,
  SourceLimits,
  SourcePreflightResult,
} from './types'
import { perKindFileLimit } from './sourceLimits'

function captureFormatFromProbe(head: ArrayBuffer): CaptureFormat | null {
  const probed = probeFormat(head)
  if (probed.format === null) return null
  return probed.format
}

export function createPcapSourceAdapter(deps?: {
  getProfile?: () => ReturnType<typeof getActivePcapProfile>
  getProfileRevision?: () => number
  createProcessingClient?: () => PcapProcessingWorkerClient
}): SourceAdapter<PcapSourceDiscovery, PcapSourcePlan> {
  const getProfile = deps?.getProfile ?? getActivePcapProfile
  const getProfileRevision = deps?.getProfileRevision ?? getActivePcapProfileRevision
  const createProcessingClient = deps?.createProcessingClient ?? (() => new PcapProcessingWorkerClient())
  let active: {
    client: PcapProcessingWorkerClient
    generationId: string
    sourceId: string
    signal?: AbortSignal
    onAbort?: () => void
  } | null = null

  function releaseActive(expected?: PcapProcessingWorkerClient): void {
    if (!active || (expected && active.client !== expected)) return
    if (active.signal && active.onAbort) {
      active.signal.removeEventListener('abort', active.onAbort)
    }
    active.client.terminate()
    active = null
  }

  return {
    kind: SK.Pcap,

    probe(head: Uint8Array, file: File): ProbeResult {
      void file
      if (head.byteLength < 4) {
        return { ok: false, code: 'too-small', message: 'Capture header too short' }
      }
      const buf = head.buffer.slice(head.byteOffset, head.byteOffset + head.byteLength) as ArrayBuffer
      const format = captureFormatFromProbe(buf)
      if (format === null) {
        return { ok: false, code: 'unknown-format', message: 'Not a PCAP/PCAPNG capture' }
      }
      return { ok: true, kind: SK.Pcap }
    },

    async preflight(file: File, limits: SourceLimits): Promise<SourcePreflightResult> {
      const cap = Math.min(perKindFileLimit(SK.Pcap), limits.maxFileBytes)
      if (file.size > cap) {
        return { ok: false, code: 'too-large', message: `Capture exceeds ${cap} bytes` }
      }
      const result = await preflightPcapFile(file)
      if (!result.ok) {
        return { ok: false, code: result.code, message: result.message }
      }
      return { ok: true, byteLength: result.byteLength, kind: SK.Pcap }
    },

    async discover(request: DiscoveryRequest): Promise<PcapSourceDiscovery> {
      const head = await request.file.slice(0, 16).arrayBuffer()
      const format = captureFormatFromProbe(head)
      if (format === null) {
        throw new Error('Unknown capture format')
      }
      const profile = getProfile()
      const policy = profileToSanitizationPolicy(profile)
      releaseActive()
      const client = createProcessingClient()
      const onAbort = () => {
        client.cancel(request.generationId)
        releaseActive(client)
      }
      active = {
        client,
        generationId: request.generationId,
        sourceId: request.sourceId,
        signal: request.signal,
        onAbort,
      }
      request.signal?.addEventListener('abort', onAbort, { once: true })

      try {
        const workerResult = await client.processCapture({
          blob: request.file,
          format,
          policy,
          generationId: request.generationId,
          sourceId: request.sourceId,
          onProgress: (phase, done, total) => request.onProgress?.(phase, done, total),
        })
        if (request.signal?.aborted || active?.client !== client) throw new Error('cancelled')

        const container = containerFromWire(workerResult.container)
        const discovery = sourceDiscoveryFromWire(workerResult.discovery, container.packetDiscovery)
        const identities = identitiesFromDiscovery(discovery)
        return {
          kind: 'pcap',
          generationId: request.generationId,
          sourceId: request.sourceId,
          fileName: request.file.name,
          byteLength: request.file.size,
          format,
          identities,
          discovery,
          container: {
            descriptors: container.descriptors,
            checkpoints: container.checkpoints,
            issues: container.issues,
            classicHeader: container.classicHeader,
            pcapngSections: container.pcapngSections,
            pcapngInterfaces: container.pcapngInterfaces,
          },
          policy,
        }
      } catch (error) {
        releaseActive(client)
        throw error
      }
    },

    async buildPlan(
      request: BuildPlanRequest & { discovery: PcapSourceDiscovery },
    ): Promise<PcapSourcePlan> {
      const profile = getProfile()
      const profileRevision = request.profileRevision ?? getProfileRevision()
      const worker = active
      if (!worker
        || worker.generationId !== request.generationId
        || worker.sourceId !== request.sourceId) {
        throw new Error('PCAP processing worker session is unavailable or stale')
      }

      try {
        // T04: remaining closure failures soft-fail — deferred resolve masks fields + records incidents.
        void validateMappingClosure(request.discovery.discovery.intents, request.snapshot)
        const planWire = await worker.client.buildPlan({
          generationId: request.generationId,
          profile,
          format: request.discovery.format,
          fileName: request.discovery.fileName,
          snapshot: request.snapshot,
          onProgress: () => undefined,
        })
        return {
          kind: 'pcap',
          generationId: request.generationId,
          sourceId: request.sourceId,
          mappingRevision: request.snapshot.mappingRevision,
          profileRevision,
          plan: planFromWire(planWire, profile.id),
          outputFileName: request.discovery.fileName.replace(/(\.[^.]+)?$/, '.anonym.pcap'),
        }
      } finally {
        // The immutable plan plus source Blob/descriptors are sufficient for review
        // and export. Do not retain the worker-owned PacketEnvelope[] afterwards.
        releaseActive(worker.client)
      }
    },
  }
}

export const pcapSourceAdapter = createPcapSourceAdapter()
