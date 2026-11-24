/**
 * Text source adapter — wraps text preflight, worker discovery, and plan build (Stage 23).
 */

import { SourceKind as SK } from '../domain/sourceArtifact'
import { MAX_TEXT_FILE_BYTES } from '../domain/capabilityContract'
import { preflightFile } from '../features/import-log/preflight'
import { detectTextEncoding } from '../features/import-log/textEncoding.ts'
import { DetectionWorkerClient } from '../app/workerClient'
import { getActiveProfile, getActiveProfileRevision } from '../features/rules/activeProfile'
import { rulesetToDetectorConfig } from '../domain/configSchema'
import { registerEntitiesFromSnapshot } from '../mapping/textIdentity'
import { entityKeyToIndex, packResolvedMatches, fromTransferableBuffers } from '../engine/packedMatchIndex'
import { buildReplacementPlan } from '../engine/transform'
import { patchEntitySummariesFromSnapshot } from '../engine/entityRegistry'
import { discoverTextFile } from './textDiscovery'
import type { Entity, EntitySummary, ResolvedMatch } from '../domain/types'
import type {
  BuildPlanRequest,
  DiscoveryRequest,
  ProbeResult,
  SourceAdapter,
  SourceLimits,
  SourcePreflightResult,
  TextSourceDiscovery,
  TextSourcePlan,
} from './types'
import { perKindFileLimit } from './sourceLimits'

function looksBinary(head: Uint8Array): boolean {
  // T43 — UTF-16 text contains NULs; defer to encoding-aware preflight.
  const enc = detectTextEncoding(head)
  if (enc.label === 'utf-16le' || enc.label === 'utf-16be') return false
  const n = Math.min(head.byteLength, 8192)
  for (let i = 0; i < n; i++) {
    if (head[i] === 0) return true
  }
  return false
}

export function createTextSourceAdapter(deps?: {
  getProfile?: () => ReturnType<typeof getActiveProfile>
  getProfileRevision?: () => number
  createDetectionClient?: () => DetectionWorkerClient
}): SourceAdapter<TextSourceDiscovery, TextSourcePlan> {
  const getProfile = deps?.getProfile ?? getActiveProfile
  const getProfileRevision = deps?.getProfileRevision ?? getActiveProfileRevision
  const createDetectionClient = deps?.createDetectionClient ?? (() => new DetectionWorkerClient())

  return {
    kind: SK.Text,

    probe(head: Uint8Array): ProbeResult {
      if (looksBinary(head)) {
        return { ok: false, code: 'binary', message: 'Input looks binary' }
      }
      return { ok: true, kind: SK.Text }
    },

    async preflight(file: File, limits: SourceLimits): Promise<SourcePreflightResult> {
      const cap = Math.min(perKindFileLimit(SK.Text), limits.maxFileBytes, MAX_TEXT_FILE_BYTES)
      if (file.size > cap) {
        return {
          ok: false,
          code: 'too-large-file',
          message: `Text file exceeds ${cap} bytes`,
        }
      }
      const result = await preflightFile(file)
      if (!result.ok) {
        return { ok: false, code: result.code, message: result.message }
      }
      return { ok: true, byteLength: result.byteLength, kind: SK.Text }
    },

    async discover(request: DiscoveryRequest): Promise<TextSourceDiscovery> {
      const client = createDetectionClient()
      try {
        const profile = getProfile()
        const discovered = await discoverTextFile({
          file: request.file,
          sourceId: request.sourceId,
          client,
          profile,
          signal: request.signal,
          onProgress: request.onProgress,
        })
        return {
          kind: 'text',
          generationId: request.generationId,
          sourceId: request.sourceId,
          fileName: request.file.name,
          byteLength: request.file.size,
          lineCount: discovered.detection.lineCount,
          identities: discovered.identities,
          detection: discovered.detection,
          lineEndings: discovered.lineEndings,
        }
      } finally {
        client.dispose()
      }
    },

    async buildPlan(
      request: BuildPlanRequest & { discovery: TextSourceDiscovery },
    ): Promise<TextSourcePlan> {
      const profile = getProfile()
      const profileRevision = request.profileRevision ?? getProfileRevision()
      const discovery = request.discovery
      const customRules = rulesetToDetectorConfig(profile).customRules
      const packedRaw = fromTransferableBuffers(discovery.detection.packedMatches)
      const summaries = patchEntitySummariesFromSnapshot(discovery.detection.entities, request.snapshot)
      const entities: Entity[] = summaries.map((s) => ({
        key: s.key,
        category: s.category,
        originalSample: s.originalSample,
        normalized: s.normalized,
        replacement: s.replacement,
        occurrenceCount: s.occurrenceCount,
        occurrenceIndexes: new Uint32Array(0),
        enabled: s.enabled,
        source: s.source,
        sourceId: s.sourceId,
        createdOrder: s.createdOrder,
      }))
      const matches = rebuildMatchesFromPacked(packedRaw, summaries)
      const withRules = registerEntitiesFromSnapshot(matches, request.snapshot, customRules)
      const entityIndexByKey = entityKeyToIndex(withRules)
      const enabledByKey = new Map(withRules.map((e) => [e.key, e.enabled]))
      const packed = packResolvedMatches(
        matches,
        entityIndexByKey,
        (key) => enabledByKey.get(key) ?? true,
      )
      const plan = buildReplacementPlan(packed, withRules.length > 0 ? withRules : entities)
      return {
        kind: 'text',
        generationId: request.generationId,
        sourceId: request.sourceId,
        mappingRevision: request.snapshot.mappingRevision,
        profileRevision,
        plan,
        packed,
        matches,
        outputFileName: discovery.fileName.replace(/(\.[^.]+)?$/, '.anonym.log'),
      }
    },
  }
}

function rebuildMatchesFromPacked(
  packed: ReturnType<typeof fromTransferableBuffers>,
  summaries: readonly EntitySummary[],
): ResolvedMatch[] {
  const matches: ResolvedMatch[] = []
  const n = packed.starts.length
  for (let i = 0; i < n; i++) {
    const summary = summaries[packed.entityIndexes[i]!]
    if (!summary) continue
    const start = packed.starts[i]!
    const len = packed.lengths[i]!
    matches.push({
      entityKey: summary.key,
      category: summary.category,
      original: summary.originalSample,
      normalized: summary.normalized,
      line: packed.lines[i]!,
      start,
      end: start + len,
      detectorId: summary.sourceId ?? 'builtin',
      priority: 0,
      confidence: 1,
    })
  }
  return matches
}

export const textSourceAdapter = createTextSourceAdapter()
