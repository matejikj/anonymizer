/**
 * Detection session state machine used by the Worker (ARCHITECTURE §8 / §7.3).
 * Processes complete physical lines only; keeps line tail between chunks.
 */

import type { Entity, EntitySummary, RawMatch, ResolvedMatch } from '../domain/types.ts'
import type { RulesetConfig } from '../domain/configSchema.ts'
import {
  createDefaultRulesetConfig,
  rulesetToDetectorConfig,
} from '../domain/configSchema.ts'
import {
  createLineAssembler,
  pushBytes,
  pushText,
  type AssembledLine,
  type LineAssemblerState,
} from '../features/import-log/streamingDecode.ts'
import { detectOnPhysicalLine } from '../engine/detectLine.ts'
import { resolveOverlaps } from '../engine/resolveOverlaps.ts'
import { registerEntitySkeletons, toEntitySummaries } from '../engine/entityRegistry.ts'
import { createEntityRegistry } from '../engine/replacements.ts'
import {
  entityKeyToIndex,
  packResolvedMatches,
  toTransferableBuffers,
  type PackedMatchBuffers,
} from '../engine/packedMatchIndex.ts'
import { buildReplacementPlan } from '../engine/transform.ts'
import type { ReplacementPlanBuffers } from './protocol.ts'
import { INPUT_LIMITS } from '../features/import-log/inputLimits.ts'
import { IncidentLog } from '../domain/anonymizationIncident.ts'
import type { IncidentLogSnapshot } from '../domain/anonymizationIncident.ts'

/** Detector id for T07 length-preserving whole-line masks (never stores original text). */
export const LINE_ISOLATION_DETECTOR_ID = 'line-isolation'


export const LINE_BATCH_HEARTBEAT = 250

export interface DetectionSessionHooks {
  onProgress: (processedBytes: number, processedLines: number) => void
  onRuleStarted: (ruleId: string) => void
  onHeartbeat: (ruleId?: string) => void
}

export class DetectionSession {
  requestId = ''
  profile: RulesetConfig = createDefaultRulesetConfig()
  excludeRuleIds = new Set<string>()
  private assembler: LineAssemblerState = createLineAssembler()
  private rawMatches: RawMatch[] = []
  private lastProgressAt = 0
  /** Lines buffered for custom-regex batching with heartbeats. */
  private pendingLines: AssembledLine[] = []
  private finalized = false
  private resolved: ResolvedMatch[] = []
  private entities: Entity[] = []
  private hooks: DetectionSessionHooks
  private incidentLog = new IncidentLog()

  constructor(hooks: DetectionSessionHooks) {
    this.hooks = hooks
  }
  start(requestId: string, profile: RulesetConfig, excludeRuleIds: Iterable<string> = []): void {
    this.requestId = requestId
    this.profile = profile
    this.excludeRuleIds = new Set(excludeRuleIds)
    this.assembler = createLineAssembler()
    this.rawMatches = []
    this.pendingLines = []
    this.finalized = false
    this.resolved = []
    this.entities = []
    this.lastProgressAt = 0
    this.incidentLog = new IncidentLog()
  }

  pushByteChunk(
    bytes: ArrayBuffer,
    byteOffset: number,
    byteLength: number,
    final: boolean,
  ): void {
    if (this.finalized) return
    const view = new Uint8Array(bytes, byteOffset, byteLength)
    const { lines } = pushBytes(this.assembler, view, final)
    this.enqueueLines(lines)
    if (final) this.flushPending(true)
    this.maybeProgress()
  }

  pushTextChunk(text: string, final: boolean): void {
    if (this.finalized) return
    const { lines } = pushText(this.assembler, text, final)
    this.enqueueLines(lines)
    if (final) this.flushPending(true)
    this.maybeProgress()
  }

  private enqueueLines(lines: AssembledLine[]): void {
    for (const line of lines) {
      this.pendingLines.push(line)
      if (this.pendingLines.length >= LINE_BATCH_HEARTBEAT) {
        this.flushPending(false)
      }
    }
  }

  private flushPending(isFinal: boolean): void {
    if (this.pendingLines.length === 0 && !isFinal) return
    const config = rulesetToDetectorConfig(this.profile, {
      excludeRuleIds: this.excludeRuleIds,
    })
    const builtins = this.profile.profile.builtins

    // Emit rule-started for each enabled custom regex once per flush wave
    for (const rule of config.customRules) {
      if (rule.kind === 'regex') {
        this.hooks.onRuleStarted(rule.id)
        this.hooks.onHeartbeat(rule.id)
      }
    }

    const batch = this.pendingLines
    this.pendingLines = []
    for (let i = 0; i < batch.length; i++) {
      const line = batch[i]!
      if (line.start + line.text.length > Number.MAX_SAFE_INTEGER) continue
      try {
        const matches = detectOnPhysicalLine(
          line.text,
          line.line,
          line.start,
          config,
          builtins,
        )
        for (let m = 0; m < matches.length; m++) this.rawMatches.push(matches[m]!)
      } catch {
        // T07: isolate detector failure to this physical line — length-preserving mask.
        this.rawMatches.push(lineIsolationMatch(line))
        this.incidentLog.record({
          unit: 'line',
          sourceId: this.requestId || 'text',
          lineNumber: line.line,
          stage: 'detection',
          reason: 'detector-exception',
          fallback: 'line-masked',
        })
      }
      if ((i + 1) % LINE_BATCH_HEARTBEAT === 0) {
        this.hooks.onHeartbeat()
        this.hooks.onProgress(this.assembler.processedBytes, this.assembler.processedLines)
      }
    }

    if (this.assembler.processedLines > INPUT_LIMITS.fileMaxLines) {
      throw Object.assign(new Error('Překročen limit počtu řádků'), {
        code: 'line-limit',
      })
    }

    this.hooks.onProgress(this.assembler.processedBytes, this.assembler.processedLines)
    if (isFinal) this.finalized = true
  }

  private maybeProgress(): void {
    const now = Date.now()
    if (now - this.lastProgressAt < 100) return
    this.lastProgressAt = now
    this.hooks.onProgress(this.assembler.processedBytes, this.assembler.processedLines)
  }

  finalizeDetection(): {
    packedMatches: PackedMatchBuffers
    transfer: ArrayBuffer[]
    entities: EntitySummary[]
    lineCount: number
    incidents: IncidentLogSnapshot
  } {
    if (!this.finalized) this.flushPending(true)
    this.resolved = resolveOverlaps(this.rawMatches)
    const customRules = rulesetToDetectorConfig(this.profile, { excludeRuleIds: this.excludeRuleIds })
      .customRules
    const registry = createEntityRegistry(customRules)
    const entities = registerEntitySkeletons(registry, this.resolved)
    applyLineIsolationReplacements(entities, this.resolved)
    this.entities = entities
    const entityIndexByKey = entityKeyToIndex(entities)
    const packed = packResolvedMatches(
      this.resolved,
      entityIndexByKey,
      (key) => registry.entities.get(key)?.enabled ?? true,
    )
    const { buffers, transfer } = toTransferableBuffers(packed)
    return {
      packedMatches: buffers,
      transfer,
      entities: toEntitySummaries(entities),
      lineCount: this.assembler.processedLines,
      incidents: this.incidentLog.snapshot(),
    }
  }

  applyReplacements(replacements: Record<string, string>): void {
    for (const entity of this.entities) {
      if (entity.sourceId === LINE_ISOLATION_DETECTOR_ID) continue
      const alias = replacements[entity.key]
      if (alias != null) entity.replacement = alias
    }
  }

  buildPlan(entityBitset: ArrayBuffer): {
    planBuffers: ReplacementPlanBuffers
    transfer: ArrayBuffer[]
  } {
    const enabled = new Uint8Array(entityBitset)
    for (let i = 0; i < this.entities.length; i++) {
      const ent = this.entities[i]!
      ent.enabled = i < enabled.length ? enabled[i] !== 0 : ent.enabled
    }
    const entityIndexByKey = entityKeyToIndex(this.entities)
    const packed = packResolvedMatches(
      this.resolved,
      entityIndexByKey,
      (key) => this.entities.find((e) => e.key === key)?.enabled ?? true,
    )
    const plan = buildReplacementPlan(packed, this.entities)
    const enabledFlags = new Uint8Array(plan.replacements.length)
    for (let i = 0; i < plan.replacements.length; i++) {
      enabledFlags[i] = plan.replacements[i] == null ? 0 : 1
    }
    const lengthDeltas = plan.lengthDeltas.buffer.slice(
      plan.lengthDeltas.byteOffset,
      plan.lengthDeltas.byteOffset + plan.lengthDeltas.byteLength,
    ) as ArrayBuffer
    const fenwick = plan.fenwick.buffer.slice(
      plan.fenwick.byteOffset,
      plan.fenwick.byteOffset + plan.fenwick.byteLength,
    ) as ArrayBuffer
    const flagsBuf = enabledFlags.buffer.slice(
      enabledFlags.byteOffset,
      enabledFlags.byteOffset + enabledFlags.byteLength,
    ) as ArrayBuffer
    return {
      planBuffers: {
        lengthDeltas,
        fenwick,
        enabledFlags: flagsBuf,
        count: plan.replacements.length,
      },
      transfer: [lengthDeltas, fenwick, flagsBuf],
    }
  }
}

/** Whole-line mask match — never embeds the original line text. */
function lineIsolationMatch(line: AssembledLine): RawMatch {
  const len = line.text.length
  return {
    start: line.start,
    end: line.start + len,
    line: line.line,
    category: 'custom',
    original: '',
    normalized: `${LINE_ISOLATION_DETECTOR_ID}:${line.line}`,
    detectorId: LINE_ISOLATION_DETECTOR_ID,
    ruleId: LINE_ISOLATION_DETECTOR_ID,
    priority: 10_000,
    confidence: 1,
  }
}

function applyLineIsolationReplacements(
  entities: Entity[],
  resolved: readonly ResolvedMatch[],
): void {
  for (const entity of entities) {
    if (entity.sourceId !== LINE_ISOLATION_DETECTOR_ID) continue
    const match = resolved.find((m) => m.entityKey === entity.key)
    const len = match ? match.end - match.start : 0
    entity.replacement = len > 0 ? 'x'.repeat(len) : ''
    entity.enabled = true
  }
}
