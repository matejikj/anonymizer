/**
 * T66 — merge IdentityRegistry hits into a text export plan so shared-session
 * identities (e.g. SIP user from a PCAP) rewrite free-text logs too.
 */

import type { Category, Entity, PackedMatchIndex } from '../../domain/types'
import type { IdentityCategory } from '../../mapping/identityCategories'
import type { MappingSnapshot } from '../../mapping/types'
import { IdentityRegistry } from '../../mapping/identityRegistry'
import { buildReplacementPlan } from '../../engine/transform'
import { FLAG_ENABLED } from '../../engine/packedMatchIndex'
import { fenwickBuild } from '../../engine/fenwick'
import type { ExportPlanSnapshot } from './replacementSnapshot'

function mapToTextCategory(category: IdentityCategory): Category {
  switch (category) {
    case 'hostname':
      return 'hostname'
    case 'email':
      return 'email'
    case 'sip-phone':
      return 'sip-phone'
    case 'person':
      return 'person'
    case 'user-id':
    case 'sip-user':
    case 'sip-token':
      return 'user-id'
    case 'ipv4':
    case 'ip':
      return 'ip'
    case 'port':
      return 'port'
    case 'custom':
      return 'custom'
    default:
      return 'internal-id'
  }
}

function overlapsPacked(start: number, end: number, packed: PackedMatchIndex): boolean {
  for (let i = 0; i < packed.starts.length; i++) {
    const s = packed.starts[i]!
    const e = s + packed.lengths[i]!
    if (start < e && end > s) return true
  }
  return false
}

function lineAt(text: string, offset: number): number {
  let line = 0
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text.charCodeAt(i) === 0x0a) line += 1
  }
  return line
}

function aliasForSpan(alias: string, spanLen: number): string {
  if (alias.length === spanLen) return alias
  if (alias.length > spanLen) return alias.slice(0, spanLen)
  return alias + '-'.repeat(spanLen - alias.length)
}

/**
 * Append propagation matches for spellings not already covered by detectors.
 * Uses the published mapping snapshot (shared across correlation sources).
 */
export function applyIdentityPropagationToExportPlan(
  snapshot: ExportPlanSnapshot,
  mappingSnapshot: MappingSnapshot,
): ExportPlanSnapshot {
  const registry = IdentityRegistry.fromMappingSnapshot(mappingSnapshot)
  if (registry.size === 0) return snapshot

  const hits = registry.findHitsInText(snapshot.original)
  if (hits.length === 0) return snapshot

  const entities: Entity[] = [...snapshot.entities]
  const keyToIndex = new Map<string, number>()
  for (let i = 0; i < entities.length; i++) keyToIndex.set(entities[i]!.key, i)

  type Extra = {
    start: number
    length: number
    line: number
    entityIndex: number
    replacement: string
  }
  const extras: Extra[] = []

  for (const hit of hits) {
    if (overlapsPacked(hit.start, hit.end, snapshot.packed)) continue
    const spanLen = hit.end - hit.start
    const key = `propagate:${hit.identity.category}:${hit.identity.canonical}`
    let entityIndex = keyToIndex.get(key)
    const replacement = aliasForSpan(hit.identity.alias, spanLen)
    if (entityIndex === undefined) {
      entityIndex = entities.length
      keyToIndex.set(key, entityIndex)
      entities.push({
        key,
        category: mapToTextCategory(hit.identity.category),
        originalSample: hit.spelling,
        normalized: hit.identity.canonical,
        replacement,
        occurrenceCount: 1,
        occurrenceIndexes: new Uint32Array([hit.start]),
        enabled: true,
        source: 'builtin',
        sourceId: mappingSnapshot.sourceId,
        createdOrder: entityIndex,
      })
    }
    extras.push({
      start: hit.start,
      length: spanLen,
      line: lineAt(snapshot.original, hit.start),
      entityIndex,
      replacement,
    })
  }

  if (extras.length === 0) return snapshot

  const n = snapshot.packed.starts.length + extras.length
  const starts = new Uint32Array(n)
  const lengths = new Uint32Array(n)
  const lines = new Uint32Array(n)
  const entityIndexes = new Uint32Array(n)
  const flags = new Uint16Array(n)
  const replacements: Array<string | null> = new Array(n)

  let i = 0
  let j = 0
  let k = 0
  while (i < snapshot.packed.starts.length || j < extras.length) {
    const useExtra =
      i >= snapshot.packed.starts.length
      || (j < extras.length && extras[j]!.start < snapshot.packed.starts[i]!)
    if (useExtra) {
      const e = extras[j]!
      starts[k] = e.start
      lengths[k] = e.length
      lines[k] = e.line
      entityIndexes[k] = e.entityIndex
      flags[k] = FLAG_ENABLED
      replacements[k] = e.replacement
      j += 1
    } else {
      starts[k] = snapshot.packed.starts[i]!
      lengths[k] = snapshot.packed.lengths[i]!
      lines[k] = snapshot.packed.lines[i]!
      entityIndexes[k] = snapshot.packed.entityIndexes[i]!
      flags[k] = snapshot.packed.flags[i]!
      replacements[k] = snapshot.plan.replacements[i] ?? null
      i += 1
    }
    k += 1
  }

  const packed: PackedMatchIndex = { starts, lengths, lines, entityIndexes, flags }
  const basePlan = buildReplacementPlan(packed, entities)
  for (let idx = 0; idx < n; idx++) {
    const rep = replacements[idx]
    if (rep === null) continue
    basePlan.replacements[idx] = rep
    basePlan.lengthDeltas[idx] = rep.length - lengths[idx]!
  }
  basePlan.fenwick = fenwickBuild(basePlan.lengthDeltas)

  return {
    ...snapshot,
    entities,
    packed,
    plan: basePlan,
    planRevision: snapshot.planRevision + 1,
  }
}
