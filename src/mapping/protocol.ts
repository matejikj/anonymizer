/**
 * Mapping worker wire protocol (Stage 7 / Stage 18 / Stage 19).
 * Versioned messages with generation ID and bounded payload validation.
 */

import { MAPPING_CAPABILITY_LIMITS } from '../domain/capabilityContract'
import type { CustomRule } from '../domain/types'
import type { MappingConfig } from '../pcap/anonymization/mapping'
import { canonicalizeIdentity, defaultIdentityWireConstraint } from './canonicalize'
import { ALL_IDENTITY_CATEGORIES, type IdentityCategory } from './identityCategories'
import type {
  AliasDisposition,
  CanonicalIdentity,
  IdentitySourceRef,
  MappingSnapshot,
  MappingSnapshotEntry,
  OccurrenceRef,
  RepresentationAlias,
  WireRepresentationConstraint,
} from './types'
import type { ReverseLookupCandidate } from './reverseIndex'
import { maxCanonicalStringLength } from './pcapCanonical'

export const MAPPING_PROTOCOL_VERSION = 5

export type MappingRequestId = string

export type WireRepresentationConstraintWire =
  | { kind: 'ipv4-wire' }
  | { kind: 'ipv6-wire' }
  | { kind: 'mac-wire' }
  | { kind: 'hostname-ascii'; labelCount: number; maxLabelLength: number }
  | { kind: 'port-wire'; protocol: 'tcp' | 'udp' | 'sctp' | 'unknown' }
  | { kind: 'vlan-wire' }
  | { kind: 'radio-id-wire'; bitWidth: 24 }
  | { kind: 'ssrc-wire' }
  | { kind: 'timestamp-wire' }
  | { kind: 'text-ascii'; byteLength: number }

export interface WireIdentitySourceRef {
  detectorId: string
  ruleId?: string
}

export interface WireOccurrenceRef {
  kind: 'text' | 'packet'
  sourceId: string
  line?: number
  start?: number
  end?: number
  packetIndex?: number
}

export interface WireCanonicalIdentity {
  category: IdentityCategory
  canonical: string
  constraint: WireRepresentationConstraintWire
  originalSpelling?: string
  source?: WireIdentitySourceRef
  occurrence?: WireOccurrenceRef
  /** T06 — optional port flow hint (sip/stun/…). */
  portFlowHint?: string
  /** T06 revision — optional SDP media mate canonical. */
  mediaMateCanonical?: string
}

export interface WireRepresentationAlias {
  alias: string
  constraint: WireRepresentationConstraintWire
  disposition: AliasDisposition
}

export interface WireMappingSnapshotEntry {
  identityId: number
  category: IdentityCategory
  canonical: string
  alias: string
  aliases: WireRepresentationAlias[]
  constraint: WireRepresentationConstraintWire
  disposition: AliasDisposition
  source?: WireIdentitySourceRef
  occurrenceCount: number
}

export interface WireMappingSnapshot {
  scope: 'request' | 'session'
  revision: number
  mappingRevision?: number
  canonicalizationVersion?: number
  generationId: string
  sourceId: string
  overflow: boolean
  entries: WireMappingSnapshotEntry[]
}

export interface WireReverseLookupCandidate {
  identityId: number
  category: IdentityCategory
  canonical: string | null
  alias: string
  fingerprint: string | null
  disposition: AliasDisposition
  occurrenceCount: number
}

export type MappingWorkerRequest =
  | {
      type: 'ping'
      protocolVersion: number
      requestId: MappingRequestId
    }
  | {
      type: 'resolve'
      protocolVersion: number
      requestId: MappingRequestId
      generationId: string
      sourceId: string
      config: MappingConfig
      identities: WireCanonicalIdentity[]
      customRules?: CustomRule[]
      correlationOptions?: import('./types').CorrelationResolveOptions
    }
  | {
      type: 'cancel'
      protocolVersion: number
      requestId: MappingRequestId
      generationId: string
    }
  | {
      type: 'lookup-original'
      protocolVersion: number
      requestId: MappingRequestId
      category: IdentityCategory
      canonical: string
    }
  | {
      type: 'lookup-alias'
      protocolVersion: number
      requestId: MappingRequestId
      alias: string
    }
  | {
      type: 'release-occurrence'
      protocolVersion: number
      requestId: MappingRequestId
      category: IdentityCategory
      canonical: string
      occurrence: WireOccurrenceRef
    }
  | {
      type: 'reset-session'
      protocolVersion: number
      requestId: MappingRequestId
    }
  | {
      type: 'resolve-staging'
      protocolVersion: number
      requestId: MappingRequestId
      generationId: string
      sourceId: string
      config: MappingConfig
      identities: WireCanonicalIdentity[]
      customRules?: CustomRule[]
      correlationOptions?: import('./types').CorrelationResolveOptions
    }
  | {
      type: 'commit-staging'
      protocolVersion: number
      requestId: MappingRequestId
    }
  | {
      type: 'abort-staging'
      protocolVersion: number
      requestId: MappingRequestId
    }

export type MappingWorkerResponse =
  | {
      type: 'pong'
      requestId: MappingRequestId
      revision: number
    }
  | {
      type: 'resolved'
      requestId: MappingRequestId
      generationId: string
      snapshot: WireMappingSnapshot
    }
  | {
      /** Request-scoped preview — must NOT replace the published session snapshot. */
      type: 'staging-preview'
      requestId: MappingRequestId
      generationId: string
      snapshot: WireMappingSnapshot
    }
  | {
      type: 'error'
      requestId: MappingRequestId
      generationId?: string
      code: string
      message: string
    }
  | {
      type: 'lookup-result'
      requestId: MappingRequestId
      candidates: WireReverseLookupCandidate[]
    }
  | {
      type: 'occurrence-released'
      requestId: MappingRequestId
      mappingRevision: number
      scrubbed: boolean
      snapshot: WireMappingSnapshot | null
    }
  | {
      type: 'session-reset'
      requestId: MappingRequestId
    }
  | {
      type: 'staging-committed'
      requestId: MappingRequestId
      generationId: string
      snapshot: WireMappingSnapshot
    }
  | {
      type: 'staging-aborted'
      requestId: MappingRequestId
    }

export const MAPPING_WORKER_ERROR = {
  cancelled: 'cancelled',
  invalidVersion: 'invalid-protocol-version',
  invalidMessage: 'invalid-message',
  oversizeBatch: 'mapping-oversize-batch',
  oversizeField: 'mapping-oversize-field',
  invalidIdentity: 'mapping-invalid-identity',
  internal: 'internal',
} as const

const VALID_CATEGORIES = new Set<IdentityCategory>(ALL_IDENTITY_CATEGORIES)

export interface ProtocolValidationError {
  code: string
  message: string
}

export function validateMappingConfig(config: unknown): ProtocolValidationError | null {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { code: MAPPING_WORKER_ERROR.invalidMessage, message: 'config must be an object' }
  }
  const value = config as Record<string, unknown>
  // T16 — `imsiPlmn` is part of PcapMapping (7 keys). Older 6-key payloads are rejected.
  if (Object.keys(value).length !== 7
    || (value.ip !== 'topology-preserving' && value.ip !== 'privacy-preserving')
    || value.mac !== 'locally-administered'
    || (value.timestamps !== 'relative'
      && value.timestamps !== 'relative-bucketed'
      && value.timestamps !== 'enumerated')
    || (value.ephemeralPorts !== 'preserve' && value.ephemeralPorts !== 'permute')
    || (value.contentSignalingPorts !== 'preserve' && value.contentSignalingPorts !== 'permute')
    || (value.vlan !== 'map' && value.vlan !== 'preserve')
    || (value.imsiPlmn !== 'preserve-plmn' && value.imsiPlmn !== 'map-all')) {
    return { code: MAPPING_WORKER_ERROR.invalidMessage, message: 'invalid mapping config' }
  }
  return null
}

export function validateProtocolVersion(version: number): ProtocolValidationError | null {
  if (version !== MAPPING_PROTOCOL_VERSION) {
    return {
      code: MAPPING_WORKER_ERROR.invalidVersion,
      message: `Unsupported protocol version ${version}`,
    }
  }
  return null
}

export function validateResolveIdentities(
  identities: unknown,
): { ok: true; identities: CanonicalIdentity[] } | { ok: false; error: ProtocolValidationError } {
  if (!Array.isArray(identities)) {
    return { ok: false, error: { code: MAPPING_WORKER_ERROR.invalidMessage, message: 'identities must be array' } }
  }
  if (identities.length > MAPPING_CAPABILITY_LIMITS.maxIdentities) {
    return {
      ok: false,
      error: {
        code: MAPPING_WORKER_ERROR.oversizeBatch,
        message: `Batch size ${identities.length} exceeds ${MAPPING_CAPABILITY_LIMITS.maxIdentities}`,
      },
    }
  }

  const maxLen = maxCanonicalStringLength()
  const out: CanonicalIdentity[] = []

  for (let i = 0; i < identities.length; i++) {
    const raw = identities[i]
    if (!raw || typeof raw !== 'object') {
      return { ok: false, error: { code: MAPPING_WORKER_ERROR.invalidIdentity, message: `identity[${i}] invalid` } }
    }
    const item = raw as WireCanonicalIdentity
    if (!VALID_CATEGORIES.has(item.category)) {
      return { ok: false, error: { code: MAPPING_WORKER_ERROR.invalidIdentity, message: `identity[${i}] bad category` } }
    }
    if (typeof item.canonical !== 'string' || item.canonical.length > maxLen) {
      return { ok: false, error: { code: MAPPING_WORKER_ERROR.oversizeField, message: `identity[${i}] canonical too long` } }
    }
    const normalized = canonicalizeIdentity(item.category, item.canonical)
    if (normalized === null) {
      return { ok: false, error: { code: MAPPING_WORKER_ERROR.invalidIdentity, message: `identity[${i}] canonical invalid` } }
    }
    const constraint = parseWireConstraint(item.constraint)
      ?? defaultIdentityWireConstraint(item.category, normalized, item.originalSpelling)
    if (!constraint) {
      return { ok: false, error: { code: MAPPING_WORKER_ERROR.invalidIdentity, message: `identity[${i}] constraint invalid` } }
    }
    const portFlowHint =
      typeof item.portFlowHint === 'string' && item.portFlowHint.length > 0
        ? (item.portFlowHint as import('../pcap/anonymization/portPolicy').PortFlowHint)
        : undefined
    const mediaMateCanonical =
      typeof item.mediaMateCanonical === 'string' && item.mediaMateCanonical.length > 0
        ? item.mediaMateCanonical
        : undefined
    out.push({
      category: item.category,
      canonical: normalized,
      constraint,
      originalSpelling: item.originalSpelling,
      source: parseSource(item.source),
      occurrence: parseOccurrence(item.occurrence),
      portFlowHint,
      mediaMateCanonical,
    })
  }

  return { ok: true, identities: out }
}

function parseSource(raw: unknown): IdentitySourceRef | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const o = raw as WireIdentitySourceRef
  if (typeof o.detectorId !== 'string') return undefined
  return { detectorId: o.detectorId, ruleId: o.ruleId }
}

function parseOccurrence(raw: unknown): OccurrenceRef | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const o = raw as WireOccurrenceRef
  if (typeof o.sourceId !== 'string') return undefined
  if (o.kind === 'text') {
    if (!Number.isInteger(o.line) || !Number.isInteger(o.start) || !Number.isInteger(o.end)) return undefined
    return { kind: 'text', sourceId: o.sourceId, line: o.line!, start: o.start!, end: o.end! }
  }
  if (o.kind === 'packet') {
    if (!Number.isInteger(o.packetIndex)) return undefined
    return { kind: 'packet', sourceId: o.sourceId, packetIndex: o.packetIndex! }
  }
  return undefined
}

function parseWireConstraint(raw: unknown): WireRepresentationConstraint | null {
  if (!raw || typeof raw !== 'object' || !('kind' in raw)) return null
  const kind = (raw as { kind: string }).kind
  switch (kind) {
    case 'ipv4-wire':
    case 'ipv6-wire':
    case 'mac-wire':
    case 'vlan-wire':
    case 'ssrc-wire':
    case 'timestamp-wire':
      return { kind }
    case 'hostname-ascii': {
      const o = raw as { labelCount?: number; maxLabelLength?: number }
      if (!Number.isInteger(o.labelCount) || o.labelCount! < 1 || o.labelCount! > 256) return null
      if (!Number.isInteger(o.maxLabelLength) || o.maxLabelLength! < 1 || o.maxLabelLength! > 255) return null
      return { kind, labelCount: o.labelCount!, maxLabelLength: o.maxLabelLength! }
    }
    case 'port-wire': {
      const p = (raw as { protocol?: string }).protocol
      if (p !== 'tcp' && p !== 'udp' && p !== 'sctp' && p !== 'unknown') return null
      return { kind, protocol: p }
    }
    case 'radio-id-wire': {
      const bitWidth = (raw as { bitWidth?: number }).bitWidth
      if (bitWidth !== 24) return null
      return { kind, bitWidth: 24 }
    }
    case 'text-ascii': {
      const byteLength = (raw as { byteLength?: number }).byteLength
      if (!Number.isInteger(byteLength) || byteLength! < 0 || byteLength! > maxCanonicalStringLength()) return null
      return { kind, byteLength: byteLength! }
    }
    default:
      return null
  }
}

export function snapshotToWire(snapshot: MappingSnapshot): WireMappingSnapshot {
  return {
    scope: snapshot.scope,
    revision: snapshot.revision,
    mappingRevision: snapshot.mappingRevision,
    canonicalizationVersion: snapshot.canonicalizationVersion,
    generationId: snapshot.generationId,
    sourceId: snapshot.sourceId,
    overflow: snapshot.overflow,
    entries: snapshot.entries.map((e) => ({
      identityId: e.identityId,
      category: e.category,
      canonical: e.canonical,
      alias: e.alias,
      aliases: e.aliases.map((a) => ({
        alias: a.alias,
        constraint: a.constraint as WireRepresentationConstraintWire,
        disposition: a.disposition,
      })),
      constraint: e.constraint as WireRepresentationConstraintWire,
      disposition: e.disposition,
      source: e.source,
      occurrenceCount: e.occurrenceCount,
    })),
  }
}

export function snapshotFromWire(wire: WireMappingSnapshot): MappingSnapshot {
  const rev = wire.mappingRevision ?? wire.revision
  const scope = wire.scope === 'request' ? 'request' : 'session'
  const base = {
    revision: rev,
    mappingRevision: rev,
    canonicalizationVersion: wire.canonicalizationVersion ?? 1,
    generationId: wire.generationId,
    sourceId: wire.sourceId,
    overflow: wire.overflow,
    entries: wire.entries.map((e): MappingSnapshotEntry => ({
      identityId: e.identityId,
      category: e.category,
      canonical: e.canonical,
      alias: e.alias,
      aliases: e.aliases.map((a): RepresentationAlias => ({
        alias: a.alias,
        constraint: a.constraint as WireRepresentationConstraint,
        disposition: a.disposition,
      })),
      constraint: e.constraint as WireRepresentationConstraint,
      disposition: e.disposition,
      ...(e.source !== undefined ? { source: e.source } : {}),
      occurrenceCount: e.occurrenceCount,
    })),
  }
  return scope === 'request'
    ? { scope: 'request', ...base }
    : { scope: 'session', ...base }
}

export function lookupCandidatesToWire(
  candidates: readonly ReverseLookupCandidate[],
): WireReverseLookupCandidate[] {
  return candidates.map((c) => ({
    identityId: c.identityId,
    category: c.category,
    canonical: c.canonical,
    alias: c.alias,
    fingerprint: c.fingerprint,
    disposition: c.disposition,
    occurrenceCount: c.occurrences.length,
  }))
}
