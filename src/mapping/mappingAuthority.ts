/**
 * MappingAuthority — single owner of mutable mapping registry (Stage 7 / 18 / 19).
 * Runs inside the mapping worker; application layer receives MappingSnapshot only.
 */

import { MAX_ENTITY_CARDINALITY } from '../domain/capabilityContract'
import type { CustomRule } from '../domain/types'
import {
  SessionMapping,
  DEFAULT_MAPPING_CONFIG,
  type MappingConfig,
} from '../pcap/anonymization/mapping'
import {
  createProductionSessionMapping,
  createTestSessionMapping,
} from '../pcap/anonymization/testModeSeed'
import { formatIpv4TextFromWire, formatPortTextFromWire } from '../pcap/anonymization/wireTextFormat'
import { maskAlphanumeric } from './textAliasEngine'
import type { EntityCategory } from '../pcap/anonymization/entityRegistry'
import { isPcapIdentityCategory, isTextIdentityCategory } from './identityCategories'
import { isWireTransportPort } from './canonicalize'
import {
  aliasForConstraint,
  aliasForSnapshotConstraintStrict,
  MappingRegistry,
  primaryAlias,
  reservedAlias,
} from './mappingRegistry'
import { TextAliasEngine } from './textAliasEngine'
import {
  createSessionFingerprintKey,
  fingerprintCanonicalIdentitySync,
  type SessionFingerprintKey,
} from './identityFingerprint'
import { OccurrenceIndex } from './occurrenceIndex'
import { ReverseIndex } from './reverseIndex'
import { createResolveJournalBatch, type ResolveJournalBatch } from './resolveJournal'
import {
  registryKeyForResolve,
  CROSS_FORMAT_CANONICALIZATION_VERSION,
  usesSharedWireEngine,
  usesCrossFormatTextEngine,
  storageCategoryForCrossFormat,
  crossFormatCategoryFromIdentity,
  constraintsCompatible,
  canonicalizeCrossFormatCategory,
} from './crossFormat'
import type {
  AliasDisposition,
  CanonicalIdentity,
  LookupByAliasRequest,
  LookupByOriginalRequest,
  LookupResult,
  MappingSnapshotEntry,
  MappingPlanSnapshot,
  MappingSessionSnapshot,
  ReleaseOccurrenceRequest,
  ReleaseOccurrenceResult,
  ResolveRequest,
  ResolveResult,
} from './types'
import { RESOLVE_ERROR, type ResolveErrorCode } from './types'

function stagingAliasKey(id: CanonicalIdentity, options: ResolveRequest['correlationOptions']): string {
  const key = registryKeyForResolve(id, options)
  const original = id.originalSpelling ?? id.canonical
  // One shared user may need several wire lengths in the same source/batch.
  return id.constraint.kind === 'text-ascii'
    && crossFormatCategoryFromIdentity(id.category, original, id.constraint) === 'user'
    ? JSON.stringify([key, id.constraint.byteLength])
    : key
}

function dispositionFor(
  id: CanonicalIdentity,
  alias: string,
  customRules?: readonly CustomRule[],
): AliasDisposition {
  const ruleId = id.source?.ruleId
  if (ruleId && customRules) {
    const rule = customRules.find((r) => r.id === ruleId)
    if (rule?.replacementMode === 'fixed') return 'ambiguous-fixed'
  }
  if (id.category === 'timestamp') return 'preserved'
  if (id.category === 'port' && id.constraint.kind === 'port-wire' && alias === id.canonical) return 'preserved'
  return 'bijective'
}

export class MappingAuthority {
  private pcapEngine: SessionMapping
  private textEngine: TextAliasEngine
  private registry: MappingRegistry
  private reverseIndex: ReverseIndex
  private occurrenceIndex: OccurrenceIndex
  private fingerprintKey: SessionFingerprintKey
  private mappingRevision = 0
  private snapshot: MappingSessionSnapshot | null = null
  private cancelledGeneration: string | null = null
  private pendingJournal: ResolveJournalBatch | null = null
  private activeCorrelationOptions: import('./types').CorrelationResolveOptions | undefined

  constructor(
    config: MappingConfig = DEFAULT_MAPPING_CONFIG,
    options?: { readonly seed?: string },
  ) {
    this.pcapEngine =
      typeof options?.seed === 'string' && options.seed.length > 0
        ? createTestSessionMapping(options.seed, config)
        : createProductionSessionMapping(config)
    this.textEngine = new TextAliasEngine()
    this.registry = new MappingRegistry()
    this.reverseIndex = new ReverseIndex()
    this.occurrenceIndex = new OccurrenceIndex()
    this.fingerprintKey = createSessionFingerprintKey()
  }

  /** @deprecated use getMappingRevision */
  getRevision(): number {
    return this.mappingRevision
  }

  getMappingRevision(): number {
    return this.mappingRevision
  }

  getPublishedSnapshot(): MappingSessionSnapshot | null {
    return this.snapshot
  }

  getRegistry(): MappingRegistry {
    return this.registry
  }

  getReverseIndex(): ReverseIndex {
    return this.reverseIndex
  }

  getOccurrenceIndex(): OccurrenceIndex {
    return this.occurrenceIndex
  }

  requestCancel(generationId: string): void {
    this.cancelledGeneration = generationId
  }

  clearCancel(): void {
    this.cancelledGeneration = null
  }

  resetSession(): void {
    this.pcapEngine = createProductionSessionMapping(DEFAULT_MAPPING_CONFIG)
    this.textEngine = new TextAliasEngine()
    this.registry.clear()
    this.reverseIndex.clear()
    this.occurrenceIndex = new OccurrenceIndex()
    this.fingerprintKey = createSessionFingerprintKey()
    this.mappingRevision = 0
    this.snapshot = null
    this.cancelledGeneration = null
    this.pendingJournal = null
  }

  hasPendingStaging(): boolean {
    return this.pendingJournal !== null
  }

  abortStaging(): void {
    this.pendingJournal = null
  }

  resolveStaging(request: ResolveRequest, config?: MappingConfig): ResolveResult {
    if (this.pendingJournal) {
      return {
        ok: false,
        code: RESOLVE_ERROR.stagingConflict,
        message: 'Resolve staging already pending',
      }
    }
    const prepared = this.prepareResolveBatch(request, config)
    if (!prepared.ok) return prepared
    this.pendingJournal = prepared.batch
    const preview = this.previewSnapshotFromBatch(prepared.batch)
    return { ok: true, snapshot: preview }
  }

  commitStaging(): ResolveResult {
    const batch = this.pendingJournal
    if (!batch) {
      return { ok: false, code: RESOLVE_ERROR.stagingEmpty, message: 'No pending resolve staging' }
    }
    this.pendingJournal = null
    return this.applyResolveBatch(batch)
  }

  resolve(request: ResolveRequest, config?: MappingConfig): ResolveResult {
    const prepared = this.prepareResolveBatch(request, config)
    if (!prepared.ok) return prepared
    return this.applyResolveBatch(prepared.batch)
  }

  private prepareResolveBatch(
    request: ResolveRequest,
    config?: MappingConfig,
  ): { ok: true; batch: ResolveJournalBatch } | { ok: false; code: ResolveErrorCode; message: string } {
    this.activeCorrelationOptions = request.correlationOptions
    if (this.cancelledGeneration === request.generationId) {
      this.cancelledGeneration = null
      return { ok: false, code: RESOLVE_ERROR.cancelled, message: 'Resolve cancelled' }
    }

    const uniqueNew = new Set<string>()
    for (const id of request.identities) {
      const regKey = registryKeyForResolve(id, this.activeCorrelationOptions)
      const existing = this.registry.findByRegistryKey(regKey)
      if (!existing) {
        uniqueNew.add(regKey)
      }
    }

    if (this.registry.size + uniqueNew.size > MAX_ENTITY_CARDINALITY) {
      return {
        ok: false,
        code: RESOLVE_ERROR.cardinalityOverflow,
        message: `Would exceed ${MAX_ENTITY_CARDINALITY} identities`,
      }
    }

    for (const id of request.identities) {
      if (id.occurrence && this.occurrenceIndex.wouldExceedBudget(id.occurrence)) {
        return {
          ok: false,
          code: RESOLVE_ERROR.occurrenceIndexOverflow,
          message: 'Occurrence index byte budget exceeded',
        }
      }
    }

    // Apply mapping policy transactionally: an aborted/failed staging request must
    // not change the active session engine, while a commit adopts both state and config.
    const stagingPcap = this.pcapEngine.clone(config)
    const stagingText = request.customRules?.length
      ? this.textEngine.cloneWithCustomRules(request.customRules)
      : this.textEngine.clone()
    const stagingAliases = new Map<string, string>()

    // T06 — apply port flow hints / media mates before any port alias allocation.
    const seenMediaPairs = new Set<string>()
    for (const id of request.identities) {
      if (id.category !== 'port') continue
      if (id.portFlowHint) {
        stagingPcap.notePortFlowHint(id.canonical, id.portFlowHint)
      }
      if (id.mediaMateCanonical) {
        const key = id.canonical < id.mediaMateCanonical
          ? `${id.canonical}|${id.mediaMateCanonical}`
          : `${id.mediaMateCanonical}|${id.canonical}`
        if (!seenMediaPairs.has(key)) {
          seenMediaPairs.add(key)
          stagingPcap.noteMediaPortPair(id.canonical, id.mediaMateCanonical)
        }
      }
    }

    for (const id of request.identities) {
      if (this.cancelledGeneration === request.generationId) {
        this.cancelledGeneration = null
        return { ok: false, code: RESOLVE_ERROR.cancelled, message: 'Resolve cancelled mid-batch' }
      }

      const key = stagingAliasKey(id, this.activeCorrelationOptions)
      let alias = stagingAliases.get(key)
      if (alias === undefined) {
        alias = this.resolveAlias(id, stagingPcap, stagingText)
        stagingAliases.set(key, alias)
      }
    }

    // Engine overflow (exhausted IPv4/MAC/… pools) is fail-closed inside SessionMapping
    // (fixed anonymous tokens) and surfaces as snapshot.overflow — which blocks export.
    // Hard-rejecting the whole resolve here prevented opening max-size captures (R10)
    // after ~65k unique IPv4s from the 100 MiB fixture, even though aliases were already
    // allocated fail-closed.
    return {
      ok: true,
      batch: createResolveJournalBatch({
        generationId: request.generationId,
        sourceId: request.sourceId,
        customRules: request.customRules,
        identities: request.identities,
        stagingPcap,
        stagingText,
        stagingAliases,
      }),
    }
  }

  private applyResolveBatch(batch: ResolveJournalBatch): ResolveResult {
    this.pcapEngine.adoptFrom(batch.stagingPcap)
    this.textEngine.adoptFrom(batch.stagingText)
    this.mappingRevision++

    for (const id of batch.identities) {
      const regKey = registryKeyForResolve(id, this.activeCorrelationOptions)
      const alias = batch.stagingAliases.get(stagingAliasKey(id, this.activeCorrelationOptions))!
      const disp = dispositionFor(id, alias, batch.customRules)
      const fingerprint = fingerprintCanonicalIdentitySync(
        this.fingerprintKey,
        id.category,
        id.canonical,
        id.constraint,
        id.originalSpelling,
      )

      const existing = this.registry.findByRegistryKey(regKey) ?? this.registry.findByKey(id.category, id.canonical)
      if (existing && !existing.plaintextActive) {
        this.registry.restorePlaintext(existing.identityId)
        this.reverseIndex.restorePlaintext(existing.identityId, id.canonical)
      }

      const { entry: regEntry, aliasRejected } = this.registry.register({
        category: id.category,
        canonical: id.canonical,
        alias,
        constraint: id.constraint,
        disposition: disp,
        source: id.source ?? { detectorId: 'unknown' },
        originalSample: id.originalSpelling,
        occurrence: id.occurrence,
        fingerprint,
        registryKey: regKey,
      })

      if (aliasRejected) {
        this.mappingRevision--
        return {
          ok: false,
          code: RESOLVE_ERROR.aliasOverflow,
          message: 'Alias limit per identity exceeded',
        }
      }

      if (id.occurrence) {
        const ok = this.occurrenceIndex.append(regEntry.identityId, id.occurrence)
        if (!ok) {
          this.mappingRevision--
          return {
            ok: false,
            code: RESOLVE_ERROR.occurrenceIndexOverflow,
            message: 'Occurrence index byte budget exceeded',
          }
        }
      }

      this.reverseIndex.register({
        identityId: regEntry.identityId,
        category: id.category,
        canonical: id.canonical,
        alias: reservedAlias(regEntry),
        fingerprint,
        disposition: disp,
      })
      for (const a of regEntry.aliases) {
        this.reverseIndex.addAlias(regEntry.identityId, a.alias)
      }
    }

    const snapshot = this.materializeSessionSnapshot(batch.generationId, batch.sourceId)
    this.snapshot = snapshot
    this.cancelledGeneration = null
    return { ok: true, snapshot }
  }

  private materializeSessionSnapshot(generationId: string, sourceId: string): MappingSessionSnapshot {
    const entries: MappingSnapshotEntry[] = this.registry
      .entries()
      .slice()
      .sort((a, b) => a.identityId - b.identityId)
      .map((regEntry) => {
        const primary = primaryAlias(regEntry)
        const primaryConstraint = regEntry.aliases[0]?.constraint ?? { kind: 'text-ascii' as const, byteLength: 0 }
        return {
          identityId: regEntry.identityId,
          category: regEntry.category,
          canonical: regEntry.canonical,
          alias: primary,
          aliases: Object.freeze([...regEntry.aliases]),
          constraint: primaryConstraint,
          disposition: regEntry.primaryDisposition,
          source: regEntry.source,
          occurrenceCount: regEntry.occurrenceCount,
        }
      })

    return {
      scope: 'session',
      revision: this.mappingRevision,
      mappingRevision: this.mappingRevision,
      canonicalizationVersion: CROSS_FORMAT_CANONICALIZATION_VERSION,
      generationId,
      sourceId,
      overflow: this.pcapEngine.overflow || this.textEngine.overflow,
      entries: Object.freeze(entries),
    }
  }

  private previewSnapshotFromBatch(batch: ResolveJournalBatch): MappingPlanSnapshot {
    const nextRevision = this.mappingRevision + 1
    const entries: MappingSnapshotEntry[] = []

    for (const id of batch.identities) {
      const regKey = registryKeyForResolve(id, this.activeCorrelationOptions)
      const alias = batch.stagingAliases.get(stagingAliasKey(id, this.activeCorrelationOptions))!
      const disp = dispositionFor(id, alias, batch.customRules)
      const existing = this.registry.findByRegistryKey(regKey) ?? this.registry.findByKey(id.category, id.canonical)
      // An identity already committed by an earlier correlation source may not yet carry an
      // alias for *this* batch's constraint (e.g. dt.log commits an ipv4-wire alias, then
      // dt.pcap stages a text-ascii alias for the same IP embedded in SIP headers). Preview
      // must reflect the freshly staged alias here too, or validateMappingClosure sees a
      // stale, incomplete alias list and rejects a perfectly valid resolution as
      // 'missing-constraint-alias'.
      const existingConstraintAlias = existing
        ? aliasForSnapshotConstraintStrict(existing, id.constraint)
        : undefined
      const resolvedAlias = existingConstraintAlias ?? alias
      const identityId = existing?.identityId ?? -1
      const aliases = existing
        ? (existingConstraintAlias !== undefined
            ? Object.freeze([...existing.aliases])
            : Object.freeze([...existing.aliases, { alias, constraint: id.constraint, disposition: disp }]))
        : Object.freeze([{
            alias,
            constraint: id.constraint,
            disposition: disp,
          }])
      const baseCount = existing ? this.occurrenceIndex.countForIdentity(existing.identityId) : 0
      const occurrenceCount = id.occurrence ? baseCount + 1 : baseCount

      entries.push({
        identityId,
        category: id.category,
        canonical: id.canonical,
        alias: resolvedAlias,
        aliases,
        constraint: id.constraint,
        disposition: disp,
        source: id.source,
        occurrenceCount,
      })
    }

    return {
      scope: 'request',
      revision: nextRevision,
      mappingRevision: nextRevision,
      canonicalizationVersion: CROSS_FORMAT_CANONICALIZATION_VERSION,
      generationId: batch.generationId,
      sourceId: batch.sourceId,
      overflow: batch.stagingPcap.overflow || batch.stagingText.overflow,
      entries: Object.freeze([...entries]),
    }
  }

  lookupByOriginal(request: LookupByOriginalRequest): LookupResult {
    const candidates = this.reverseIndex.lookupByOriginal(
      request.category,
      request.canonical,
      (id) => this.occurrenceIndex.occurrencesFor(id),
    )
    return { ok: true, candidates }
  }

  lookupByAlias(request: LookupByAliasRequest): LookupResult {
    const candidates = this.reverseIndex.lookupByAlias(
      request.alias,
      (id) => this.occurrenceIndex.occurrencesFor(id),
    )
    return { ok: true, candidates }
  }

  releaseOccurrence(request: ReleaseOccurrenceRequest): ReleaseOccurrenceResult {
    const entry =
      this.registry.findByKey(request.category, request.canonical)
      ?? this.registry.entries().find(
        (e) => e.category === request.category && e.canonical === request.canonical,
      )
    if (!entry) {
      return { ok: false, code: RESOLVE_ERROR.identityNotFound, message: 'Identity not found' }
    }

    const removed = this.occurrenceIndex.remove(entry.identityId, request.occurrence)
    if (!removed) {
      return { ok: true, mappingRevision: this.mappingRevision, scrubbed: false }
    }

    entry.occurrenceCount = Math.max(0, entry.occurrenceCount - 1)

    let scrubbed = false
    if (this.occurrenceIndex.countForIdentity(entry.identityId) === 0) {
      this.reverseIndex.scrubPlaintext(entry.identityId)
      this.registry.markPlaintextScrubbed(entry.identityId)
      scrubbed = true
    }

    this.mappingRevision++
    if (this.snapshot) {
      this.snapshot = this.materializeSessionSnapshot(this.snapshot.generationId, this.snapshot.sourceId)
    }

    return { ok: true, mappingRevision: this.mappingRevision, scrubbed }
  }

  private usesTextAliasEngine(id: CanonicalIdentity): boolean {
    // SDP session-id is a PCAP-only digit string allocated by SessionMapping (T01).
    if (id.category === 'sdp-session-id') return false
    // T16 — IMSI/IMEI are PCAP SessionMapping digit strings, not TextAliasEngine.
    if (id.category === 'imsi' || id.category === 'imei') return false
    // T20 — SNMP engine ID is PCAP SessionMapping hex, not TextAliasEngine.
    if (id.category === 'snmp-engine-id') return false
    // T26 — GTP TEID is PCAP SessionMapping 32-bit, not TextAliasEngine.
    if (id.category === 'teid') return false
    // T25 — SS7 point code is PCAP SessionMapping, not TextAliasEngine.
    if (id.category === 'point-code') return false
    // T14 — opaque-id is PCAP SessionMapping (length-stable), not TextAliasEngine.
    if (id.category === 'opaque-id') return false
    // T69 — free-token is PCAP SessionMapping (length-stable), not TextAliasEngine.
    if (id.category === 'free-token') return false
    // T74 — opaque-bin-id is PCAP SessionMapping (length-stable hex), not TextAliasEngine.
    if (id.category === 'opaque-bin-id') return false
    // T40 — SSID is PCAP SessionMapping (binary length-stable), not TextAliasEngine.
    if (id.category === 'ssid') return false
    const original = id.originalSpelling ?? id.canonical
    // T45 — phone/email/user always allocate via TextAliasEngine (storage categories).
    if (usesCrossFormatTextEngine(id.category, original, id.constraint)) return true
    // Explicit text-ascii representations always use the text engine so wire vs text
    // can receive distinct aliases under cross-format linking (sharedAlias: false).
    if (id.constraint.kind === 'text-ascii') return true
    if (this.activeCorrelationOptions?.crossFormatLinking
      && usesSharedWireEngine(id.category, original, id.constraint)) {
      return false
    }
    // Remaining non-text-ascii constraints on PCAP categories use the wire engine.
    if (isPcapIdentityCategory(id.category)) {
      return false
    }
    if (id.category === 'ip') return true
    return false
  }

  /** T45 — allocate phone/email/user aliases under shared storage category + CF canonical. */
  private resolveCrossFormatTextAlias(
    id: CanonicalIdentity,
    stagingText: TextAliasEngine,
    original: string,
  ): string | null {
    const cf = crossFormatCategoryFromIdentity(id.category, original, id.constraint)
    if (cf !== 'phone' && cf !== 'email' && cf !== 'user') return null
    const source = isPcapIdentityCategory(id.category) ? 'pcap' as const : 'text' as const
    const cfCanon = canonicalizeCrossFormatCategory(cf, original, source)
    if (!cfCanon) return null
    if (cf === 'user' && id.constraint.kind === 'text-ascii') {
      return stagingText.mapUserAlias(cfCanon, original, id.constraint.byteLength, id.source?.ruleId)
    }
    const storage = storageCategoryForCrossFormat(cf)
    return stagingText.get(storage, cfCanon)
      ?? stagingText.map(storage, cfCanon, original, id.source?.ruleId)
  }

  private resolvePcapTextAlias(
    id: CanonicalIdentity,
    stagingPcap: SessionMapping,
    original: string,
  ): string | null {
    if (id.constraint.kind !== 'text-ascii' || !isPcapIdentityCategory(id.category)) {
      return null
    }
    // A transport-qualified port (`udp/5070`) only ever comes from PCAP (text logs canonicalize
    // to bare digits), so SIP/SDP text ports always reuse the wire alias: the header then agrees
    // with the UDP/TCP header and preserved signaling ports stay preserved in text too.
    if (id.category === 'port' && isWireTransportPort(id.canonical)) {
      const wireMapped = stagingPcap.get('port', id.canonical) ?? stagingPcap.map('port', id.canonical)
      const portNum = Number.parseInt(wireMapped.split('/')[1]!, 10)
      return formatPortTextFromWire(portNum, original)
    }
    // Dual-listed categories (hostname): text detectors must use TextAliasEngine
    // for deterministic host-N / length-stable text. Only PCAP-sourced text-ascii spans
    // reshape an existing wire alias into a fixed-length text slot (CF-02 / CF-07).
    if (isTextIdentityCategory(id.category) && id.source?.detectorId !== 'pcap') {
      return null
    }
    const cat = id.category as EntityCategory
    if (cat === 'ipv4') {
      const wire = stagingPcap.get('ipv4', id.canonical) ?? stagingPcap.map('ipv4', id.canonical)
      try {
        return formatIpv4TextFromWire(wire, id.constraint.byteLength)
      } catch {
        return maskAlphanumeric(original, wire.replace(/\D/g, 'x'))
      }
    }
    if (cat === 'ipv6') {
      const wire = stagingPcap.get('ipv6', id.canonical) ?? stagingPcap.map('ipv6', id.canonical)
      return wire.length === id.constraint.byteLength
        ? wire
        : maskAlphanumeric(original, wire.replace(/[^a-fA-F0-9]/g, 'x'))
    }
    if (cat === 'hostname') {
      const wire = stagingPcap.get('hostname', id.canonical) ?? stagingPcap.map('hostname', id.canonical)
      return wire.length === id.constraint.byteLength
        ? wire
        : maskAlphanumeric(original, wire.replace(/\./g, ''))
    }
    if (
      cat === 'sdp-session-id'
      || cat === 'opaque-id'
      || cat === 'free-token'
      || cat === 'imsi'
      || cat === 'imei'
      || cat === 'snmp-engine-id'
    ) {
      return stagingPcap.aliasFor(cat, id.canonical, id.constraint, original)
    }
    return null
  }

  private resolveAlias(
    id: CanonicalIdentity,
    stagingPcap: SessionMapping,
    stagingText: TextAliasEngine,
  ): string {
    const original = id.originalSpelling ?? id.canonical
    const regKey = registryKeyForResolve(id, this.activeCorrelationOptions)
    if (crossFormatCategoryFromIdentity(id.category, original, id.constraint) === 'user'
      && id.constraint.kind === 'text-ascii') {
      const userAlias = this.resolveCrossFormatTextAlias(id, stagingText, original)
      if (userAlias !== null) return userAlias
    }
    const existing = this.registry.findByRegistryKey(regKey) ?? this.registry.findByKey(id.category, id.canonical)
    if (existing) {
      const cf = crossFormatCategoryFromIdentity(id.category, original, id.constraint)
      const primary = existing.aliases[0]
      if (cf && primary) {
        const compat = constraintsCompatible(cf, primary.constraint, id.constraint)
        if (compat.compatible && !compat.sharedAlias) {
          // Distinct representation — allocate a constraint-specific alias.
          const cfText = this.resolveCrossFormatTextAlias(id, stagingText, original)
          if (cfText !== null) return cfText
          if (id.constraint.kind === 'text-ascii') {
            const pcapText = this.resolvePcapTextAlias(id, stagingPcap, original)
            if (pcapText !== null) return pcapText
            return stagingText.get(id.category, id.canonical)
              ?? stagingText.map(id.category, id.canonical, original, id.source?.ruleId)
          }
          if (cf === 'hostname' && isPcapIdentityCategory(id.category)) {
            const cat = id.category as EntityCategory
            return stagingPcap.get(cat, id.canonical)
              ?? stagingPcap.map(cat, id.canonical)
          }
          if (usesSharedWireEngine(id.category, original, id.constraint)) {
            const storage = storageCategoryForCrossFormat(cf) as EntityCategory
            return stagingPcap.get(storage, id.canonical)
              ?? stagingPcap.map(storage, id.canonical)
          }
          if (this.usesTextAliasEngine(id)) {
            return stagingText.get(id.category, id.canonical)
              ?? stagingText.map(id.category, id.canonical, original, id.source?.ruleId)
          }
        }
      }
      return aliasForConstraint(existing, id.constraint)
    }

    const pcapText = this.resolvePcapTextAlias(id, stagingPcap, original)
    if (pcapText !== null) return pcapText

    const cfText = this.resolveCrossFormatTextAlias(id, stagingText, original)
    if (cfText !== null) return cfText

    if (this.usesTextAliasEngine(id)) {
      return stagingText.get(id.category, id.canonical)
        ?? stagingText.map(id.category, id.canonical, original, id.source?.ruleId)
    }

    const cf = crossFormatCategoryFromIdentity(id.category, original, id.constraint)
    // Text `ip` / shared categories use the wire engine when cross-format linking is on
    // (usesTextAliasEngine is false). Do not require a PCAP identity category.
    if (cf && usesSharedWireEngine(id.category, original, id.constraint)) {
      const storage = storageCategoryForCrossFormat(cf) as EntityCategory
      return stagingPcap.get(storage, id.canonical)
        ?? stagingPcap.map(storage, id.canonical)
    }

    if (cf === 'hostname' && isPcapIdentityCategory(id.category)) {
      const cat = id.category as EntityCategory
      return stagingPcap.get(cat, id.canonical)
        ?? stagingPcap.map(cat, id.canonical)
    }

    if (isPcapIdentityCategory(id.category)) {
      const cat = id.category as EntityCategory
      return stagingPcap.get(cat, id.canonical)
        ?? stagingPcap.map(cat, id.canonical)
    }

    return original
  }
}
