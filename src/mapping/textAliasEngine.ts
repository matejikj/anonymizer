/**
 * Text alias engine — sole text pseudonym generator (Stage 18).
 * Owned by MappingAuthority; not used directly by detectors.
 */

import type { Category, CustomRule } from '../domain/types'
import { assertNoNewline } from '../domain/invariants'
import { MAX_ENTITY_CARDINALITY } from '../domain/capabilityContract'
import type { IdentityCategory } from './identityCategories'
import { identityMappingKey } from './canonicalize'
import { formatPortTextFromWire, maskDigitsPreservingFormat } from '../pcap/anonymization/wireTextFormat'
import { DYNAMIC_PORT_MIN, isPreservedServicePort } from '../pcap/anonymization/portPolicy'

export interface TextReplacementCounters {
  ip: number
  hostname: number
  sipPhone: number
  sipCallId: number
  sipToken: number
  sipUser: number
  /** T14 — opaque-id PCAP category. */
  opaqueId: number
  /** T69 — free-text token outside vocabulary. */
  freeToken: number
  /** T74 — sender-bound binary id (hex of wire octets). */
  opaqueBinId: number
  /** T40 — 802.11 / RADIUS SSID (length-stable wire bytes). */
  ssid: number
  email: number
  person: number
  userId: number
  internalId: number
  port: number
  custom: number
}

export function createTextReplacementCounters(): TextReplacementCounters {
  return {
    ip: 0,
    hostname: 0,
    sipPhone: 0,
    sipCallId: 0,
    sipToken: 0,
    sipUser: 0,
    opaqueId: 0,
    freeToken: 0,
    opaqueBinId: 0,
    ssid: 0,
    email: 0,
    person: 0,
    userId: 0,
    internalId: 0,
    port: 0,
    custom: 0,
  }
}

export class TextAliasEngine {
  private readonly _map = new Map<string, string>()
  private readonly _counters: TextReplacementCounters = createTextReplacementCounters()
  private readonly _customRulesById = new Map<string, CustomRule>()
  private readonly _userRepresentations = new Map<string, string>()
  private readonly _usedUserAliases = new Set<string>()
  private readonly _nextUserAliasByLength = new Map<number, number>()
  private _overflow = false

  constructor(customRules: readonly CustomRule[] = []) {
    for (const r of customRules) this._customRulesById.set(r.id, r)
  }

  get size(): number {
    return this._map.size
  }

  get overflow(): boolean {
    return this._overflow
  }

  clone(): TextAliasEngine {
    const copy = new TextAliasEngine()
    for (const [k, v] of this._map) copy._map.set(k, v)
    Object.assign(copy._counters, this._counters)
    copy._overflow = this._overflow
    for (const [k, v] of this._customRulesById) copy._customRulesById.set(k, v)
    for (const [k, v] of this._userRepresentations) copy._userRepresentations.set(k, v)
    for (const v of this._usedUserAliases) copy._usedUserAliases.add(v)
    for (const [k, v] of this._nextUserAliasByLength) copy._nextUserAliasByLength.set(k, v)
    return copy
  }

  cloneWithCustomRules(rules: readonly CustomRule[]): TextAliasEngine {
    const copy = this.clone()
    for (const r of rules) copy._customRulesById.set(r.id, r)
    return copy
  }

  adoptFrom(staging: TextAliasEngine): void {
    this._map.clear()
    for (const [k, v] of staging._map) this._map.set(k, v)
    Object.assign(this._counters, staging._counters)
    this._overflow = staging._overflow
    this._userRepresentations.clear()
    for (const [k, v] of staging._userRepresentations) this._userRepresentations.set(k, v)
    this._usedUserAliases.clear()
    for (const v of staging._usedUserAliases) this._usedUserAliases.add(v)
    this._nextUserAliasByLength.clear()
    for (const [k, v] of staging._nextUserAliasByLength) this._nextUserAliasByLength.set(k, v)
  }

  /** Allocate the final wire-sized shared user alias, before publishing the snapshot. */
  mapUserAlias(canonical: string, original: string, byteLength: number, ruleId?: string): string {
    if (!Number.isSafeInteger(byteLength) || byteLength < 1) {
      throw new Error('Invalid user alias length')
    }
    // Explicit fixed rules are intentionally non-bijective and may change text length.
    if (ruleId && this._customRulesById.get(ruleId)?.replacementMode === 'fixed') {
      return this.map('user-id', canonical, original, ruleId)
    }
    const key = JSON.stringify([canonical, byteLength])
    const existing = this._userRepresentations.get(key)
    if (existing !== undefined) return existing
    if (this._overflow) return 'x'.repeat(byteLength)

    const primary = this.map('user-id', canonical, original, ruleId)
    const available = (alias: string) => !this._usedUserAliases.has(alias)
      && alias.toLowerCase() !== original.trim().toLowerCase()
    // Keep readable account-N aliases when they fit. Never truncate their distinguishing suffix.
    let alias = primary.padEnd(byteLength, 'x')
    if (primary.length > byteLength || !available(alias)) {
      const capacity = 36 ** byteLength
      let next = this._nextUserAliasByLength.get(byteLength) ?? 0
      let found = false
      // Fixed-width base36 uses the whole slot; the used set detects wrap/exhaustion.
      for (let attempts = 0; attempts < capacity; attempts++) {
        alias = next.toString(36).padStart(byteLength, '0')
        next = next + 1 < capacity ? next + 1 : 0
        if (available(alias)) {
          found = true
          break
        }
      }
      this._nextUserAliasByLength.set(byteLength, next)
      if (!found) {
        this._overflow = true
        alias = 'x'.repeat(byteLength)
      }
    }
    this._userRepresentations.set(key, alias)
    this._usedUserAliases.add(alias)
    return alias
  }

  get(category: IdentityCategory, canonical: string): string | undefined {
    return this._map.get(identityMappingKey(category, canonical))
  }

  map(
    category: IdentityCategory,
    canonical: string,
    originalSample: string,
    ruleId?: string,
  ): string {
    const key = identityMappingKey(category, canonical)
    const existing = this._map.get(key)
    if (existing !== undefined) return existing

    if (this._map.size >= MAX_ENTITY_CARDINALITY) {
      this._overflow = true
      if (category === 'sip-call-id' || category === 'sip-token' || category === 'sip-user') {
        return fallbackSipWireOverflowAlias(category, originalSample)
      }
      return fallbackOverflowAlias(category as Category, originalSample)
    }

    const customRule = ruleId != null ? this._customRulesById.get(ruleId) : undefined
    const alias = category === 'sip-call-id' || category === 'sip-token' || category === 'sip-user'
      ? generateSipWireAlias(category, originalSample, this._counters)
      : generateTextAlias(category as Category, originalSample, this._counters, customRule)
    if (typeof alias !== 'string' || alias.length === 0) {
      throw new Error(`TextAliasEngine: no alias generator for category ${category}`)
    }
    assertNoNewline(alias, 'alias')
    this._map.set(key, alias)
    return alias
  }
}

export function generateTextAlias(
  category: Category,
  original: string,
  counters: TextReplacementCounters,
  customRule?: CustomRule,
): string {
  if (customRule?.replacementMode === 'fixed' && customRule.fixedReplacement != null) {
    assertNoNewline(customRule.fixedReplacement, 'fixedReplacement')
    return customRule.fixedReplacement
  }

  switch (category) {
    case 'ip': {
      const n = ++counters.ip
      const third = 90 + Math.floor((n - 1) / 254)
      const fourth = ((n - 1) % 254) + 1
      return `10.255.${third}.${fourth}`
    }
    case 'hostname': {
      const n = ++counters.hostname
      return `host-${n}.example.invalid`
    }
    case 'sip-phone': {
      const n = ++counters.sipPhone;
      const mappedDigits = String(900_000_000 + n);
      return maskDigitsPreservingFormat(original, mappedDigits);
    }
    case 'email': {
      const n = ++counters.email
      return `user${n}@example.invalid`
    }
    case 'person': {
      const n = ++counters.person
      return `Person ${n}`
    }
    case 'user-id': {
      const n = ++counters.userId
      return `account-${n}`
    }
    case 'internal-id': {
      const n = ++counters.internalId
      if (original.startsWith('MP_')) return `MP_internal-${n}`
      if (original.startsWith('GRP_')) return `GRP_internal-${n}`
      return `internal-${n}`
    }
    case 'port': {
      const digits = original.replace(/\D/g, '')
      const digitSlots = digits.length
      const portNum = Number.parseInt(digits, 10)
      if (!Number.isFinite(portNum)) return original
      // CF-14: system + known service ports stay fixed in text aliases too
      if (isPreservedServicePort(portNum)) return original
      const max = 10 ** digitSlots - 1
      const rangeMax = Math.min(65535, max)
      const minDynamic = Math.min(DYNAMIC_PORT_MIN, rangeMax)
      if (rangeMax < minDynamic) return original
      const n = ++counters.port
      const mapped = minDynamic + ((n - 1) % (rangeMax - minDynamic + 1))
      return formatPortTextFromWire(mapped, original)
    }
    case 'custom': {
      const n = ++counters.custom
      return `custom-${n}`
    }
  }
}

export function generateSipWireAlias(
  category: 'sip-call-id' | 'sip-token' | 'sip-user',
  original: string,
  counters: TextReplacementCounters,
): string {
  switch (category) {
    case 'sip-call-id': {
      const n = ++counters.sipCallId
      return maskAlphanumeric(original, expandToken(`call${n}`))
    }
    case 'sip-token': {
      const n = ++counters.sipToken
      return maskAlphanumeric(original, expandToken(`tok${n}`))
    }
    case 'sip-user': {
      const n = ++counters.sipUser
      return maskAlphanumeric(original, expandToken(`usr${n}`))
    }
  }
}

/** T14 — length-stable opaque token alias (printable shape preserved). */
export function generateOpaqueIdAlias(
  original: string,
  counters: TextReplacementCounters,
): string {
  const n = ++counters.opaqueId
  return maskAlphanumeric(original, expandToken(`oid${n}`))
}

/** T69 — length-stable free-text token alias (e.g. Tk7q…). */
export function generateFreeTokenAlias(
  original: string,
  counters: TextReplacementCounters,
): string {
  const n = ++counters.freeToken
  return maskAlphanumeric(original, expandToken(`Tk${n}`))
}

/** T74 — length-stable hex alias for binary opaque ids. */
export function generateOpaqueBinIdAlias(
  originalHex: string,
  counters: TextReplacementCounters,
): string {
  const n = ++counters.opaqueBinId
  return maskAlphanumeric(originalHex, expandToken(`ob${n}`))
}

/** T40 — length-stable SSID alias (binary wire derived from alias string). */
export function generateSsidAlias(
  original: string,
  counters: TextReplacementCounters,
): string {
  const n = ++counters.ssid
  return maskAlphanumeric(original, expandToken(`wssid${n}`))
}

/** Keyed pseudorandom alphanumeric stream — avoids an obviously-templated a-z0-9 repeat in output. */
function expandToken(seed: string): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let state = 0x811c9dc5
  for (let i = 0; i < seed.length; i++) {
    state ^= seed.charCodeAt(i)
    state = Math.imul(state, 0x01000193) >>> 0
  }
  if (state === 0) state = 0x9e3779b9
  let out = seed
  while (out.length < 64) {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    state >>>= 0
    out += alphabet[state % alphabet.length]
  }
  return out
}

export function maskAlphanumeric(original: string, fill: string): string {
  let fi = 0
  return Array.from(original).map((ch) => {
    if (/[a-zA-Z0-9]/.test(ch)) {
      const mapped = fill[fi % fill.length] ?? 'x'
      fi++
      return mapped
    }
    return ch
  }).join('')
}

function fallbackSipWireOverflowAlias(
  category: 'sip-call-id' | 'sip-token' | 'sip-user',
  original: string,
): string {
  void category
  return maskAlphanumeric(original, 'x')
}

function fallbackOverflowAlias(category: Category, original: string): string {
  switch (category) {
    case 'ip':
      return '0.0.0.0'
    case 'hostname':
      return 'x.example.invalid'
    case 'sip-phone':
      return original.replace(/\d/g, '0') || '0'
    case 'email':
      return 'redacted@example.invalid'
    case 'person':
      return 'Person'
    case 'user-id':
      return 'account'
    case 'internal-id':
      return 'internal'
    case 'port':
      return original.startsWith(':') ? ':0' : '0'
    case 'custom':
      return 'custom'
  }
}
