/**
 * Compile canonical effective correlation policy from text + PCAP profiles (Stage 26).
 */

import type { RulesetConfig, RulesetBuiltinToggles } from '../../domain/configSchema'
import { builtinEnabled } from '../../domain/configSchema'
import type { Category } from '../../domain/types'
import { SourceKind } from '../../domain/sourceArtifact'
import type { PcapProfile } from '../../pcap/profile/schema'
import type { CrossFormatCategory } from '../../mapping/crossFormat/types'
import { isWireCompatibleReplacement, isWireValidIpv6 } from './wireValid'
import type {
  CompileCorrelationPolicyOptions,
  CorrelationEffectivePolicy,
  PcapCategoryRepresentation,
  PcapEffectivePolicy,
  TextCategoryRepresentation,
  TextEffectivePolicy,
} from './types'

const CROSS_FORMAT_CATEGORIES: readonly CrossFormatCategory[] = [
  'ipv4', 'ipv6', 'mac', 'hostname', 'port', 'phone', 'email', 'user',
]

const TEXT_CATEGORY_FOR_CF: Record<CrossFormatCategory, Category | null> = {
  ipv4: 'ip',
  ipv6: 'ip',
  mac: null,
  hostname: 'hostname',
  port: 'port',
  phone: 'sip-phone',
  email: 'email',
  user: 'user-id',
}

function fnv1aHash(input: string): string {
  let h = 2166136261
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`
}

function textBuiltinEnabled(toggles: RulesetBuiltinToggles, cf: CrossFormatCategory): boolean {
  const cat = TEXT_CATEGORY_FOR_CF[cf]
  if (cat === null || cat === 'custom') return false
  return builtinEnabled(toggles, cat)
}

function textCategoryRepresentation(
  config: RulesetConfig,
  cf: CrossFormatCategory,
): TextCategoryRepresentation {
  const { profile } = config

  const fixedFromRules = (): TextCategoryRepresentation | null => {
    for (const rule of profile.rules) {
      if (!rule.enabled) continue
      if (!categoryRuleMatches(cf, rule.category)) continue
      if (rule.category === 'ip' && rule.replacement.kind === 'fixed' && rule.replacement.value != null) {
        const value = rule.replacement.value
        if (cf === 'ipv6' && !isWireValidIpv6(value)) continue
        if (cf === 'ipv4' && isWireValidIpv6(value)) continue
      }
      if (rule.replacement.kind === 'fixed' && rule.replacement.value != null) {
        const value = rule.replacement.value
        return {
          kind: 'fixed',
          value,
          wireCompatible: isWireCompatibleReplacement(cf, value),
        }
      }
    }
    return null
  }

  if (!textBuiltinEnabled(profile.builtins, cf)) {
    return fixedFromRules() ?? { kind: 'disabled' }
  }

  return fixedFromRules() ?? { kind: 'generated', wireCompatible: cf !== 'port' }
}

function categoryRuleMatches(cf: CrossFormatCategory, ruleCategory: Category): boolean {
  if (cf === 'ipv4' || cf === 'ipv6') return ruleCategory === 'ip'
  if (cf === 'hostname') return ruleCategory === 'hostname'
  if (cf === 'port') return ruleCategory === 'port'
  if (cf === 'phone') return ruleCategory === 'sip-phone'
  if (cf === 'email') return ruleCategory === 'email'
  if (cf === 'user') return ruleCategory === 'user-id'
  return false
}

function pcapCategoryRepresentation(profile: PcapProfile, cf: CrossFormatCategory): PcapCategoryRepresentation {
  switch (cf) {
    case 'ipv4':
    case 'ipv6':
      return profile.mapping.ip === 'topology-preserving'
        || profile.mapping.ip === 'privacy-preserving'
        ? { kind: 'wire-valid' }
        : { kind: 'disabled' }
    case 'mac':
      return profile.mapping.mac === 'locally-administered'
        ? { kind: 'wire-valid' }
        : { kind: 'disabled' }
    case 'hostname':
      return { kind: 'wire-valid' }
    case 'port':
      return profile.mapping.ephemeralPorts === 'preserve'
        ? { kind: 'preserved' }
        : { kind: 'wire-valid' }
    case 'phone':
    case 'email':
    case 'user':
      // T45 — SIP/text identity categories; always wire-valid when PCAP profile is active.
      void profile
      return { kind: 'wire-valid' }
  }
}

function discoverySectionsText(config: RulesetConfig): unknown {
  const { profile } = config
  return {
    builtins: profile.builtins,
    rules: profile.rules.map((r) => ({
      id: r.id,
      enabled: r.enabled,
      kind: r.kind,
      pattern: r.pattern,
      category: r.category,
      replacement: r.replacement,
      priority: r.priority ?? null,
    })),
    settings: profile.settings,
  }
}

function discoverySectionsPcap(profile: PcapProfile): unknown {
  return {
    preset: profile.preset,
    unsupportedPayloadPolicy: profile.unsupportedPayloadPolicy,
    malformedPayloadPolicy: profile.malformedPayloadPolicy,
    mediaPolicy: profile.mediaPolicy,
    preservePacketLengths: profile.preservePacketLengths,
    preservePacketOrder: profile.preservePacketOrder,
    protocols: profile.protocols,
  }
}

function representationSectionsText(categories: Readonly<Record<CrossFormatCategory, TextCategoryRepresentation>>): unknown {
  return { categories }
}

export function compileTextEffectivePolicy(config: RulesetConfig): TextEffectivePolicy {
  const categories = Object.fromEntries(
    CROSS_FORMAT_CATEGORIES.map((cf) => [cf, textCategoryRepresentation(config, cf)]),
  ) as Record<CrossFormatCategory, TextCategoryRepresentation>

  return {
    profileId: config.profile.id,
    profileName: config.profile.name,
    categories,
    discoveryHash: fnv1aHash(stableStringify(discoverySectionsText(config))),
    representationHash: fnv1aHash(stableStringify(representationSectionsText(categories))),
  }
}

export function compilePcapEffectivePolicy(profile: PcapProfile): PcapEffectivePolicy {
  const categories = Object.fromEntries(
    CROSS_FORMAT_CATEGORIES.map((cf) => [cf, pcapCategoryRepresentation(profile, cf)]),
  ) as Record<CrossFormatCategory, PcapCategoryRepresentation>

  return {
    profileId: profile.id,
    profileName: profile.name,
    categories,
    discoveryHash: fnv1aHash(stableStringify(discoverySectionsPcap(profile))),
    representationHash: fnv1aHash(stableStringify({
      categories,
      mapping: profile.mapping,
    })),
  }
}

export function compileCorrelationPolicy(
  options: CompileCorrelationPolicyOptions,
): CorrelationEffectivePolicy {
  const hasText = options.sourceKinds.includes(SourceKind.Text)
  const hasPcap = options.sourceKinds.includes(SourceKind.Pcap)

  const text = hasText && options.textProfile
    ? compileTextEffectivePolicy(options.textProfile)
    : null
  const pcap = hasPcap && options.pcapProfile
    ? compilePcapEffectivePolicy(options.pcapProfile)
    : null

  const representationHash = fnv1aHash(stableStringify({
    text: text?.representationHash ?? null,
    pcap: pcap?.representationHash ?? null,
  }))
  const discoveryHash = fnv1aHash(stableStringify({
    text: text?.discoveryHash ?? null,
    pcap: pcap?.discoveryHash ?? null,
  }))
  const policyHash = fnv1aHash(stableStringify({ representationHash, discoveryHash }))

  return {
    text,
    pcap,
    sourceKinds: Object.freeze([...options.sourceKinds]),
    representationHash,
    discoveryHash,
    policyHash,
  }
}

export function hashEffectivePolicy(policy: CorrelationEffectivePolicy): string {
  return policy.policyHash
}
