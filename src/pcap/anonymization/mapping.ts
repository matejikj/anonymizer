/**
 * Session mapping engine — generates consistent pseudonyms for each entity.
 * Uses CSPRNG; mapping lives only in session RAM. Never serialized.
 *
 * Preserves:
 * - Address family (IPv4→IPv4, IPv6→IPv6)
 * - IP semantic class (private→private, multicast preserved, broadcast preserved)
 * - MAC unicast/local bits (maps to locally-administered unicast)
 * - Hostname label count and per-label length
 * - VLAN range 1–4094
 * - Well-known ports preserved; ephemeral mapped within range
 */

import type { IdentityCategory } from '../../mapping/identityCategories';
import type { WireRepresentationConstraint } from '../../mapping/types';
import {
  createTextReplacementCounters,
  generateOpaqueIdAlias,
  generateFreeTokenAlias,
  generateOpaqueBinIdAlias,
  generateSsidAlias,
  generateSipWireAlias,
  generateTextAlias,
  type TextReplacementCounters,
} from '../../mapping/textAliasEngine';
import { defaultWireConstraint, sdpSessionIdDigits } from '../../mapping/pcapCanonical';
import type { EntityCategory } from './entityRegistry';
import { MAX_ENTITY_CARDINALITY } from './entityRegistry';
import { formatTextAliasFromWire } from './wireTextFormat';
import {
  DYNAMIC_PORT_MAX,
  DYNAMIC_PORT_MIN,
  USER_REGISTERED_PORT_MAX,
  USER_REGISTERED_PORT_MIN,
  isDynamicPort,
  isPreservedServicePort,
  isUserRegisteredPort,
  mergePortFlowHints,
  shouldPreservePort,
  type PortFlowHint,
} from './portPolicy';
import {
  allocateExclusiveId,
  allocateExclusiveIdSparse,
  type DenseProbeCursor,
} from './exclusiveIdAllocation';
import {
  finalizeImeiAliasDigits,
  IMSI_PLMN_SCOPE_SEP,
  imsiWireDigits,
} from '../protocols/application/binproto/tbcd';
import type { TimestampMappingConfig } from './timestampMapping';
import {
  createPrefixPreservingKey,
  derivePreservedIpv4HostBits,
  derivePreservedIpv6HostBits,
  type PrefixPreservingKey,
} from './prefixPreservingId';
import { IPV4_BLOCK_DOMAIN_SIZE } from './mappingDomainRegistry.ts';
import type { IpMappingMode } from './entityNamespaces';
import { entityMapKey } from './entityNamespaces';
import { expandSeedToEntropy, freshEntropy } from './seedEntropy';
import {
  applyEui64Iid,
  classifyEmbeddedIpv4,
  expandIpv6Canonical,
  format6to4,
  formatIpv4Mapped,
  formatIpv6Groups,
  formatIpv6MulticastMac,
  formatIsatap,
  formatNat64WellKnown,
  formatSolicitedNodeIpv6,
  formatSolicitedNodeMac,
  formatTeredo,
  isIpv6Multicast,
  isIpv6MulticastMac,
  isPreservedIpv6Multicast,
  isSolicitedNodeIpv6,
  isSolicitedNodeMac,
  ipv6Groups,
  macFromEui64Ipv6,
  solicitedNodeLow24,
  solicitedNodeMacLow24,
  unicastLow24,
} from '../../mapping/ipv6Semantics';

export interface MappingConfig {
  /**
   * IP alias mode (step 12) — bound to PCAP profile, not a third UI toggle.
   * `topology-preserving` (diagnostic): integer-mix host bits in a fixed /24 bucket of the
   * target /16 (T38.prefix); collisions stay in-bucket (not AES Crypto-PAn).
   * `privacy-preserving` (high-privacy): class-preserving random exclusive IDs only.
   */
  readonly ip: IpMappingMode;
  readonly mac: 'locally-administered';
  readonly timestamps: TimestampMappingConfig;
  /** Small-domain permutation for ephemeral ports (not generic FPE). */
  readonly ephemeralPorts: 'preserve' | 'permute';
  /**
   * T06 — when discovery attaches a signaling flow hint (e.g. SIP on 5070):
   * `preserve` keeps the port (diagnostic); `permute` remaps it (high-privacy).
   * Catalog service ports are always preserved regardless of this flag.
   */
  readonly contentSignalingPorts: 'preserve' | 'permute';
  /** VLAN 1–4094: exclusive permutation when `map` (not FPE). */
  readonly vlan: 'map' | 'preserve';
  /**
   * T16 — when IMSI canonical carries an explicit PLMN scope (`mcc+mnc\\x1fmsin`):
   * `preserve-plmn` keeps MCC+MNC and remaps MSIN (diagnostic); `map-all` remaps
   * the whole digit string (high-privacy / no PLMN trust).
   */
  readonly imsiPlmn: 'preserve-plmn' | 'map-all';
}

/** Minimal mapping surface for sanitize/plan (SessionMapping, snapshot adapter, passthrough). */
export interface MappingLike {
  map(category: IdentityCategory, canonical: string): string
  get(category: IdentityCategory, canonical: string): string | undefined
  aliasFor(
    category: IdentityCategory,
    canonical: string,
    constraint: WireRepresentationConstraint,
    originalSpelling?: string,
  ): string
  readonly overflow: boolean
}

export const DEFAULT_MAPPING_CONFIG: MappingConfig = {
  ip: 'topology-preserving',
  mac: 'locally-administered',
  timestamps: 'relative',
  ephemeralPorts: 'preserve',
  contentSignalingPorts: 'preserve',
  vlan: 'map',
  imsiPlmn: 'preserve-plmn',
};

/** Destination /16 blocks mapped IPv4 addresses are drawn from — 65536 slots each. */
const IPV4_PRIVATE_BASE: readonly [number, number] = [10, 254];
const IPV4_PUBLIC_BASE: readonly [number, number] = [198, 51];
const IPV4_BLOCK_SIZE = IPV4_BLOCK_DOMAIN_SIZE;

const VLAN_MIN = 1;
const VLAN_MAX = 4094;

/** 24-bit radio subscriber/talkgroup ID space (e.g. DMR). Small enough for a full linear-probe fallback. */
const RADIO_ID_SPACE = 0x1000000;

/** Bounded random attempts before falling back to a full (feasible-size) linear probe. */
const RANDOM_RETRY_ATTEMPTS = 32;

export class SessionMapping implements MappingLike {
  private readonly _map = new Map<string, string>();
  private readonly _textAliasByConstraint = new Map<string, string>();
  private readonly _usedIpv4 = new Set<string>();
  private readonly _usedIpv6 = new Set<string>();
  /** T48 — persistent /16 slot indexes (O(1) membership; never rebuilt per map). */
  private readonly _usedIpv4PrivateSlots = new Set<number>();
  private readonly _usedIpv4PublicSlots = new Set<number>();
  private readonly _ipv4PrivateProbe: DenseProbeCursor = { offset: 0 };
  private readonly _ipv4PublicProbe: DenseProbeCursor = { offset: 0 };
  /** T48 — persistent 32-bit suffix indexes for ULA / documentation unicast targets. */
  private readonly _usedIpv6UlaSuffixes = new Set<number>();
  private readonly _usedIpv6DocSuffixes = new Set<number>();
  private readonly _usedMac = new Set<string>();
  private readonly _usedVlan = new Set<number>();
  private readonly _vlanProbe: DenseProbeCursor = { offset: 0 };
  private readonly _usedRadioId = new Set<number>();
  private readonly _radioIdProbe: DenseProbeCursor = { offset: 0 };
  private readonly _usedSsrc = new Set<number>();
  private readonly _usedTeid = new Set<number>();
  /** T25 — SS7 point codes; separate pools for 14-bit (ITU) and 24-bit (ANSI/M3UA). */
  private readonly _usedPointCode14 = new Set<number>();
  private readonly _usedPointCode24 = new Set<number>();
  private readonly _usedSdpSessionId = new Set<string>();
  /** T16 — length-stable IMSI / IMEI digit aliases (separate from SDP session-id). */
  private readonly _usedImsi = new Set<string>();
  private readonly _usedImei = new Set<string>();
  private readonly _usedSnmpEngineId = new Set<string>();
  private readonly _usedPorts = new Map<string, Set<number>>();
  /** Alias pair-index allocations per transport (`proto|pairKey` → pair index). */
  private readonly _portPairAlias = new Map<string, number>();
  private readonly _usedPortPairs = new Map<string, Set<number>>();
  private readonly _portPairProbes = new Map<string, DenseProbeCursor>();
  /** Discovery flow hints for port identities (`tcp/5070` → sip). */
  private readonly _portFlowHints = new Map<string, PortFlowHint>();
  /**
   * T06 revision — explicit SDP media mates (`udp/5004` ↔ `udp/5006` for non-+1 a=rtcp).
   * Mux (same port) stores self as mate.
   */
  private readonly _mediaPortMates = new Map<string, string>();
  /** Linked alias ports for explicit media mates (canonical → alias port number). */
  private readonly _mediaMateAliases = new Map<string, number>();
  /**
   * T33 — solicited-node / 33:33:ff group: original low-24 → alias low-24.
   * Shared by SN IPv6 and SN multicast MAC so suffix never echoes the original.
   */
  private readonly _snGroupLow24 = new Map<number, number>();
  /** T33 — other IPv6 multicast MAC low-32 allocations (33:33:xx:xx:xx:xx). */
  private readonly _usedIpv6McastMacLow32 = new Set<number>();
  private _hostnameCounter = 1;
  private _textCounters: TextReplacementCounters = createTextReplacementCounters();
  private _config: MappingConfig;
  private readonly _random: Uint8Array;
  private _seeded: boolean;
  private _randomOffset = 0;
  private _overflow = false;
  private _prefixKey: PrefixPreservingKey;
  /** T38 — diagnostic /24 third octet in target /16 (stable across slot collisions). */
  private readonly _ipv4Topology24ThirdOctet = new Map<string, number>();
  /** Inverse: each target third octet is owned by at most one original /24. */
  private readonly _ipv4TopologyThirdOctetOwner = new Map<number, string>();

  /**
   * @param config mapping policy (IP mode, ports, VLAN, …)
   * @param options.seed TEST MODE only — deterministic entropy. Production must omit seed
   *   (use {@link createProductionSessionMapping} / {@link createTestSessionMapping}).
   */
  constructor(
    config: MappingConfig = DEFAULT_MAPPING_CONFIG,
    options?: { readonly seed?: string },
  ) {
    this._config = { ...DEFAULT_MAPPING_CONFIG, ...config };
    this._seeded = typeof options?.seed === 'string' && options.seed.length > 0
    this._random = this._seeded
      ? expandSeedToEntropy(options!.seed!)
      : freshEntropy(4096)
    this._prefixKey = createPrefixPreservingKey(() => this._nextRandomU32());
  }

  /** True when this session was constructed with an injected TEST MODE seed. */
  get seeded(): boolean {
    return this._seeded
  }

  get size(): number { return this._map.size; }
  get overflow(): boolean { return this._overflow; }

  /** Deep copy for transactional staging (Stage 7 MappingAuthority). */
  clone(config: MappingConfig = this._config): SessionMapping {
    const copy = new SessionMapping(config)
    copy._seeded = this._seeded
    for (const [k, v] of this._map) copy._map.set(k, v)
    for (const v of this._usedIpv4) copy._usedIpv4.add(v)
    for (const v of this._usedIpv6) copy._usedIpv6.add(v)
    for (const v of this._usedIpv4PrivateSlots) copy._usedIpv4PrivateSlots.add(v)
    for (const v of this._usedIpv4PublicSlots) copy._usedIpv4PublicSlots.add(v)
    copy._ipv4PrivateProbe.offset = this._ipv4PrivateProbe.offset
    copy._ipv4PublicProbe.offset = this._ipv4PublicProbe.offset
    for (const v of this._usedIpv6UlaSuffixes) copy._usedIpv6UlaSuffixes.add(v)
    for (const v of this._usedIpv6DocSuffixes) copy._usedIpv6DocSuffixes.add(v)
    for (const v of this._usedMac) copy._usedMac.add(v)
    for (const v of this._usedVlan) copy._usedVlan.add(v)
    copy._vlanProbe.offset = this._vlanProbe.offset
    for (const v of this._usedRadioId) copy._usedRadioId.add(v)
    copy._radioIdProbe.offset = this._radioIdProbe.offset
    for (const v of this._usedSsrc) copy._usedSsrc.add(v)
    for (const v of this._usedTeid) copy._usedTeid.add(v)
    for (const v of this._usedSdpSessionId) copy._usedSdpSessionId.add(v)
    for (const v of this._usedImsi) copy._usedImsi.add(v)
    for (const v of this._usedImei) copy._usedImei.add(v)
    for (const v of this._usedSnmpEngineId) copy._usedSnmpEngineId.add(v)
    for (const [protocol, ports] of this._usedPorts) {
      copy._usedPorts.set(protocol, new Set(ports))
    }
    for (const [k, v] of this._portPairAlias) copy._portPairAlias.set(k, v)
    for (const [protocol, pairs] of this._usedPortPairs) {
      copy._usedPortPairs.set(protocol, new Set(pairs))
    }
    for (const [k, v] of this._portPairProbes) {
      copy._portPairProbes.set(k, { offset: v.offset })
    }
    for (const [k, v] of this._portFlowHints) copy._portFlowHints.set(k, v)
    for (const [k, v] of this._mediaPortMates) copy._mediaPortMates.set(k, v)
    for (const [k, v] of this._mediaMateAliases) copy._mediaMateAliases.set(k, v)
    for (const [k, v] of this._snGroupLow24) copy._snGroupLow24.set(k, v)
    for (const v of this._usedIpv6McastMacLow32) copy._usedIpv6McastMacLow32.add(v)
    for (const [k, v] of this._textAliasByConstraint) copy._textAliasByConstraint.set(k, v)
    copy._hostnameCounter = this._hostnameCounter
    copy._textCounters = { ...this._textCounters }
    copy._random.set(this._random)
    copy._randomOffset = this._randomOffset
    copy._overflow = this._overflow
    copy._prefixKey = this._prefixKey
    for (const [k, v] of this._ipv4Topology24ThirdOctet) copy._ipv4Topology24ThirdOctet.set(k, v)
    for (const [k, v] of this._ipv4TopologyThirdOctetOwner) copy._ipv4TopologyThirdOctetOwner.set(k, v)
    return copy
  }

  /** Replace internal state from a committed staging engine. */
  adoptFrom(staging: SessionMapping): void {
    this._config = { ...staging._config }
    this._map.clear()
    for (const [k, v] of staging._map) this._map.set(k, v)
    this._usedIpv4.clear()
    for (const v of staging._usedIpv4) this._usedIpv4.add(v)
    this._usedIpv6.clear()
    for (const v of staging._usedIpv6) this._usedIpv6.add(v)
    this._usedIpv4PrivateSlots.clear()
    for (const v of staging._usedIpv4PrivateSlots) this._usedIpv4PrivateSlots.add(v)
    this._usedIpv4PublicSlots.clear()
    for (const v of staging._usedIpv4PublicSlots) this._usedIpv4PublicSlots.add(v)
    this._ipv4PrivateProbe.offset = staging._ipv4PrivateProbe.offset
    this._ipv4PublicProbe.offset = staging._ipv4PublicProbe.offset
    this._usedIpv6UlaSuffixes.clear()
    for (const v of staging._usedIpv6UlaSuffixes) this._usedIpv6UlaSuffixes.add(v)
    this._usedIpv6DocSuffixes.clear()
    for (const v of staging._usedIpv6DocSuffixes) this._usedIpv6DocSuffixes.add(v)
    this._usedMac.clear()
    for (const v of staging._usedMac) this._usedMac.add(v)
    this._usedVlan.clear()
    for (const v of staging._usedVlan) this._usedVlan.add(v)
    this._vlanProbe.offset = staging._vlanProbe.offset
    this._usedRadioId.clear()
    for (const v of staging._usedRadioId) this._usedRadioId.add(v)
    this._radioIdProbe.offset = staging._radioIdProbe.offset
    this._usedSsrc.clear()
    for (const v of staging._usedSsrc) this._usedSsrc.add(v)
    this._usedTeid.clear()
    for (const v of staging._usedTeid) this._usedTeid.add(v)
    this._usedSdpSessionId.clear()
    for (const v of staging._usedSdpSessionId) this._usedSdpSessionId.add(v)
    this._usedImsi.clear()
    for (const v of staging._usedImsi) this._usedImsi.add(v)
    this._usedImei.clear()
    for (const v of staging._usedImei) this._usedImei.add(v)
    this._usedSnmpEngineId.clear()
    for (const v of staging._usedSnmpEngineId) this._usedSnmpEngineId.add(v)
    this._usedPorts.clear()
    for (const [protocol, ports] of staging._usedPorts) {
      this._usedPorts.set(protocol, new Set(ports))
    }
    this._portPairAlias.clear()
    for (const [k, v] of staging._portPairAlias) this._portPairAlias.set(k, v)
    this._usedPortPairs.clear()
    for (const [protocol, pairs] of staging._usedPortPairs) {
      this._usedPortPairs.set(protocol, new Set(pairs))
    }
    this._portPairProbes.clear()
    for (const [k, v] of staging._portPairProbes) {
      this._portPairProbes.set(k, { offset: v.offset })
    }
    this._portFlowHints.clear()
    for (const [k, v] of staging._portFlowHints) this._portFlowHints.set(k, v)
    this._mediaPortMates.clear()
    for (const [k, v] of staging._mediaPortMates) this._mediaPortMates.set(k, v)
    this._mediaMateAliases.clear()
    for (const [k, v] of staging._mediaMateAliases) this._mediaMateAliases.set(k, v)
    this._snGroupLow24.clear()
    for (const [k, v] of staging._snGroupLow24) this._snGroupLow24.set(k, v)
    this._usedIpv6McastMacLow32.clear()
    for (const v of staging._usedIpv6McastMacLow32) this._usedIpv6McastMacLow32.add(v)
    this._textAliasByConstraint.clear()
    for (const [k, v] of staging._textAliasByConstraint) this._textAliasByConstraint.set(k, v)
    this._hostnameCounter = staging._hostnameCounter
    Object.assign(this._textCounters, staging._textCounters)
    this._random.set(staging._random)
    this._randomOffset = staging._randomOffset
    this._seeded = staging._seeded
    this._overflow = staging._overflow
    this._prefixKey = staging._prefixKey
    this._ipv4Topology24ThirdOctet.clear()
    for (const [k, v] of staging._ipv4Topology24ThirdOctet) this._ipv4Topology24ThirdOctet.set(k, v)
    this._ipv4TopologyThirdOctetOwner.clear()
    for (const [k, v] of staging._ipv4TopologyThirdOctetOwner) this._ipv4TopologyThirdOctetOwner.set(k, v)
  }

  /** Get or create mapping for an entity. Returns the pseudonym. */
  map(category: IdentityCategory, canonical: string): string {
    // T33 — store IPv6 under expanded 8-hextet form so ::ffff: / SN spellings share one key.
    const canon =
      category === 'ipv6'
        ? (expandIpv6Canonical(canonical) ?? canonical.toLowerCase())
        : category === 'mac'
          ? canonical.toLowerCase()
          : canonical
    const key = entityMapKey(category, canon);
    const existing = this._map.get(key);
    if (existing !== undefined) return existing;

    if (this._map.size >= MAX_ENTITY_CARDINALITY) {
      this._overflow = true;
      // Fail-closed: return a fixed anonymous token so callers still get a length-safe value
      return category === 'ipv4' ? '0.0.0.0'
        : category === 'ipv6' ? '0:0:0:0:0:0:0:0'
        : category === 'mac' ? '02:00:00:00:00:00'
        : category === 'hostname' ? 'x'.repeat(Math.max(1, canon.length))
        : category === 'vlan' ? '0'
        : category === 'port' ? canon
        : category === 'radioId' ? '0'
        : category === 'ssrc' || category === 'teid' ? '0'
        : category === 'point-code'
          ? (canon.startsWith('pc/14/')
            ? (canon === 'pc/14/0' ? 'pc/14/1' : 'pc/14/0')
            : (canon === 'pc/24/0' ? 'pc/24/1' : 'pc/24/0'))
        : category === 'sdp-session-id' || category === 'imsi' || category === 'imei'
          ? (() => {
            const digits =
              category === 'sdp-session-id'
                ? sdpSessionIdDigits(canon)
                : category === 'imsi'
                  ? imsiWireDigits(canon)
                  : canon
            return digits.startsWith('0')
              ? (digits.length === 1 ? '1' : `0${'9'.repeat(digits.length - 1)}`)
              : '9'.repeat(Math.max(1, digits.length))
          })()
        : category === 'opaque-id' || category === 'ssid' || category === 'free-token'
          || category === 'opaque-bin-id'
          ? 'x'.repeat(Math.max(1, canon.length))
        : category === 'snmp-engine-id'
          ? 'f'.repeat(Math.max(1, canon.length))
        : category === 'sip-phone' ? canon.replace(/\d/g, '0') || '0'
        : category === 'sip-call-id' || category === 'sip-token' || category === 'sip-user'
          ? 'x'.repeat(Math.max(1, canon.length))
        : category === 'email' || category === 'user-id' || category === 'person'
          ? 'x'.repeat(Math.max(1, canon.length))
        : `anon-overflow`;
    }

    let mapped: string;
    switch (category) {
      case 'ipv4': mapped = this._mapIpv4(canon); break;
      case 'ipv6': mapped = this._mapIpv6(canon); break;
      case 'mac': mapped = this._mapMac(canon); break;
      case 'hostname': mapped = this._mapHostname(canon); break;
      case 'vlan': mapped = this._mapVlan(canon); break;
      case 'port': mapped = this._mapPort(canon); break;
      case 'radioId': mapped = this._mapRadioId(canon); break;
      case 'ssrc': mapped = this._mapSsrc(canon); break;
      case 'teid': mapped = this._mapTeid(canon); break;
      case 'point-code': mapped = this._mapPointCode(canon); break;
      case 'sdp-session-id': mapped = this._mapSdpSessionId(canon); break;
      case 'imsi': mapped = this._mapImsi(canon); break;
      case 'imei': mapped = this._mapImei(canon); break;
      case 'snmp-engine-id': mapped = this._mapHexString(canon, this._usedSnmpEngineId); break;
      case 'opaque-id':
        mapped = generateOpaqueIdAlias(canon, this._textCounters);
        break;
      case 'free-token':
        mapped = generateFreeTokenAlias(canon, this._textCounters);
        break;
      case 'opaque-bin-id':
        mapped = generateOpaqueBinIdAlias(canon, this._textCounters);
        break;
      case 'ssid':
        mapped = generateSsidAlias(canon, this._textCounters);
        break;
      case 'timestamp': mapped = canon; break;
      case 'sip-call-id':
      case 'sip-token':
      case 'sip-user':
        mapped = generateSipWireAlias(category, canon, this._textCounters);
        break;
      case 'sip-phone':
        mapped = generateTextAlias('sip-phone', canon, this._textCounters);
        break;
      case 'email':
        mapped = generateTextAlias('email', canon, this._textCounters);
        break;
      case 'user-id':
        mapped = generateTextAlias('user-id', canon, this._textCounters);
        break;
      case 'person':
        mapped = generateTextAlias('person', canon, this._textCounters);
        break;
      default: {
        // T48 — missing strategy is fail-closed overflow, not a silent anon-N token.
        this._overflow = true;
        mapped = 'anon-overflow';
        break;
      }
    }

    this._map.set(key, mapped);
    return mapped;
  }

  /** Get existing mapping without creating. */
  get(category: IdentityCategory, canonical: string): string | undefined {
    const canon =
      category === 'ipv6'
        ? (expandIpv6Canonical(canonical) ?? canonical.toLowerCase())
        : category === 'mac'
          ? canonical.toLowerCase()
          : canonical
    return this._map.get(entityMapKey(category, canon));
  }

  aliasFor(
    category: IdentityCategory,
    canonical: string,
    constraint: WireRepresentationConstraint,
    originalSpelling?: string,
  ): string {
    const spelling = originalSpelling ?? canonical;
    if (constraint.kind === 'text-ascii') {
      const cacheKey = `${category}:${canonical}:text:${constraint.byteLength}:${spelling}`;
      const cached = this._textAliasByConstraint.get(cacheKey);
      if (cached !== undefined) return cached;

      const wireAlias = this.map(category, canonical);
      const textAlias = formatTextAliasFromWire(
        category,
        wireAlias,
        constraint.byteLength,
        spelling,
      );
      this._textAliasByConstraint.set(cacheKey, textAlias);
      return textAlias;
    }

    const wire = defaultWireConstraint(category as EntityCategory, canonical);
    if (wire && wire.kind === constraint.kind) {
      return this.map(category, canonical);
    }
    return this.map(category, canonical);
  }

  /** Check that no original value appears as a mapped value. */
  hasNoOriginalInOutput(): boolean {
    const originals = new Set<string>();
    for (const [key] of this._map) {
      const canonical = key.substring(key.indexOf(':') + 1);
      originals.add(canonical);
    }
    for (const mapped of this._map.values()) {
      if (originals.has(mapped)) return false;
    }
    return true;
  }

  private _mapIpv4(ip: string): string {
    // Preserve broadcast, unspecified, multicast
    if (ip === '0.0.0.0' || ip === '255.255.255.255') return ip;
    const parts = ip.split('.').map(Number);
    if (parts[0]! >= 224 && parts[0]! <= 239) return ip; // multicast

    // Map into same class — exclusive slot in a fixed /16, never alias===original.
    const isPrivate = isPrivateIpv4(parts);
    const base = isPrivate ? IPV4_PRIVATE_BASE : IPV4_PUBLIC_BASE;
    const usedSlots = isPrivate ? this._usedIpv4PrivateSlots : this._usedIpv4PublicSlots;
    const denseProbe = isPrivate ? this._ipv4PrivateProbe : this._ipv4PublicProbe;

    const address32 = ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
    // Topology-preserving: allocate inside a fixed /24 bucket so prefix↔host stays coherent
    // after first-candidate collisions (T38.prefix); privacy-preserving uses the full /16.
    const topology = this._config.ip === 'topology-preserving';
    let bucketThird: number | undefined;
    if (topology) {
      const network24 = address32 & 0xffffff00;
      const prefix24Key = ipv4Prefix24Key(parts);
      bucketThird = this._ipv4Topology24ThirdOctet.get(prefix24Key);
      if (bucketThird === undefined) {
        bucketThird = assignTopology24ThirdOctet(
          this._ipv4Topology24ThirdOctet,
          this._ipv4TopologyThirdOctetOwner,
          prefix24Key,
          deriveTopology24ThirdOctet(this._prefixKey, network24),
          usedSlots,
        );
      }
    }
    let offeredPreserved = !topology;
    const nextRandom = () => {
      if (!topology) return this._nextRandomU16();
      if (!offeredPreserved) {
        offeredPreserved = true;
        return derivePreservedIpv4HostBits(this._prefixKey, address32, 16) & 0xff;
      }
      return this._nextRandomU16();
    };

    const slot = allocateExclusiveId({
      used: usedSlots,
      min: 0,
      max: IPV4_BLOCK_SIZE - 1,
      reject: (n) => {
        if (formatIpv4Block(base, n) === ip) return true;
        if (topology && bucketThird !== undefined && ((n >> 8) & 0xff) !== bucketThird) return true;
        return false;
      },
      nextRandom,
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
      denseProbe,
    });
    if (slot === null) {
      this._overflow = true;
      return isPrivate ? '0.0.0.0' : '255.255.255.255';
    }
    const candidate = formatIpv4Block(base, slot);
    usedSlots.add(slot);
    this._usedIpv4.add(candidate);
    return candidate;
  }

  private _mapIpv6(ip: string): string {
    const expanded = expandIpv6Canonical(ip) ?? ip.toLowerCase()
    if (expanded === '0:0:0:0:0:0:0:0') return '0:0:0:0:0:0:0:0'

    // T33 — well-known multicast constants only; solicited-node and other groups are identities.
    if (isPreservedIpv6Multicast(expanded)) return expanded
    if (isSolicitedNodeIpv6(expanded)) {
      const low = solicitedNodeLow24(expanded)!
      const aliasLow = this._aliasLow24ForSnGroup(low)
      const candidate = formatSolicitedNodeIpv6(aliasLow)
      this._usedIpv6.add(candidate)
      return candidate
    }
    if (isIpv6Multicast(expanded)) {
      // Non-SN multicast group: allocate exclusive address in ff02::/16 with random low 32 bits.
      return this._mapGenericIpv6Multicast(expanded)
    }

    const embedded = classifyEmbeddedIpv4(expanded)
    if (embedded) {
      const mapped = this._mapEmbeddedIpv4Form(embedded)
      if (mapped) {
        this._usedIpv6.add(mapped)
        return mapped
      }
    }

    // EUI-64 only when the implied MAC is already mapped (NDP/L2 evidence), never from shape alone.
    const impliedMac = macFromEui64Ipv6(expanded)
    if (impliedMac) {
      const macAlias = this.get('mac', impliedMac)
      if (macAlias) {
        const prefixGroups = ipv6Groups(expanded)!.slice(0, 4)
        // Remap /64 prefix via a synthetic unicast then re-apply EUI-64 from MAC alias.
        const prefixProbe = formatIpv6Groups([...prefixGroups, 0, 0, 0, 1])
        const prefixMapped = this._mapIpv6UnicastCore(prefixProbe, { skipEui64: true })
        const withEui = applyEui64Iid(prefixMapped, macAlias)
        if (withEui && !this._usedIpv6.has(withEui) && withEui !== expanded) {
          this._usedIpv6.add(withEui)
          this._rememberUnicastLow24(expanded, withEui)
          return withEui
        }
      }
    }

    const candidate = this._mapIpv6UnicastCore(expanded, { skipEui64: true })
    this._rememberUnicastLow24(expanded, candidate)
    return candidate
  }

  private _mapIpv6UnicastCore(
    expanded: string,
    _opts: { readonly skipEui64: boolean },
  ): string {
    const isLinkLocal = expanded.startsWith('fe80:')
    const prefix = isLinkLocal ? 'fd00:0:0:0' : '2001:db8:0:0'
    const usedSuffixes = isLinkLocal ? this._usedIpv6UlaSuffixes : this._usedIpv6DocSuffixes

    const origLow = unicastLow24(expanded)
    const forcedLow24 = origLow !== null ? this._snGroupLow24.get(origLow) : undefined

    const addressWords = ipv6ToWords(expanded)
    const topology = this._config.ip === 'topology-preserving'
    let offeredPreserved = !topology
    const nextRandom = () => {
      if (forcedLow24 !== undefined) {
        // Prefer SN-consistent low24 in the bottom 24 bits of the 32-bit suffix slot.
        const hi = this._nextRandomByte() & 0xff
        return ((hi << 24) | (forcedLow24 & 0xffffff)) >>> 0
      }
      if (!offeredPreserved) {
        offeredPreserved = true
        return derivePreservedIpv6HostBits(this._prefixKey, addressWords, 32)
      }
      return this._nextRandomU32()
    }

    const suffix = allocateExclusiveIdSparse({
      used: usedSuffixes,
      space: 0x100000000,
      reject: (n) => formatIpv6Suffix(prefix, n) === expanded,
      nextRandom,
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
    })
    if (suffix === null) {
      this._overflow = true
      return '0:0:0:0:0:0:0:0'
    }
    const candidate = formatIpv6Suffix(prefix, suffix)
    usedSuffixes.add(suffix)
    this._usedIpv6.add(candidate)
    return candidate
  }

  private _mapEmbeddedIpv4Form(
    embedded: NonNullable<ReturnType<typeof classifyEmbeddedIpv4>>,
  ): string | null {
    switch (embedded.kind) {
      case 'ipv4-mapped': {
        const v4 = this.map('ipv4', embedded.ipv4)
        return formatIpv4Mapped(v4)
      }
      case 'nat64-well-known': {
        const v4 = this.map('ipv4', embedded.ipv4)
        return formatNat64WellKnown(v4)
      }
      case '6to4': {
        const v4 = this.map('ipv4', embedded.ipv4)
        return format6to4(v4, embedded.rest)
      }
      case 'isatap': {
        const v4 = this.map('ipv4', embedded.ipv4)
        // Prefix (first /64) goes through ordinary unicast mapping of a probe address.
        const probe = formatIpv6Groups([...embedded.prefix, 0, 0, 0, 1])
        const mappedProbe = this.get('ipv6', probe) ?? this._mapIpv6UnicastCore(probe, { skipEui64: true })
        const pg = ipv6Groups(mappedProbe)
        if (!pg) return null
        return formatIsatap(pg.slice(0, 4), v4)
      }
      case 'teredo': {
        const server = this.map('ipv4', embedded.serverIpv4)
        const client = this.map('ipv4', embedded.clientIpv4)
        const portCanon = `udp/${embedded.udpPort}`
        const portMapped = this.map('port', portCanon)
        const portNum = Number.parseInt(portMapped.split('/')[1] ?? String(embedded.udpPort), 10)
        return formatTeredo(server, client, portNum)
      }
      default:
        return null
    }
  }

  private _mapGenericIpv6Multicast(expanded: string): string {
    const used = this._usedIpv6
    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      const low32 = this._nextRandomU32()
      const candidate = formatIpv6Groups([
        0xff02,
        0,
        0,
        0,
        0,
        0,
        (low32 >>> 16) & 0xffff,
        low32 & 0xffff,
      ])
      if (!used.has(candidate) && candidate !== expanded && !isPreservedIpv6Multicast(candidate)) {
        used.add(candidate)
        return candidate
      }
    }
    this._overflow = true
    return 'ff02:0:0:0:0:0:0:1'
  }

  private _aliasLow24ForSnGroup(originalLow24: number): number {
    const existing = this._snGroupLow24.get(originalLow24)
    if (existing !== undefined) return existing

    // Prefer low24 from an already-mapped unicast parent sharing the original suffix.
    for (const [key, alias] of this._map) {
      if (!key.startsWith('ipv6:')) continue
      const canon = key.slice('ipv6:'.length)
      const canonExp = expandIpv6Canonical(canon) ?? canon
      if (isIpv6Multicast(canonExp)) continue
      if (unicastLow24(canonExp) !== originalLow24) continue
      const aliasExp = expandIpv6Canonical(alias) ?? alias
      const aliasLow = unicastLow24(aliasExp)
      if (aliasLow !== null && aliasLow !== originalLow24) {
        this._snGroupLow24.set(originalLow24, aliasLow)
        return aliasLow
      }
      if (aliasLow !== null) {
        // Parent alias kept same low24 (collision) — still bind group, then force remap below.
        break
      }
    }

    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      const n = this._nextRandomU32() & 0xffffff
      if (n !== originalLow24 && n !== 0) {
        this._snGroupLow24.set(originalLow24, n)
        return n
      }
    }
    const fallback = (originalLow24 ^ 0x00a5a5a5) & 0xffffff
    const aliasLow = fallback === originalLow24 ? (fallback ^ 1) & 0xffffff : fallback
    this._snGroupLow24.set(originalLow24, aliasLow)
    return aliasLow
  }

  private _rememberUnicastLow24(originalExpanded: string, aliasExpanded: string): void {
    const origLow = unicastLow24(originalExpanded)
    const aliasLow = unicastLow24(aliasExpanded)
    if (origLow === null || aliasLow === null) return
    if (!this._snGroupLow24.has(origLow)) this._snGroupLow24.set(origLow, aliasLow)
  }

  private _mapMac(mac: string): string {
    if (mac === 'ff:ff:ff:ff:ff:ff') return mac
    const normalized = mac.toLowerCase()

    // T33 — solicited-node Ethernet (33:33:ff:XX:XX:XX) must track SN IPv6 group alias.
    if (isSolicitedNodeMac(normalized)) {
      const low = solicitedNodeMacLow24(normalized)!
      const aliasLow = this._aliasLow24ForSnGroup(low)
      const candidate = formatSolicitedNodeMac(aliasLow)
      this._usedMac.add(candidate)
      return candidate
    }

    // Other IPv6 multicast MACs (33:33:*) — map low-32; do not preserve original bits (T38 for group policy).
    if (isIpv6MulticastMac(normalized)) {
      return this._mapIpv6MulticastMac(normalized)
    }

    const firstByte = parseInt(normalized.substring(0, 2), 16)
    // IPv4 multicast / other L2 multicast (01:00:5e, …) — preserve (not B9).
    if (firstByte & 0x01) return normalized

    // IANA-reserved VRRP virtual-router MAC (RFC 5798): 00:00:5e:00:01:{VRID}.
    if (/^00:00:5e:00:01:[0-9a-f]{2}$/i.test(normalized)) return normalized

    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      const candidate = this._generateLocalMac()
      if (!this._usedMac.has(candidate) && candidate !== normalized) {
        this._usedMac.add(candidate)
        return candidate
      }
    }
    this._overflow = true
    const fallback = '02:00:00:00:00:00'
    return fallback === normalized ? '02:00:00:00:00:01' : fallback
  }

  private _mapIpv6MulticastMac(mac: string): string {
    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      const low32 = this._nextRandomU32()
      if (this._usedIpv6McastMacLow32.has(low32)) continue
      const candidate = formatIpv6MulticastMac(low32)
      if (candidate === mac.toLowerCase()) continue
      // Avoid colliding with solicited-node ff pattern accidentally preserving structure only — OK.
      this._usedIpv6McastMacLow32.add(low32)
      this._usedMac.add(candidate)
      return candidate
    }
    this._overflow = true
    return '33:33:00:00:00:01'
  }

  private _generateLocalMac(): string {
    // Locally-administered unicast (bit 1 set, bit 0 clear on the first byte = 0x02).
    // All 5 free bytes are drawn straight from the CSPRNG pool — a 40-bit value doesn't
    // fit a 32-bit JS bitwise shift, which previously collapsed the second byte silently
    // (`n >> 32` behaves like `n >> 0` on JS numbers).
    const bytes = [
      0x02,
      this._nextRandomByte(),
      this._nextRandomByte(),
      this._nextRandomByte(),
      this._nextRandomByte(),
      this._nextRandomByte(),
    ];
    return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
  }

  private _mapHostname(hostname: string): string {
    // Preserve label count and per-label length
    const labels = hostname.split('.');
    const mapped = labels.map((label, i) => {
      if (i === labels.length - 1 && (label === 'local' || label === 'invalid' || label === 'example')) {
        return 'invalid'; // safe TLD
      }
      return this._generateLabel(label.length);
    });
    return mapped.join('.');
  }

  private _generateLabel(length: number): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const n = this._hostnameCounter++;
    let result = '';
    let val = n;
    for (let i = 0; i < length; i++) {
      const b = this._nextRandomByte();
      result += chars[(b + val) % chars.length];
      val = (val >> 3) | (b << 5);
    }
    return result || 'a';
  }

  private _mapVlan(vlan: string): string {
    const id = parseInt(vlan, 10);
    // Reserved VLAN IDs stay identity mappings and are reported by the sanitizer.
    if (id === 0 || id === 4095) return vlan;
    if (this._config.vlan === 'preserve') return vlan;
    if (!Number.isInteger(id) || id < VLAN_MIN || id > VLAN_MAX) return vlan;

    const candidate = allocateExclusiveId({
      used: this._usedVlan,
      min: VLAN_MIN,
      max: VLAN_MAX,
      reject: (n) => n === id,
      nextRandom: () => this._nextRandomU16(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
      denseProbe: this._vlanProbe,
    });
    if (candidate === null) {
      // Fail closed — never echo the original VLAN ID.
      this._overflow = true;
      return '0';
    }
    this._usedVlan.add(candidate);
    return `${candidate}`;
  }

  private _mapRadioId(idStr: string): string {
    const id = parseInt(idStr, 10);
    // Reserved: 0 ("no ID") and the all-ones ID (all-call/broadcast talkgroup on DMR).
    if (id === 0 || id === RADIO_ID_SPACE - 1) return idStr;

    const candidate = allocateExclusiveId({
      used: this._usedRadioId,
      min: 0,
      max: RADIO_ID_SPACE - 1,
      reject: (n) => n === id || n === 0 || n === RADIO_ID_SPACE - 1,
      nextRandom: () => this._nextRandomU32(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
      denseProbe: this._radioIdProbe,
    });
    if (candidate === null) {
      this._overflow = true;
      return '0';
    }
    this._usedRadioId.add(candidate);
    return `${candidate}`;
  }

  private _mapSsrc(idStr: string): string {
    const id = Number(idStr) >>> 0;
    const candidate = allocateExclusiveIdSparse({
      used: this._usedSsrc,
      space: 0x100000000,
      reject: (n) => (n >>> 0) === id,
      nextRandom: () => this._nextRandomU32(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
    });
    if (candidate === null) {
      this._overflow = true;
      // Fail closed — never echo the original SSRC.
      return id === 0 ? '1' : '0';
    }
    const mapped = candidate >>> 0;
    this._usedSsrc.add(mapped);
    return `${mapped}`;
  }

  /** T26 — GTP TEID (32-bit); 0 is a wire sentinel preserved by sanitizers, not mapped here. */
  private _mapTeid(idStr: string): string {
    const id = Number(idStr) >>> 0;
    const candidate = allocateExclusiveIdSparse({
      used: this._usedTeid,
      space: 0x100000000,
      reject: (n) => (n >>> 0) === id || (n >>> 0) === 0,
      nextRandom: () => this._nextRandomU32(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
    });
    if (candidate === null) {
      this._overflow = true;
      return id === 0 ? '1' : '0';
    }
    const mapped = candidate >>> 0;
    this._usedTeid.add(mapped);
    return `${mapped}`;
  }

  /** T25 — SS7 point code `pc/<14|24>/<n>`; width-stable bijection; 0 sentinel preserved by sanitizers. */
  private _mapPointCode(canon: string): string {
    const m = /^pc\/(14|24)\/(\d{1,8})$/.exec(canon);
    if (!m) {
      this._overflow = true;
      return 'pc/24/0';
    }
    const width = Number(m[1]) as 14 | 24;
    const id = Number(m[2]);
    const space = width === 14 ? 0x4000 : 0x1000000;
    const used = width === 14 ? this._usedPointCode14 : this._usedPointCode24;
    const candidate = allocateExclusiveIdSparse({
      used,
      space,
      reject: (n) => (n >>> 0) === id || (n >>> 0) === 0,
      nextRandom: () => this._nextRandomU32(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
    });
    if (candidate === null) {
      this._overflow = true;
      return id === 0 ? `pc/${width}/1` : `pc/${width}/0`;
    }
    const mapped = candidate >>> 0;
    used.add(mapped);
    return `pc/${width}/${mapped}`;
  }

  /**
   * SDP o= session-id — length-stable digit string (1–64). Never Number/BigInt as key.
   * Leading zero preserved in the alias iff the original starts with `0`.
   */
  private _mapSdpSessionId(canonical: string): string {
    // Author-scoped keys (`user\\x1fdigits`) still emit length-stable digit aliases.
    return this._mapLengthStableDigits(sdpSessionIdDigits(canonical), this._usedSdpSessionId)
  }

  /**
   * T16 — IMSI length-stable alias. With explicit PLMN scope and `imsiPlmn=preserve-plmn`,
   * MCC+MNC stay; only MSIN is remapped. Otherwise the whole digit string is remapped.
   */
  private _mapImsi(canonical: string): string {
    const sep = canonical.indexOf(IMSI_PLMN_SCOPE_SEP)
    if (sep > 0 && this._config.imsiPlmn === 'preserve-plmn') {
      const plmn = canonical.slice(0, sep)
      const msin = canonical.slice(sep + 1)
      const mappedMsin = this._mapLengthStableDigits(msin, this._usedImsi)
      return `${plmn}${mappedMsin}`
    }
    return this._mapLengthStableDigits(imsiWireDigits(canonical), this._usedImsi)
  }

  /**
   * T16 — IMEI/IMEISV length-stable alias. 15-digit IMEI aliases carry a valid Luhn
   * check digit; 14-digit bodies and 16-digit IMEISV stay pure digit remaps (no Luhn).
   */
  private _mapImei(canonical: string): string {
    const len = canonical.length
    const used = this._usedImei
    const leadingZero = canonical.startsWith('0')
    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      const bodyLen = len === 15 ? 14 : len
      const body = this._generateSdpSessionIdDigits(bodyLen, leadingZero)
      const candidate = finalizeImeiAliasDigits(body, len)
      if (candidate && candidate !== canonical && !used.has(candidate)) {
        used.add(candidate)
        return candidate
      }
    }
    this._overflow = true
    // Deterministic Luhn-valid fallback for 15-digit; length-stable for others.
    if (len === 15) {
      for (let n = 0; n < 1000; n++) {
        const body = String(n).padStart(14, '0')
        const candidate = finalizeImeiAliasDigits(body, 15)
        if (candidate && candidate !== canonical && !used.has(candidate)) {
          used.add(candidate)
          return candidate
        }
      }
    }
    return this._mapLengthStableDigits(canonical, used)
  }

  /**
   * Length-stable digit string (SDP session-id / IMSI / IMEI overflow). Never Number as key.
   * Leading zero preserved in the alias iff the original starts with `0`.
   */
  private _mapLengthStableDigits(canonical: string, used: Set<string>): string {
    const len = canonical.length;
    const leadingZero = canonical.startsWith('0');
    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      const candidate = this._generateSdpSessionIdDigits(len, leadingZero);
      if (candidate !== canonical && !used.has(candidate)) {
        used.add(candidate);
        return candidate;
      }
    }
    // Fail-closed: prefer a deterministic non-original digit string; L=1 +"0" has no
    // leading-zero alternative, so violate the leading-zero rule rather than echo.
    this._overflow = true;
    if (len === 1 && leadingZero) {
      used.add('1');
      return '1';
    }
    const fallback = leadingZero
      ? `0${'9'.repeat(len - 1)}`
      : '9'.repeat(len);
    if (fallback !== canonical && !used.has(fallback)) {
      used.add(fallback);
      return fallback;
    }
    // Scan only small widths — 10^L grows past Number for L≥16.
    if (len <= 6) {
      const start = leadingZero ? 0 : 10 ** (len - 1);
      const end = 10 ** len;
      for (let n = start; n < end; n++) {
        const candidate = String(n).padStart(len, '0');
        if (leadingZero !== candidate.startsWith('0')) continue;
        if (candidate === canonical || used.has(candidate)) continue;
        used.add(candidate);
        return candidate;
      }
    }
    if (fallback !== canonical) {
      used.add(fallback);
      return fallback;
    }
    const lastResort = leadingZero
      ? (len === 1 ? '1' : `0${'8'.repeat(len - 1)}`)
      : '8'.repeat(len);
    used.add(lastResort);
    return lastResort;
  }

  private _generateSdpSessionIdDigits(len: number, leadingZero: boolean): string {
    const chars: string[] = new Array(len);
    if (leadingZero) {
      chars[0] = '0';
      for (let i = 1; i < len; i++) chars[i] = String(this._nextRandomByte() % 10);
    } else {
      chars[0] = String(1 + (this._nextRandomByte() % 9));
      for (let i = 1; i < len; i++) chars[i] = String(this._nextRandomByte() % 10);
    }
    return chars.join('');
  }

  /** T20 — length-stable lowercase hex (SNMP engine ID). */
  private _mapHexString(canonical: string, used: Set<string>): string {
    const len = canonical.length
    const hex = '0123456789abcdef'
    for (let attempt = 0; attempt < RANDOM_RETRY_ATTEMPTS; attempt++) {
      let candidate = ''
      for (let i = 0; i < len; i++) {
        candidate += hex[this._nextRandomByte() % 16]!
      }
      if (candidate !== canonical && !used.has(candidate)) {
        used.add(candidate)
        return candidate
      }
    }
    this._overflow = true
    const fallback = 'f'.repeat(len)
    if (fallback !== canonical && !used.has(fallback)) {
      used.add(fallback)
      return fallback
    }
    const alt = 'e'.repeat(len)
    used.add(alt !== canonical ? alt : fallback)
    return alt !== canonical ? alt : fallback
  }

  /**
   * T06 — attach a discovery flow hint before resolve/map so content-recognized
   * signaling ports (e.g. SIP on 5070) share the same preserve decision in discovery and plan.
   */
  notePortFlowHint(canonical: string, flow: PortFlowHint): void {
    const prev = this._portFlowHints.get(canonical)
    this._portFlowHints.set(canonical, mergePortFlowHints(prev, flow) ?? flow)
  }

  /**
   * T06 revision — register an SDP-negotiated RTP/RTCP mate (including non-+1 a=rtcp and mux).
   */
  noteMediaPortPair(rtpCanonical: string, rtcpCanonical: string): void {
    this._mediaPortMates.set(rtpCanonical, rtcpCanonical)
    this._mediaPortMates.set(rtcpCanonical, rtpCanonical)
    if (rtpCanonical !== rtcpCanonical) {
      const rtpFlow = this._portFlowHints.get(rtpCanonical)
      const rtcpFlow = this._portFlowHints.get(rtcpCanonical)
      this._portFlowHints.set(rtpCanonical, mergePortFlowHints(rtpFlow, 'rtp') ?? 'rtp')
      this._portFlowHints.set(rtcpCanonical, mergePortFlowHints(rtcpFlow, 'rtcp') ?? 'rtcp')
    } else {
      const prev = this._portFlowHints.get(rtpCanonical)
      this._portFlowHints.set(rtpCanonical, mergePortFlowHints(prev, 'rtp') ?? 'rtp')
    }
  }

  private _mapPort(portStr: string): string {
    // Format: "tcp/80" or "udp/53"
    const slash = portStr.indexOf('/');
    const proto = portStr.substring(0, slash);
    const port = parseInt(portStr.substring(slash + 1), 10);

    let used = this._usedPorts.get(proto);
    if (!used) {
      used = new Set<number>();
      this._usedPorts.set(proto, used);
    }

    const flow = this._portFlowHints.get(portStr)
    const preserveContentSignaling = this._config.contentSignalingPorts === 'preserve'
    // CF-14 / T06: preserve by semantic catalog or content signaling hint (policy-gated).
    if (
      isPreservedServicePort(port)
      || shouldPreservePort(port, { flow, preserveContentSignaling })
    ) {
      used.add(port);
      return portStr;
    }

    if (this._config.ephemeralPorts === 'preserve') {
      if (used.has(port)) {
        this._overflow = true;
        return portStr;
      }
      used.add(port);
      return portStr;
    }

    const rangeMin = isUserRegisteredPort(port) ? USER_REGISTERED_PORT_MIN : DYNAMIC_PORT_MIN
    const rangeMax = isUserRegisteredPort(port) ? USER_REGISTERED_PORT_MAX : DYNAMIC_PORT_MAX
    const pairNamespace = isUserRegisteredPort(port) ? 'u' as const : 'd' as const

    // Explicit SDP mate (may be non-+1 or mux).
    const mateCanon = this._mediaPortMates.get(portStr)
    if (mateCanon !== undefined) {
      const linked = this._allocateLinkedMediaPort(proto, portStr, port, mateCanon, used, rangeMin, rangeMax)
      if (linked === null) {
        this._overflow = true
        const fallback = port === DYNAMIC_PORT_MIN ? DYNAMIC_PORT_MIN + 1 : DYNAMIC_PORT_MIN
        return `${proto}/${fallback}`
      }
      return `${proto}/${linked}`
    }

    // Classic RTP/RTCP +1 only when content/SDP marked the port as media — do not force
    // unrelated UDP neighbors into a pair (T06 revision).
    const isMedia = flow === 'rtp' || flow === 'rtcp'
    const mapped = isMedia
      ? this._allocatePairedPort(proto, port, used, rangeMin, rangeMax, pairNamespace)
      : this._allocateSoloPort(proto, port, used, rangeMin, rangeMax, pairNamespace)

    if (mapped === null) {
      this._overflow = true;
      const fallback = port === DYNAMIC_PORT_MIN ? DYNAMIC_PORT_MIN + 1 : DYNAMIC_PORT_MIN;
      return `${proto}/${fallback}`;
    }

    return `${proto}/${mapped}`;
  }

  /**
   * Allocate aliases for an explicit RTP/RTCP mate pair. Mux (same canonical) keeps one port.
   * Non-+1 mates get independent solo aliases that stay linked for the session.
   */
  private _allocateLinkedMediaPort(
    proto: string,
    portStr: string,
    port: number,
    mateCanon: string,
    used: Set<number>,
    rangeMin: number,
    rangeMax: number,
  ): number | null {
    const existing = this._mediaMateAliases.get(portStr)
    if (existing !== undefined) return existing

    if (mateCanon === portStr) {
      // rtcp-mux — single media port.
      const solo = this._allocateSoloPort(proto, port, used, rangeMin, rangeMax, isUserRegisteredPort(port) ? 'u' : 'd')
      if (solo === null) return null
      this._mediaMateAliases.set(portStr, solo)
      return solo
    }

    const mateSlash = mateCanon.indexOf('/')
    const matePort = Number.parseInt(mateCanon.slice(mateSlash + 1), 10)
    if (!Number.isFinite(matePort)) return null

    // Classic +1 negotiated pair → reuse pair permute so parity/RTCP=+1 hold.
    if (Math.abs(port - matePort) === 1) {
      const paired = this._allocatePairedPort(
        proto,
        port,
        used,
        rangeMin,
        rangeMax,
        isUserRegisteredPort(port) ? 'u' : 'd',
      )
      if (paired === null) return null
      const mateAlias = (port & 1) === 0 ? paired + 1 : paired - 1
      this._mediaMateAliases.set(portStr, paired)
      this._mediaMateAliases.set(mateCanon, mateAlias)
      return paired
    }

    // Explicit non-+1 a=rtcp — two solo aliases, session-linked.
    const aliasSelf = this._allocateSoloPort(
      proto,
      port,
      used,
      rangeMin,
      rangeMax,
      isUserRegisteredPort(port) ? 'u' : 'd',
    )
    if (aliasSelf === null) return null
    const aliasMate = this._allocateSoloPort(
      proto,
      matePort,
      used,
      rangeMin,
      rangeMax,
      isUserRegisteredPort(matePort) ? 'u' : 'd',
    )
    if (aliasMate === null) return null
    this._mediaMateAliases.set(portStr, aliasSelf)
    this._mediaMateAliases.set(mateCanon, aliasMate)
    return aliasSelf
  }

  /** Independent ephemeral permute — does not reserve the odd/even neighbor. */
  private _allocateSoloPort(
    proto: string,
    port: number,
    used: Set<number>,
    rangeMin: number,
    rangeMax: number,
    namespace: 'd' | 'u',
  ): number | null {
    const probeKey = `${proto}|solo|${namespace}`
    let denseProbe = this._portPairProbes.get(probeKey)
    if (!denseProbe) {
      denseProbe = { offset: 0 }
      this._portPairProbes.set(probeKey, denseProbe)
    }
    const alias = allocateExclusiveId({
      used,
      min: rangeMin,
      max: rangeMax,
      reject: (p) => isPreservedServicePort(p) || p === port,
      nextRandom: () => this._nextRandomU16(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
      denseProbe,
    })
    if (alias === null) return null
    used.add(alias)
    return alias
  }

  /**
   * Allocate a pair-preserving alias. Same original pair index always gets the same π;
   * both even/odd ports of the alias pair are reserved in `used`.
   */
  private _allocatePairedPort(
    proto: string,
    port: number,
    used: Set<number>,
    rangeMin: number,
    rangeMax: number,
    pairNamespace: 'd' | 'u',
  ): number | null {
    const pairCount = Math.floor((rangeMax - rangeMin + 1) / 2)
    if (pairCount <= 0) return null

    const parity = port & 1
    let pairKey: string
    let origPairIndex: number | null = null
    if (pairNamespace === 'd' && isDynamicPort(port)) {
      origPairIndex = Math.floor((port - rangeMin) / 2)
      pairKey = `${proto}|d:${origPairIndex}`
    } else if (pairNamespace === 'u' && isUserRegisteredPort(port)) {
      origPairIndex = Math.floor((port - rangeMin) / 2)
      pairKey = `${proto}|u:${origPairIndex}`
    } else {
      // System / cross-range: one dedicated pair slot per original port (mate reserved).
      pairKey = `${proto}|s:${port}`
    }

    const existing = this._portPairAlias.get(pairKey)
    if (existing !== undefined) {
      return rangeMin + 2 * existing + parity
    }

    let usedPairs = this._usedPortPairs.get(proto)
    if (!usedPairs) {
      usedPairs = new Set<number>()
      this._usedPortPairs.set(proto, usedPairs)
    }
    const probeKey = `${proto}|${pairNamespace}`
    let denseProbe = this._portPairProbes.get(probeKey)
    if (!denseProbe) {
      denseProbe = { offset: 0 }
      this._portPairProbes.set(probeKey, denseProbe)
    }

    const aliasPair = allocateExclusiveId({
      used: usedPairs,
      min: 0,
      max: pairCount - 1,
      reject: (pi) => {
        const even = rangeMin + 2 * pi
        const odd = even + 1
        if (even > rangeMax || odd > rangeMax) return true
        if (isPreservedServicePort(even) || isPreservedServicePort(odd)) return true
        if (used.has(even) || used.has(odd)) return true
        // No fixed point for same-range pairs.
        if (origPairIndex !== null && pi === origPairIndex) return true
        return false
      },
      nextRandom: () => this._nextRandomU16(),
      randomAttempts: RANDOM_RETRY_ATTEMPTS,
      denseProbe,
    })
    if (aliasPair === null) return null

    const even = rangeMin + 2 * aliasPair
    const odd = even + 1
    used.add(even)
    used.add(odd)
    usedPairs.add(aliasPair)
    this._portPairAlias.set(pairKey, aliasPair)
    return even + parity
  }

  private _nextRandomByte(): number {
    if (this._randomOffset >= this._random.length) {
      this._randomOffset = 0
      if (this._seeded) {
        // Deterministic wrap — same seed yields the same infinite stream.
      } else {
        this._random.set(freshEntropy(this._random.length))
      }
    }
    return this._random[this._randomOffset++]!;
  }

  private _nextRandomU16(): number {
    return (this._nextRandomByte() << 8) | this._nextRandomByte();
  }

  private _nextRandomU32(): number {
    return (
      (this._nextRandomByte() << 24) |
      (this._nextRandomByte() << 16) |
      (this._nextRandomByte() << 8) |
      this._nextRandomByte()
    ) >>> 0;
  }
}

function isPrivateIpv4(parts: number[]): boolean {
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true; // link-local
  return false;
}

function formatIpv4Block(base: readonly [number, number], slot: number): string {
  return `${base[0]}.${base[1]}.${(slot >> 8) & 0xff}.${slot & 0xff}`;
}

function ipv4Prefix24Key(parts: readonly number[]): string {
  return `${parts[0]}.${parts[1]}.${parts[2]}`;
}

/** Third octet in the fixed target /16 for all hosts in the same original /24. */
function deriveTopology24ThirdOctet(key: PrefixPreservingKey, network24: number): number {
  return (derivePreservedIpv4HostBits(key, network24 >>> 0, 16) >>> 8) & 0xff;
}

function countUsedIpv4ThirdSlots(used: ReadonlySet<number>, third: number): number {
  const base = third * 256;
  let n = 0;
  for (let i = 0; i < 256; i++) {
    if (used.has(base + i)) n++;
  }
  return n;
}

/** Pick a target third octet with free slots; skip thirds owned by another /24 or already full. */
function assignTopology24ThirdOctet(
  prefixToThird: Map<string, number>,
  thirdOwner: Map<number, string>,
  prefix24Key: string,
  preferredThird: number,
  usedSlots: ReadonlySet<number>,
): number {
  let third = preferredThird & 0xff;
  const start = third;
  for (;;) {
    const owner = thirdOwner.get(third);
    const slotsUsed = countUsedIpv4ThirdSlots(usedSlots, third);
    const canUse =
      slotsUsed < 256 && (owner === undefined || owner === prefix24Key);
    if (canUse) {
      prefixToThird.set(prefix24Key, third);
      thirdOwner.set(third, prefix24Key);
      return third;
    }
    third = (third + 1) & 0xff;
    if (third === start) {
      prefixToThird.set(prefix24Key, third);
      thirdOwner.set(third, prefix24Key);
      return third;
    }
  }
}

function formatIpv6Suffix(prefix: string, n: number): string {
  return `${prefix}:0:0:${((n >>> 16) & 0xffff).toString(16)}:${(n & 0xffff).toString(16)}`;
}

/** Parses the canonical (always 8-group, no `::` compression) IPv6 text form into 4 big-endian 32-bit words. */
function ipv6ToWords(ip: string): readonly [number, number, number, number] {
  const groups = ip.split(':').map((g) => Number.parseInt(g, 16) & 0xffff);
  const word = (hi: number, lo: number) => (((groups[hi] ?? 0) << 16) | (groups[lo] ?? 0)) >>> 0;
  return [word(0, 1), word(2, 3), word(4, 5), word(6, 7)];
}
