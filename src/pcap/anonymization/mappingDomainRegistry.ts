/**
 * T48 — declared finite alias domains per mapping category.
 * Missing strategy must not fall through to a silent `anon-N` token.
 */

import { ENTITY_CATEGORIES, type EntityCategory } from './entityRegistry.ts'
import {
  DYNAMIC_PORT_MAX,
  DYNAMIC_PORT_MIN,
  DYNAMIC_PORT_PAIR_COUNT,
  USER_REGISTERED_PORT_MAX,
  USER_REGISTERED_PORT_MIN,
} from './portPolicy.ts'

export type MappingDomainKind =
  | 'ipv4-block'
  | 'ipv6-suffix'
  | 'mac-local'
  | 'vlan'
  | 'port-pair'
  | 'radio-id'
  | 'ssrc'
  | 'sdp-session-id'
  | 'opaque-id'
  | 'imsi'
  | 'imei'
  | 'snmp-engine-id'
  | 'teid'
  | 'point-code'
  | 'ssid'
  | 'sip-wire'
  | 'hostname-label'
  | 'passthrough'

export interface MappingDomainSpec {
  readonly category: EntityCategory
  readonly kind: MappingDomainKind
  /** Finite slot count when applicable; null = sparse / unbounded practical space. */
  readonly domainSize: number | null
  readonly reservedNote: string
  readonly exhaustion: 'overflow-sentinel' | 'pair-fallback' | 'sparse-retry' | 'n/a'
  readonly uniqueness: 'session-bijection' | 'length-stable' | 'passthrough'
}

/** IPv4 private/public target /16 blocks (65_536 slots each). */
export const IPV4_BLOCK_DOMAIN_SIZE = 65_536

/** Dynamic UDP/TCP pair count in 49152–65535. */
export const DYNAMIC_PORT_PAIR_DOMAIN_SIZE = DYNAMIC_PORT_PAIR_COUNT

/** User-registered pair count in 1024–49151. */
export const USER_REGISTERED_PORT_PAIR_DOMAIN_SIZE = Math.floor(
  (USER_REGISTERED_PORT_MAX - USER_REGISTERED_PORT_MIN + 1) / 2,
)

export const MAPPING_DOMAIN_SPECS: readonly MappingDomainSpec[] = [
  {
    category: 'ipv4',
    kind: 'ipv4-block',
    domainSize: IPV4_BLOCK_DOMAIN_SIZE,
    reservedNote: '0.0.0.0 / 255.255.255.255 / multicast preserved; two class blocks',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'session-bijection',
  },
  {
    category: 'ipv6',
    kind: 'ipv6-suffix',
    domainSize: 0x100000000,
    reservedNote: 'well-known multicast preserved; SN/embedded forms special-cased',
    exhaustion: 'sparse-retry',
    uniqueness: 'session-bijection',
  },
  {
    category: 'mac',
    kind: 'mac-local',
    domainSize: 2 ** 40,
    reservedNote: 'broadcast/multicast/VRRP preserved; locally-administered unicast',
    exhaustion: 'sparse-retry',
    uniqueness: 'session-bijection',
  },
  {
    category: 'vlan',
    kind: 'vlan',
    domainSize: 4094,
    reservedNote: '0 and 4095 reserved',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'session-bijection',
  },
  {
    category: 'port',
    kind: 'port-pair',
    domainSize: DYNAMIC_PORT_PAIR_DOMAIN_SIZE,
    reservedNote: `catalog preserved; dynamic pairs ${DYNAMIC_PORT_MIN}–${DYNAMIC_PORT_MAX}; user-reg pairs separate`,
    exhaustion: 'pair-fallback',
    uniqueness: 'session-bijection',
  },
  {
    category: 'radioId',
    kind: 'radio-id',
    domainSize: 0x1000000,
    reservedNote: '0 and 0xffffff reserved',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'session-bijection',
  },
  {
    category: 'ssrc',
    kind: 'ssrc',
    domainSize: 0x100000000,
    reservedNote: '32-bit sparse',
    exhaustion: 'sparse-retry',
    uniqueness: 'session-bijection',
  },
  {
    category: 'sdp-session-id',
    kind: 'sdp-session-id',
    domainSize: null,
    reservedNote: 'digit string 1–64; L=1 "0" has no leading-zero alternative',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'length-stable',
  },
  {
    category: 'opaque-id',
    kind: 'opaque-id',
    domainSize: null,
    reservedNote: 'T14 length-stable opaque token; richer typed categories supersede later',
    exhaustion: 'n/a',
    uniqueness: 'length-stable',
  },
  {
    category: 'imsi',
    kind: 'imsi',
    domainSize: null,
    reservedNote: 'T16 digit string 5–15; no PLMN split without explicit context',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'length-stable',
  },
  {
    category: 'imei',
    kind: 'imei',
    domainSize: null,
    reservedNote: 'T16 IMEI 14–15 / IMEISV 16; TAC not unconditionally preserved',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'length-stable',
  },
  {
    category: 'snmp-engine-id',
    kind: 'snmp-engine-id',
    domainSize: null,
    reservedNote: 'T20 hex of 5–32 wire octets; length-stable',
    exhaustion: 'overflow-sentinel',
    uniqueness: 'length-stable',
  },
  {
    category: 'teid',
    kind: 'teid',
    domainSize: 0x100000000,
    reservedNote: 'T26 GTP 32-bit TEID; 0 sentinel preserved by sanitizer',
    exhaustion: 'sparse-retry',
    uniqueness: 'session-bijection',
  },
  {
    category: 'point-code',
    kind: 'point-code',
    domainSize: 0x1000000,
    reservedNote: 'T25 SS7 PC 14/24-bit; canonical pc/<w>/<n>; 0 sentinel preserved',
    exhaustion: 'sparse-retry',
    uniqueness: 'session-bijection',
  },
  {
    category: 'ssid',
    kind: 'ssid',
    domainSize: null,
    reservedNote: 'T40 binary SSID 1–32 octets; canonical ssid/<hex>; shared with RADIUS Called-Station suffix',
    exhaustion: 'n/a',
    uniqueness: 'length-stable',
  },
  {
    category: 'hostname',
    kind: 'hostname-label',
    domainSize: null,
    reservedNote: 'per-label length-stable',
    exhaustion: 'n/a',
    uniqueness: 'length-stable',
  },
  {
    category: 'timestamp',
    kind: 'passthrough',
    domainSize: null,
    reservedNote: 'handled by timestamp mapping policy',
    exhaustion: 'n/a',
    uniqueness: 'passthrough',
  },
  {
    category: 'sip-call-id',
    kind: 'sip-wire',
    domainSize: null,
    reservedNote: 'textAliasEngine wire mask',
    exhaustion: 'n/a',
    uniqueness: 'length-stable',
  },
  {
    category: 'sip-token',
    kind: 'sip-wire',
    domainSize: null,
    reservedNote: 'textAliasEngine wire mask',
    exhaustion: 'n/a',
    uniqueness: 'length-stable',
  },
  {
    category: 'sip-user',
    kind: 'sip-wire',
    domainSize: null,
    reservedNote: 'textAliasEngine wire mask',
    exhaustion: 'n/a',
    uniqueness: 'length-stable',
  },
] as const

const BY_CATEGORY = new Map<EntityCategory, MappingDomainSpec>(
  MAPPING_DOMAIN_SPECS.map((s) => [s.category, s]),
)

export function mappingDomainFor(category: EntityCategory): MappingDomainSpec {
  const spec = BY_CATEGORY.get(category)
  if (!spec) {
    throw new Error(`mapping-domain-missing:${category}`)
  }
  return spec
}

/** Assert every EntityCategory has a declared domain (registration completeness). */
export function assertMappingDomainsComplete(
  categories: readonly EntityCategory[] = ENTITY_CATEGORIES,
): void {
  for (const c of categories) {
    mappingDomainFor(c)
  }
  if (categories.length !== MAPPING_DOMAIN_SPECS.length) {
    throw new Error(
      `mapping-domain-count-mismatch:specs=${MAPPING_DOMAIN_SPECS.length}:categories=${categories.length}`,
    )
  }
}
