/**
 * Read-only mapping view backed by immutable MappingSnapshot (Stage 8 plan build).
 * CF-02: constraint-aware lookup — missing alias is an error, never a canonical fallback.
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { WireRepresentationConstraint } from '../../mapping/types'
import type { MappingLike } from '../anonymization/mapping'
import { MappingLookupError } from '../anonymization/mappingErrors'
import type { MappingSnapshot } from '../../mapping/types'
import { mappingKey } from '../../mapping/types'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { defaultWireConstraint } from '../../mapping/pcapCanonical'
import type { EntityCategory } from '../anonymization/entityRegistry'
import { aliasForSnapshotConstraint, aliasForSnapshotConstraintStrict } from '../../mapping/mappingRegistry'
import { formatTextAliasFromWire } from '../anonymization/wireTextFormat'
import { indexSnapshotEntriesByMappingKey, type MergedSnapshotEntry } from './snapshotEntryIndex'

export class SnapshotMappingAdapter implements MappingLike {
  private readonly entries: ReadonlyMap<string, MergedSnapshotEntry>
  readonly overflow: boolean

  constructor(snapshot: MappingSnapshot) {
    this.entries = indexSnapshotEntriesByMappingKey(snapshot)
    this.overflow = snapshot.overflow
  }

  map(category: IdentityCategory, rawCanonical: string): string {
    const canonical = requireCanonical(category, rawCanonical)
    const constraint = defaultWireConstraint(category as EntityCategory, canonical)
    if (constraint === null) {
      throw new MappingLookupError('missing-wire-constraint', { category })
    }
    const spelling = rawCanonical !== canonical ? rawCanonical : undefined
    return this.aliasFor(category, canonical, constraint, spelling)
  }

  get(category: IdentityCategory, rawCanonical: string): string | undefined {
    const canonical = canonicalizeIdentity(category, rawCanonical)
    if (canonical === null) return undefined
    const entry = this.entries.get(mappingKey(category, canonical))
    return entry?.alias
  }

  aliasFor(
    category: IdentityCategory,
    rawCanonical: string,
    constraint: WireRepresentationConstraint,
    originalSpelling?: string,
  ): string {
    const canonical = requireCanonical(category, rawCanonical)
    const entry = this.entries.get(mappingKey(category, canonical))
    if (!entry) {
      if (this.overflow) return overflowPlaceholder(category, canonical)
      throw new MappingLookupError('missing-snapshot-alias', { category })
    }

    let alias = aliasForSnapshotConstraintStrict(entry, constraint)
    if (alias === undefined) {
      alias = aliasForSnapshotConstraint(entry, constraint)
      if (alias === undefined) {
        throw new MappingLookupError('missing-snapshot-alias', { category })
      }
      // Identity aliases are only accepted when the snapshot entry explicitly stores them
      // (strict path). Fallback derivation must not silently return the canonical value —
      // except text-ascii, which can re-encode a wire/identity alias to the needed length.
      if (alias === entry.canonical && constraint.kind !== 'text-ascii') {
        throw new MappingLookupError('missing-snapshot-alias', { category })
      }
    }

    if (constraint.kind === 'text-ascii') {
      const spelling = originalSpelling ?? rawCanonical
      if (alias === entry.canonical || alias.length !== constraint.byteLength) {
        alias = formatTextAliasFromWire(category, entry.alias, constraint.byteLength, spelling)
      }
    }

    return alias
  }
}

function requireCanonical(category: IdentityCategory, raw: string): string {
  const canonical = canonicalizeIdentity(category, raw)
  if (canonical === null) {
    throw new MappingLookupError('canonicalize-failed', { category })
  }
  return canonical
}

function overflowPlaceholder(category: IdentityCategory, canonical: string): string {
  switch (category) {
    case 'ipv4': return '0.0.0.0'
    case 'ipv6': return '::'
    case 'mac': return '02:00:00:00:00:00'
    case 'hostname': return 'x'.repeat(Math.max(1, canonical.length))
    case 'vlan': return '0'
    case 'port': return canonical
    case 'radioId': return '0'
    case 'ssrc': return '0'
    case 'teid': return '0'
    case 'point-code':
      return canonical.startsWith('pc/14/')
        ? (canonical === 'pc/14/0' ? 'pc/14/1' : 'pc/14/0')
        : (canonical === 'pc/24/0' ? 'pc/24/1' : 'pc/24/0')
    case 'sdp-session-id':
    case 'imsi':
    case 'imei':
      return canonical.startsWith('0')
        ? (canonical.length === 1 ? '1' : `0${'9'.repeat(canonical.length - 1)}`)
        : '9'.repeat(Math.max(1, canonical.length))
    case 'opaque-id':
    case 'ssid':
      return 'x'.repeat(Math.max(1, canonical.length))
    case 'snmp-engine-id':
      return 'f'.repeat(Math.max(1, canonical.length))
    case 'sip-call-id':
    case 'sip-token':
    case 'sip-user':
      return 'x'.repeat(Math.max(1, canonical.length))
    case 'sip-phone':
      return canonical.replace(/\d/g, '0') || '0'
    default: return 'anon-overflow'
  }
}
