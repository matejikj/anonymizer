/**
 * Typed entity registry for PCAP anonymization.
 * Tracks unique entities, assigns stable session mappings via CSPRNG.
 * Mapping is RAM-only — never persisted to profile or storage.
 */

export type EntityCategory =
  | 'ipv4'
  | 'ipv6'
  | 'mac'
  | 'hostname'
  | 'vlan'
  | 'port'
  | 'timestamp'
  | 'radioId'
  | 'ssrc'
  | 'sdp-session-id'
  | 'opaque-id'
  | 'sip-call-id'
  | 'sip-token'
  | 'sip-user'
  /** T16 — mobile subscriber identity (digit string). */
  | 'imsi'
  /** T16 — equipment identity (digit string; IMEISV allowed). */
  | 'imei'
  /** T20 — SNMPv3 authoritative / context engine ID (hex of wire octets). */
  | 'snmp-engine-id'
  /** T26 — GTP TEID / F-TEID tunnel endpoint id (32-bit). */
  | 'teid'
  /** T25 — SS7/SIGTRAN point code (14- or 24-bit; canonical `pc/<w>/<n>`). */
  | 'point-code'
  /** T40 — 802.11 / RADIUS Called-Station SSID octets (canonical `ssid/<hex>`). */
  | 'ssid'
  /** T69 — free-text token outside vocabulary (length-stable pseudonym). */
  | 'free-token'
  /** T74 — sender-bound binary identifier (length-stable wire octets). */
  | 'opaque-bin-id'

/** Complete PCAP entity category list — keep in sync with {@link EntityCategory}. */
export const ENTITY_CATEGORIES: readonly EntityCategory[] = [
  'ipv4',
  'ipv6',
  'mac',
  'hostname',
  'vlan',
  'port',
  'timestamp',
  'radioId',
  'ssrc',
  'sdp-session-id',
  'opaque-id',
  'sip-call-id',
  'sip-token',
  'sip-user',
  'imsi',
  'imei',
  'snmp-engine-id',
  'teid',
  'point-code',
  'ssid',
  'free-token',
  'opaque-bin-id',
] as const

export interface EntityRecord {
  readonly category: EntityCategory;
  readonly canonical: string;
  readonly firstPacket: number;
  count: number;
}

import { MAX_ENTITY_CARDINALITY } from '../../domain/capabilityContract.ts';

export { MAX_ENTITY_CARDINALITY };

export class EntityRegistry {
  private readonly _map = new Map<string, EntityRecord>()
  private readonly _occurrences = new Map<string, number[]>()
  private readonly _lastOccurrence = new Map<string, number>()
  private _overflow = false

  get size(): number { return this._map.size; }
  get overflow(): boolean { return this._overflow; }

  add(category: EntityCategory, canonical: string, packetNumber: number, packetIndex?: number): EntityRecord | null {
    const key = `${category}:${canonical}`;
    const existing = this._map.get(key);
    if (existing) {
      existing.count++;
      if (packetIndex !== undefined) this.trackOccurrence(key, packetIndex);
      return existing;
    }
    if (this._map.size >= MAX_ENTITY_CARDINALITY) {
      this._overflow = true;
      return null;
    }
    const record: EntityRecord = { category, canonical, firstPacket: packetNumber, count: 1 };
    this._map.set(key, record);
    if (packetIndex !== undefined) this.trackOccurrence(key, packetIndex);
    return record;
  }

  private trackOccurrence(key: string, packetIndex: number): void {
    // Callers always visit packets in non-decreasing packetIndex order, so a
    // duplicate call for the same key can only repeat the current index —
    // comparing against the last-added index is equivalent to the previous
    // list.includes() scan but O(1) instead of O(occurrences seen so far).
    if (this._lastOccurrence.get(key) === packetIndex) return;
    this._lastOccurrence.set(key, packetIndex);
    let list = this._occurrences.get(key);
    if (!list) {
      list = [];
      this._occurrences.set(key, list);
    }
    list.push(packetIndex);
  }

  occurrenceMap(): ReadonlyMap<string, readonly number[]> {
    return this._occurrences;
  }

  occurrencesFor(key: string): readonly number[] {
    return this._occurrences.get(key) ?? [];
  }

  get(category: EntityCategory, canonical: string): EntityRecord | undefined {
    return this._map.get(`${category}:${canonical}`);
  }

  entries(): IterableIterator<[string, EntityRecord]> {
    return this._map.entries();
  }

  clear(): void {
    this._map.clear();
    this._occurrences.clear();
    this._lastOccurrence.clear();
    this._overflow = false;
  }
}
