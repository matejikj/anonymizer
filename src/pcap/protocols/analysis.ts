/**
 * Packet analysis engine — decodes all packets, builds histogram,
 * coverage, entity index and paged packet summaries.
 */

import { EntityRegistry } from '../anonymization/entityRegistry';
import type { PacketEnvelope } from '../domain/types';
import type { DecodedNode, EntityCollector, ProtocolModule } from './types';
import type { StructuralSpanInput } from '../coverage/buildUnifiedCoverage';
import { structuralSpansFromNode } from '../coverage/buildUnifiedCoverage';
import { decodeLink } from './registry';
import { initProtocols } from './init';
import { catalogLegacyModules } from '../kernel/catalog';

/** Derived from the shared kernel manifest — do not maintain a parallel module list. */
let cachedModulesById: Map<string, ProtocolModule> | null = null
function modulesById(): Map<string, ProtocolModule> {
  if (!cachedModulesById) {
    cachedModulesById = new Map(catalogLegacyModules().map((m) => [m.id, m]))
  }
  return cachedModulesById
}

export interface ProtocolHistogram {
  readonly counts: ReadonlyMap<string, number>;
}

export interface CoverageEntry {
  readonly protocolId: string;
  readonly packetCount: number;
  readonly unsupportedCount: number;
  readonly issues: readonly string[];
}

export interface EntityEntry {
  readonly key: string;
  readonly category: string;
  readonly value: string;
  readonly firstPacket: number;
  readonly count: number;
}

export interface PacketSummary {
  readonly packetNumber: number;
  readonly protocols: readonly string[];
  readonly issues: readonly string[];
  readonly hasUnsupported: boolean;
}

export interface AnalysisResult {
  readonly histogram: ProtocolHistogram;
  readonly coverage: readonly CoverageEntry[];
  readonly entities: readonly EntityEntry[];
  readonly summaries: readonly PacketSummary[];
  readonly totalPackets: number;
  readonly decodedPackets: number;
  readonly unsupportedLinkTypes: ReadonlySet<number>;
  readonly entityOverflow: boolean;
  /** Per-packet structural byte spans (Stage 10). */
  readonly structuralSpans: readonly (readonly StructuralSpanInput[])[];
  /** Entity key → packet indices (Stage 10). */
  readonly entityOccurrenceLists: ReadonlyMap<string, readonly number[]>;
}

export function analyzePackets(packets: readonly PacketEnvelope[]): AnalysisResult {
  initProtocols();

  const histogram = new Map<string, number>();
  const registry = new EntityRegistry();
  const coverageMap = new Map<string, { packetCount: number; unsupportedCount: number; issues: Set<string> }>();
  const summaries: PacketSummary[] = [];
  const structuralSpans: StructuralSpanInput[][] = [];
  const unsupportedLinkTypes = new Set<number>();
  let decodedPackets = 0;

  for (let packetIndex = 0; packetIndex < packets.length; packetIndex++) {
    const pkt = packets[packetIndex]!;
    const indexedCollector: EntityCollector = {
      addIpv4(addr, pnum) { registry.add('ipv4', formatIp4(addr), pnum, packetIndex); },
      addIpv6(addr, pnum) { registry.add('ipv6', formatIp6(addr), pnum, packetIndex); },
      addMac(addr, pnum) { registry.add('mac', formatMac(addr), pnum, packetIndex); },
      addHostname(name, pnum) { registry.add('hostname', name, pnum, packetIndex); },
      addPort(port, proto, pnum) { registry.add('port', `${proto}/${port}`, pnum, packetIndex); },
      addVlan(id, pnum) { registry.add('vlan', `${id}`, pnum, packetIndex); },
    };

    const tree = decodeLink(pkt.data, pkt.linkType);
    const packetStructural: StructuralSpanInput[] = [];
    if (!tree) {
      unsupportedLinkTypes.add(pkt.linkType);
      summaries.push({ packetNumber: pkt.packetNumber, protocols: [], issues: [`unsupported-linktype:${pkt.linkType}`], hasUnsupported: true });
      structuralSpans.push(packetStructural);
      continue;
    }

    decodedPackets++;
    const protocols: string[] = [];
    const issues: string[] = [];
    let hasUnsupported = false;

    structuralSpansFromNode(packetIndex, tree, packetStructural);
    collectTree(tree, protocols, issues, indexedCollector, pkt.packetNumber, histogram, coverageMap);
    if (issues.some(i => i.startsWith('unsupported'))) hasUnsupported = true;

    summaries.push({ packetNumber: pkt.packetNumber, protocols, issues, hasUnsupported });
    structuralSpans.push(packetStructural);
  }

  const coverage: CoverageEntry[] = [];
  for (const [id, entry] of coverageMap) {
    coverage.push({ protocolId: id, packetCount: entry.packetCount, unsupportedCount: entry.unsupportedCount, issues: [...entry.issues] });
  }

  const entities: EntityEntry[] = [];
  for (const [key, record] of registry.entries()) {
    entities.push({
      key,
      category: record.category,
      value: record.canonical,
      firstPacket: record.firstPacket,
      count: record.count,
    });
  }
  entities.sort((a, b) => a.firstPacket - b.firstPacket);

  return {
    histogram: { counts: histogram },
    coverage,
    entities,
    summaries,
    totalPackets: packets.length,
    decodedPackets,
    unsupportedLinkTypes,
    entityOverflow: registry.overflow,
    structuralSpans,
    entityOccurrenceLists: registry.occurrenceMap(),
  };
}

/** Get a page of packet summaries */
export function getPacketPage(summaries: readonly PacketSummary[], offset: number, limit: number): readonly PacketSummary[] {
  return summaries.slice(offset, offset + limit);
}

function collectTree(
  node: DecodedNode,
  protocols: string[],
  issues: string[],
  collector: EntityCollector,
  packetNumber: number,
  histogram: Map<string, number>,
  coverageMap: Map<string, { packetCount: number; unsupportedCount: number; issues: Set<string> }>,
): void {
  const firstInPacket = !protocols.includes(node.protocolId);
  protocols.push(node.protocolId);
  histogram.set(node.protocolId, (histogram.get(node.protocolId) ?? 0) + 1);

  let entry = coverageMap.get(node.protocolId);
  if (!entry) {
    entry = { packetCount: 0, unsupportedCount: 0, issues: new Set() };
    coverageMap.set(node.protocolId, entry);
  }
  if (firstInPacket) entry.packetCount++;

  for (const issue of node.issues) {
    issues.push(issue);
    entry.issues.add(issue);
    if (issue.startsWith('unsupported')) entry.unsupportedCount++;
  }

  const mod = findModuleById(node.protocolId);
  if (mod) mod.collect(node, collector, packetNumber);

  for (const child of node.children) {
    collectTree(child, protocols, issues, collector, packetNumber, histogram, coverageMap);
  }
}

function findModuleById(id: string): ProtocolModule | undefined {
  return modulesById().get(id);
}

function formatIp4(b: Uint8Array): string { return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`; }
function formatIp6(b: Uint8Array): string {
  const g: string[] = [];
  for (let i = 0; i < 16; i += 2) g.push(((b[i]! << 8) | b[i + 1]!).toString(16));
  return g.join(':');
}
function formatMac(b: Uint8Array): string { return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(':'); }
