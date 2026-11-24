/**
 * Wire adapters for PCAP container metadata (Stage 9).
 */

import type {
  ClassicPcapHeader,
  PacketRecordDescriptor,
  PacketTimestamp,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
} from '../domain/types'
import type { EntityReplacementIntent, PacketDiscoveryResult, TransformationIntent } from '../discovery/types'
import type { IdentityCategory } from '../../mapping/identityCategories'
import {
  coverageRollupFromPacked,
  unpackDescriptors,
  type WireCoverageRollup,
  type WirePackedContainer,
} from './packedCaptureWire'

/**
 * The main thread only ever reads `kind`/`canonical`/`category` off an entity-replacement
 * intent (`pcapSession.ts`'s text-search matching) — `constraint`/`originalSpelling` are needed
 * only for mapping-closure resolution, which runs inside the worker against its own discovery
 * result before this wire payload is built. Dropping them here is the single biggest per-intent
 * saving at capture scale (a fresh object + string per entity occurrence otherwise).
 */
export type WireEntityReplacementIntent = {
  readonly kind: 'entity-replacement'
  readonly packetIndex: number
  readonly offset: number
  readonly byteLength: number
  readonly category: IdentityCategory
  readonly canonical: string
}
export type WireTransformationIntent = WireEntityReplacementIntent | Exclude<TransformationIntent, EntityReplacementIntent>

export interface WirePacketTimestamp {
  ticks: string
  unitsPerSecond: string
  offsetSeconds: string
}

export interface WirePacketRecordDescriptor {
  packetNumber: number
  timestamp: WirePacketTimestamp
  capturedLength: number
  originalLength: number
  linkType: number
  interfaceId: number
  sectionIndex: number
  fileOffset: number
  dataOffset: number
}

export interface WireSparseCheckpoint {
  packetNumber: number
  fileOffset: number
}

export interface WirePacketDiscoveryCompact {
  packetIndex: number
  packetNumber: number
  drop: boolean
  truncatedLength?: number
  issues: string[]
  coverage: Array<{ protocol: string; offset: number; length: number; status: string }>
  intents: WireTransformationIntent[]
}

export interface WireContainerMetadata {
  descriptors: WirePacketRecordDescriptor[]
  checkpoints: WireSparseCheckpoint[]
  issues: ParseIssue[]
  classicHeader?: unknown
  pcapngSections?: unknown[]
  pcapngInterfaces?: unknown[]
  packetDiscovery: WirePacketDiscoveryCompact[]
  /**
   * R10 — transferable packed columns for descriptors + packetDiscovery.
   * When present, `descriptors`/`packetDiscovery` arrays are empty placeholders;
   * {@link containerFromWire} unpacks `packed` instead.
   */
  packed?: WirePackedContainer
}

function tsToWire(ts: PacketTimestamp): WirePacketTimestamp {
  return {
    ticks: ts.ticks.toString(),
    unitsPerSecond: ts.unitsPerSecond.toString(),
    offsetSeconds: ts.offsetSeconds.toString(),
  }
}

// `unitsPerSecond`/`offsetSeconds` take only a handful of distinct values across a whole
// capture (one per interface/section) — cache their BigInt conversion so hundreds of thousands
// of packets share the same few instances instead of allocating one pair each.
const sharedTimestampBigIntCache = new Map<string, bigint>()
function sharedBigInt(value: string): bigint {
  let cached = sharedTimestampBigIntCache.get(value)
  if (cached === undefined) {
    cached = BigInt(value)
    sharedTimestampBigIntCache.set(value, cached)
  }
  return cached
}

function tsFromWire(w: WirePacketTimestamp): PacketTimestamp {
  return {
    ticks: BigInt(w.ticks),
    unitsPerSecond: sharedBigInt(w.unitsPerSecond),
    offsetSeconds: sharedBigInt(w.offsetSeconds),
  }
}

export function descriptorsToWire(descriptors: readonly PacketRecordDescriptor[]): WirePacketRecordDescriptor[] {
  return descriptors.map((d) => ({
    packetNumber: d.packetNumber,
    timestamp: tsToWire(d.timestamp),
    capturedLength: d.capturedLength,
    originalLength: d.originalLength,
    linkType: d.linkType,
    interfaceId: d.interfaceId,
    sectionIndex: d.sectionIndex,
    fileOffset: d.fileOffset,
    dataOffset: d.dataOffset,
  }))
}

export function descriptorsFromWire(wire: WirePacketRecordDescriptor[]): PacketRecordDescriptor[] {
  return wire.map((d) => ({
    packetNumber: d.packetNumber,
    timestamp: tsFromWire(d.timestamp),
    capturedLength: d.capturedLength,
    originalLength: d.originalLength,
    linkType: d.linkType,
    interfaceId: d.interfaceId,
    sectionIndex: d.sectionIndex,
    fileOffset: d.fileOffset,
    dataOffset: d.dataOffset,
  }))
}

export function containerToWire(input: {
  descriptors: readonly PacketRecordDescriptor[]
  checkpoints: readonly SparseCheckpoint[]
  issues: readonly ParseIssue[]
  classicHeader?: ClassicPcapHeader
  pcapngSections?: PcapngSectionInfo[]
  pcapngInterfaces?: PcapngInterfaceInfo[]
  packetDiscovery: readonly PacketDiscoveryResult[]
}): WireContainerMetadata {
  return {
    descriptors: descriptorsToWire(input.descriptors),
    checkpoints: input.checkpoints.map((c) => ({ packetNumber: c.packetNumber, fileOffset: c.fileOffset })),
    issues: [...input.issues],
    classicHeader: input.classicHeader,
    pcapngSections: input.pcapngSections ? [...input.pcapngSections] : undefined,
    pcapngInterfaces: input.pcapngInterfaces ? [...input.pcapngInterfaces] : undefined,
    packetDiscovery: input.packetDiscovery.map((pd) => ({
      packetIndex: pd.packetIndex,
      packetNumber: pd.packetNumber,
      drop: pd.drop,
      truncatedLength: pd.truncatedLength,
      issues: [...pd.issues],
      coverage: pd.coverage.map((c) => ({
        protocol: c.protocol,
        offset: c.offset,
        length: c.length,
        status: c.status,
      })),
      // `intents` are needed only for mapping-closure resolution, which already ran against the
      // worker's own discovery result before this wire payload is built (from the *other* copy
      // in `discoveryWire.intents` — see `processingOrchestrator.ts`). The main thread's own use
      // of entity-replacement intents (`pcapSession.ts`'s text-search matching) has been rebuilt
      // on `entityOccurrenceIndex`/`analysis.entities`, so nothing reads this on the main thread
      // anymore — sending `[]` avoids a fresh object (+ a `constraint` object + strings) per
      // entity occurrence surviving the worker→main-thread transfer for every packet.
      intents: [],
    })),
  }
}

export function containerFromWire(wire: WireContainerMetadata): {
  descriptors: PacketRecordDescriptor[]
  checkpoints: SparseCheckpoint[]
  issues: ParseIssue[]
  classicHeader?: ClassicPcapHeader
  pcapngSections?: PcapngSectionInfo[]
  pcapngInterfaces?: PcapngInterfaceInfo[]
  packetDiscovery: PacketDiscoveryResult[]
  coverageRollup?: WireCoverageRollup
} {
  if (wire.packed) {
    // R10: do not materialize 235k PacketDiscoveryResult rows (+ issue strings) on the UI
    // thread — plan build already used the worker's full discovery; UI honesty uses coverageRollup.
    return {
      descriptors: unpackDescriptors(wire.packed.descriptors),
      checkpoints: wire.packed.checkpoints.map((c) => ({
        packetNumber: c.packetNumber,
        fileOffset: c.fileOffset,
      })),
      issues: [...wire.packed.issues],
      classicHeader: wire.packed.classicHeader as ClassicPcapHeader | undefined,
      pcapngSections: wire.packed.pcapngSections as PcapngSectionInfo[] | undefined,
      pcapngInterfaces: wire.packed.pcapngInterfaces as PcapngInterfaceInfo[] | undefined,
      packetDiscovery: [],
      coverageRollup: coverageRollupFromPacked(wire.packed),
    }
  }

  return {
    descriptors: descriptorsFromWire(wire.descriptors),
    checkpoints: wire.checkpoints.map((c) => ({ packetNumber: c.packetNumber, fileOffset: c.fileOffset })),
    issues: [...wire.issues],
    classicHeader: wire.classicHeader as ClassicPcapHeader | undefined,
    pcapngSections: wire.pcapngSections as PcapngSectionInfo[] | undefined,
    pcapngInterfaces: wire.pcapngInterfaces as PcapngInterfaceInfo[] | undefined,
    packetDiscovery: wire.packetDiscovery.map((pd) => ({
      packetIndex: pd.packetIndex,
      packetNumber: pd.packetNumber,
      drop: pd.drop,
      truncatedLength: pd.truncatedLength,
      issues: [...pd.issues],
      // Deliberately narrower than `TransformationIntent` at runtime (see
      // `WireEntityReplacementIntent`) — the main thread only ever reads
      // `kind`/`canonical`/`category` off these (`pcapSession.ts` text-search matching).
      intents: [...(pd.intents ?? [])] as unknown as PacketDiscoveryResult['intents'],
      coverage: pd.coverage.map((c) => ({
        protocol: c.protocol,
        offset: c.offset,
        length: c.length,
        status: c.status as import('../sanitize/types').CoverageStatus,
      })),
    })),
  }
}
