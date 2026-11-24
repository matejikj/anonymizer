/**
 * Core domain types for the PCAP anonymization engine.
 */

export const PCAP_MAGIC_MICRO_LE = 0xa1b2c3d4;
export const PCAP_MAGIC_MICRO_BE = 0xd4c3b2a1;
export const PCAP_MAGIC_NANO_LE = 0xa1b23c4d;
export const PCAP_MAGIC_NANO_BE = 0x4d3cb2a1;

export const PCAPNG_MAGIC = 0x0a0d0d0a; // Section Header Block type
export const PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;

export const Endian = { Little: 0, Big: 1 } as const;
export type Endian = (typeof Endian)[keyof typeof Endian];

export const TimestampResolution = { Microseconds: 0, Nanoseconds: 1 } as const;
export type TimestampResolution = (typeof TimestampResolution)[keyof typeof TimestampResolution];

export const CaptureFormat = { ClassicPcap: 0, Pcapng: 1 } as const;
export type CaptureFormat = (typeof CaptureFormat)[keyof typeof CaptureFormat];

export interface ClassicPcapHeader {
  readonly format: typeof CaptureFormat.ClassicPcap;
  readonly endian: Endian;
  readonly timestampResolution: TimestampResolution;
  readonly versionMajor: number;
  readonly versionMinor: number;
  readonly snapLen: number;
  readonly linkType: number;
  readonly tzOffset: number;
  readonly sigfigs: number;
}

export interface PcapngSectionInfo {
  readonly sectionIndex: number;
  readonly endian: Endian;
  readonly versionMajor: number;
  readonly versionMinor: number;
  readonly sectionLength: bigint; // -1 means unspecified
}

export interface PcapngInterfaceInfo {
  readonly interfaceId: number;
  readonly sectionIndex: number;
  readonly linkType: number;
  readonly snapLen: number;
  readonly tsResol: TimestampResolution;
  readonly tsResolValue: number; // raw if_tsresol
  readonly tsOffset: bigint;
  readonly name?: string;
}

export interface PacketTimestamp {
  readonly ticks: bigint;
  readonly unitsPerSecond: bigint;
  readonly offsetSeconds: bigint;
}

export interface PacketEnvelope {
  readonly packetNumber: number;
  readonly timestamp: PacketTimestamp;
  readonly capturedLength: number;
  readonly originalLength: number;
  readonly linkType: number;
  readonly interfaceId: number;
  readonly sectionIndex: number;
  readonly fileOffset: number;
  readonly data: Uint8Array;
}

/** Slim packet index entry — payload loaded on demand from Blob.slice (Stage 6). */
export interface PacketRecordDescriptor {
  readonly packetNumber: number;
  readonly timestamp: PacketTimestamp;
  readonly capturedLength: number;
  readonly originalLength: number;
  readonly linkType: number;
  readonly interfaceId: number;
  readonly sectionIndex: number;
  /** File offset of record/block start. */
  readonly fileOffset: number;
  /** File offset where packet payload bytes begin. */
  readonly dataOffset: number;
}

export interface CaptureStats {
  readonly format: CaptureFormat;
  readonly packetCount: number;
  readonly totalBytes: number;
  readonly firstTimestamp: PacketTimestamp | null;
  readonly lastTimestamp: PacketTimestamp | null;
  readonly interfaces: readonly PcapngInterfaceInfo[];
  readonly sections: readonly PcapngSectionInfo[];
  readonly linkTypes: ReadonlySet<number>;
  readonly issues: readonly ParseIssue[];
}

export const IssueSeverity = { Warning: 0, Error: 1, Fatal: 2 } as const;
export type IssueSeverity = (typeof IssueSeverity)[keyof typeof IssueSeverity];

export interface ParseIssue {
  readonly severity: IssueSeverity;
  readonly code: string;
  readonly message: string;
  readonly packetNumber?: number;
  readonly fileOffset?: number;
}

import { PCAP_RECORD_LIMITS } from '../../domain/capabilityContract.ts';

export const MAX_RECORD_SIZE = PCAP_RECORD_LIMITS.maxRecordSize;
export const MAX_PACKET_COUNT = 20_000_000;
export const SPARSE_CHECKPOINT_INTERVAL = 4096;

export interface SparseCheckpoint {
  readonly packetNumber: number;
  readonly fileOffset: number;
}
