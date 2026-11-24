/**
 * PcapSourceDescriptor — slim PCAP source artifact (Stage 9 / SourceArtifact contract).
 */

import type {
  CaptureFormat,
  ClassicPcapHeader,
  PacketRecordDescriptor,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
} from '../domain/types'

export interface PcapSourceDescriptor {
  readonly fileName: string
  readonly fileSize: number
  readonly format: CaptureFormat
  readonly sourceFile: File
  readonly descriptors: readonly PacketRecordDescriptor[]
  readonly checkpoints: readonly SparseCheckpoint[]
  readonly issues: readonly ParseIssue[]
  readonly classicHeader?: ClassicPcapHeader
  readonly pcapngSections?: readonly PcapngSectionInfo[]
  readonly pcapngInterfaces?: readonly PcapngInterfaceInfo[]
}

export type { PacketRecordDescriptor, SparseCheckpoint, ParseIssue }
