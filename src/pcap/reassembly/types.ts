/**
 * Capture-level IP/TCP reassembly types (step 9).
 */

import type { BytePatch, CoverageStatus, LayerCoverage, SanitizationPolicy } from '../sanitize/types';
import type { TransformationIntent } from '../discovery/types';

export interface ReassemblyLimits {
  readonly maxConcurrentFlows: number;
  readonly maxBytesPerFlow: number;
  readonly maxDatagramBytes: number;
  readonly maxFragmentGroups: number;
  /** Max bytes buffered while probing off-port TCP for a SIP start-line (CF-05). */
  readonly maxSipProbeBytes: number;
  /** Max bytes buffered while probing off-port TCP for an HTTP request/response line. */
  readonly maxHttpProbeBytes: number;
  /** Soft cap for HTTP decoded / reassembled application size (alias of flow budget when unset). */
  readonly maxHttpDecodedSize: number;
  /** Reserved — multipart MIME part count (fail-closed when exceeded). */
  readonly maxMultipartParts: number;
  /** Reserved — JSON / nested structure depth. */
  readonly maxParserNesting: number;
  /** Tunnel encapsulation depth (aligned with sanitize/tunnel MAX_TUNNEL_DEPTH). */
  readonly maxTunnelDepth: number;
  /** T17/V15 — max concurrent SCTP association directions tracked for DATA/I-DATA reassembly. */
  readonly maxSctpAssociations: number;
  /** T17/V15 — max concurrent fragmented user messages pending per association direction. */
  readonly maxSctpMessagesPerAssociation: number;
  /** T17/V15 — max user-message bytes for one reassembled SCTP DATA/I-DATA message. */
  readonly maxSctpMessageBytes: number;
  /** T17/V15 — max DATA/I-DATA fragments retained for one logical message. */
  readonly maxSctpFragmentsPerMessage: number;
}

export interface FlowEndpoint {
  readonly srcIp: string;
  readonly dstIp: string;
  readonly srcPort: number;
  readonly dstPort: number;
  readonly ipProto: number;
}

export interface ByteProvenance {
  /** Offset in the reassembled buffer. */
  readonly assembledOffset: number;
  readonly packetIndex: number;
  /** Absolute byte offset in the capture packet buffer. */
  readonly packetOffset: number;
  readonly length: number;
}

export type ReassemblyStatus =
  | 'complete'
  | 'incomplete'
  | 'gap'
  | 'overlap-conflict'
  | 'limit-exceeded';

/** T17/V15 — metadata for an SCTP user message reassembled across DATA/I-DATA chunks. */
export interface SctpReassemblyMeta {
  readonly ppid: number;
  readonly streamId: number;
  readonly isIdata: boolean;
  readonly unordered: boolean;
  /** V17 — association direction key for scoped UE/session identity. */
  readonly assocKey?: string;
  /** Absolute user-data spans in source packets owned by a complete multi-fragment message. */
  readonly fragmentSpans: readonly {
    readonly packetIndex: number;
    readonly offset: number;
    readonly length: number;
  }[];
}

export interface ReassembledView {
  readonly bytes: Uint8Array;
  readonly provenance: readonly ByteProvenance[];
  readonly transport: 'tcp' | 'udp' | 'sctp';
  readonly flowKey: string;
  readonly packetIndices: readonly number[];
  readonly status: ReassemblyStatus;
  /** IP next-header / protocol when view came from IP fragment reassembly. */
  readonly ipProto?: number;
  /** Present when transport === 'sctp'. */
  readonly sctp?: SctpReassemblyMeta;
}

export interface PacketReassemblyOverlay {
  readonly patches: readonly BytePatch[];
  readonly coverage: readonly LayerCoverage[];
  readonly issues: readonly string[];
  readonly drop: boolean;
  readonly truncatedLength?: number;
  readonly intents: readonly TransformationIntent[];
  /** When true, engine skips per-segment SIP incomplete handling. */
  readonly skipAppLayer: boolean;
}

/**
 * Absolute user-data span in a capture packet that belongs to a complete multi-fragment
 * SCTP message (owned by reassembly — per-packet sanitize must not mask it).
 */
export interface SctpOwnedPayloadSpan {
  readonly offset: number;
  readonly length: number;
}

export interface ReassemblyContext {
  readonly views: readonly ReassembledView[];
  readonly overlays: ReadonlyMap<number, PacketReassemblyOverlay>;
  readonly limitExceeded: boolean;
  readonly mediaFlowIndex: import('../discovery/mediaFlowIndex').MediaFlowIndex;
  overlayFor(packetIndex: number): PacketReassemblyOverlay | undefined;
  /**
   * T17/V15 — packetIndex → user-data spans owned by complete multi-fragment SCTP messages.
   * Absent for single-chunk B+E messages (handled by per-packet sanitizeSctp).
   */
  readonly sctpCompletePayloadSpans?: ReadonlyMap<number, readonly SctpOwnedPayloadSpan[]>;
  /** True when the given absolute packet offset falls in a complete SCTP reassembled span. */
  isSctpCompletePayload?(packetIndex: number, offset: number): boolean;
}

export interface ReassemblyBuildInput {
  readonly packets: readonly { readonly data: Uint8Array; readonly capturedLength: number; readonly linkType: number }[];
  readonly policy: SanitizationPolicy;
  readonly limits?: ReassemblyLimits;
}

export type { CoverageStatus, LayerCoverage, BytePatch, TransformationIntent };
