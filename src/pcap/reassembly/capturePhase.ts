/**
 * Capture-level reassembly phase (step 9 / CF-04 / CF-05 / enterprise step 3).
 *
 * TCP logical stream → sanitize → project patches onto every captured occurrence
 * (original + retransmit + identical overlap). Gaps / resource limits → MASK
 * (diagnostic) or MASK/DROP (high-privacy) — never leave-original.
 *
 * T17/V15 — SCTP DATA/I-DATA complete-message reassembly by association/stream/MID/FSN;
 * PPID dispatch runs on the reassembled user message, patches project onto fragments.
 */

import type { PacketEnvelope } from '../domain/types';
import type { SanitizationPolicy } from '../sanitize/types';
import { MediaFlowIndex } from '../discovery/mediaFlowIndex';
import { looksLikeSipStart } from '../protocols/application/sip/startLine';
import { looksLikeHttpBuffer } from '../sanitize/http';
import { mergePatchesStrict } from '../plan/mergePatchesStrict';
import { DEFAULT_REASSEMBLY_LIMITS } from './limits';
import { IpFragmentReassembler } from './ipFragment';
import { TcpStreamReassembler } from './tcpStream';
import { SctpMessageReassembler } from './sctpMessage';
import {
  parseIpv4Fragment,
  parseIpv6Fragment,
  parseTcpSegment,
  parseSctpDataFragments,
  isSipPort,
  isHttpPort,
} from './parsePacket';
import { overlayForReassemblyFailure } from './policy';
import { processSipOverReassembledView, sanitizeReassembledView } from './sipOverReassembled';
import { processHttpOverReassembledView } from './httpOverReassembled';
import {
  processSctpOverReassembledView,
  sanitizeSctpReassembledView,
} from './sctpOverReassembled';
import { unwrapTransportDatagram } from './transportUnwrap';
import type {
  PacketReassemblyOverlay,
  ReassemblyContext,
  ReassemblyLimits,
  ReassembledView,
  SctpOwnedPayloadSpan,
} from './types';

/** Off-port TCP probe state (CF-05 content-first promotion). */
interface TcpProbeState {
  bytes: number;
  promoted: boolean;
  rejected: boolean;
  prefix: Uint8Array[];
  segments: import('./parsePacket').ParsedTcpSegment[];
  kind: 'sip' | 'http' | 'unknown';
}

export function runCaptureReassembly(
  packets: readonly PacketEnvelope[],
  policy: SanitizationPolicy,
  limits: ReassemblyLimits = DEFAULT_REASSEMBLY_LIMITS,
  options?: { readonly journal?: import('../kernel/journal').SemanticJournalBuilder },
): ReassemblyContext {
  const needTcpIp = policy.sipSdp || policy.http;
  const data = packets.map((p) => p.data);
  const sctp = new SctpMessageReassembler(limits);
  let sctpCaptureOrder = 0;

  // T17/V15 — always ingest fragmented SCTP DATA/I-DATA (independent of SIP/HTTP policy).
  for (let i = 0; i < packets.length; i++) {
    const pkt = packets[i]!;
    const frags = parseSctpDataFragments(
      pkt.data,
      pkt.linkType,
      pkt.capturedLength,
      i,
      sctpCaptureOrder,
    );
    if (!frags) continue;
    for (const frag of frags) {
      sctp.ingest(frag);
      sctpCaptureOrder = Math.max(sctpCaptureOrder, frag.captureOrder + 1);
    }
  }
  const sctpAssembled = sctp.assembleAll(data);
  const sctpCompleteSpans = sctpAssembled.completeSpans;

  const sctpOnly =
    !needTcpIp
    && (sctpAssembled.views.length > 0 || sctp.limitExceeded || sctpCompleteSpans.size > 0);
  if (!needTcpIp && !sctpOnly) {
    return emptyContext();
  }

  const tcp = new TcpStreamReassembler(limits);
  const ipFrag = new IpFragmentReassembler(limits);
  const tcpPayloadOffsets = new Map<number, number>();
  const probes = new Map<string, TcpProbeState>();

  if (needTcpIp) {
    for (let i = 0; i < packets.length; i++) {
      const pkt = packets[i]!;
      const seg = parseTcpSegment(pkt.data, pkt.linkType, pkt.capturedLength, i);
      if (seg) {
        const sipHint = policy.sipSdp && isSipPort(seg.endpoint.srcPort, seg.endpoint.dstPort);
        const httpHint = policy.http && isHttpPort(seg.endpoint.srcPort, seg.endpoint.dstPort);
        const probeKey = `${seg.endpoint.srcIp}:${seg.endpoint.srcPort}->${seg.endpoint.dstIp}:${seg.endpoint.dstPort}`;

        let shouldIngest = sipHint || httpHint;
        if (!shouldIngest && seg.payloadLength > 0 && (policy.sipSdp || policy.http)) {
          let probe = probes.get(probeKey);
          if (!probe) {
            probe = { bytes: 0, promoted: false, rejected: false, prefix: [], segments: [], kind: 'unknown' };
            probes.set(probeKey, probe);
          }
          if (!probe.rejected) {
            if (probe.promoted) {
              shouldIngest = true;
            } else {
              const slice = pkt.data.subarray(seg.payloadOffset, seg.payloadOffset + seg.payloadLength);
              probe.prefix.push(slice);
              probe.bytes += slice.length;
              probe.segments.push(seg);
              const prefix = concatPrefixes(probe.prefix);
              const sipMatch = policy.sipSdp && looksLikeSipStart(prefix, 0, prefix.length);
              const httpMatch = policy.http && looksLikeHttpBuffer(prefix, 0, prefix.length);
              if (sipMatch || httpMatch) {
                probe.promoted = true;
                probe.kind = sipMatch ? 'sip' : 'http';
                for (const earlier of probe.segments) {
                  tcp.ingest(earlier);
                  if (earlier.payloadLength > 0) {
                    tcpPayloadOffsets.set(earlier.packetIndex, earlier.payloadOffset);
                  }
                }
                shouldIngest = false; // already ingested above, including the current segment
              } else {
                const probeBudget = Math.max(
                  policy.sipSdp ? limits.maxSipProbeBytes : 0,
                  policy.http ? limits.maxHttpProbeBytes : 0,
                );
                if (probe.bytes >= probeBudget) {
                  probe.rejected = true;
                }
              }
            }
          }
        }

        if (shouldIngest) {
          tcp.ingest(seg);
          if (seg.payloadLength > 0) {
            tcpPayloadOffsets.set(i, seg.payloadOffset);
          }
        }
      }

      const v4 = parseIpv4Fragment(pkt.data, pkt.linkType, pkt.capturedLength, i);
      if (v4) ipFrag.ingestIpv4(v4, pkt.interfaceId, pkt.sectionIndex);

      const v6 = parseIpv6Fragment(pkt.data, pkt.linkType, pkt.capturedLength, i);
      if (v6) ipFrag.ingestIpv6(v6, pkt.interfaceId, pkt.sectionIndex);
    }
  }

  const tcpViews = needTcpIp
    ? tcp.assembleAll(data).filter((view) => keepTcpView(view, policy, limits))
    : [];
  const ipViewsRaw = needTcpIp ? ipFrag.assembleAll(data) : [];
  const ipViews: ReassembledView[] = [];

  for (const view of ipViewsRaw) {
    if (view.status !== 'complete') {
      ipViews.push(view);
      continue;
    }
    const unwrapped = unwrapTransportDatagram(view);
    if (!unwrapped) {
      ipViews.push({ ...view, status: 'incomplete' });
      continue;
    }
    if (unwrapped.bytes.length === 0) continue;
    if (!policy.sipSdp || !looksLikeSipStart(unwrapped.bytes, 0, unwrapped.bytes.length)) {
      // Non-SIP fragmented datagram — do not create SIP failure overlays.
      continue;
    }
    ipViews.push(unwrapped);
  }

  const views: ReassembledView[] = [...tcpViews, ...ipViews, ...sctpAssembled.views];

  const overlays = new Map<number, PacketReassemblyOverlay>();
  const mediaFlowIndex = new MediaFlowIndex();
  let limitExceeded = sctp.limitExceeded;

  for (const view of views) {
    if (view.status === 'limit-exceeded') limitExceeded = true;

    if (view.transport === 'sctp') {
      if (view.status !== 'complete') continue;
      const sctpOverlays = processSctpOverReassembledView(view);
      for (const [idx, overlay] of sctpOverlays) {
        mergeOverlay(overlays, idx, overlay);
      }
      continue;
    }

    if (view.status !== 'complete') {
      for (const packetIndex of view.packetIndices) {
        const payloadOffset = tcpPayloadOffsets.get(packetIndex)
          ?? firstProvenancePacketOffset(view, packetIndex)
          ?? 0;
        const pkt = packets[packetIndex];
        const payloadLength = pkt ? Math.max(0, pkt.capturedLength - payloadOffset) : 0;
        overlays.set(
          packetIndex,
          overlayForReassemblyFailure(
            policy,
            packetIndex,
            payloadOffset,
            payloadLength,
            view.status,
            view.transport,
          ),
        );
      }
      continue;
    }

    if (view.bytes.length === 0) continue;

    // HTTP decoded-size budget (enterprise step 3 resource limits).
    if (
      looksLikeHttpBuffer(view.bytes)
      && view.bytes.length > limits.maxHttpDecodedSize
    ) {
      limitExceeded = true;
      for (const packetIndex of view.packetIndices) {
        const payloadOffset = tcpPayloadOffsets.get(packetIndex)
          ?? firstProvenancePacketOffset(view, packetIndex)
          ?? 0;
        const pkt = packets[packetIndex];
        const payloadLength = pkt ? Math.max(0, pkt.capturedLength - payloadOffset) : 0;
        overlays.set(
          packetIndex,
          overlayForReassemblyFailure(
            policy,
            packetIndex,
            payloadOffset,
            payloadLength,
            'limit-exceeded',
            view.transport,
          ),
        );
      }
      continue;
    }

    const primaryIndex = view.packetIndices[0] ?? 0;
    const payloadOffset = tcpPayloadOffsets.get(primaryIndex)
      ?? firstProvenancePacketOffset(view, primaryIndex)
      ?? 0;

    if (policy.http && looksLikeHttpBuffer(view.bytes)) {
      const httpOverlays = processHttpOverReassembledView(view, primaryIndex, payloadOffset);
      for (const [idx, overlay] of httpOverlays) {
        mergeOverlay(overlays, idx, overlay);
      }
      continue;
    }

    if (policy.sipSdp && (view.transport === 'tcp' || view.transport === 'udp')) {
      const sipResult = processSipOverReassembledView(
        view,
        view.transport,
        primaryIndex,
        payloadOffset,
        mediaFlowIndex,
        { journal: options?.journal },
      );

      for (const [idx, overlay] of sipResult.overlays) {
        mergeOverlay(overlays, idx, overlay);
      }
    }
  }

  return buildReassemblyContext(views, overlays, limitExceeded, mediaFlowIndex, sctpCompleteSpans);
}

function keepTcpView(
  view: ReassembledView,
  policy: SanitizationPolicy,
  _limits: ReassemblyLimits,
): boolean {
  if (view.status !== 'complete') {
    // Incomplete / gap / conflict / limit — still need failure overlays when we have packets.
    return view.packetIndices.length > 0;
  }
  if (view.bytes.length === 0) return false;
  if (policy.http && looksLikeHttpBuffer(view.bytes)) return true;
  if (policy.sipSdp && looksLikeSipStart(view.bytes, 0, view.bytes.length)) return true;
  return false;
}

function concatPrefixes(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function firstProvenancePacketOffset(view: ReassembledView, packetIndex: number): number | undefined {
  for (const p of view.provenance) {
    if (p.packetIndex === packetIndex) return p.packetOffset;
  }
  return undefined;
}

function mergeOverlay(
  overlays: Map<number, PacketReassemblyOverlay>,
  idx: number,
  overlay: PacketReassemblyOverlay,
): void {
  const existing = overlays.get(idx);
  if (!existing) {
    overlays.set(idx, overlay);
    return;
  }
  overlays.set(idx, {
    patches: [...existing.patches, ...overlay.patches],
    coverage: [...existing.coverage, ...overlay.coverage],
    issues: [...existing.issues, ...overlay.issues],
    drop: existing.drop || overlay.drop,
    truncatedLength: overlay.truncatedLength ?? existing.truncatedLength,
    intents: [...existing.intents, ...overlay.intents],
    skipAppLayer: existing.skipAppLayer || overlay.skipAppLayer,
  });
}

function buildReassemblyContext(
  views: readonly ReassembledView[],
  overlays: Map<number, PacketReassemblyOverlay>,
  limitExceeded: boolean,
  mediaFlowIndex: MediaFlowIndex,
  sctpCompletePayloadSpans: ReadonlyMap<number, readonly SctpOwnedPayloadSpan[]>,
): ReassemblyContext {
  return {
    views,
    overlays,
    limitExceeded,
    mediaFlowIndex,
    sctpCompletePayloadSpans,
    overlayFor(packetIndex: number) {
      return overlays.get(packetIndex);
    },
    isSctpCompletePayload(packetIndex: number, offset: number) {
      const spans = sctpCompletePayloadSpans.get(packetIndex);
      if (!spans) return false;
      for (const span of spans) {
        if (offset >= span.offset && offset < span.offset + span.length) return true;
        if (offset === span.offset) return true;
      }
      return false;
    },
  };
}

function emptyContext(): ReassemblyContext {
  return buildReassemblyContext([], new Map(), false, new MediaFlowIndex(), new Map());
}

export function mergePacketWithReassemblyOverlay(
  base: {
    patches: import('../sanitize/types').BytePatch[];
    coverage: import('../sanitize/types').LayerCoverage[];
    issues: string[];
    drop: boolean;
    truncatedLength?: number;
  },
  overlay: PacketReassemblyOverlay | undefined,
): typeof base & { intents: import('../discovery/types').TransformationIntent[] } {
  if (!overlay) {
    return { ...base, intents: [] };
  }

  return {
    patches: [...base.patches, ...overlay.patches],
    coverage: [...base.coverage, ...overlay.coverage],
    issues: [...base.issues, ...overlay.issues],
    drop: base.drop || overlay.drop,
    truncatedLength: overlay.truncatedLength ?? base.truncatedLength,
    intents: [...overlay.intents],
  };
}

export function applyReassemblyPatchesToResults(
  results: import('../sanitize/types').PacketSanitizationResult[],
  reassembly: ReassemblyContext,
  mapping: import('../anonymization/mapping').MappingLike,
  packets: readonly PacketEnvelope[],
  /** T-01 — when packets are payload-less stubs, lengths come from descriptors. */
  bufferLengths?: readonly number[],
  /** T14 — capture-aligned payload time for HTTP/SIP Date on reassembled views. */
  payloadTime?: import('../kernel/payloadTimeCodec').PayloadTimeSession,
): void {
  for (const view of reassembly.views) {
    if (view.status !== 'complete') continue;
    let byPacket: Map<number, import('../sanitize/types').BytePatch[]>
    try {
      if (view.transport === 'sctp') {
        byPacket = sanitizeSctpReassembledView(view, mapping);
      } else {
        byPacket = sanitizeReassembledView(view, mapping, view.transport, payloadTime);
      }
    } catch {
      // T07: one TCP/SIP/SCTP stream failure must not abort other flows.
      continue;
    }
    for (const [packetIndex, patches] of byPacket) {
      const result = results[packetIndex];
      const pkt = packets[packetIndex];
      if (!result || !pkt) continue;
      const bufferLength = bufferLengths?.[packetIndex] ?? pkt.data.length;
      try {
        const merged = mergePatchesStrict(bufferLength, packetIndex, [...result.patches, ...patches]);
        results[packetIndex] = {
          ...result,
          patches: merged,
        };
      } catch {
        // Keep prior patches for this packet; stream isolation already skipped the bad merge.
      }
    }
  }
}
