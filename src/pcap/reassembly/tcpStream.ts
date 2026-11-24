/**
 * Bounded TCP stream reassembly (step 9 / CF-04 / enterprise step 3).
 * Each directional 4-tuple has its own sequence space, ISN, and conflict scope.
 * Identical retransmit / overlap bytes record alternate provenance so patches
 * project onto every captured occurrence.
 */

import { directionalStreamKey } from './flowKey';
import type { ByteProvenance, FlowEndpoint, ReassembledView, ReassemblyLimits, ReassemblyStatus } from './types';
import type { ParsedTcpSegment } from './parsePacket';

interface StoredSegment {
  readonly seq: number;
  readonly packetIndex: number;
  readonly payloadOffset: number;
  readonly payloadLength: number;
  readonly captureOrder: number;
}

interface TcpFlowAccumulator {
  readonly key: string;
  readonly endpoint: FlowEndpoint;
  readonly generation: number;
  readonly segments: StoredSegment[];
  initialSeq: number | null;
  sawRst: boolean;
  sawFin: boolean;
  closed: boolean;
  limitExceeded: boolean;
}

export class TcpStreamReassembler {
  private readonly _flows = new Map<string, TcpFlowAccumulator>();
  /** Latest generation per directional 4-tuple (without generation suffix). */
  private readonly _generationByTuple = new Map<string, number>();
  private _flowCount = 0;
  private _captureOrder = 0;
  private readonly _limits: ReassemblyLimits;

  constructor(limits: ReassemblyLimits) {
    this._limits = limits;
  }

  ingest(segment: ParsedTcpSegment): void {
    if (segment.payloadLength <= 0 && !segment.syn && !segment.rst && !segment.fin) return;

    const tupleId = tupleIdFromEndpoint(segment.endpoint);
    let generation = this._generationByTuple.get(tupleId) ?? 0;

    // New SYN after an established generation opens a new connection (CF-04).
    if (segment.syn) {
      const currentKey = directionalStreamKey(segment.endpoint, generation);
      const current = this._flows.get(currentKey);
      if (current && current.initialSeq !== null) {
        generation += 1;
        this._generationByTuple.set(tupleId, generation);
      } else if (!this._generationByTuple.has(tupleId)) {
        this._generationByTuple.set(tupleId, 0);
      }
    }

    const flow = this.flowFor(segment.endpoint, generation);

    if (segment.rst) {
      flow.sawRst = true;
      flow.closed = true;
      return;
    }

    if (segment.syn && flow.initialSeq === null) {
      flow.initialSeq = (segment.seq + 1) >>> 0;
    }

    if (segment.payloadLength > 0) {
      flow.segments.push({
        seq: segment.seq >>> 0,
        packetIndex: segment.packetIndex,
        payloadOffset: segment.payloadOffset,
        payloadLength: segment.payloadLength,
        captureOrder: this._captureOrder++,
      });
    }

    if (segment.fin) {
      flow.sawFin = true;
      flow.closed = true;
    }
  }

  /** Whether this directional tuple has been accepted for SIP reassembly. */
  hasFlow(endpoint: FlowEndpoint): boolean {
    const tupleId = tupleIdFromEndpoint(endpoint);
    const generation = this._generationByTuple.get(tupleId) ?? 0;
    return this._flows.has(directionalStreamKey(endpoint, generation));
  }

  assembleAll(data: readonly Uint8Array[]): ReassembledView[] {
    const out: ReassembledView[] = [];
    for (const flow of this._flows.values()) {
      const view = this.assembleFlow(flow, data);
      if (view) out.push(view);
    }
    return out;
  }

  flowKeys(): readonly string[] {
    return [...this._flows.keys()];
  }

  packetIndicesForKey(key: string): readonly number[] {
    const flow = this._flows.get(key);
    if (!flow) return [];
    const set = new Set<number>();
    for (const s of flow.segments) set.add(s.packetIndex);
    return [...set].sort((a, b) => a - b);
  }

  private flowFor(endpoint: FlowEndpoint, generation: number): TcpFlowAccumulator {
    const key = directionalStreamKey(endpoint, generation);
    let flow = this._flows.get(key);
    if (!flow) {
      if (this._flowCount >= this._limits.maxConcurrentFlows) {
        flow = {
          key,
          endpoint,
          generation,
          segments: [],
          initialSeq: null,
          sawRst: false,
          sawFin: false,
          closed: false,
          limitExceeded: true,
        };
      } else {
        this._flowCount++;
        flow = {
          key,
          endpoint,
          generation,
          segments: [],
          initialSeq: null,
          sawRst: false,
          sawFin: false,
          closed: false,
          limitExceeded: false,
        };
      }
      this._flows.set(key, flow);
    }
    return flow;
  }

  private assembleFlow(
    flow: TcpFlowAccumulator,
    data: readonly Uint8Array[],
  ): ReassembledView | null {
    if (flow.limitExceeded) {
      return emptyView(flow, 'limit-exceeded');
    }
    if (flow.segments.length === 0) return null;

    let baseSeq = flow.initialSeq;
    if (baseSeq === null) {
      // No SYN: pick the base that minimizes the reassembled span (CF-04 wrap-safe).
      baseSeq = pickBaseSeq(flow.segments);
    }

    const sorted = [...flow.segments].sort((a, b) => {
      const ra = relativeSeq(a.seq, baseSeq!);
      const rb = relativeSeq(b.seq, baseSeq!);
      if (ra !== rb) return ra < rb ? -1 : 1;
      return a.captureOrder - b.captureOrder;
    });

    // PF-07: first pass is pure arithmetic over segments (no per-byte work) to find the
    // exact span needed, so the second pass can write into fixed-size typed arrays sized to
    // the real stream length — not one object allocated per byte in a Map (which cost tens of
    // bytes of V8/Map overhead for every single byte of a reassembled stream).
    let highWaterRel = 0;
    for (const seg of sorted) {
      if (seg.payloadLength <= 0) continue;
      const endRel = relativeSeq(seg.seq, baseSeq) + seg.payloadLength;
      if (endRel > highWaterRel) highWaterRel = endRel;
    }

    if (highWaterRel > this._limits.maxBytesPerFlow) {
      flow.limitExceeded = true;
      return emptyView(flow, 'limit-exceeded');
    }
    if (highWaterRel === 0) {
      return emptyView(flow, 'incomplete');
    }

    const totalLen = highWaterRel;
    const bytesArr = new Uint8Array(totalLen);
    const presentArr = new Uint8Array(totalLen);
    // -1 (via Int32Array) means "no provenance recorded yet" at this position.
    const provPacketIndex = new Int32Array(totalLen).fill(-1);
    const provPacketOffset = new Uint32Array(totalLen);
    // Enterprise step 3: identical retransmit / overlap copies — project patches to ALL occurrences.
    const altSpans: ByteProvenance[] = [];
    let conflict = false;

    for (const seg of sorted) {
      if (seg.payloadLength <= 0) continue;
      const pkt = data[seg.packetIndex];
      if (!pkt) continue;

      let altStart: number | null = null;
      let altPktOff = 0;
      let altLen = 0;
      const flushAlt = (): void => {
        if (altStart !== null && altLen > 0) {
          altSpans.push({
            assembledOffset: altStart,
            packetIndex: seg.packetIndex,
            packetOffset: altPktOff,
            length: altLen,
          });
        }
        altStart = null;
        altLen = 0;
      };

      for (let i = 0; i < seg.payloadLength; i++) {
        const streamOff = relativeSeq((seg.seq + i) >>> 0, baseSeq);
        if (streamOff >= totalLen) break; // segment exceeds the computed span — ignore tail

        const byte = pkt[seg.payloadOffset + i]!;
        if (presentArr[streamOff] === 1) {
          if (bytesArr[streamOff] !== byte) {
            conflict = true;
            flushAlt();
            continue;
          }
          // Same byte already present — record alternate occurrence (retransmit / identical overlap).
          const pktOff = seg.payloadOffset + i;
          if (altStart === null) {
            altStart = streamOff;
            altPktOff = pktOff;
            altLen = 1;
          } else if (streamOff === altStart + altLen && pktOff === altPktOff + altLen) {
            altLen++;
          } else {
            flushAlt();
            altStart = streamOff;
            altPktOff = pktOff;
            altLen = 1;
          }
          continue;
        }
        flushAlt();
        bytesArr[streamOff] = byte;
        presentArr[streamOff] = 1;
        provPacketIndex[streamOff] = seg.packetIndex;
        provPacketOffset[streamOff] = seg.payloadOffset + i;
      }
      flushAlt();
    }

    if (conflict) {
      return emptyView(flow, 'overlap-conflict');
    }

    let hasGap = false;
    for (let i = 0; i < totalLen; i++) {
      if (presentArr[i] === 0) {
        hasGap = true;
        break;
      }
    }

    // 'gap' when missing middle/tail; 'incomplete' kept as synonym for capture-phase overlays.
    const status: ReassemblyStatus = hasGap ? 'gap' : 'complete';
    return buildView(
      flow,
      { bytesArr, presentArr, provPacketIndex, provPacketOffset },
      totalLen,
      status,
      altSpans,
    );
  }
}

function tupleIdFromEndpoint(ep: FlowEndpoint): string {
  return `${ep.ipProto}:${ep.srcIp}:${ep.srcPort}->${ep.dstIp}:${ep.dstPort}`;
}

/** Unsigned 32-bit distance of seq ahead of base (wrap-safe). */
function relativeSeq(seq: number, base: number): number {
  return (seq - base) >>> 0;
}

/**
 * Choose ISN substitute that keeps all segment payloads in the smallest forward window.
 *
 * PF-07: O(n log n) replacement for the original O(n^2) "try every segment as base, measure
 * the resulting span" search (a real cost on long flows captured mid-stream, i.e. without a
 * SYN — the only case this function is used for). Segment sequence numbers form a 32-bit
 * modular ring; sorted by raw value, the correct base is the start of the segment right after
 * the single largest circular gap between one segment's end and the next segment's start —
 * that is the point least likely to be in the middle of real contiguous data, so anchoring
 * there (instead of, say, at the smallest raw seq) avoids an artificial blow-up in span when
 * the true stream wraps past 2^32. Segments that genuinely overlap in raw sequence space (not
 * wraparound) can make one gap look artificially large; the worst outcome from that is
 * picking a base that yields a larger `highWaterRel` than strictly necessary, which the
 * existing `maxBytesPerFlow` check already rejects safely — this never causes bad bytes to be
 * emitted, only a (rare, retransmission-heavy) capture to fail closed as 'limit-exceeded'
 * instead of reassembling.
 */
function pickBaseSeq(segments: readonly StoredSegment[]): number {
  if (segments.length === 1) return segments[0]!.seq;

  const sorted = [...segments].sort((a, b) => (a.seq >>> 0) - (b.seq >>> 0));
  let bestIndex = 0;
  let bestGap = -1;
  for (let i = 0; i < sorted.length; i++) {
    const cur = sorted[i]!;
    const next = sorted[(i + 1) % sorted.length]!;
    const curEnd = (cur.seq + cur.payloadLength) >>> 0;
    const gap = relativeSeq(next.seq, curEnd);
    if (gap > bestGap) {
      bestGap = gap;
      bestIndex = (i + 1) % sorted.length;
    }
  }
  return sorted[bestIndex]!.seq;
}

interface AssembledBytes {
  readonly bytesArr: Uint8Array;
  readonly presentArr: Uint8Array;
  readonly provPacketIndex: Int32Array;
  readonly provPacketOffset: Uint32Array;
}

function buildView(
  flow: TcpFlowAccumulator,
  assembled: AssembledBytes,
  totalLen: number,
  status: ReassemblyStatus,
  altSpans: readonly ByteProvenance[] = [],
): ReassembledView {
  const { bytesArr, presentArr, provPacketIndex, provPacketOffset } = assembled;
  const provenance: ByteProvenance[] = [];
  const packetIndices = new Set<number>();

  let i = 0;
  while (i < totalLen) {
    if (presentArr[i] === 0) {
      i++;
      continue;
    }
    const start = i;
    const startPacketIndex = provPacketIndex[i]!;
    const startPacketOffset = provPacketOffset[i]!;
    let j = i + 1;
    while (
      j < totalLen
      && presentArr[j] === 1
      && provPacketIndex[j] === startPacketIndex
      && provPacketOffset[j] === startPacketOffset + (j - start)
    ) {
      j++;
    }
    const len = j - start;
    provenance.push({
      assembledOffset: start,
      packetIndex: startPacketIndex,
      packetOffset: startPacketOffset,
      length: len,
    });
    packetIndices.add(startPacketIndex);
    i = j;
  }

  for (const alt of altSpans) {
    provenance.push(alt);
    packetIndices.add(alt.packetIndex);
  }

  return {
    bytes: bytesArr,
    provenance,
    transport: 'tcp',
    flowKey: flow.key,
    packetIndices: [...packetIndices].sort((a, b) => a - b),
    status,
  };
}

function emptyView(
  flow: TcpFlowAccumulator,
  status: ReassemblyStatus,
): ReassembledView {
  const packetIndices = [...new Set(flow.segments.map((s) => s.packetIndex))].sort((a, b) => a - b);
  return {
    bytes: new Uint8Array(0),
    provenance: [],
    transport: 'tcp',
    flowKey: flow.key,
    packetIndices,
    status,
  };
}
