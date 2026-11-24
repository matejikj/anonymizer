/**
 * Bounded IPv4/IPv6 fragment reassembly (step 9 / CF-05).
 */

import { ipv4FragmentKey, ipv6FragmentKey } from './flowKey';
import type { ByteProvenance, ReassembledView, ReassemblyLimits, ReassemblyStatus } from './types';
import type { ParsedIpv4Fragment, ParsedIpv6Fragment } from './parsePacket';

interface FragmentPiece {
  readonly offset: number;
  readonly packetIndex: number;
  readonly payloadOffset: number;
  readonly payloadLength: number;
  readonly moreFragments: boolean;
  readonly captureOrder: number;
}

interface FragmentGroup {
  readonly key: string;
  readonly ipProto: number;
  readonly pieces: FragmentPiece[];
  limitExceeded: boolean;
}

export class IpFragmentReassembler {
  private readonly _groups = new Map<string, FragmentGroup>();
  private _groupCount = 0;
  private _captureOrder = 0;
  private readonly _limits: ReassemblyLimits;

  constructor(limits: ReassemblyLimits) {
    this._limits = limits;
  }

  ingestIpv4(frag: ParsedIpv4Fragment, interfaceId = 0, sectionIndex = 0): void {
    const key = ipv4FragmentKey(
      frag.srcIp,
      frag.dstIp,
      frag.ipProto,
      frag.identification,
      interfaceId,
      sectionIndex,
    );
    this.ingest(key, frag.ipProto, {
      offset: frag.fragmentOffset,
      packetIndex: frag.packetIndex,
      payloadOffset: frag.payloadOffset,
      payloadLength: frag.payloadLength,
      moreFragments: frag.moreFragments,
      captureOrder: this._captureOrder++,
    });
  }

  ingestIpv6(frag: ParsedIpv6Fragment, interfaceId = 0, sectionIndex = 0): void {
    const key = ipv6FragmentKey(
      frag.srcIp,
      frag.dstIp,
      frag.nextHeader,
      frag.identification,
      interfaceId,
      sectionIndex,
    );
    this.ingest(key, frag.nextHeader, {
      offset: frag.fragmentOffset,
      packetIndex: frag.packetIndex,
      payloadOffset: frag.payloadOffset,
      payloadLength: frag.payloadLength,
      moreFragments: frag.moreFragments,
      captureOrder: this._captureOrder++,
    });
  }

  assembleAll(data: readonly Uint8Array[]): ReassembledView[] {
    const out: ReassembledView[] = [];
    for (const group of this._groups.values()) {
      const view = this.assembleGroup(group, data);
      if (view) out.push(view);
    }
    return out;
  }

  private ingest(key: string, ipProto: number, piece: FragmentPiece): void {
    let group = this._groups.get(key);
    if (!group) {
      if (this._groupCount >= this._limits.maxFragmentGroups) {
        group = { key, ipProto, pieces: [], limitExceeded: true };
      } else {
        this._groupCount++;
        group = { key, ipProto, pieces: [], limitExceeded: false };
      }
      this._groups.set(key, group);
    }
    if (!group.limitExceeded) {
      group.pieces.push(piece);
    }
  }

  private assembleGroup(group: FragmentGroup, data: readonly Uint8Array[]): ReassembledView | null {
    if (group.pieces.length === 0) return null;

    const packetIndices = [...new Set(group.pieces.map((p) => p.packetIndex))].sort((a, b) => a - b);
    const transport = group.ipProto === 6 ? 'tcp' : 'udp';

    if (group.limitExceeded) {
      return {
        bytes: new Uint8Array(0),
        provenance: [],
        transport,
        flowKey: group.key,
        packetIndices,
        status: 'limit-exceeded',
        ipProto: group.ipProto,
      };
    }

    const sorted = [...group.pieces].sort((a, b) => {
      if (a.offset !== b.offset) return a.offset - b.offset;
      return a.captureOrder - b.captureOrder;
    });

    let totalLen = 0;
    let overlapConflict = false;
    const coverage = new Array<{ offset: number; length: number; piece: FragmentPiece }>();

    for (const piece of sorted) {
      const end = piece.offset + piece.payloadLength;
      if (end > this._limits.maxDatagramBytes) {
        return {
          bytes: new Uint8Array(0),
          provenance: [],
          transport,
          flowKey: group.key,
          packetIndices,
          status: 'limit-exceeded',
          ipProto: group.ipProto,
        };
      }

      for (const existing of coverage) {
        const existingEnd = existing.offset + existing.length;
        if (piece.offset < existingEnd && end > existing.offset) {
          const pieceData = data[piece.packetIndex];
          const existData = data[existing.piece.packetIndex];
          if (!pieceData || !existData) continue;
          const overlapStart = Math.max(piece.offset, existing.offset);
          const overlapEnd = Math.min(end, existingEnd);
          for (let o = overlapStart; o < overlapEnd; o++) {
            const a = pieceData[piece.payloadOffset + (o - piece.offset)]!;
            const b = existData[existing.piece.payloadOffset + (o - existing.offset)]!;
            if (a !== b) overlapConflict = true;
          }
        }
      }

      coverage.push({ offset: piece.offset, length: piece.payloadLength, piece });
      totalLen = Math.max(totalLen, end);
    }

    if (overlapConflict) {
      return {
        bytes: new Uint8Array(0),
        provenance: [],
        transport,
        flowKey: group.key,
        packetIndices,
        status: 'overlap-conflict',
        ipProto: group.ipProto,
      };
    }

    const hasGap = (() => {
      if (sorted.length === 0) return true;
      if (sorted[0]!.offset !== 0) return true;
      let expected = 0;
      for (const piece of sorted) {
        if (piece.offset > expected) return true;
        expected = Math.max(expected, piece.offset + piece.payloadLength);
      }
      return false;
    })();

    const lastPiece = sorted[sorted.length - 1]!;
    const complete = !hasGap && !lastPiece.moreFragments;
    const status: ReassemblyStatus = complete
      ? 'complete'
      : hasGap
        ? 'gap'
        : 'incomplete';

    if (!complete) {
      return {
        bytes: new Uint8Array(0),
        provenance: [],
        transport,
        flowKey: group.key,
        packetIndices,
        status,
        ipProto: group.ipProto,
      };
    }

    const bytes = new Uint8Array(totalLen);
    const provenance: ByteProvenance[] = [];

    for (const piece of sorted) {
      const pkt = data[piece.packetIndex];
      if (!pkt) continue;
      bytes.set(pkt.subarray(piece.payloadOffset, piece.payloadOffset + piece.payloadLength), piece.offset);
      provenance.push({
        assembledOffset: piece.offset,
        packetIndex: piece.packetIndex,
        packetOffset: piece.payloadOffset,
        length: piece.payloadLength,
      });
    }

    return {
      bytes,
      provenance,
      transport,
      flowKey: group.key,
      packetIndices,
      status: 'complete',
      ipProto: group.ipProto,
    };
  }
}
