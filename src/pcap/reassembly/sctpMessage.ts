/**
 * T17/V15 — bounded SCTP DATA / I-DATA complete-message reassembly (RFC 9260 / RFC 8260).
 *
 * Groups fragments by association direction (4-tuple + verification tag), stream, and
 * SSN (DATA) or MID (I-DATA). Only emits views for multi-fragment messages that become
 * complete within the capture; incomplete sets stay fail-closed on the per-packet path.
 */

import { directionalStreamKey } from './flowKey';
import type { ParsedSctpDataFragment } from './parsePacket';
import type {
  ByteProvenance,
  ReassembledView,
  ReassemblyLimits,
  SctpOwnedPayloadSpan,
} from './types';

interface MessageBucket {
  readonly key: string;
  readonly assocKey: string;
  readonly isIdata: boolean;
  readonly unordered: boolean;
  readonly streamId: number;
  readonly messageId: number;
  readonly fragments: ParsedSctpDataFragment[];
  ppid: number;
  limitExceeded: boolean;
  conflict: boolean;
}

export class SctpMessageReassembler {
  private readonly _messages = new Map<string, MessageBucket>();
  private readonly _assocMessageCount = new Map<string, number>();
  private readonly _assocCount = new Set<string>();
  private readonly _limits: ReassemblyLimits;
  private _limitExceeded = false;

  constructor(limits: ReassemblyLimits) {
    this._limits = limits;
  }

  get limitExceeded(): boolean {
    return this._limitExceeded;
  }

  ingest(fragment: ParsedSctpDataFragment): void {
    const assocKey = `${directionalStreamKey(fragment.endpoint, 0)}:vtag=${fragment.verificationTag >>> 0}`;
    if (!this._assocCount.has(assocKey)) {
      if (this._assocCount.size >= this._limits.maxSctpAssociations) {
        this._limitExceeded = true;
        return;
      }
      this._assocCount.add(assocKey);
    }

    const msgKey =
      `${assocKey}|${fragment.isIdata ? 'I' : 'D'}|`
      + `${fragment.unordered ? 'U' : 'O'}|sid=${fragment.streamId}|mid=${fragment.messageId >>> 0}`;

    let bucket = this._messages.get(msgKey);
    if (!bucket) {
      const count = this._assocMessageCount.get(assocKey) ?? 0;
      if (count >= this._limits.maxSctpMessagesPerAssociation) {
        this._limitExceeded = true;
        return;
      }
      this._assocMessageCount.set(assocKey, count + 1);
      bucket = {
        key: msgKey,
        assocKey,
        isIdata: fragment.isIdata,
        unordered: fragment.unordered,
        streamId: fragment.streamId,
        messageId: fragment.messageId,
        fragments: [],
        ppid: 0,
        limitExceeded: false,
        conflict: false,
      };
      this._messages.set(msgKey, bucket);
    }

    if (bucket.limitExceeded || bucket.conflict) return;

    if (bucket.fragments.length >= this._limits.maxSctpFragmentsPerMessage) {
      bucket.limitExceeded = true;
      this._limitExceeded = true;
      return;
    }

    // Duplicate TSN/FSN: identical bytes share provenance later; conflicting overlap fail-closed.
    const seq = fragment.isIdata ? fragment.fsn : fragment.tsn;
    const existing = bucket.fragments.find((f) =>
      fragment.isIdata ? f.fsn === seq : f.tsn === seq,
    );
    if (existing) {
      if (
        existing.userLength !== fragment.userLength
        || existing.beginning !== fragment.beginning
        || existing.ending !== fragment.ending
      ) {
        bucket.conflict = true;
      }
      // Identical retransmit — keep first occurrence for primary provenance; ignore duplicate.
      return;
    }

    if (fragment.beginning) {
      bucket.ppid = fragment.ppid;
    }

    bucket.fragments.push(fragment);
  }

  assembleAll(data: readonly Uint8Array[]): {
    readonly views: ReassembledView[];
    readonly completeSpans: Map<number, SctpOwnedPayloadSpan[]>;
  } {
    const views: ReassembledView[] = [];
    const completeSpans = new Map<number, SctpOwnedPayloadSpan[]>();

    for (const bucket of this._messages.values()) {
      const view = this.assembleBucket(bucket, data);
      if (!view) continue;
      if (view.status === 'limit-exceeded') {
        this._limitExceeded = true;
      }
      if (view.status !== 'complete' || !view.sctp) continue;

      views.push(view);
      for (const span of view.sctp.fragmentSpans) {
        const list = completeSpans.get(span.packetIndex) ?? [];
        list.push({ offset: span.offset, length: span.length });
        completeSpans.set(span.packetIndex, list);
      }
    }

    return { views, completeSpans };
  }

  private assembleBucket(
    bucket: MessageBucket,
    data: readonly Uint8Array[],
  ): ReassembledView | null {
    if (bucket.limitExceeded) {
      return emptySctpView(bucket.key, 'limit-exceeded');
    }
    if (bucket.conflict) {
      return emptySctpView(bucket.key, 'overlap-conflict');
    }
    if (bucket.fragments.length === 0) return null;

    const beginFrag = bucket.fragments.find((f) => f.beginning);
    if (!beginFrag) {
      return emptySctpView(bucket.key, 'incomplete', packetIndicesOf(bucket.fragments));
    }

    const sorted = [...bucket.fragments].sort((a, b) => {
      if (bucket.isIdata) {
        if (a.fsn !== b.fsn) return a.fsn < b.fsn ? -1 : 1;
      } else {
        const da = relativeTsn(a.tsn, beginFrag.tsn);
        const db = relativeTsn(b.tsn, beginFrag.tsn);
        if (da !== db) return da < db ? -1 : 1;
      }
      return a.captureOrder - b.captureOrder;
    });

    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    if (!first.beginning || !last.ending) {
      return emptySctpView(bucket.key, 'incomplete', packetIndicesOf(sorted));
    }

    // Contiguous FSN 0..n or contiguous TSN from the B fragment.
    if (bucket.isIdata) {
      for (let i = 0; i < sorted.length; i++) {
        if (sorted[i]!.fsn !== i) {
          return emptySctpView(bucket.key, 'gap', packetIndicesOf(sorted));
        }
      }
    } else {
      const base = first.tsn;
      for (let i = 0; i < sorted.length; i++) {
        if (sorted[i]!.tsn !== ((base + i) >>> 0)) {
          return emptySctpView(bucket.key, 'gap', packetIndicesOf(sorted));
        }
      }
    }

    let total = 0;
    for (const f of sorted) total += f.userLength;
    if (total > this._limits.maxSctpMessageBytes) {
      return emptySctpView(bucket.key, 'limit-exceeded', packetIndicesOf(sorted));
    }

    const bytes = new Uint8Array(total);
    const provenance: ByteProvenance[] = [];
    const fragmentSpans: Array<{
      packetIndex: number
      offset: number
      length: number
    }> = [];
    let assembledOffset = 0;
    const packetIndices = new Set<number>();

    for (const frag of sorted) {
      const pkt = data[frag.packetIndex];
      if (!pkt || frag.userLength < 0) {
        return emptySctpView(bucket.key, 'incomplete', packetIndicesOf(sorted));
      }
      if (frag.userOffset + frag.userLength > pkt.length) {
        return emptySctpView(bucket.key, 'incomplete', packetIndicesOf(sorted));
      }
      if (frag.userLength > 0) {
        bytes.set(pkt.subarray(frag.userOffset, frag.userOffset + frag.userLength), assembledOffset);
        provenance.push({
          assembledOffset,
          packetIndex: frag.packetIndex,
          packetOffset: frag.userOffset,
          length: frag.userLength,
        });
        fragmentSpans.push({
          packetIndex: frag.packetIndex,
          offset: frag.userOffset,
          length: frag.userLength,
        });
        assembledOffset += frag.userLength;
      }
      packetIndices.add(frag.packetIndex);
    }

    const ppid = first.beginning ? first.ppid : bucket.ppid;
    return {
      bytes,
      provenance,
      transport: 'sctp',
      flowKey: bucket.key,
      packetIndices: [...packetIndices].sort((a, b) => a - b),
      status: 'complete',
      ipProto: 132,
      sctp: {
        ppid,
        streamId: bucket.streamId,
        isIdata: bucket.isIdata,
        unordered: bucket.unordered,
        assocKey: bucket.assocKey,
        fragmentSpans,
      },
    };
  }
}

function relativeTsn(tsn: number, base: number): number {
  return (tsn - base) >>> 0;
}

function packetIndicesOf(frags: readonly ParsedSctpDataFragment[]): number[] {
  const set = new Set<number>();
  for (const f of frags) set.add(f.packetIndex);
  return [...set].sort((a, b) => a - b);
}

function emptySctpView(
  flowKey: string,
  status: ReassembledView['status'],
  packetIndices: readonly number[] = [],
): ReassembledView {
  return {
    bytes: new Uint8Array(0),
    provenance: [],
    transport: 'sctp',
    flowKey,
    packetIndices,
    status,
    ipProto: 132,
  };
}
