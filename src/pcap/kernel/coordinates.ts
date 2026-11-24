/**
 * SourceSpanMap — logical message ranges → ordered physical packet/file segments.
 * Packet-local offsets are never confused with capture-wide file offsets.
 */

export interface PhysicalSegment {
  readonly sourceId: string
  readonly packetIndex: number
  readonly packetNumber: number
  /** Offset within the captured packet payload. */
  readonly packetOffset: number
  readonly length: number
  /** File offset of the payload byte (descriptor.dataOffset + packetOffset). */
  readonly fileOffset: number
}

export interface LogicalSpan {
  readonly logicalMessageId: number
  readonly logicalOffset: number
  readonly length: number
  readonly segments: readonly PhysicalSegment[]
}

export class SourceSpanMap {
  private readonly spans: LogicalSpan[] = []

  add(span: LogicalSpan): void {
    this.spans.push(span)
  }

  /** All physical segments covering a logical range (retransmission-aware). */
  segmentsFor(logicalMessageId: number, logicalOffset: number, length: number): PhysicalSegment[] {
    const out: PhysicalSegment[] = []
    for (const span of this.spans) {
      if (span.logicalMessageId !== logicalMessageId) continue
      const overlapStart = Math.max(span.logicalOffset, logicalOffset)
      const overlapEnd = Math.min(span.logicalOffset + span.length, logicalOffset + length)
      if (overlapStart >= overlapEnd) continue
      const rel = overlapStart - span.logicalOffset
      const take = overlapEnd - overlapStart
      for (const seg of span.segments) {
        if (rel + take <= 0 || rel >= seg.length) continue
        const segRel = Math.max(0, rel)
        const segTake = Math.min(seg.length - segRel, take)
        out.push({
          sourceId: seg.sourceId,
          packetIndex: seg.packetIndex,
          packetNumber: seg.packetNumber,
          packetOffset: seg.packetOffset + segRel,
          length: segTake,
          fileOffset: seg.fileOffset + segRel,
        })
      }
    }
    return out
  }

  get all(): readonly LogicalSpan[] {
    return this.spans
  }
}
