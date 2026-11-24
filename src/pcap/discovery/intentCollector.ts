/**
 * Collects transformation intents during discovery (Stage 8 / T06).
 */

import type { IdentityCategory } from '../../mapping/identityCategories'
import type { WireRepresentationConstraint } from '../../mapping/types'
import { canonicalizeIdentity, defaultIdentityWireConstraint } from '../../mapping/canonicalize'
import {
  mergePortFlowHints,
  type PortFlowHint,
} from '../anonymization/portPolicy.ts'
import type {
  DropRecordIntent,
  EntityReplacementIntent,
  FixedRedactionIntent,
  MaskRangeIntent,
  TransformationIntent,
  TruncationIntent,
} from './types'

export class IntentCollector {
  private readonly _intents: TransformationIntent[] = []
  private readonly _portFlowHints = new Map<string, PortFlowHint>()
  /** T06 — SDP media mates (`udp/rtp` → `udp/rtcp`). */
  private readonly _mediaPortPairs = new Map<string, string>()

  get intents(): readonly TransformationIntent[] {
    return this._intents
  }

  get portFlowHints(): ReadonlyMap<string, PortFlowHint> {
    return this._portFlowHints
  }

  get mediaPortPairs(): ReadonlyMap<string, string> {
    return this._mediaPortPairs
  }

  /**
   * T06 — content-recognized signaling/media role for a port identity.
   * Signaling wins over media when the same port is hinted twice.
   */
  recordPortFlowHint(rawCanonical: string, flow: PortFlowHint): void {
    const canonical = canonicalizeIdentity('port', rawCanonical)
    if (canonical === null) return
    const merged = mergePortFlowHints(this._portFlowHints.get(canonical), flow)
    if (merged) this._portFlowHints.set(canonical, merged)
  }

  /** T06 revision — explicit RTP/RTCP mate from SDP (incl. non-+1 a=rtcp / mux). */
  recordMediaPortPair(rtpCanonicalRaw: string, rtcpCanonicalRaw: string): void {
    const rtp = canonicalizeIdentity('port', rtpCanonicalRaw)
    const rtcp = canonicalizeIdentity('port', rtcpCanonicalRaw)
    if (rtp === null || rtcp === null) return
    this._mediaPortPairs.set(rtp, rtcp)
    this._mediaPortPairs.set(rtcp, rtp)
    this.recordPortFlowHint(rtp, 'rtp')
    this.recordPortFlowHint(rtcp, rtp === rtcp ? 'rtp' : 'rtcp')
  }

  recordEntityReplacement(
    packetIndex: number,
    offset: number,
    category: IdentityCategory,
    rawCanonical: string,
    byteLength: number,
    constraint?: WireRepresentationConstraint,
    originalSpelling?: string,
  ): void {
    const spelling = originalSpelling ?? rawCanonical
    const canonical = canonicalizeIdentity(category, rawCanonical)
    if (canonical === null) return
    const c = constraint ?? defaultIdentityWireConstraint(category, canonical, spelling)
    if (c === null) return
    const intent: EntityReplacementIntent = {
      kind: 'entity-replacement',
      packetIndex,
      offset,
      byteLength,
      category,
      canonical,
      constraint: c,
      originalSpelling: spelling !== canonical ? spelling : undefined,
    }
    this._intents.push(intent)
  }

  recordFixedRedaction(packetIndex: number, offset: number, byteLength: number): void {
    const intent: FixedRedactionIntent = {
      kind: 'fixed-redaction',
      packetIndex,
      offset,
      byteLength,
    }
    this._intents.push(intent)
  }

  recordTruncation(packetIndex: number, truncatedLength: number): void {
    const intent: TruncationIntent = {
      kind: 'truncation',
      packetIndex,
      truncatedLength,
    }
    this._intents.push(intent)
  }

  recordDrop(packetIndex: number): void {
    const intent: DropRecordIntent = {
      kind: 'drop-record',
      packetIndex,
    }
    this._intents.push(intent)
  }

  recordMaskRange(
    packetIndex: number,
    offset: number,
    byteLength: number,
    reason: string,
    protocol: string,
  ): void {
    if (byteLength <= 0) return
    const intent: MaskRangeIntent = {
      kind: 'mask-range',
      packetIndex,
      offset,
      byteLength,
      reason,
      protocol,
    }
    this._intents.push(intent)
  }
}
