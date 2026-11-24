/**
 * T30 — CoAP Block2 transfer tracking across UDP datagrams (RFC 7252 / RFC 7959).
 * Finalize pass upgrades coverage when all blocks are present in the capture.
 */

import type { LayerCoverage } from '../types.ts'
import type { PacketDiscoveryResult } from '../../discovery/types.ts'

export interface CoapBlock2Segment {
  readonly packetIndex: number
  readonly blockNum: number
  readonly more: boolean
  readonly payloadOffset: number
  readonly payloadLength: number
  readonly blockOptionOffset: number
  readonly blockOptionLength: number
}

interface TransferState {
  readonly exchangeKey: string
  readonly segments: Map<number, CoapBlock2Segment>
  expectedFinalBlock: number | null
}

export class CoapBlock2Session {
  private readonly transfers = new Map<string, TransferState>()

  recordSegment(exchangeKey: string, segment: CoapBlock2Segment): void {
    let transfer = this.transfers.get(exchangeKey)
    if (!transfer) {
      transfer = { exchangeKey, segments: new Map(), expectedFinalBlock: null }
      this.transfers.set(exchangeKey, transfer)
    }
    transfer.segments.set(segment.blockNum, segment)
    if (!segment.more) {
      transfer.expectedFinalBlock = segment.blockNum
    }
  }

  transferIsComplete(transfer: TransferState): boolean {
    if (transfer.expectedFinalBlock === null) return false
    const need = transfer.expectedFinalBlock + 1
    for (let i = 0; i < need; i++) {
      if (!transfer.segments.has(i)) return false
    }
    return true
  }

  /** After all packets are sanitized, fix payload coverage for Block2 transfers. */
  finalizeDiscovery(packetDiscovery: PacketDiscoveryResult[]): void {
    for (const transfer of this.transfers.values()) {
      const complete = this.transferIsComplete(transfer)
      const segments = [...transfer.segments.values()].sort((a, b) => a.blockNum - b.blockNum)
      const multi =
        segments.length > 1
        || (segments[0] !== undefined && (segments[0].more || segments[0].blockNum > 0))
      if (!multi) continue

      for (const seg of segments) {
        const pd = packetDiscovery.find((row) => row.packetIndex === seg.packetIndex)
        if (!pd) continue
        const nextCoverage = patchPayloadCoverage(pd.coverage, seg.payloadOffset, seg.payloadLength, complete)
        const nextIssues = [...pd.issues]
        removeIssue(nextIssues, 'coap-block2-pending')
        if (complete) {
          if (!nextIssues.includes('coap-block2-reassembled')) nextIssues.push('coap-block2-reassembled')
        } else if (!nextIssues.includes('coap-block2-incomplete')) {
          nextIssues.push('coap-block2-incomplete')
        }
        Object.assign(pd, { coverage: nextCoverage, issues: nextIssues })
      }
    }
  }
}

function patchPayloadCoverage(
  coverage: readonly LayerCoverage[],
  payloadOffset: number,
  payloadLength: number,
  complete: boolean,
): LayerCoverage[] {
  const payloadEnd = payloadOffset + payloadLength
  return coverage.map((span) => {
    if (span.offset < payloadOffset || span.offset + span.length > payloadEnd) return span
    if (span.status !== 'requires-reassembly') return span
    return {
      ...span,
      status: complete
        ? span.protocol.includes('json') || span.protocol.includes('body')
          ? 'redacted'
          : 'covered'
        : 'requires-reassembly',
    }
  })
}

function removeIssue(issues: string[], code: string): void {
  const at = issues.indexOf(code)
  if (at >= 0) issues.splice(at, 1)
}

/** RFC 7959 Block1/Block2 option value (baseline + 8-bit extended NUM). */
export function parseCoapBlockOption(value: Uint8Array): {
  blockNum: number
  more: boolean
  szx: number
} | null {
  if (value.length === 0) return null
  const first = value[0]!
  const numNibble = (first >> 4) & 0x0f
  const more = ((first >> 3) & 1) === 1
  const szx = first & 0x07
  if (numNibble === 0x0f) {
    if (value.length < 2) return null
    return { blockNum: value[1]!, more, szx }
  }
  return { blockNum: numNibble, more, szx }
}

export function coapBlock2ExchangeKey(input: {
  readonly srcIp?: string
  readonly dstIp?: string
  readonly srcPort: number
  readonly dstPort: number
  readonly token: Uint8Array
  readonly uriPathFingerprint: string
}): string {
  const aIp = input.srcIp ?? '?'
  const bIp = input.dstIp ?? '?'
  const flow =
    aIp < bIp || (aIp === bIp && input.srcPort <= input.dstPort)
      ? `${aIp}:${input.srcPort}<->${bIp}:${input.dstPort}`
      : `${bIp}:${input.dstPort}<->${aIp}:${input.srcPort}`
  const tokenHex = hexBytes(input.token)
  return `coap-block2:${flow}:${tokenHex}:${input.uriPathFingerprint}`
}

function hexBytes(bytes: Uint8Array): string {
  if (bytes.length === 0) return '-'
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0')
  }
  return out
}

export function uriPathFingerprintFromOptions(uriPathParts: readonly Uint8Array[]): string {
  if (uriPathParts.length === 0) return '-'
  let h = 0
  for (const part of uriPathParts) {
    for (let i = 0; i < part.length; i++) {
      h = (h * 31 + part[i]!) >>> 0
    }
    h = (h * 31 + 0x2f) >>> 0
  }
  return h.toString(16)
}
