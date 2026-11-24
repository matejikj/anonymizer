/**
 * Session-scoped fingerprint remapping (step 7).
 * TCP SEQ offsets, IPv4 ID aliases, IPv6 flow labels — mutable across packets
 * within one plan build; never serialized to reports.
 *
 * When constructed with an opaque seed (plan `timestampAnchorSeed` / generation
 * entropy), allocation is deterministic for that seed so plan builds stay pure.
 */

import { allocateExclusiveId, allocateExclusiveIdSparse } from './exclusiveIdAllocation'
import { directionalStreamKey } from '../reassembly/flowKey'
import { expandSeedToEntropy, freshEntropy } from './seedEntropy'

const IPV4_ID_SPACE = 0x10000
const FLOW_LABEL_SPACE = 0x100000 // 20-bit
const RANDOM_RETRY = 32
const ENTROPY_BYTES = 1024

export class FingerprintSession {
  private readonly _seqOffset = new Map<string, number>()
  private readonly _ipv4Id = new Map<string, number>()
  private readonly _usedIpv4Id = new Set<number>()
  private readonly _flowLabel = new Map<string, number>()
  private readonly _usedFlowLabel = new Set<number>()
  private readonly _random: Uint8Array
  private readonly _seeded: boolean
  private _randomOffset = 0

  constructor(seed?: string) {
    this._seeded = typeof seed === 'string' && seed.length > 0
    this._random = this._seeded
      ? expandSeedToEntropy(seed!, ENTROPY_BYTES)
      : freshEntropy(ENTROPY_BYTES)
  }

  /**
   * Per-direction SEQ space offset (mod 2^32).
   * ACK/SACK on the reverse path use the peer direction's offset.
   */
  tcpSeqOffset(directionKey: string): number {
    const existing = this._seqOffset.get(directionKey)
    if (existing !== undefined) return existing
    // Non-zero offset so ISN never stays at original (reject 0).
    let offset = this.nextU32()
    if (offset === 0) offset = 1
    this._seqOffset.set(directionKey, offset)
    return offset
  }

  tcpSeqOffsetForEndpoint(ep: {
    srcIp: string
    dstIp: string
    srcPort: number
    dstPort: number
  }): { forward: number; reverse: number; forwardKey: string; reverseKey: string } {
    const forwardKey = directionalStreamKey({
      ipProto: 6,
      srcIp: ep.srcIp,
      dstIp: ep.dstIp,
      srcPort: ep.srcPort,
      dstPort: ep.dstPort,
    })
    const reverseKey = directionalStreamKey({
      ipProto: 6,
      srcIp: ep.dstIp,
      dstIp: ep.srcIp,
      srcPort: ep.dstPort,
      dstPort: ep.srcPort,
    })
    return {
      forward: this.tcpSeqOffset(forwardKey),
      reverse: this.tcpSeqOffset(reverseKey),
      forwardKey,
      reverseKey,
    }
  }

  /** Stable IPv4 ID remap so fragments of the same datagram stay joinable. */
  mapIpv4Id(srcIp: string, dstIp: string, ipProto: number, originalId: number): number {
    const key = `${srcIp}|${dstIp}|${ipProto}|${originalId}`
    const existing = this._ipv4Id.get(key)
    if (existing !== undefined) return existing
    const id = originalId & 0xffff
    const mapped = allocateExclusiveId({
      used: this._usedIpv4Id,
      min: 0,
      max: IPV4_ID_SPACE - 1,
      reject: (n) => n === id,
      nextRandom: () => this.nextU16(),
      randomAttempts: RANDOM_RETRY,
    })
    const alias = mapped === null ? (id === 0 ? 1 : 0) : mapped
    this._usedIpv4Id.add(alias)
    this._ipv4Id.set(key, alias)
    return alias
  }

  /** Stable 20-bit flow label within a unidirectional IP pair. */
  mapFlowLabel(srcIp: string, dstIp: string, originalLabel: number): number {
    const label = originalLabel & 0xfffff
    const key = `${srcIp}|${dstIp}|${label}`
    const existing = this._flowLabel.get(key)
    if (existing !== undefined) return existing
    const mapped = allocateExclusiveIdSparse({
      used: this._usedFlowLabel,
      space: FLOW_LABEL_SPACE,
      reject: (n) => (n & 0xfffff) === label,
      nextRandom: () => this.nextU32(),
      randomAttempts: RANDOM_RETRY,
    })
    const alias = mapped === null ? (label === 0 ? 1 : 0) : (mapped & 0xfffff)
    this._usedFlowLabel.add(alias)
    this._flowLabel.set(key, alias)
    return alias
  }

  private nextU16(): number {
    return ((this.nextByte() << 8) | this.nextByte()) >>> 0
  }

  private nextU32(): number {
    return (
      ((this.nextByte() << 24) | (this.nextByte() << 16) | (this.nextByte() << 8) | this.nextByte())
      >>> 0
    )
  }

  private nextByte(): number {
    if (this._randomOffset >= this._random.length) {
      this._randomOffset = 0
      if (this._seeded) {
        // Deterministic wrap — same seed yields the same infinite stream.
      } else {
        this._random.set(freshEntropy(this._random.length))
      }
    }
    return this._random[this._randomOffset++]!
  }
}

export function addU32Mod(value: number, offset: number): number {
  return (value + offset) >>> 0
}

export function u32ToBytes(value: number): Uint8Array {
  const v = value >>> 0
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff])
}

export function readU32(data: Uint8Array, offset: number): number {
  return (
    ((data[offset]! << 24) >>> 0)
    + (data[offset + 1]! << 16)
    + (data[offset + 2]! << 8)
    + data[offset + 3]!
  )
}
