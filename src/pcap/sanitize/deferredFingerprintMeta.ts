/**
 * T-01.B — wire meta for fingerprint deferrals so journal carries `fingerprint` ops.
 */

import type {
  FingerprintField,
  TcpSeqFingerprintKind,
} from '../kernel/operations'
import type { DeferredPatchMeta } from './types'

export function deferredIpv4IdFingerprintMeta(
  packetIndex: number,
  srcIp: string,
  dstIp: string,
  ipProto: number,
  originalId: number,
): Partial<DeferredPatchMeta> {
  return {
    fallbackKind: 'binary-mask',
    protocol: 'ipv4-id',
    packetIndex,
    fingerprintField: 'ipv4-id',
    srcIp,
    dstIp,
    ipProto,
    originalU16: originalId & 0xffff,
    reasonCode: 'fingerprint:ipv4-id',
  }
}

export function deferredFlowLabelFingerprintMeta(
  packetIndex: number,
  srcIp: string,
  dstIp: string,
  headerByte0: number,
  headerByte1: number,
  originalLabel: number,
): Partial<DeferredPatchMeta> {
  return {
    fallbackKind: 'binary-mask',
    protocol: 'ipv6-flow',
    packetIndex,
    fingerprintField: 'flow-label',
    srcIp,
    dstIp,
    flowHeaderByte0: headerByte0,
    flowHeaderByte1: headerByte1,
    originalU32: originalLabel & 0xfffff,
    reasonCode: 'fingerprint:ipv6-flow',
  }
}

export function deferredTcpU32FingerprintMeta(
  packetIndex: number,
  srcIp: string,
  dstIp: string,
  srcPort: number,
  dstPort: number,
  tcpSeqKind: TcpSeqFingerprintKind,
  originalU32: number,
): Partial<DeferredPatchMeta> {
  return {
    fallbackKind: 'binary-mask',
    protocol: 'tcp-seq',
    packetIndex,
    fingerprintField: 'tcp-u32',
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    tcpSeqKind,
    originalU32: originalU32 >>> 0,
    reasonCode: `fingerprint:tcp-${tcpSeqKind}`,
  }
}

/** @internal — assert field wiring in tests. */
export type { FingerprintField }
