/**
 * T42 — ONC RPC (RFC 5531) + XDR helpers shared by portmapper and NFS.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapAsciiIdentity, maskBytes, readU32be } from './common.ts'

const MSG_CALL = 0
const MSG_REPLY = 1
const AUTH_SYS = 1
const AUTH_NONE = 0
const RPCSEC_GSS = 6

export function looksLikeOncRpcCall(
  buffer: Uint8Array,
  offset: number,
  length: number,
  expectProg?: number,
): boolean {
  // UDP: xid + msg_type + rpcvers + prog …
  if (length < 24) return false
  const msgType = readU32be(buffer, offset + 4)
  if (msgType !== MSG_CALL && msgType !== MSG_REPLY) return false
  if (msgType === MSG_CALL) {
    const rpcvers = readU32be(buffer, offset + 8)
    if (rpcvers !== 2) return false
    if (expectProg !== undefined) {
      const prog = readU32be(buffer, offset + 12)
      if (prog !== expectProg) return false
    }
  }
  return true
}

/**
 * Strip TCP record-marking fragments into a contiguous view (single last fragment only
 * in baseline — multi-fragment reassembly is identify+mask of whole payload).
 */
export function peelTcpRecordMark(
  buffer: Uint8Array,
  offset: number,
  length: number,
): { bodyOff: number; bodyLen: number; markCovered: boolean } | null {
  if (length < 4) return null
  const mark = readU32be(buffer, offset)
  const last = (mark & 0x8000_0000) !== 0
  const fragLen = mark & 0x7fff_ffff
  if (!last || fragLen + 4 > length || fragLen < 24) {
    // Multi-fragment or truncated — caller masks whole
    return null
  }
  return { bodyOff: offset + 4, bodyLen: fragLen, markCovered: true }
}

export function sanitizeOncRpcMessage(input: {
  readonly buffer: Uint8Array
  readonly offset: number
  readonly length: number
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly intents?: IntentCollector
  readonly packetIndex: number
  readonly highPrivacy: boolean
  readonly transport: 'tcp' | 'udp'
  readonly protocol: string
  readonly onCallBody?: (
    bodyOff: number,
    bodyLen: number,
    prog: number,
    vers: number,
    proc: number,
  ) => void
  readonly onReplyBody?: (
    bodyOff: number,
    bodyLen: number,
    prog: number,
    vers: number,
    proc: number,
  ) => void
}): AppLayerResult | null {
  const {
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    transport,
    protocol,
    onCallBody,
    onReplyBody,
  } = input
  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []

  let msgOff = offset
  let msgLen = length
  if (transport === 'tcp') {
    const peeled = peelTcpRecordMark(buffer, offset, length)
    if (!peeled) {
      maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-rm`, protocol)
      coverage.push({
        protocol: `${protocol}-body`,
        offset,
        length,
        status: 'redacted',
      })
      issues.push(`${protocol}-tcp-record-fragmented`)
      return { coverage, issues }
    }
    coverage.push({ protocol, offset, length: 4, status: 'covered' })
    msgOff = peeled.bodyOff
    msgLen = peeled.bodyLen
  }

  if (msgLen < 24 || !looksLikeOncRpcCall(buffer, msgOff, msgLen)) {
    return coverage.length > 0 ? { coverage, issues } : null
  }

  const msgType = readU32be(buffer, msgOff + 4)
  coverage.push({ protocol, offset: msgOff, length: 8, status: 'covered' }) // xid + type

  let cursor = msgOff + 8
  let prog = 0
  let vers = 0
  let proc = 0

  if (msgType === MSG_CALL) {
    if (cursor + 16 > msgOff + msgLen) return { coverage, issues }
    const rpcvers = readU32be(buffer, cursor)
    prog = readU32be(buffer, cursor + 4)
    vers = readU32be(buffer, cursor + 8)
    proc = readU32be(buffer, cursor + 12)
    coverage.push({ protocol, offset: cursor, length: 16, status: 'covered' })
    cursor += 16
    if (rpcvers !== 2) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        cursor,
        msgOff + msgLen - cursor,
        `${protocol}-rpcvers`,
        protocol,
      )
      return { coverage, issues }
    }
    const cred = sanitizeOpaqueAuth(
      buffer,
      cursor,
      msgOff + msgLen - cursor,
      collector,
      mapping,
      intents,
      packetIndex,
      protocol,
      coverage,
      issues,
    )
    cursor = cred.next
    const verf = sanitizeOpaqueAuth(
      buffer,
      cursor,
      msgOff + msgLen - cursor,
      collector,
      mapping,
      intents,
      packetIndex,
      protocol,
      coverage,
      issues,
    )
    cursor = verf.next
    const bodyLen = msgOff + msgLen - cursor
    if (bodyLen > 0) {
      onCallBody?.(cursor, bodyLen, prog, vers, proc)
      if (!onCallBody) {
        maskBytes(collector, intents, packetIndex, cursor, bodyLen, `${protocol}-args`, protocol)
        coverage.push({
          protocol: `${protocol}-body`,
          offset: cursor,
          length: bodyLen,
          status: 'redacted',
        })
      }
    }
  } else {
    // REPLY: verifier + accept/reject status …
    const verf = sanitizeOpaqueAuth(
      buffer,
      cursor,
      msgOff + msgLen - cursor,
      collector,
      mapping,
      intents,
      packetIndex,
      protocol,
      coverage,
      issues,
    )
    cursor = verf.next
    if (cursor + 4 > msgOff + msgLen) return { coverage, issues }
    const replyStat = readU32be(buffer, cursor)
    coverage.push({ protocol, offset: cursor, length: 4, status: 'covered' })
    cursor += 4
    if (replyStat === 0 /* MSG_ACCEPTED */ && cursor + 4 <= msgOff + msgLen) {
      const acceptStat = readU32be(buffer, cursor)
      coverage.push({ protocol, offset: cursor, length: 4, status: 'covered' })
      cursor += 4
      if (acceptStat === 0 /* SUCCESS */) {
        const bodyLen = msgOff + msgLen - cursor
        if (bodyLen > 0) {
          onReplyBody?.(cursor, bodyLen, prog, vers, proc)
          if (!onReplyBody) {
            maskBytes(
              collector,
              intents,
              packetIndex,
              cursor,
              bodyLen,
              `${protocol}-results`,
              protocol,
            )
            coverage.push({
              protocol: `${protocol}-body`,
              offset: cursor,
              length: bodyLen,
              status: 'redacted',
            })
          }
        }
      } else if (msgOff + msgLen > cursor) {
        coverage.push({
          protocol,
          offset: cursor,
          length: msgOff + msgLen - cursor,
          status: 'covered',
        })
      }
    } else if (msgOff + msgLen > cursor) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        cursor,
        msgOff + msgLen - cursor,
        `${protocol}-reject`,
        protocol,
      )
      coverage.push({
        protocol: `${protocol}-body`,
        offset: cursor,
        length: msgOff + msgLen - cursor,
        status: 'redacted',
      })
    }
  }

  coverage.push({ protocol, offset: msgOff, length: msgLen, status: 'covered' })
  return { coverage, issues }
}

function sanitizeOpaqueAuth(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): { next: number } {
  if (length < 8) return { next: offset + length }
  const flavor = readU32be(buffer, offset)
  const bodyLen = readU32be(buffer, offset + 4)
  const padded = (bodyLen + 3) & ~3
  if (8 + padded > length) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-auth`, protocol)
    coverage.push({
      protocol: `${protocol}-auth`,
      offset,
      length,
      status: 'redacted',
    })
    return { next: offset + length }
  }
  coverage.push({ protocol, offset, length: 8, status: 'covered' })
  const bodyOff = offset + 8
  if (flavor === AUTH_NONE || bodyLen === 0) {
    coverage.push({ protocol, offset: bodyOff, length: padded, status: 'covered' })
  } else if (flavor === AUTH_SYS) {
    sanitizeAuthSys(
      buffer,
      bodyOff,
      bodyLen,
      collector,
      mapping,
      intents,
      packetIndex,
      protocol,
      coverage,
    )
    if (padded > bodyLen) {
      coverage.push({
        protocol,
        offset: bodyOff + bodyLen,
        length: padded - bodyLen,
        status: 'covered',
      })
    }
  } else if (flavor === RPCSEC_GSS) {
    // Integrity wrap may be plaintext; privacy unknown — mask body (T23 Kerberos child later)
    maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, `${protocol}-gss`, protocol)
    coverage.push({
      protocol: `${protocol}-auth`,
      offset: bodyOff,
      length: bodyLen,
      status: 'redacted',
    })
    issues.push(`${protocol}-rpcsec-gss-masked`)
    if (padded > bodyLen) {
      coverage.push({
        protocol,
        offset: bodyOff + bodyLen,
        length: padded - bodyLen,
        status: 'covered',
      })
    }
  } else {
    maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, `${protocol}-auth`, protocol)
    coverage.push({
      protocol: `${protocol}-auth`,
      offset: bodyOff,
      length: bodyLen,
      status: 'redacted',
    })
  }
  return { next: offset + 8 + padded }
}

function sanitizeAuthSys(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  coverage: AppLayerResult['coverage'],
): void {
  // stamp(4) + machinename (len+pad) + uid + gid + gids[]
  if (length < 8) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-authsys`, protocol)
    return
  }
  coverage.push({ protocol, offset, length: 4, status: 'covered' }) // stamp
  let p = offset + 4
  const end = offset + length
  if (p + 4 > end) return
  const nameLen = readU32be(buffer, p)
  p += 4
  const namePad = (nameLen + 3) & ~3
  if (p + namePad > end) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-authsys`, protocol)
    return
  }
  if (nameLen > 0) {
    mapAsciiIdentity(
      buffer,
      p,
      nameLen,
      'hostname',
      collector,
      mapping,
      intents,
      packetIndex,
      protocol,
    )
    coverage.push({
      protocol: `${protocol}-auth`,
      offset: p,
      length: nameLen,
      status: 'covered',
    })
  }
  p += namePad
  // uid, gid — preserve 0 (root); map others as opaque fixed-width hex via mask of non-zero
  if (p + 8 > end) return
  const uid = readU32be(buffer, p)
  const gid = readU32be(buffer, p + 4)
  for (const [off, id] of [
    [p, uid],
    [p + 4, gid],
  ] as const) {
    if (id === 0) {
      coverage.push({ protocol, offset: off, length: 4, status: 'covered' })
    } else {
      // Scoped numeric alias: length-preserving mask (deterministic fill) — keeps wire width
      maskBytes(collector, intents, packetIndex, off, 4, `${protocol}-uid`, protocol)
      coverage.push({
        protocol: `${protocol}-auth`,
        offset: off,
        length: 4,
        status: 'redacted',
      })
    }
  }
  p += 8
  if (p + 4 <= end) {
    const nGids = readU32be(buffer, p)
    coverage.push({ protocol, offset: p, length: 4, status: 'covered' })
    p += 4
    const gidsBytes = nGids * 4
    if (p + gidsBytes <= end && gidsBytes > 0) {
      maskBytes(collector, intents, packetIndex, p, gidsBytes, `${protocol}-gids`, protocol)
      coverage.push({
        protocol: `${protocol}-auth`,
        offset: p,
        length: gidsBytes,
        status: 'redacted',
      })
    }
  }
  coverage.push({ protocol: `${protocol}-auth`, offset, length, status: 'covered' })
}
