/**
 * T17 — SCTP (RFC 9260): map ports + INIT multihoming addresses; mask cookies/HB;
 * complete DATA by PPID (Diameter 46/47, M3UA 3, S1AP 18, NGAP 60).
 * Multi-fragment DATA/I-DATA: complete sets sanitized via reassembly (V15); incomplete →
 * requires-reassembly + mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { ReassemblyContext } from '../reassembly/types'
import type { PatchCollector } from './PatchCollector'
import type { LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { sanitizeDiameter, looksLikeDiameter } from './diameter'
import { sanitizeM3ua, looksLikeM3ua } from './sigtran'
import { sanitizeM2pa, looksLikeM2pa, PPID_M2PA } from './m2pa.ts'
import { sanitizeIua, looksLikeIua, PPID_IUA } from './isdn/index.ts'
import { sanitizeS1ap, looksLikeS1ap, PPID_S1AP } from './s1ap.ts'
import { sanitizeNgap, looksLikeNgap, PPID_NGAP } from './ngap.ts'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'

export const IPPROTO_SCTP = 132

const CHUNK_DATA = 0
const CHUNK_INIT = 1
const CHUNK_INIT_ACK = 2
const CHUNK_SACK = 3
const CHUNK_HEARTBEAT = 4
const CHUNK_HEARTBEAT_ACK = 5
const CHUNK_ABORT = 6
const CHUNK_SHUTDOWN = 7
const CHUNK_SHUTDOWN_ACK = 8
const CHUNK_ERROR = 9
const CHUNK_COOKIE_ECHO = 10
const CHUNK_COOKIE_ACK = 11
const CHUNK_SHUTDOWN_COMPLETE = 14
const CHUNK_I_DATA = 64

const PARAM_IPV4 = 5
const PARAM_IPV6 = 6
const PARAM_STATE_COOKIE = 7
const PARAM_COOKIE_PRESERVATIVE = 9
const PARAM_HOST_NAME = 11
const PARAM_SUPPORTED_ADDR = 12

const PPID_M3UA = 3
/** IANA: M2UA = 2 (was mislabeled as 18; 18 is S1AP). */
const PPID_M2UA = 2
const PPID_SUA = 4
const PPID_DIAMETER = 46
const PPID_DIAMETER_DTLS = 47

const MAX_CHUNKS = 64
const MAX_PARAMS = 64

export function sanitizeSctp(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
  reassemblyContext?: ReassemblyContext,
  /** Outer IP endpoints for association-scoped identity (V17). */
  endpoints?: { readonly srcIp?: string; readonly dstIp?: string },
): { coverage: LayerCoverage[]; lastCoveredOffset: number; issues: string[] } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = data.length
  if (offset + 12 > end) {
    coverage.push({ protocol: 'sctp', offset, length: end - offset, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset, issues: ['sctp-trunc'] }
  }

  const srcPort = (data[offset]! << 8) | data[offset + 1]!
  const dstPort = (data[offset + 2]! << 8) | data[offset + 3]!
  const vtag =
    ((data[offset + 4]! << 24) >>> 0)
    + (data[offset + 5]! << 16)
    + (data[offset + 6]! << 8)
    + data[offset + 7]!
  const assocScope =
    `sctp:${endpoints?.srcIp ?? '?'}:${srcPort}>${endpoints?.dstIp ?? '?'}:${dstPort}@${vtag >>> 0}`
  patchSctpPort(offset, srcPort, collector, packetIndex, intents)
  patchSctpPort(offset + 2, dstPort, collector, packetIndex, intents)

  coverage.push({ protocol: 'sctp', offset, length: 12, status: 'covered' })

  let pos = offset + 12
  let chunkCount = 0
  while (pos + 4 <= end && chunkCount < MAX_CHUNKS) {
    const type = data[pos]!
    const length = (data[pos + 2]! << 8) | data[pos + 3]!
    if (length < 4 || pos + length > end) {
      coverage.push({
        protocol: 'sctp-chunk',
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      issues.push('sctp-chunk-trunc')
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'sctp-chunk-trunc')
      return { coverage, lastCoveredOffset: end, issues }
    }

    const chunkValueStart = pos + 4
    const chunkValueLen = length - 4
    const padded = (length + 3) & ~3
    const flags = data[pos + 1]!

    switch (type) {
      case CHUNK_DATA:
      case CHUNK_I_DATA:
        sanitizeDataChunk(
          data,
          pos,
          length,
          flags,
          type === CHUNK_I_DATA,
          collector,
          mapping,
          packetIndex,
          intents,
          coverage,
          issues,
          reassemblyContext,
          assocScope,
        )
        break
      case CHUNK_INIT:
      case CHUNK_INIT_ACK:
        if (chunkValueLen < 16) {
          coverage.push({ protocol: 'sctp-init', offset: pos, length, status: 'malformed' })
          maskSpan(collector, intents, packetIndex, chunkValueStart, chunkValueLen, 'sctp-init-short')
          break
        }
        coverage.push({ protocol: 'sctp-init', offset: pos, length: 20, status: 'covered' })
        sanitizeInitParams(
          data,
          chunkValueStart + 16,
          chunkValueLen - 16,
          collector,
          mapping,
          packetIndex,
          intents,
          coverage,
          issues,
        )
        break
      case CHUNK_SACK:
      case CHUNK_SHUTDOWN:
      case CHUNK_SHUTDOWN_ACK:
      case CHUNK_COOKIE_ACK:
      case CHUNK_SHUTDOWN_COMPLETE:
        coverage.push({ protocol: 'sctp-chunk', offset: pos, length, status: 'covered' })
        break
      case CHUNK_HEARTBEAT:
      case CHUNK_HEARTBEAT_ACK:
      case CHUNK_COOKIE_ECHO:
        if (chunkValueLen > 0) {
          maskSpan(collector, intents, packetIndex, chunkValueStart, chunkValueLen, 'sctp-opaque')
        }
        coverage.push({ protocol: 'sctp-chunk', offset: pos, length, status: 'redacted' })
        break
      case CHUNK_ABORT:
      case CHUNK_ERROR:
        sanitizeErrorCauses(
          data,
          chunkValueStart,
          chunkValueLen,
          collector,
          mapping,
          packetIndex,
          intents,
          coverage,
          issues,
        )
        break
      default: {
        if (chunkValueLen > 0) {
          maskSpan(collector, intents, packetIndex, chunkValueStart, chunkValueLen, 'sctp-unknown-chunk')
        }
        coverage.push({
          protocol: `sctp-chunk-${type}`,
          offset: pos,
          length,
          status: 'redacted',
        })
        issues.push(`sctp-unknown-chunk:${type}`)
        const action = type >> 6
        if (action === 0 || action === 1) {
          const rest = end - (pos + padded)
          if (rest > 0) {
            maskSpan(collector, intents, packetIndex, pos + padded, rest, 'sctp-stop-remainder')
            coverage.push({
              protocol: 'sctp-remainder',
              offset: pos + padded,
              length: rest,
              status: 'redacted',
            })
          }
          return { coverage, lastCoveredOffset: end, issues }
        }
        break
      }
    }

    pos += padded
    chunkCount++
  }
  if (chunkCount >= MAX_CHUNKS) issues.push('sctp-chunk-budget')

  return { coverage, lastCoveredOffset: Math.min(pos, end), issues }
}

function sanitizeDataChunk(
  data: Uint8Array,
  chunkOff: number,
  length: number,
  flags: number,
  isIdata: boolean,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
  reassemblyContext?: ReassemblyContext,
  identityScope?: string,
): void {
  // RFC 9260 DATA = 16B; RFC 8260 I-DATA = 20B (PPID/FSN share one 4B field at +16 by B bit).
  const fixedLen = isIdata ? 20 : 16
  if (length < fixedLen) {
    coverage.push({ protocol: 'sctp-data', offset: chunkOff, length, status: 'malformed' })
    maskSpan(collector, intents, packetIndex, chunkOff + 4, Math.max(0, length - 4), 'sctp-data-short')
    return
  }
  const beginning = (flags & 0x02) !== 0
  const ending = (flags & 0x01) !== 0
  const userOff = chunkOff + fixedLen
  // DATA: PPID at +12. I-DATA: when B=1 field at +16 is PPID; when B=0 it is FSN.
  let ppid = 0
  if (isIdata) {
    if (beginning) {
      ppid =
        ((data[chunkOff + 16]! << 24)
          | (data[chunkOff + 17]! << 16)
          | (data[chunkOff + 18]! << 8)
          | data[chunkOff + 19]!)
        >>> 0
    }
  } else {
    ppid =
      ((data[chunkOff + 12]! << 24)
        | (data[chunkOff + 13]! << 16)
        | (data[chunkOff + 14]! << 8)
        | data[chunkOff + 15]!)
      >>> 0
  }
  const userLen = chunkOff + length - userOff

  coverage.push({
    protocol: 'sctp-data',
    offset: chunkOff,
    length: fixedLen,
    status: 'covered',
  })

  if (userLen < 0) {
    coverage.push({ protocol: 'sctp-data', offset: chunkOff, length, status: 'malformed' })
    return
  }

  if (!beginning || !ending) {
    // V15: complete multi-fragment message owned by capture reassembly — do not mask;
    // PPID dispatch runs on the reassembled buffer and projects patches back.
    if (
      userLen > 0
      && reassemblyContext?.isSctpCompletePayload?.(packetIndex, userOff)
    ) {
      coverage.push({
        protocol: 'sctp-data-payload',
        offset: userOff,
        length: userLen,
        status: 'covered',
      })
      issues.push('sctp-reassembled-deferred')
      return
    }
    if (userLen > 0) {
      maskSpan(collector, intents, packetIndex, userOff, userLen, 'sctp-data-fragment')
    }
    coverage.push({
      protocol: 'sctp-data-payload',
      offset: userOff,
      length: Math.max(0, userLen),
      status: 'requires-reassembly',
    })
    issues.push('sctp-requires-reassembly')
    return
  }

  if (userLen === 0) {
    coverage.push({ protocol: 'sctp-data-payload', offset: userOff, length: 0, status: 'covered' })
    return
  }

  const dispatched = sanitizeSctpUserMessage(
    data,
    userOff,
    userLen,
    ppid,
    collector,
    mapping,
    packetIndex,
    intents,
    identityScope,
  )
  coverage.push(...dispatched.coverage)
  for (const i of dispatched.issues) issues.push(i)
}

/**
 * PPID dispatch for a complete SCTP user message (single chunk or reassembled).
 * Shared by per-packet B+E DATA and capture-level multi-fragment reassembly.
 */
export function sanitizeSctpUserMessage(
  data: Uint8Array,
  userOff: number,
  userLen: number,
  ppid: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
  identityScope?: string,
): { coverage: LayerCoverage[]; issues: string[] } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (userLen <= 0) {
    coverage.push({ protocol: 'sctp-data-payload', offset: userOff, length: 0, status: 'covered' })
    return { coverage, issues }
  }

  if (
    (ppid === PPID_DIAMETER || ppid === PPID_DIAMETER_DTLS)
    && looksLikeDiameter(data, userOff, userLen)
  ) {
    const r = sanitizeDiameter(data, userOff, userLen, collector, mapping, intents, packetIndex)
    if (r) {
      coverage.push(...r.coverage)
      if (r.issues) for (const i of r.issues) issues.push(i)
      return { coverage, issues }
    }
  }

  if (ppid === PPID_M3UA && looksLikeM3ua(data, userOff, userLen)) {
    const r = sanitizeM3ua(data, userOff, userLen, collector, mapping, intents, packetIndex)
    if (r) {
      coverage.push(...r.coverage)
      if (r.issues) for (const i of r.issues) issues.push(i)
      return { coverage, issues }
    }
  }

  // T25 — M2PA (RFC 4165) PPID 5 → ANSI OPC/DPC map + protocol data mask
  if (ppid === PPID_M2PA && looksLikeM2pa(data, userOff, userLen)) {
    const r = sanitizeM2pa(data, userOff, userLen, collector, mapping, intents, packetIndex)
    if (r) {
      coverage.push(...r.coverage)
      if (r.issues) for (const i of r.issues) issues.push(i)
      return { coverage, issues }
    }
  }

  // T51 — IUA (RFC 4233) PPID 1 → Q.931 / LAPD child
  if (ppid === PPID_IUA && looksLikeIua(data, userOff, userLen)) {
    const r = sanitizeIua(data, userOff, userLen, collector, mapping, intents, packetIndex)
    if (r) {
      coverage.push(...r.coverage)
      if (r.issues) for (const i of r.issues) issues.push(i)
      return { coverage, issues }
    }
  }

  // T57 — S1AP (TS 36.413) PPID 18 → APER structured + NAS child
  if (ppid === PPID_S1AP && looksLikeS1ap(data, userOff, userLen)) {
    const r = sanitizeS1ap(data, userOff, userLen, collector, mapping, intents, packetIndex, identityScope)
    if (r) {
      coverage.push(...r.coverage)
      if (r.issues) for (const i of r.issues) issues.push(i)
      return { coverage, issues }
    }
  }

  // T58 — NGAP (TS 38.413) PPID 60 → APER structured + NAS child + N2 transfers
  if (ppid === PPID_NGAP && looksLikeNgap(data, userOff, userLen)) {
    const r = sanitizeNgap(data, userOff, userLen, collector, mapping, intents, packetIndex, identityScope)
    if (r) {
      coverage.push(...r.coverage)
      if (r.issues) for (const i of r.issues) issues.push(i)
      return { coverage, issues }
    }
  }

  // M2UA / SUA / unparsed M3UA/S1AP/NGAP — identify+mask
  if (
    ppid === PPID_M2UA
    || ppid === PPID_SUA
    || ppid === PPID_M3UA
    || ppid === PPID_S1AP
    || ppid === PPID_NGAP
  ) {
    maskSpan(collector, intents, packetIndex, userOff, userLen, `sctp-ppid-${ppid}`)
    coverage.push({
      protocol: `sctp-ppid-${ppid}`,
      offset: userOff,
      length: userLen,
      status: 'redacted',
    })
    issues.push(
      ppid === PPID_M3UA ? 'sctp-m3ua-unparsed' : `sctp-ppid-identify-mask:${ppid}`,
    )
    return { coverage, issues }
  }

  maskSpan(collector, intents, packetIndex, userOff, userLen, `sctp-ppid-${ppid}`)
  coverage.push({
    protocol: `sctp-ppid-${ppid}`,
    offset: userOff,
    length: userLen,
    status: 'redacted',
  })
  issues.push(`sctp-unknown-ppid:${ppid}`)
  return { coverage, issues }
}

function sanitizeInitParams(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  let pos = offset
  const end = offset + length
  let n = 0
  while (pos + 4 <= end && n < MAX_PARAMS) {
    const type = (data[pos]! << 8) | data[pos + 1]!
    const plen = (data[pos + 2]! << 8) | data[pos + 3]!
    if (plen < 4 || pos + plen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'sctp-param-trunc')
      coverage.push({
        protocol: 'sctp-param',
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      issues.push('sctp-param-trunc')
      return
    }
    const valOff = pos + 4
    const valLen = plen - 4
    if (type === PARAM_IPV4 && valLen >= 4) {
      patchIpv4(data, valOff, collector, packetIndex, intents)
      coverage.push({ protocol: 'sctp-param-ipv4', offset: pos, length: plen, status: 'covered' })
    } else if (type === PARAM_IPV6 && valLen >= 16) {
      patchIpv6(data, valOff, collector, packetIndex, intents)
      coverage.push({ protocol: 'sctp-param-ipv6', offset: pos, length: plen, status: 'covered' })
    } else if (type === PARAM_HOST_NAME && valLen > 0) {
      patchHostname(data, valOff, valLen, collector, packetIndex, intents)
      coverage.push({ protocol: 'sctp-param-hostname', offset: pos, length: plen, status: 'covered' })
    } else if (type === PARAM_STATE_COOKIE && valLen > 0) {
      maskSpan(collector, intents, packetIndex, valOff, valLen, 'sctp-cookie')
      coverage.push({ protocol: 'sctp-param-cookie', offset: pos, length: plen, status: 'redacted' })
    } else if (type === PARAM_COOKIE_PRESERVATIVE || type === PARAM_SUPPORTED_ADDR) {
      coverage.push({ protocol: 'sctp-param', offset: pos, length: plen, status: 'covered' })
    } else if (valLen > 0) {
      maskSpan(collector, intents, packetIndex, valOff, valLen, `sctp-param-${type}`)
      coverage.push({
        protocol: `sctp-param-${type}`,
        offset: pos,
        length: plen,
        status: 'redacted',
      })
    } else {
      coverage.push({ protocol: 'sctp-param', offset: pos, length: plen, status: 'covered' })
    }
    pos += (plen + 3) & ~3
    n++
  }
  void mapping
}

function sanitizeErrorCauses(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  let pos = offset
  const end = offset + length
  let n = 0
  while (pos + 4 <= end && n < MAX_PARAMS) {
    const code = (data[pos]! << 8) | data[pos + 1]!
    const clen = (data[pos + 2]! << 8) | data[pos + 3]!
    if (clen < 4 || pos + clen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'sctp-cause-trunc')
      issues.push('sctp-cause-trunc')
      break
    }
    const infoOff = pos + 4
    const infoLen = clen - 4
    if (code === 5 && infoLen >= 8) {
      sanitizeInitParams(
        data,
        infoOff,
        infoLen,
        collector,
        mapping,
        packetIndex,
        intents,
        coverage,
        issues,
      )
    } else if (infoLen > 0) {
      maskSpan(collector, intents, packetIndex, infoOff, infoLen, `sctp-cause-${code}`)
    }
    coverage.push({ protocol: 'sctp-cause', offset: pos, length: 4, status: 'covered' })
    pos += (clen + 3) & ~3
    n++
  }
  coverage.push({ protocol: 'sctp-error', offset, length, status: 'covered' })
}

function patchSctpPort(
  offset: number,
  port: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const canonical = `sctp/${port}`
  intents?.recordEntityReplacement(packetIndex, offset, 'port', canonical, 2)
  try {
    collector.addDeferred(offset, 2, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('port', canonical)
      const slash = mapped.indexOf('/')
      if (slash < 0) return null
      const mappedPort = Number.parseInt(mapped.slice(slash + 1), 10)
      if (!Number.isInteger(mappedPort) || mappedPort < 0 || mappedPort > 65535 || mappedPort === port) {
        return null
      }
      return new Uint8Array([(mappedPort >> 8) & 0xff, mappedPort & 0xff])
    })
  } catch {
    /* overlap */
  }
}

function patchIpv4(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`
  if (ip === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4)
  collector.addDeferred(offset, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', ip)
    return new Uint8Array(mapped.split('.').map(Number))
  })
}

function patchIpv6(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  const ip = ipv6Bytes16ToText(data, offset)
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16)
  try {
    collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv6', ip)
      return ipv6TextToBytes16(mapped)
    })
  } catch {
    /* overlap */
  }
}

function patchHostname(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): void {
  let hostLen = length
  for (let i = 0; i < length; i++) {
    if (data[offset + i] === 0) {
      hostLen = i
      break
    }
  }
  if (hostLen <= 0) return
  const raw = new TextDecoder('latin1').decode(data.subarray(offset, offset + hostLen))
  intents?.recordEntityReplacement(packetIndex, offset, 'hostname', raw, hostLen)
  collector.addDeferred(offset, hostLen, ({ mapping: live }) => {
    const alias = live.aliasFor(
      'hostname',
      raw,
      { kind: 'text-ascii', byteLength: hostLen },
      raw,
    )
    return computeFixedLengthAsciiBytes(offset, hostLen, alias)
  })
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'sctp')
}
