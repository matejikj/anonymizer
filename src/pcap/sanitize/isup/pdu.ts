/**
 * T25/T37 — ITU ISUP user-part PDU walk (shared M3UA ISUP and SIP-I `application/isup`).
 */

import type { MappingLike } from '../../anonymization/mapping'
import type { IntentCollector } from '../../discovery/intentCollector'
import type { PatchCollector } from '../PatchCollector'
import type { LayerCoverage } from '../types'
import { mapTbcdSipPhoneField, maskWireSpan } from './tbcdPhoneMap.ts'

const ISUP_IAM = 0x01
const ISUP_SAM = 0x02
const ISUP_INR = 0x03
const ISUP_INF = 0x04
const ISUP_COT = 0x05
const ISUP_ACM = 0x06
const ISUP_CON = 0x07
const ISUP_FOT = 0x08
const ISUP_ANM = 0x09
const ISUP_REL = 0x0c
const ISUP_SUS = 0x0d
const ISUP_RES = 0x0e
const ISUP_RLC = 0x10
const ISUP_CCR = 0x11
const ISUP_RSC = 0x12
const ISUP_BLO = 0x13
const ISUP_UBL = 0x14
const ISUP_BLA = 0x15
const ISUP_UBA = 0x16
const ISUP_GRS = 0x17
const ISUP_CGB = 0x18
const ISUP_CGU = 0x19
const ISUP_CGBA = 0x1a
const ISUP_CGUA = 0x1b
const ISUP_CMR = 0x1c
const ISUP_CMC = 0x1d
const ISUP_CMRJ = 0x1e
const ISUP_FAR = 0x1f
const ISUP_FAA = 0x20
const ISUP_FRJ = 0x21
const ISUP_FAC = 0x33
const ISUP_USR = 0x2d
const ISUP_CPG = 0x2c
const ISUP_APM = 0x41
const ISUP_PRI = 0x42

const ISUP_PARAM_CALLED = 0x04
const ISUP_PARAM_CALLING = 0x0a
const ISUP_PARAM_REDIRECTING = 0x0b
const ISUP_PARAM_REDIRECTION = 0x0c
const ISUP_PARAM_ORIGINAL_CALLED = 0x09
const ISUP_PARAM_GENERIC_NUMBER = 0xc0
const ISUP_PARAM_USER_TO_USER = 0x20
const ISUP_PARAM_ACCESS_TRANSPORT = 0x03

export type IsupPduSurface = 'sigtran' | 'sip-i'

export interface IsupPduSink {
  cover(part: string, offset: number, length: number, status: LayerCoverage['status']): void
  issue(token: string): void
  mapNumberParam(valueOffset: number, paramLen: number): void
  redact(offset: number, length: number, domain: string): void
}

function protocolId(surface: IsupPduSurface, part: string): string {
  const base = surface === 'sigtran' ? 'isup' : 'sip-isup'
  return part ? `${base}-${part}` : base
}

/** Shared ISUP decode/sanitize walk — one implementation for T25 M3UA and T37 SIP-I bodies. */
export function analyzeIsupPdu(
  buffer: Uint8Array,
  abs: number,
  len: number,
  _surface: IsupPduSurface,
  sink: IsupPduSink,
): void {
  void _surface
  if (len < 3) {
    sink.redact(abs, len, 'isup-short')
    sink.cover('', abs, len, 'malformed')
    return
  }
  sink.cover('', abs, 3, 'covered')
  const msgType = buffer[abs + 2]!
  let pos = abs + 3

  if (msgType === ISUP_IAM) {
    if (len < 3 + 5 + 2) {
      sink.redact(pos, abs + len - pos, 'isup-iam-short')
      sink.cover('iam', abs, len, 'malformed')
      return
    }
    sink.cover('iam-fixed', pos, 5, 'covered')
    const ptrCalledAt = pos + 5
    const ptrOptAt = pos + 6
    const ptrCalled = buffer[ptrCalledAt]!
    const ptrOpt = buffer[ptrOptAt]!
    const calledOff = ptrCalledAt + ptrCalled
    if (ptrCalled > 0 && calledOff + 1 < abs + len) {
      const calledLen = buffer[calledOff]!
      sink.mapNumberParam(calledOff + 1, calledLen)
    }
    if (ptrOpt > 0) {
      walkIsupOptional(buffer, ptrOptAt + ptrOpt, abs + len, sink)
    }
    return
  }

  if (
    msgType === ISUP_ACM || msgType === ISUP_ANM || msgType === ISUP_CPG || msgType === ISUP_REL
    || msgType === ISUP_CON || msgType === ISUP_SUS || msgType === ISUP_RES || msgType === ISUP_RLC
    || msgType === ISUP_FAC || msgType === ISUP_USR || msgType === ISUP_APM || msgType === ISUP_PRI
    || msgType === ISUP_SAM || msgType === ISUP_INR || msgType === ISUP_INF || msgType === ISUP_COT
    || msgType === ISUP_FOT || msgType === ISUP_CCR || msgType === ISUP_RSC || msgType === ISUP_BLO
    || msgType === ISUP_UBL || msgType === ISUP_BLA || msgType === ISUP_UBA || msgType === ISUP_GRS
    || msgType === ISUP_CGB || msgType === ISUP_CGU || msgType === ISUP_CGBA || msgType === ISUP_CGUA
    || msgType === ISUP_CMR || msgType === ISUP_CMC || msgType === ISUP_CMRJ || msgType === ISUP_FAR
    || msgType === ISUP_FAA || msgType === ISUP_FRJ
  ) {
    if (msgType === ISUP_ACM && pos + 3 <= abs + len) {
      sink.cover('acm-bci', pos, 2, 'covered')
      const ptrAt = pos + 2
      const ptr = buffer[ptrAt]!
      if (ptr > 0) walkIsupOptional(buffer, ptrAt + ptr, abs + len, sink)
      return
    }
    if (msgType === ISUP_ANM && pos + 1 <= abs + len) {
      const ptrAt = pos
      const ptr = buffer[ptrAt]!
      if (ptr > 0) walkIsupOptional(buffer, ptrAt + ptr, abs + len, sink)
      return
    }
    if (msgType === ISUP_REL && pos + 2 <= abs + len) {
      const ptrCauseAt = pos
      const ptrOptAt = pos + 1
      const ptrCause = buffer[ptrCauseAt]!
      const ptrOpt = buffer[ptrOptAt]!
      if (ptrCause > 0) {
        const causeOff = ptrCauseAt + ptrCause
        if (causeOff < abs + len) {
          const causeLen = buffer[causeOff]!
          sink.cover(
            'cause',
            causeOff,
            Math.min(1 + causeLen, abs + len - causeOff),
            'covered',
          )
        }
      }
      if (ptrOpt > 0) {
        walkIsupOptional(buffer, ptrOptAt + ptrOpt, abs + len, sink)
      }
      return
    }
    if (pos < abs + len) {
      sink.redact(pos, abs + len - pos, `isup-type-0x${msgType.toString(16)}`)
      sink.cover('msg', pos, abs + len - pos, 'redacted')
      sink.issue(`isup-partial:${msgType}`)
    }
    return
  }

  sink.redact(pos, abs + len - pos, `isup-unknown-0x${msgType.toString(16)}`)
  sink.cover('msg', abs, len, 'redacted')
  sink.issue(`isup-unsupported-type:${msgType}`)
}

function walkIsupOptional(
  buffer: Uint8Array,
  abs: number,
  limit: number,
  sink: IsupPduSink,
): void {
  let pos = abs
  let guard = 0
  while (pos < limit && guard++ < 64) {
    const name = buffer[pos]!
    if (name === 0) {
      sink.cover('opt-end', pos, 1, 'covered')
      break
    }
    if (pos + 2 > limit) {
      sink.redact(pos, limit - pos, 'isup-opt-short')
      break
    }
    const plen = buffer[pos + 1]!
    const valOff = pos + 2
    if (valOff + plen > limit) {
      sink.redact(pos, limit - pos, 'isup-opt-oob')
      sink.issue('isup-optional-oob')
      break
    }
    if (
      name === ISUP_PARAM_CALLED || name === ISUP_PARAM_CALLING
      || name === ISUP_PARAM_REDIRECTING || name === ISUP_PARAM_REDIRECTION
      || name === ISUP_PARAM_ORIGINAL_CALLED || name === ISUP_PARAM_GENERIC_NUMBER
    ) {
      sink.mapNumberParam(valOff, plen)
    } else if (name === ISUP_PARAM_USER_TO_USER || name === ISUP_PARAM_ACCESS_TRANSPORT) {
      sink.redact(valOff, plen, `isup-param-0x${name.toString(16)}`)
      sink.cover('secret', valOff, plen, 'redacted')
    } else {
      sink.redact(valOff, plen, `isup-param-0x${name.toString(16)}`)
      sink.cover('opt', pos, 2 + plen, 'redacted')
    }
    pos = valOff + plen
  }
}

class PatchIsupSink implements IsupPduSink {
  private readonly buffer: Uint8Array
  private readonly surface: IsupPduSurface
  private readonly collector: PatchCollector
  private readonly mapping: MappingLike
  private readonly intents: IntentCollector | undefined
  private readonly packetIndex: number
  private readonly coverage: LayerCoverage[]
  private readonly issues: string[]

  constructor(
    buffer: Uint8Array,
    surface: IsupPduSurface,
    collector: PatchCollector,
    mapping: MappingLike,
    intents: IntentCollector | undefined,
    packetIndex: number,
    coverage: LayerCoverage[],
    issues: string[],
  ) {
    this.buffer = buffer
    this.surface = surface
    this.collector = collector
    this.mapping = mapping
    this.intents = intents
    this.packetIndex = packetIndex
    this.coverage = coverage
    this.issues = issues
  }

  cover(part: string, offset: number, length: number, status: LayerCoverage['status']): void {
    this.coverage.push({
      protocol: protocolId(this.surface, part),
      offset,
      length,
      status,
    })
  }

  issue(token: string): void {
    this.issues.push(token)
  }

  mapNumberParam(valueOffset: number, paramLen: number): void {
    mapIsupNumberPatch(
      this.buffer,
      valueOffset,
      paramLen,
      this.surface,
      this.collector,
      this.mapping,
      this.intents,
      this.packetIndex,
      this.coverage,
    )
  }

  redact(offset: number, length: number, domain: string): void {
    const protocol = this.surface === 'sigtran' ? 'sigtran' : 'sip-isup'
    maskWireSpan(this.collector, this.intents, this.packetIndex, offset, length, domain, protocol)
  }
}

function mapIsupNumberPatch(
  buffer: Uint8Array,
  abs: number,
  len: number,
  surface: IsupPduSurface,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (len < 3) {
    const protocol = surface === 'sigtran' ? 'sigtran' : 'sip-isup'
    maskWireSpan(collector, intents, packetIndex, abs, len, 'isup-num-short', protocol)
    return
  }
  coverage.push({
    protocol: protocolId(surface, 'number-hdr'),
    offset: abs,
    length: 2,
    status: 'covered',
  })
  const protocol = surface === 'sigtran' ? 'sigtran' : 'sip-isup'
  mapTbcdSipPhoneField(
    buffer,
    abs + 2,
    len - 2,
    collector,
    mapping,
    intents,
    packetIndex,
    protocolId(surface, 'number'),
    protocol,
  )
  coverage.push({
    protocol: protocolId(surface, 'number'),
    offset: abs + 2,
    length: len - 2,
    status: 'covered',
  })
}

/** ITU ISUP user part — shared by M3UA (T25) and SIP-I MIME bodies (T37). */
export function sanitizeIsupPdu(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  analyzeIsupPdu(
    buffer,
    abs,
    len,
    'sigtran',
    new PatchIsupSink(buffer, 'sigtran', collector, mapping, intents, packetIndex, coverage, issues),
  )
}
