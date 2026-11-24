/**
 * T25 — M2PA (RFC 4165) over SCTP PPID 5: identify Payload Data; map ANSI 24-bit OPC/DPC;
 * mask protocol data (fail-closed). Link management messages: header preserve + body mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { mapPointCodeAnsi24, maskSigtranSpan } from './sigtran.ts'

export const PPID_M2PA = 5

const M2PA_VERSION = 1
/** RFC 4165 §3.3.5 Payload Data (SS7). */
const M2PA_CLASS_PAYLOAD = 11
const M2PA_TYPE_PAYLOAD_DATA = 1

const M2PA_HDR_LEN = 10
/** Correlation id (4) + ANSI routing label DPC/OPC/SLS (7). */
const M2PA_PAYLOAD_PREFIX = 11

export function looksLikeM2pa(data: Uint8Array, offset: number, length: number): boolean {
  if (length < M2PA_HDR_LEN) return false
  if (data[offset] !== M2PA_VERSION) return false
  const msgLen =
    ((data[offset + 6]! << 24)
      | (data[offset + 7]! << 16)
      | (data[offset + 8]! << 8)
      | data[offset + 9]!)
    >>> 0
  return msgLen === length
}

export function sanitizeM2pa(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeM2pa(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  coverage.push({ protocol: 'm2pa', offset, length: M2PA_HDR_LEN, status: 'covered' })

  const msgClass = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
  const msgType = (buffer[offset + 4]! << 8) | buffer[offset + 5]!
  const bodyOff = offset + M2PA_HDR_LEN
  const bodyLen = length - M2PA_HDR_LEN

  if (msgClass === M2PA_CLASS_PAYLOAD && msgType === M2PA_TYPE_PAYLOAD_DATA) {
    if (bodyLen >= M2PA_PAYLOAD_PREFIX) {
      coverage.push({
        protocol: 'm2pa-payload-data',
        offset: bodyOff,
        length: M2PA_PAYLOAD_PREFIX,
        status: 'covered',
      })
      // Correlation id preserved (4 octets).
      const rlOff = bodyOff + 4
      mapPointCodeAnsi24(buffer, rlOff, collector, mapping, intents, packetIndex, 'm2pa-dpc')
      mapPointCodeAnsi24(buffer, rlOff + 3, collector, mapping, intents, packetIndex, 'm2pa-opc')
      coverage.push({ protocol: 'm2pa-ansi-pc', offset: rlOff, length: 7, status: 'covered' })
      const protoOff = bodyOff + M2PA_PAYLOAD_PREFIX
      const protoLen = bodyLen - M2PA_PAYLOAD_PREFIX
      if (protoLen > 0) {
        maskSigtranSpan(collector, intents, packetIndex, protoOff, protoLen, 'm2pa-protocol-data')
        coverage.push({
          protocol: 'm2pa-protocol-data',
          offset: protoOff,
          length: protoLen,
          status: 'redacted',
        })
      }
    } else {
      maskSigtranSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'm2pa-payload-short')
      coverage.push({ protocol: 'm2pa-payload-data', offset: bodyOff, length: bodyLen, status: 'malformed' })
      issues.push('m2pa-payload-trunc')
    }
    return { coverage, issues: issues.length > 0 ? issues : undefined }
  }

  if (bodyLen > 0) {
    maskSigtranSpan(collector, intents, packetIndex, bodyOff, bodyLen, `m2pa-class-${msgClass}`)
    coverage.push({
      protocol: 'm2pa-identify-mask',
      offset: bodyOff,
      length: bodyLen,
      status: 'redacted',
    })
    issues.push(`m2pa-identify-mask:${msgClass}/${msgType}`)
  }
  return { coverage, issues: issues.length > 0 ? issues : undefined }
}
