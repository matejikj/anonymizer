/**
 * T30 — Modbus/TCP (TCP 502): MBAP + function/addresses preserve; register/coil values mask.
 * Request vs response grammars are distinguished per function code (FC 05/06 write value is
 * never treated as address/count).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes, readU16be } from './common.ts'

export const MODBUS_TCP_PORT = 502

export function isModbusPortHint(src: number, dst: number): boolean {
  return src === MODBUS_TCP_PORT || dst === MODBUS_TCP_PORT
}

export function looksLikeModbus(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const proto = readU16be(buffer, offset + 2)
  const len = readU16be(buffer, offset + 4)
  return proto === 0 && len >= 2 && len + 6 <= length + 64
}

export function sanitizeModbus(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isModbusPortHint(srcPort, dstPort) && !looksLikeModbus(buffer, offset, length)) {
    return null
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 8 <= end) {
    const proto = readU16be(buffer, pos + 2)
    const len = readU16be(buffer, pos + 4)
    if (proto !== 0 || len < 2 || pos + 6 + len > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'modbus-desync', 'modbus')
      coverage.push({
        protocol: 'modbus-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('modbus-frame-desync')
      break
    }
    // MBAP: tx(2)+proto(2)+len(2)+unit(1) — preserve
    coverage.push({ protocol: 'modbus', offset: pos, length: 7, status: 'covered' })
    const pduOff = pos + 7
    const pduLen = len - 1
    if (pduLen <= 0) {
      pos += 6 + len
      continue
    }
    const fc = buffer[pduOff]!
    coverage.push({ protocol: 'modbus', offset: pduOff, length: 1, status: 'covered' })

    if (fc & 0x80) {
      // Exception: FC + exception code — preserve both
      coverage.push({
        protocol: 'modbus',
        offset: pduOff + 1,
        length: Math.min(1, pduLen - 1),
        status: 'covered',
      })
    } else if (fc === 0x2b) {
      sanitizeDeviceId(
        buffer,
        pduOff + 1,
        pduLen - 1,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
      )
    } else if (fc === 0x01 || fc === 0x02 || fc === 0x03 || fc === 0x04) {
      sanitizeReadFc(
        fc,
        pduOff,
        pduLen,
        collector,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (fc === 0x05 || fc === 0x06) {
      // Write Single Coil / Register: addr(2) preserve + value(2) mask (req and resp same layout)
      sanitizeWriteSingle(pduOff, pduLen, collector, intents, packetIndex, coverage, issues)
    } else if (fc === 0x0f || fc === 0x10) {
      sanitizeWriteMultiple(pduOff, pduLen, collector, intents, packetIndex, coverage, issues)
    } else {
      // Unknown FC — preserve FC, mask rest
      if (pduLen > 1) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          pduOff + 1,
          pduLen - 1,
          'modbus-body',
          'modbus',
        )
        coverage.push({
          protocol: 'modbus-body',
          offset: pduOff + 1,
          length: pduLen - 1,
          status: 'redacted',
        })
      }
    }

    pos += 6 + len
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'modbus-session', 'modbus')
    coverage.push({ protocol: 'modbus', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

/**
 * FC 01–04: request is always addr(2)+qty(2) (PDU len 5).
 * Response is byteCount(1)+values (PDU len ≠ 5).
 */
function sanitizeReadFc(
  _fc: number,
  pduOff: number,
  pduLen: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  if (pduLen === 5) {
    // Request: starting address + quantity
    coverage.push({ protocol: 'modbus', offset: pduOff + 1, length: 4, status: 'covered' })
    return
  }
  // Response (or ambiguous non-request): preserve byte-count, mask values
  if (pduLen >= 2) {
    coverage.push({ protocol: 'modbus', offset: pduOff + 1, length: 1, status: 'covered' })
    if (pduLen > 2) {
      maskProcessValues(collector, intents, packetIndex, pduOff + 2, pduLen - 2, coverage, issues)
    }
    return
  }
  if (pduLen > 1) {
    maskProcessValues(collector, intents, packetIndex, pduOff + 1, pduLen - 1, coverage, issues)
  }
}

/** FC 05/06: address preserve, written coil/register value always mask. */
function sanitizeWriteSingle(
  pduOff: number,
  pduLen: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  if (pduLen >= 3) {
    coverage.push({ protocol: 'modbus', offset: pduOff + 1, length: 2, status: 'covered' })
  }
  if (pduLen > 3) {
    maskProcessValues(collector, intents, packetIndex, pduOff + 3, pduLen - 3, coverage, issues)
  } else if (pduLen === 3) {
    // truncated value — mask remainder
    maskProcessValues(collector, intents, packetIndex, pduOff + 3, 0, coverage, issues)
  }
}

/**
 * FC 0F/10: response is addr(2)+qty(2) (PDU len 5).
 * Request is addr(2)+qty(2)+byteCount(1)+values (PDU len > 5).
 */
function sanitizeWriteMultiple(
  pduOff: number,
  pduLen: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  if (pduLen === 5) {
    // Response echo: address + quantity
    coverage.push({ protocol: 'modbus', offset: pduOff + 1, length: 4, status: 'covered' })
    return
  }
  if (pduLen >= 6) {
    // Request: addr + qty + byte count preserve; values mask
    coverage.push({ protocol: 'modbus', offset: pduOff + 1, length: 5, status: 'covered' })
    if (pduLen > 6) {
      maskProcessValues(collector, intents, packetIndex, pduOff + 6, pduLen - 6, coverage, issues)
    }
    return
  }
  if (pduLen > 1) {
    maskProcessValues(collector, intents, packetIndex, pduOff + 1, pduLen - 1, coverage, issues)
  }
}

function maskProcessValues(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  if (length <= 0) return
  maskBytes(collector, intents, packetIndex, offset, length, 'modbus-values', 'modbus')
  coverage.push({
    protocol: 'modbus-values',
    offset,
    length,
    status: 'redacted',
  })
  issues.push('modbus-process-values-masked')
}

function sanitizeDeviceId(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  if (length < 3) {
    maskBytes(collector, intents, packetIndex, offset, length, 'modbus-devid', 'modbus')
    return
  }
  coverage.push({ protocol: 'modbus', offset, length: 3, status: 'covered' })
  let p = offset + 3
  const end = offset + length
  while (p < end) {
    if (buffer[p]! >= 0x20 && buffer[p]! < 0x7f) {
      let q = p
      while (q < end && buffer[q]! >= 0x20 && buffer[q]! < 0x7f) q++
      const s = decodeAscii(buffer, p, q - p)
      if (s.length >= 2) {
        mapAsciiIdentity(
          buffer,
          p,
          q - p,
          'opaque-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'modbus',
        )
        coverage.push({ protocol: 'modbus-devid', offset: p, length: q - p, status: 'covered' })
      }
      p = q
    } else {
      p++
    }
  }
}
