/**
 * T30 — MQTT 5.0 property section: typed walk (known ids) or fail-closed mask tail on unknown id.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import {
  mapAsciiIdentity,
  maskBytes,
  readMqttRemainingLength,
  readU16be,
  sanitizeSlashPath,
} from './common.ts'

type PropWireType =
  | 'byte'
  | 'two_byte_integer'
  | 'four_byte_integer'
  | 'variable_byte_integer'
  | 'binary_data'
  | 'utf8_string'
  | 'utf8_string_pair'

/** Subset of MQTT 5.0 §2.2.2 — enough for CONNECT/PUBLISH/WILL without vendor extensions. */
const MQTT5_PROPERTY_TYPES: Readonly<Record<number, PropWireType>> = {
  1: 'byte',
  2: 'four_byte_integer',
  3: 'utf8_string',
  8: 'utf8_string',
  9: 'binary_data',
  11: 'variable_byte_integer',
  17: 'four_byte_integer',
  18: 'utf8_string',
  19: 'two_byte_integer',
  21: 'utf8_string',
  22: 'binary_data',
  23: 'byte',
  24: 'four_byte_integer',
  25: 'byte',
  26: 'utf8_string',
  28: 'utf8_string',
  31: 'utf8_string',
  33: 'byte',
  34: 'byte',
  35: 'two_byte_integer',
  36: 'two_byte_integer',
  38: 'utf8_string_pair',
  40: 'four_byte_integer',
  41: 'byte',
  42: 'byte',
  43: 'byte',
}

const MASK_UTF8_PROP = new Set([21, 22, 31])
const MAP_UTF8_PROP = new Set([3, 18, 26, 28])

export interface MqttV5PropertyWalkResult {
  readonly issues: string[]
}

export function sanitizeMqttV5Properties(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: LayerCoverage[],
  issues: string[],
): MqttV5PropertyWalkResult {
  const end = offset + length
  let p = offset
  const localIssues: string[] = []

  while (p < end) {
    const propId = buffer[p]!
    const wireType = MQTT5_PROPERTY_TYPES[propId]
    if (!wireType) {
      maskBytes(collector, intents, packetIndex, p, end - p, 'mqtt-props-unknown', 'mqtt')
      coverage.push({
        protocol: 'mqtt-body',
        offset: p,
        length: end - p,
        status: 'redacted',
      })
      localIssues.push('mqtt-v5-unknown-property')
      break
    }
    coverage.push({ protocol: 'mqtt', offset: p, length: 1, status: 'covered' })
    p++
    const value = readPropertyValue(buffer, p, end, wireType)
    if (!value) {
      maskBytes(collector, intents, packetIndex, p - 1, end - (p - 1), 'mqtt-props-truncated', 'mqtt')
      coverage.push({
        protocol: 'mqtt-body',
        offset: p - 1,
        length: end - (p - 1),
        status: 'redacted',
      })
      localIssues.push('mqtt-v5-property-truncated')
      break
    }

    if (propId === 38) {
      sanitizeUtf8Pair(
        buffer,
        value.offset,
        value.length,
        collector,
        mapping,
        intents,
        packetIndex,
        highPrivacy,
        coverage,
      )
      localIssues.push('mqtt-user-property-sanitized')
    } else if (MASK_UTF8_PROP.has(propId) || wireType === 'binary_data') {
      maskBytes(collector, intents, packetIndex, value.offset, value.length, 'mqtt-props', 'mqtt')
      coverage.push({
        protocol: 'mqtt-auth',
        offset: value.offset,
        length: value.length,
        status: 'redacted',
      })
    } else if (propId === 8 && wireType === 'utf8_string') {
      coverage.push(
        ...sanitizeSlashPath(
          buffer,
          value.offset,
          value.length,
          collector,
          mapping,
          intents,
          packetIndex,
          'mqtt',
          highPrivacy,
        ),
      )
    } else if (MAP_UTF8_PROP.has(propId) && wireType === 'utf8_string') {
      mapAsciiIdentity(
        buffer,
        value.offset,
        value.length,
        'hostname',
        collector,
        mapping,
        intents,
        packetIndex,
        'mqtt',
      )
      coverage.push({
        protocol: 'mqtt',
        offset: value.offset,
        length: value.length,
        status: 'covered',
      })
    } else {
      coverage.push({
        protocol: 'mqtt',
        offset: value.offset,
        length: value.length,
        status: 'covered',
      })
    }
    p = value.offset + value.length
  }

  for (const i of localIssues) issues.push(i)
  return { issues: localIssues }
}

function readPropertyValue(
  buffer: Uint8Array,
  offset: number,
  end: number,
  wireType: PropWireType,
): { offset: number; length: number } | null {
  switch (wireType) {
    case 'byte':
      if (offset >= end) return null
      return { offset, length: 1 }
    case 'two_byte_integer':
      if (offset + 2 > end) return null
      return { offset, length: 2 }
    case 'four_byte_integer':
      if (offset + 4 > end) return null
      return { offset, length: 4 }
    case 'variable_byte_integer': {
      const v = readMqttRemainingLength(buffer, offset, end)
      if (!v) return null
      return { offset, length: v.size }
    }
    case 'binary_data':
    case 'utf8_string': {
      if (offset + 2 > end) return null
      const slen = readU16be(buffer, offset)
      if (offset + 2 + slen > end) return null
      return { offset: offset + 2, length: slen }
    }
    case 'utf8_string_pair': {
      if (offset + 2 > end) return null
      const kLen = readU16be(buffer, offset)
      let p = offset + 2 + kLen
      if (p + 2 > end) return null
      const vLen = readU16be(buffer, p)
      p += 2 + vLen
      if (p > end) return null
      return { offset, length: p - offset }
    }
    default:
      return null
  }
}

function sanitizeUtf8Pair(
  buffer: Uint8Array,
  offset: number,
  totalLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: LayerCoverage[],
): void {
  const end = offset + totalLen
  let p = offset
  if (p + 2 > end) return
  const kLen = readU16be(buffer, p)
  p += 2
  if (p + kLen > end) return
  if (kLen > 0) {
    mapAsciiIdentity(
      buffer,
      p,
      kLen,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'mqtt',
    )
    coverage.push({ protocol: 'mqtt', offset: p, length: kLen, status: 'covered' })
  }
  p += kLen
  if (p + 2 > end) return
  const vLen = readU16be(buffer, p)
  p += 2
  if (vLen > 0 && p + vLen <= end) {
    maskBytes(collector, intents, packetIndex, p, vLen, 'mqtt-user-property', 'mqtt')
    coverage.push({ protocol: 'mqtt-auth', offset: p, length: vLen, status: 'redacted' })
  }
  void highPrivacy
}
