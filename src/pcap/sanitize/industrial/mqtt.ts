/**
 * T30 — MQTT 3.1.1/5 (TCP 1883): CONNECT credentials; PUBLISH topic/payload; control types preserve.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  mapAsciiIdentity,
  maskBytes,
  readMqttRemainingLength,
  readU16be,
  sanitizePayloadBody,
  sanitizeSlashPath,
} from './common.ts'
import { looksLikeUspRecord, sanitizeUspRecord } from '../usp.ts'
import { sanitizeMqttV5Properties } from './mqttV5Properties.ts'

export const MQTT_TCP_PORT = 1883
export const MQTT_TLS_PORT = 8883

const CONNECT = 1
const PUBLISH = 3
const SUBSCRIBE = 8
const UNSUBSCRIBE = 10

export function isMqttPortHint(src: number, dst: number): boolean {
  return (
    src === MQTT_TCP_PORT
    || dst === MQTT_TCP_PORT
    || src === MQTT_TLS_PORT
    || dst === MQTT_TLS_PORT
  )
}

export function looksLikeMqtt(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  const type = (buffer[offset]! >> 4) & 0x0f
  return type >= 1 && type <= 14
}

function looksLikeMqttPublishOrConnect(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  const type = (buffer[offset]! >> 4) & 0x0f
  return type === CONNECT || type === PUBLISH
}

export function sanitizeMqtt(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isMqttPortHint(srcPort, dstPort) && !looksLikeMqtt(buffer, offset, length)) return null
  // TLS port without plaintext MQTT → leave to TLS handler (don't claim)
  if ((srcPort === MQTT_TLS_PORT || dstPort === MQTT_TLS_PORT) && !looksLikeMqtt(buffer, offset, length)) {
    return null
  }
  // T55 — bare USP Record on MQTT port (no MQTT framing) → USP codec, not MQTT desync
  if (looksLikeUspRecord(buffer, offset, length) && !looksLikeMqttPublishOrConnect(buffer, offset, length)) {
    return sanitizeUspRecord(buffer, offset, length, collector, mapping, intents, packetIndex)
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 2 <= end) {
    const first = buffer[pos]!
    const type = (first >> 4) & 0x0f
    const rem = readMqttRemainingLength(buffer, pos + 1, end)
    if (!rem || pos + 1 + rem.size + rem.value > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'mqtt-desync', 'mqtt')
      coverage.push({
        protocol: 'mqtt-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('mqtt-frame-desync')
      break
    }
    const hdrLen = 1 + rem.size
    const payloadOff = pos + hdrLen
    const payloadLen = rem.value
    const frameLen = hdrLen + payloadLen

    if (type === CONNECT) {
      sanitizeConnect(
        buffer,
        payloadOff,
        payloadLen,
        collector,
        mapping,
        intents,
        packetIndex,
        highPrivacy,
        coverage,
        issues,
      )
    } else if (type === PUBLISH) {
      sanitizePublish(
        buffer,
        payloadOff,
        payloadLen,
        first,
        collector,
        mapping,
        intents,
        packetIndex,
        highPrivacy,
        coverage,
      )
    } else if (type === SUBSCRIBE || type === UNSUBSCRIBE) {
      // packet id + topic filters
      if (payloadLen >= 2) {
        coverage.push({ protocol: 'mqtt', offset: payloadOff, length: 2, status: 'covered' })
        let p = payloadOff + 2
        const pend = payloadOff + payloadLen
        while (p + 2 <= pend) {
          const tlen = readU16be(buffer, p)
          p += 2
          if (tlen < 0 || p + tlen > pend) break
          // Topic length prefix is structural (preserve); cover so CF-09 has no gap.
          coverage.push({ protocol: 'mqtt', offset: p - 2, length: 2, status: 'covered' })
          coverage.push(
            ...sanitizeSlashPath(
              buffer,
              p,
              tlen,
              collector,
              mapping,
              intents,
              packetIndex,
              'mqtt',
              highPrivacy,
            ),
          )
          p += tlen
          if (type === SUBSCRIBE && p < pend) {
            coverage.push({ protocol: 'mqtt', offset: p, length: 1, status: 'covered' })
            p += 1 // QoS byte
          }
        }
      }
    } else if (payloadLen > 0) {
      // CONNACK/PUBACK/… — preserve control plane; mask free properties tails conservatively
      if (type === 2 /* CONNACK */ || type === 4 || type === 5 || type === 6 || type === 7) {
        coverage.push({
          protocol: 'mqtt',
          offset: payloadOff,
          length: payloadLen,
          status: 'covered',
        })
      } else {
        maskBytes(collector, intents, packetIndex, payloadOff, payloadLen, 'mqtt-body', 'mqtt')
        coverage.push({
          protocol: 'mqtt-body',
          offset: payloadOff,
          length: payloadLen,
          status: 'redacted',
        })
      }
    }

    // Parent span: CF-09 safeExportEnd needs contiguous coverage (topic-len / QoS gaps).
    coverage.push({ protocol: 'mqtt', offset: pos, length: frameLen, status: 'covered' })
    pos += frameLen
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mqtt-session', 'mqtt')
    coverage.push({ protocol: 'mqtt', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeConnect(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // Protocol name + level + flags + keep-alive + properties(v5) + payload fields
  if (length < 10) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mqtt-connect', 'mqtt')
    coverage.push({ protocol: 'mqtt-auth', offset, length, status: 'redacted' })
    return
  }
  const protoLen = readU16be(buffer, offset)
  let p = offset + 2 + protoLen + 1 + 1 + 2 // name + level + flags + keepalive
  if (p > offset + length) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mqtt-connect', 'mqtt')
    return
  }
  const connectFlags = buffer[offset + 2 + protoLen + 1]!
  coverage.push({ protocol: 'mqtt', offset, length: p - offset, status: 'covered' })

  // MQTT 5: properties length varint before payload
  // Heuristic: if next looks like properties (small varint) and protocol level was 5
  const protoLevel = buffer[offset + 2 + protoLen]!
  if (protoLevel >= 5 && p < offset + length) {
    const propLen = readMqttRemainingLength(buffer, p, offset + length)
    if (propLen) {
      coverage.push({ protocol: 'mqtt', offset: p, length: propLen.size, status: 'covered' })
      const propsOff = p + propLen.size
      if (propLen.value > 0) {
        sanitizeMqttV5Properties(
          buffer,
          propsOff,
          propLen.value,
          collector,
          mapping,
          intents,
          packetIndex,
          highPrivacy,
          coverage,
          issues,
        )
      }
      p = propsOff + propLen.value
    }
  }

  const end = offset + length
  // Client ID
  if (p + 2 > end) return
  const cidLen = readU16be(buffer, p)
  p += 2
  if (cidLen > 0 && p + cidLen <= end) {
    mapAsciiIdentity(
      buffer,
      p,
      cidLen,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'mqtt',
    )
    coverage.push({ protocol: 'mqtt-client-id', offset: p, length: cidLen, status: 'covered' })
    p += cidLen
  }

  const hasWill = (connectFlags & 0x04) !== 0
  const hasUser = (connectFlags & 0x80) !== 0
  const hasPass = (connectFlags & 0x40) !== 0

  if (hasWill) {
    // will properties (v5) skipped/masked if present — for 3.1.1: topic + payload
    if (protoLevel >= 5 && p < end) {
      const wp = readMqttRemainingLength(buffer, p, end)
      if (wp) {
        coverage.push({ protocol: 'mqtt', offset: p, length: wp.size, status: 'covered' })
        const wPropsOff = p + wp.size
        if (wp.value > 0) {
          sanitizeMqttV5Properties(
            buffer,
            wPropsOff,
            wp.value,
            collector,
            mapping,
            intents,
            packetIndex,
            highPrivacy,
            coverage,
            issues,
          )
        }
        p = wPropsOff + wp.value
      }
    }
    if (p + 2 <= end) {
      const wTopicLen = readU16be(buffer, p)
      p += 2
      if (wTopicLen > 0 && p + wTopicLen <= end) {
        coverage.push(
          ...sanitizeSlashPath(
            buffer,
            p,
            wTopicLen,
            collector,
            mapping,
            intents,
            packetIndex,
            'mqtt',
            highPrivacy,
          ),
        )
        p += wTopicLen
      }
    }
    if (p + 2 <= end) {
      const wPayLen = readU16be(buffer, p)
      p += 2
      if (wPayLen > 0 && p + wPayLen <= end) {
        coverage.push(
          ...sanitizePayloadBody(
            buffer,
            p,
            wPayLen,
            collector,
            mapping,
            intents,
            packetIndex,
            'mqtt',
            highPrivacy,
          ),
        )
        p += wPayLen
      }
    }
  }

  if (hasUser && p + 2 <= end) {
    const uLen = readU16be(buffer, p)
    p += 2
    if (uLen > 0 && p + uLen <= end) {
      mapAsciiIdentity(
        buffer,
        p,
        uLen,
        'user-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'mqtt',
      )
      coverage.push({ protocol: 'mqtt-user', offset: p, length: uLen, status: 'covered' })
      p += uLen
    }
  }

  if (hasPass && p + 2 <= end) {
    const pwLen = readU16be(buffer, p)
    p += 2
    if (pwLen > 0 && p + pwLen <= end) {
      maskBytes(collector, intents, packetIndex, p, pwLen, 'mqtt-password', 'mqtt')
      coverage.push({ protocol: 'mqtt-auth', offset: p, length: pwLen, status: 'redacted' })
      issues.push('mqtt-password-masked')
    }
  }
}

function sanitizePublish(
  buffer: Uint8Array,
  offset: number,
  length: number,
  firstByte: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: AppLayerResult['coverage'],
): void {
  if (length < 2) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mqtt-publish', 'mqtt')
    coverage.push({ protocol: 'mqtt-body', offset, length, status: 'redacted' })
    return
  }
  const topicLen = readU16be(buffer, offset)
  let p = offset + 2
  if (topicLen < 0 || p + topicLen > offset + length) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mqtt-publish', 'mqtt')
    coverage.push({ protocol: 'mqtt-body', offset, length, status: 'redacted' })
    return
  }
  coverage.push({ protocol: 'mqtt', offset, length: 2, status: 'covered' })
  coverage.push(
    ...sanitizeSlashPath(
      buffer,
      p,
      topicLen,
      collector,
      mapping,
      intents,
      packetIndex,
      'mqtt',
      highPrivacy,
    ),
  )
  p += topicLen
  const qos = (firstByte >> 1) & 0x03
  if (qos > 0) {
    if (p + 2 > offset + length) return
    coverage.push({ protocol: 'mqtt', offset: p, length: 2, status: 'covered' })
    p += 2
  }
  // MQTT 5 properties
  // If remaining starts with a small varint and looks like props, mask props
  const rem = offset + length - p
  if (rem > 0) {
    const maybe = readMqttRemainingLength(buffer, p, offset + length)
    if (
      maybe
      && maybe.value > 0
      && maybe.size + maybe.value <= rem
      && maybe.value <= 256
    ) {
      coverage.push({ protocol: 'mqtt', offset: p, length: maybe.size, status: 'covered' })
      sanitizeMqttV5Properties(
        buffer,
        p + maybe.size,
        maybe.value,
        collector,
        mapping,
        intents,
        packetIndex,
        highPrivacy,
        coverage,
        [],
      )
      p += maybe.size + maybe.value
    }
  }
  if (p < offset + length) {
    coverage.push(
      ...sanitizePayloadBody(
        buffer,
        p,
        offset + length - p,
        collector,
        mapping,
        intents,
        packetIndex,
        'mqtt',
        highPrivacy,
      ),
    )
  }
}
