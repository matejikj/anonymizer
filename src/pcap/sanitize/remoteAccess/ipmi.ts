/**
 * T39 — IPMI / RMCP+ (UDP 623): ASF presence preserve; RAKP username map;
 * randoms/HMAC always mask; cipher-suite None is not encrypted-preserved.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapAsciiIdentity, maskBytes, readU32be } from './common.ts'

export const IPMI_UDP_PORT = 623

const RMCP_CLASS_ASF = 0x06
const RMCP_CLASS_IPMI = 0x07
const RMCPPLUS_AUTH = 0x06

// RMCP+ payload types
const RAKP1 = 0x12
const RAKP2 = 0x13
const RAKP3 = 0x14
const RAKP4 = 0x15

export function isIpmiPortHint(srcPort: number, dstPort: number): boolean {
  return srcPort === IPMI_UDP_PORT || dstPort === IPMI_UDP_PORT
}

export function looksLikeRmcp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  return buffer[offset] === 0x06 // RMCP version 1.0
}

export function sanitizeIpmi(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isIpmiPortHint(srcPort, dstPort)) return null
  if (!looksLikeRmcp(buffer, offset, length)) {
    maskBytes(collector, intents, packetIndex, offset, length, 'ipmi-unknown', 'ipmi')
    return {
      coverage: [{ protocol: 'ipmi', offset, length, status: 'redacted' }],
      issues: ['ipmi-non-rmcp-masked'],
    }
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  const cls = buffer[offset + 3]! & 0x7f

  coverage.push({ protocol: 'ipmi', offset, length: 4, status: 'covered' })

  if (cls === RMCP_CLASS_ASF) {
    // Presence ping / pong — structural preserve; mask any trailing unexpected body.
    const asfLen = Math.min(length, 8)
    coverage.push({ protocol: 'ipmi-asf', offset, length: asfLen, status: 'covered' })
    if (length > asfLen) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        offset + asfLen,
        length - asfLen,
        'ipmi-asf-tail',
        'ipmi',
      )
    }
    coverage.push({ protocol: 'ipmi', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  if (cls !== RMCP_CLASS_IPMI || length < 10) {
    maskBytes(collector, intents, packetIndex, offset + 4, length - 4, 'ipmi-body', 'ipmi')
    coverage.push({
      protocol: 'ipmi-body',
      offset: offset + 4,
      length: length - 4,
      status: 'redacted',
    })
    return { coverage, issues }
  }

  // IPMI session header (1.5 / 2.0): auth type at offset+4
  const authType = buffer[offset + 4]!
  if (authType === RMCPPLUS_AUTH && length >= 16) {
    const payloadType = buffer[offset + 5]! & 0x3f
    const encrypted = (buffer[offset + 5]! & 0x80) !== 0
    const authenticated = (buffer[offset + 5]! & 0x40) !== 0

    // Session ID / sequence — scoped opaque map of 4B session id when present
    if (length >= 16) {
      const sid = readU32be(buffer, offset + 6)
      if (sid !== 0) {
        // Keep wire length; mask as opaque session material (not a user identity).
        maskBytes(collector, intents, packetIndex, offset + 6, 4, 'ipmi-session-id', 'ipmi')
      }
      coverage.push({ protocol: 'ipmi-rmcpplus', offset: offset + 4, length: 12, status: 'covered' })
    }

    const payloadOff = offset + 16
    if (payloadOff >= end) return { coverage, issues }

    if (payloadType === RAKP1 && end - payloadOff >= 28) {
      // tag(1) reserved(3) managed SID(4) console random(16) priv(1) reserved(2) nameLen(1) name
      maskBytes(collector, intents, packetIndex, payloadOff + 8, 16, 'ipmi-rakp-random', 'ipmi')
      coverage.push({
        protocol: 'ipmi-rakp-auth',
        offset: payloadOff + 8,
        length: 16,
        status: 'redacted',
      })
      const nameLen = buffer[payloadOff + 27]!
      if (nameLen > 0 && payloadOff + 28 + nameLen <= end) {
        mapAsciiIdentity(
          buffer,
          payloadOff + 28,
          nameLen,
          'user-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'ipmi',
        )
        coverage.push({
          protocol: 'ipmi-rakp-user',
          offset: payloadOff + 28,
          length: nameLen,
          status: 'covered',
        })
        const after = payloadOff + 28 + nameLen
        if (after < end) {
          maskBytes(collector, intents, packetIndex, after, end - after, 'ipmi-rakp-tail', 'ipmi')
        }
      } else {
        maskBytes(
          collector,
          intents,
          packetIndex,
          payloadOff + 28,
          end - (payloadOff + 28),
          'ipmi-rakp-tail',
          'ipmi',
        )
      }
      coverage.push({ protocol: 'ipmi-rakp1', offset: payloadOff, length: end - payloadOff, status: 'covered' })
      return { coverage, issues }
    }

    if (payloadType === RAKP2 || payloadType === RAKP3 || payloadType === RAKP4) {
      // HMAC / GUID / random transcripts — always mask body
      maskBytes(
        collector,
        intents,
        packetIndex,
        payloadOff,
        end - payloadOff,
        'ipmi-rakp-auth',
        'ipmi',
      )
      coverage.push({
        protocol: 'ipmi-rakp-auth',
        offset: payloadOff,
        length: end - payloadOff,
        status: 'redacted',
      })
      return { coverage, issues }
    }

    if (encrypted && authenticated) {
      // Confidentiality flag set — still require proven suite; None is not proven.
      // Without suite dictionary, mask (do not label encrypted-preserved).
      maskBytes(
        collector,
        intents,
        packetIndex,
        payloadOff,
        end - payloadOff,
        'ipmi-payload',
        'ipmi',
      )
      coverage.push({
        protocol: 'ipmi-body',
        offset: payloadOff,
        length: end - payloadOff,
        status: 'redacted',
      })
      issues.push('ipmi-encrypted-unproven-masked')
      return { coverage, issues }
    }

    maskBytes(collector, intents, packetIndex, payloadOff, end - payloadOff, 'ipmi-payload', 'ipmi')
    coverage.push({
      protocol: 'ipmi-body',
      offset: payloadOff,
      length: end - payloadOff,
      status: 'redacted',
    })
    return { coverage, issues }
  }

  // IPMI 1.5 — auth type plaintext/MD5/…: mask auth code region (16B typical) + body
  if (authType !== 0 && length >= 26) {
    maskBytes(collector, intents, packetIndex, offset + 10, 16, 'ipmi-auth', 'ipmi')
    coverage.push({ protocol: 'ipmi-auth', offset: offset + 10, length: 16, status: 'redacted' })
    if (offset + 26 < end) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        offset + 26,
        end - (offset + 26),
        'ipmi-body',
        'ipmi',
      )
      coverage.push({
        protocol: 'ipmi-body',
        offset: offset + 26,
        length: end - (offset + 26),
        status: 'redacted',
      })
    }
    return { coverage, issues }
  }

  maskBytes(collector, intents, packetIndex, offset + 4, length - 4, 'ipmi-body', 'ipmi')
  coverage.push({
    protocol: 'ipmi-body',
    offset: offset + 4,
    length: length - 4,
    status: 'redacted',
  })
  coverage.push({ protocol: 'ipmi', offset, length, status: 'covered' })
  return { coverage, issues }
}
