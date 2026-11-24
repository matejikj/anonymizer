/**
 * T28 — WireGuard message sanitizer.
 * Positive type/size/reserved classification required; handshake crypto fields masked;
 * transport ciphertext preserved only with T14 assertEncryptedClassification.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import {
  assertEncryptedClassification,
} from '../kernel/encryptedClassification.ts'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

const WG_INITIATION = 1
const WG_RESPONSE = 2
const WG_COOKIE = 3
const WG_TRANSPORT = 4

const WG_LEN = {
  [WG_INITIATION]: 148,
  [WG_RESPONSE]: 92,
  [WG_COOKIE]: 64,
} as const

export function looksLikeWireGuard(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const type = data[offset]!
  const reserved =
    data[offset + 1]! | data[offset + 2]! | data[offset + 3]!
  if (reserved !== 0) return false
  if (type === WG_INITIATION) return length === WG_LEN[WG_INITIATION]
  if (type === WG_RESPONSE) return length === WG_LEN[WG_RESPONSE]
  if (type === WG_COOKIE) return length === WG_LEN[WG_COOKIE]
  if (type === WG_TRANSPORT) return length >= 16 // header + empty AEAD tag min
  return false
}

export function sanitizeWireGuard(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeWireGuard(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const type = buffer[offset]!

  // sender/receiver indices (4 bytes LE after type/reserved) — opaque-id via consistent mask
  if (length >= 8) {
    mapIndex(buffer, offset + 4, 4, collector, mapping, intents, packetIndex, 'wg-sender')
  }
  if ((type === WG_RESPONSE || type === WG_TRANSPORT) && length >= 12) {
    mapIndex(buffer, offset + 8, 4, collector, mapping, intents, packetIndex, 'wg-receiver')
  }

  if (type === WG_INITIATION) {
    // ephemeral (32) + encrypted static (48) + encrypted timestamp (28) + mac1/mac2 (32)
    maskSpan(collector, intents, packetIndex, offset + 12, length - 12, 'wg-handshake')
    coverage.push({ protocol: 'wireguard-handshake', offset, length, status: 'redacted' })
    issues.push('crypto-integrity-modified:wireguard')
  } else if (type === WG_RESPONSE) {
    maskSpan(collector, intents, packetIndex, offset + 12, length - 12, 'wg-handshake')
    coverage.push({ protocol: 'wireguard-handshake', offset, length, status: 'redacted' })
    issues.push('crypto-integrity-modified:wireguard')
  } else if (type === WG_COOKIE) {
    maskSpan(collector, intents, packetIndex, offset + 4, length - 4, 'wg-cookie')
    coverage.push({ protocol: 'wireguard-cookie', offset, length, status: 'redacted' })
  } else {
    // Transport — proven WireGuard AEAD after positive classify
    assertEncryptedClassification({
      protocolId: 'wireguard',
      variant: 'transport-data',
      phase: 'application-data',
      confidentialityProven: true,
    })
    // Keep ciphertext bytes; indices already remapped (may invalidate AEAD — report).
    coverage.push({ protocol: 'wireguard', offset, length, status: 'encrypted' })
    issues.push('crypto-integrity-modified:wireguard-index')
  }

  return { coverage, issues }
}

function mapIndex(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  const hex = bytesToHex(buffer.subarray(offset, offset + length))
  collector.addDeferred(
    offset,
    length,
    (ctx) => {
      const alias = ctx.mapping.map('opaque-id', hex)
      return createProtocolNeutralMaskFill({
        length,
        packetIndex,
        offset,
        domain: `${domain}:${alias}`,
      })
    },
    { fallbackKind: 'binary-mask', protocol: 'wireguard', category: 'opaque-id', packetIndex },
  )
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'wireguard')
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'wireguard')
}

function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    s += bytes[i]!.toString(16).padStart(2, '0')
  }
  return s
}
