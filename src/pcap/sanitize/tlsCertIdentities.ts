/**
 * Enterprise step 10 — TLS 1.2 plaintext certificate CN / SAN sanitization.
 * Maps readable hostnames and IP SANs; masks remaining DER as opaque.
 */

import type { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { ipv6TextToBytes16 } from './ipv6Wire'
import { readAsn1LengthCompat as readAsn1Length } from '../protocols/application/binproto/ber.ts'

/** X.509 CN OID 2.5.4.3 */
const CN_OID = [0x06, 0x03, 0x55, 0x04, 0x03] as const

const ASN1_UTF8_STRING = 0x0c
const ASN1_PRINTABLE_STRING = 0x13
const ASN1_TELETEX_STRING = 0x14
const ASN1_IA5_STRING = 0x16
const ASN1_BMP_STRING = 0x1e

/** GeneralName dNSName / iPAddress (context-specific primitive). */
const GN_DNS_NAME = 0x82
const GN_IP_ADDRESS = 0x87

export interface CertIdentitySpan {
  readonly offset: number
  readonly length: number
  readonly category: 'hostname' | 'ipv4' | 'ipv6'
  readonly value: string
}

/**
 * Locate readable CN / SAN DNS / SAN IP spans inside a DER certificate body.
 * Best-effort scan — malformed DER yields fewer spans; caller still masks the rest.
 */
export function findReadableCertIdentities(
  buffer: Uint8Array,
  start: number,
  length: number,
): CertIdentitySpan[] {
  const end = start + length
  const out: CertIdentitySpan[] = []
  const seen = new Set<string>()

  const push = (span: CertIdentitySpan) => {
    const key = `${span.offset}:${span.length}`
    if (seen.has(key) || span.length <= 0) return
    seen.add(key)
    out.push(span)
  }

  // CN = OID 2.5.4.3 followed by a DirectoryString.
  for (let i = start; i + CN_OID.length + 2 <= end; i++) {
    let match = true
    for (let k = 0; k < CN_OID.length; k++) {
      if (buffer[i + k] !== CN_OID[k]) {
        match = false
        break
      }
    }
    if (!match) continue
    const strOffset = i + CN_OID.length
    const parsed = readAsn1String(buffer, strOffset, end)
    if (!parsed) continue
    if (looksLikeHostname(parsed.value)) {
      push({
        offset: parsed.contentOffset,
        length: parsed.contentLength,
        category: 'hostname',
        value: parsed.value,
      })
    }
  }

  // SAN GeneralNames — scan for context tags (no full extension walk required).
  for (let i = start; i + 2 <= end; i++) {
    const tag = buffer[i]!
    if (tag === GN_DNS_NAME) {
      const lenInfo = readAsn1Length(buffer, i + 1, end)
      if (!lenInfo) continue
      const contentOffset = lenInfo.contentOffset
      const contentLength = lenInfo.length
      if (contentOffset + contentLength > end || contentLength === 0 || contentLength > 253) continue
      let host = ''
      for (let j = 0; j < contentLength; j++) host += String.fromCharCode(buffer[contentOffset + j]!)
      if (looksLikeHostname(host)) {
        push({ offset: contentOffset, length: contentLength, category: 'hostname', value: host })
      }
    } else if (tag === GN_IP_ADDRESS) {
      const lenInfo = readAsn1Length(buffer, i + 1, end)
      if (!lenInfo) continue
      const contentOffset = lenInfo.contentOffset
      const contentLength = lenInfo.length
      if (contentOffset + contentLength > end) continue
      if (contentLength === 4) {
        const ip = `${buffer[contentOffset]!}.${buffer[contentOffset + 1]!}.${buffer[contentOffset + 2]!}.${buffer[contentOffset + 3]!}`
        push({ offset: contentOffset, length: 4, category: 'ipv4', value: ip })
      } else if (contentLength === 16) {
        const parts: string[] = []
        for (let j = 0; j < 16; j += 2) {
          const v = (buffer[contentOffset + j]! << 8) | buffer[contentOffset + j + 1]!
          parts.push(v.toString(16))
        }
        push({
          offset: contentOffset,
          length: 16,
          category: 'ipv6',
          value: parts.join(':'),
        })
      }
    }
  }

  out.sort((a, b) => a.offset - b.offset)
  return out
}

/**
 * MAP readable CN/SAN identities; MASK remaining certificate DER bytes.
 * Length-preserving; identity patches and mask gaps never overlap.
 */
export function sanitizeCertificateDerIdentities(
  buffer: Uint8Array,
  certStart: number,
  certLength: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (certLength <= 0) return
  const identities = findReadableCertIdentities(buffer, certStart, certLength)
  const certEnd = certStart + certLength

  if (identities.length === 0) {
    maskOpaqueRange(collector, intents, packetIndex, certStart, certLength, 'tls-certificate-der')
    return
  }

  let cursor = certStart
  for (const id of identities) {
    if (id.offset > cursor) {
      maskOpaqueRange(
        collector,
        intents,
        packetIndex,
        cursor,
        id.offset - cursor,
        'tls-certificate-der',
      )
    }
    mapIdentitySpan(buffer, id, collector, mapping, intents, packetIndex)
    cursor = id.offset + id.length
  }
  if (cursor < certEnd) {
    maskOpaqueRange(
      collector,
      intents,
      packetIndex,
      cursor,
      certEnd - cursor,
      'tls-certificate-der',
    )
  }
}

function mapIdentitySpan(
  _buffer: Uint8Array,
  id: CertIdentitySpan,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (id.category === 'hostname') {
    intents?.recordEntityReplacement(
      packetIndex,
      id.offset,
      'hostname',
      id.value,
      id.length,
      { kind: 'text-ascii', byteLength: id.length },
      id.value,
    )
    collector.addDeferred(id.offset, id.length, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.aliasFor(
        'hostname',
        id.value,
        { kind: 'text-ascii', byteLength: id.length },
        id.value,
      )
      return computeFixedLengthAsciiBytes(id.offset, id.length, mapped)
    })
    return
  }

  if (id.category === 'ipv4' && id.length === 4) {
    intents?.recordEntityReplacement(packetIndex, id.offset, 'ipv4', id.value, 4)
    collector.addDeferred(id.offset, 4, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv4', id.value)
      return new Uint8Array(mapped.split('.').map(Number))
    })
    return
  }

  if (id.category === 'ipv6' && id.length === 16) {
    intents?.recordEntityReplacement(packetIndex, id.offset, 'ipv6', id.value, 16)
    collector.addDeferred(id.offset, 16, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('ipv6', id.value)
      return ipv6TextToBytes16(mapped) ?? new Uint8Array(16)
    })
    return
  }

  maskOpaqueRange(collector, intents, packetIndex, id.offset, id.length, 'tls-certificate-san-ip')
}

function maskOpaqueRange(
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'tls')
}

function looksLikeHostname(value: string): boolean {
  if (value.length < 1 || value.length > 253) return false
  // Reject non-printable / obvious binary.
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    if (c < 0x20 || c > 0x7e) return false
  }
  if (value.includes(' ') || value.includes('=')) return false
  // Allow single-label CN and FQDNs.
  return /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(value)
    || (value.includes('.') && /^[A-Za-z0-9._*-]+$/.test(value))
}

function readAsn1String(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { value: string; contentOffset: number; contentLength: number } | null {
  if (offset >= end) return null
  const tag = buffer[offset]!
  if (
    tag !== ASN1_UTF8_STRING
    && tag !== ASN1_PRINTABLE_STRING
    && tag !== ASN1_TELETEX_STRING
    && tag !== ASN1_IA5_STRING
    && tag !== ASN1_BMP_STRING
  ) {
    return null
  }
  const lenInfo = readAsn1Length(buffer, offset + 1, end)
  if (!lenInfo) return null
  if (lenInfo.contentOffset + lenInfo.length > end) return null
  if (tag === ASN1_BMP_STRING) {
    // BMPString is UCS-2 — skip for hostname MAP (rare in practice).
    return null
  }
  let value = ''
  for (let i = 0; i < lenInfo.length; i++) {
    value += String.fromCharCode(buffer[lenInfo.contentOffset + i]!)
  }
  return {
    value,
    contentOffset: lenInfo.contentOffset,
    contentLength: lenInfo.length,
  }
}
