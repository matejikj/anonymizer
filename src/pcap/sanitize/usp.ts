/**
 * T55 — USP (TR-369) Record sanitizer: descriptor-driven protobuf walker.
 * Maps from_id/to_id/session keys; masks MAC/certs and non-plaintext payloads;
 * unknown extensions of every wire type (varint/fixed32/fixed64/bytes) are masked;
 * Msg Get/Set/Notify strings: secrets mask, endpoint ids map. Bounded nesting.
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { computeFixedLengthAsciiBytes } from './textPatch.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import {
  USP_MAX_NESTING_DEPTH,
  fieldPolicyFor,
  type UspMessageName,
  type UspFieldPolicy,
} from './uspDescriptor.ts'

/** payload_security enum — PLAINTEXT allows Msg decode. */
const SECURITY_PLAINTEXT = 0

export function looksLikeUspRecord(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 6) return false
  // Field 1 length-delimited version "1.0" / "1.1" / "1.2" / "1.3"
  if (buffer[offset] !== 0x0a) return false
  const verLen = buffer[offset + 1]!
  if (verLen < 3 || verLen > 8 || offset + 2 + verLen > offset + length) return false
  const ver = new TextDecoder('ascii', { fatal: false }).decode(
    buffer.subarray(offset + 2, offset + 2 + verLen),
  )
  return /^1\.\d{1,2}$/.test(ver)
}

export function sanitizeUspRecord(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeUspRecord(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = [
    { protocol: 'usp', offset, length, status: 'covered' },
  ]
  const issues: string[] = []

  // First pass: read Record payload_security (field 4) so nested branch is correct regardless of field order.
  let payloadSecurity = SECURITY_PLAINTEXT
  scanPayloadSecurity(buffer, offset, length, (v) => {
    payloadSecurity = v
  })

  walkMessage(
    buffer,
    offset,
    length,
    'Record',
    0,
    payloadSecurity,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )

  return { coverage, issues }
}

function scanPayloadSecurity(
  buffer: Uint8Array,
  offset: number,
  length: number,
  onSecurity: (v: number) => void,
): void {
  const end = offset + length
  let pos = offset
  while (pos < end) {
    const tag = readVarint(buffer, pos, end)
    if (!tag) break
    pos = tag.next
    const field = tag.value >>> 3
    const wt = tag.value & 7
    if (wt === 0) {
      const v = readVarint(buffer, pos, end)
      if (!v) break
      if (field === 4) onSecurity(v.value)
      pos = v.next
      continue
    }
    if (wt === 1) {
      if (pos + 8 > end) break
      pos += 8
      continue
    }
    if (wt === 5) {
      if (pos + 4 > end) break
      pos += 4
      continue
    }
    if (wt !== 2) break
    const lenV = readVarint(buffer, pos, end)
    if (!lenV || lenV.next + lenV.value > end) break
    pos = lenV.next + lenV.value
  }
}

function walkMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  message: UspMessageName,
  depth: number,
  payloadSecurity: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (depth > USP_MAX_NESTING_DEPTH) {
    maskRange(collector, intents, packetIndex, offset, length, 'usp-depth')
    coverage.push({ protocol: 'usp-body', offset, length, status: 'redacted' })
    issues.push('usp-nesting-budget')
    return
  }

  const end = offset + length
  let pos = offset
  let ok = true

  while (pos < end) {
    const tagStart = pos
    const tag = readVarint(buffer, pos, end)
    if (!tag) {
      ok = false
      break
    }
    pos = tag.next
    const field = tag.value >>> 3
    const wt = tag.value & 7
    const policy = fieldPolicyFor(message, field)

    if (wt === 0) {
      const v = readVarint(buffer, pos, end)
      if (!v) {
        ok = false
        break
      }
      applyScalarPolicy(
        policy,
        buffer,
        pos,
        v.next - pos,
        tagStart,
        v.next,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        'varint',
      )
      pos = v.next
      continue
    }
    if (wt === 1) {
      if (pos + 8 > end) {
        ok = false
        break
      }
      applyScalarPolicy(
        policy,
        buffer,
        pos,
        8,
        tagStart,
        pos + 8,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        'fixed64',
      )
      pos += 8
      continue
    }
    if (wt === 5) {
      if (pos + 4 > end) {
        ok = false
        break
      }
      applyScalarPolicy(
        policy,
        buffer,
        pos,
        4,
        tagStart,
        pos + 4,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        'fixed32',
      )
      pos += 4
      continue
    }
    if (wt !== 2) {
      ok = false
      break
    }
    const lenV = readVarint(buffer, pos, end)
    if (!lenV || lenV.next + lenV.value > end) {
      ok = false
      break
    }
    const dataOff = lenV.next
    const dataLen = lenV.value
    pos = dataOff + dataLen
    applyLengthDelimitedPolicy(
      policy,
      buffer,
      dataOff,
      dataLen,
      tagStart,
      pos,
      depth,
      payloadSecurity,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      message,
    )
  }

  if (!ok) {
    maskRange(collector, intents, packetIndex, pos, end - pos, 'usp-desync')
    coverage.push({ protocol: 'usp-body', offset: pos, length: end - pos, status: 'malformed' })
    issues.push('usp-record-desync')
  }
}

function applyScalarPolicy(
  policy: UspFieldPolicy,
  _buffer: Uint8Array,
  valueOff: number,
  valueLen: number,
  tagStart: number,
  fieldEnd: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  wireLabel: string,
): void {
  if (policy.kind === 'preserve') {
    coverage.push({ protocol: 'usp', offset: tagStart, length: fieldEnd - tagStart, status: 'covered' })
    return
  }
  // Unknown / mask / map-id on scalar → typed unknown mask (length-preserving)
  maskRange(collector, intents, packetIndex, valueOff, valueLen, 'usp-unknown')
  coverage.push({
    protocol: 'usp-body',
    offset: valueOff,
    length: valueLen,
    status: 'redacted',
  })
  issues.push(`usp-unknown-${wireLabel}-masked`)
}

function applyLengthDelimitedPolicy(
  policy: UspFieldPolicy,
  buffer: Uint8Array,
  dataOff: number,
  dataLen: number,
  tagStart: number,
  fieldEnd: number,
  depth: number,
  payloadSecurity: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  parentMessage: UspMessageName,
): void {
  void parentMessage
  switch (policy.kind) {
    case 'preserve':
      coverage.push({ protocol: 'usp', offset: tagStart, length: fieldEnd - tagStart, status: 'covered' })
      return
    case 'map-id':
      mapBytes(
        buffer,
        dataOff,
        dataLen,
        'opaque-id',
        policy.prefix,
        collector,
        mapping,
        intents,
        packetIndex,
      )
      coverage.push({ protocol: 'usp-id', offset: dataOff, length: dataLen, status: 'covered' })
      return
    case 'mask':
      maskRange(collector, intents, packetIndex, dataOff, dataLen, policy.domain)
      coverage.push({
        protocol: policy.domain === 'usp-auth' ? 'usp-auth' : 'usp-body',
        offset: dataOff,
        length: dataLen,
        status: 'redacted',
      })
      if (policy.domain === 'usp-auth') issues.push('usp-integrity-material-masked')
      else if (policy.domain === 'usp-unknown') issues.push('usp-unknown-field-masked')
      return
    case 'nested':
      walkMessage(
        buffer,
        dataOff,
        dataLen,
        policy.message,
        depth + 1,
        payloadSecurity,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
      return
    case 'payload-msg':
      if (payloadSecurity !== SECURITY_PLAINTEXT) {
        maskRange(collector, intents, packetIndex, dataOff, dataLen, 'usp-e2e')
        coverage.push({ protocol: 'usp-body', offset: dataOff, length: dataLen, status: 'redacted' })
        issues.push('usp-non-plaintext-payload-masked')
        return
      }
      sanitizeUspMessage(
        buffer,
        dataOff,
        dataLen,
        depth + 1,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
      return
    case 'msg-body':
      sanitizeUspMessage(
        buffer,
        dataOff,
        dataLen,
        depth + 1,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
      return
    default:
      maskRange(collector, intents, packetIndex, dataOff, dataLen, 'usp-unknown')
      coverage.push({ protocol: 'usp-body', offset: dataOff, length: dataLen, status: 'redacted' })
      issues.push('usp-unknown-field-masked')
  }
}

function sanitizeUspMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  depth: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (depth > USP_MAX_NESTING_DEPTH) {
    maskRange(collector, intents, packetIndex, offset, length, 'usp-depth')
    coverage.push({ protocol: 'usp-body', offset, length, status: 'redacted' })
    issues.push('usp-nesting-budget')
    return
  }
  coverage.push({ protocol: 'usp-msg', offset, length, status: 'covered' })
  const end = offset + length
  let pos = offset
  while (pos < end) {
    const tag = readVarint(buffer, pos, end)
    if (!tag) break
    pos = tag.next
    const wt = tag.value & 7
    if (wt === 0) {
      const v = readVarint(buffer, pos, end)
      if (!v) break
      // Unknown Msg varints — typed unknown mask (no schema leaf preserve inside free Msg body)
      maskRange(collector, intents, packetIndex, pos, v.next - pos, 'usp-unknown')
      coverage.push({ protocol: 'usp-body', offset: pos, length: v.next - pos, status: 'redacted' })
      issues.push('usp-unknown-varint-masked')
      pos = v.next
      continue
    }
    if (wt === 1) {
      if (pos + 8 > end) break
      maskRange(collector, intents, packetIndex, pos, 8, 'usp-unknown')
      coverage.push({ protocol: 'usp-body', offset: pos, length: 8, status: 'redacted' })
      issues.push('usp-unknown-fixed64-masked')
      pos += 8
      continue
    }
    if (wt === 5) {
      if (pos + 4 > end) break
      maskRange(collector, intents, packetIndex, pos, 4, 'usp-unknown')
      coverage.push({ protocol: 'usp-body', offset: pos, length: 4, status: 'redacted' })
      issues.push('usp-unknown-fixed32-masked')
      pos += 4
      continue
    }
    if (wt !== 2) break
    const lenV = readVarint(buffer, pos, end)
    if (!lenV || lenV.next + lenV.value > end) break
    const dataOff = lenV.next
    const dataLen = lenV.value
    pos = dataOff + dataLen
    if (dataLen === 0) continue
    if (looksLikeNestedMessage(buffer, dataOff, dataLen)) {
      sanitizeUspMessage(
        buffer,
        dataOff,
        dataLen,
        depth + 1,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
      continue
    }
    const text = new TextDecoder('utf-8', { fatal: false }).decode(
      buffer.subarray(dataOff, dataOff + dataLen),
    )
    if (text.length !== dataLen) {
      maskRange(collector, intents, packetIndex, dataOff, dataLen, 'usp-bin')
      coverage.push({ protocol: 'usp-body', offset: dataOff, length: dataLen, status: 'redacted' })
      continue
    }
    if (isSecretText(text)) {
      maskRange(collector, intents, packetIndex, dataOff, dataLen, 'usp-secret')
      coverage.push({ protocol: 'usp-secret', offset: dataOff, length: dataLen, status: 'redacted' })
      issues.push('usp-secret-masked')
      continue
    }
    if (isIdentityText(text)) {
      mapBytes(buffer, dataOff, dataLen, 'opaque-id', 'usp-str:', collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'usp-id', offset: dataOff, length: dataLen, status: 'covered' })
      continue
    }
    if (/^Device\./i.test(text) || /^InternetGatewayDevice\./i.test(text)) {
      coverage.push({ protocol: 'usp', offset: dataOff, length: dataLen, status: 'covered' })
      continue
    }
    // Free config / unknown string — mask
    if (dataLen >= 4 && /[A-Za-z]/.test(text)) {
      maskRange(collector, intents, packetIndex, dataOff, dataLen, 'usp-val')
      coverage.push({ protocol: 'usp-body', offset: dataOff, length: dataLen, status: 'redacted' })
    }
  }
}

function looksLikeNestedMessage(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  let printable = 0
  const n = Math.min(length, 24)
  for (let i = 0; i < n; i++) {
    const b = buffer[offset + i]!
    if (b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b < 0x7f)) printable++
  }
  if (printable >= Math.ceil(n * 0.85)) return false
  const tag = buffer[offset]!
  const wt = tag & 7
  if (wt !== 0 && wt !== 1 && wt !== 2 && wt !== 5) return false
  const field = tag >>> 3
  if (field < 1 || field > 64) return false
  if (wt === 2) {
    const lenV = readVarint(buffer, offset + 1, offset + length)
    if (!lenV || lenV.next + lenV.value > offset + length) return false
    return true
  }
  if (wt === 0) {
    return readVarint(buffer, offset + 1, offset + length) !== null
  }
  if (wt === 1) return length >= 9
  if (wt === 5) return length >= 5
  return false
}

function isSecretText(text: string): boolean {
  return (
    /(?:password|passphrase|psk|secret|token|private[_-]?key|credential)/i.test(text)
    || (text.length >= 12 && /^[A-Za-z0-9+/=_-]+$/.test(text) && /[A-Za-z]/.test(text) && /\d/.test(text))
  )
}

function isIdentityText(text: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)
    || /^proto::/i.test(text)
    || /^os::/i.test(text)
    || /@/.test(text)
    || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)
  )
}

function readVarint(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { value: number; next: number } | null {
  let value = 0
  let shift = 0
  let pos = offset
  while (pos < end && shift <= 35) {
    const b = buffer[pos]!
    pos++
    value |= (b & 0x7f) << shift
    if ((b & 0x80) === 0) return { value: value >>> 0, next: pos }
    shift += 7
  }
  return null
}

function mapBytes(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: 'opaque-id',
  prefix: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  if (length <= 0) return
  const raw = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  const canon = canonicalizeIdentity(category, `${prefix}${raw}`) ?? `${prefix}${raw}`
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, length, constraint, raw)
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            length,
            live.aliasFor(category, canon, constraint, raw),
          )
        } catch {
          return createProtocolNeutralMaskFill({
            length,
            packetIndex,
            offset,
            domain: 'usp-id',
          })
        }
      },
      { fallbackKind: 'text-x', protocol: 'usp', category, packetIndex },
    )
  } catch {
    /* overlap */
  }
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'usp')
}
