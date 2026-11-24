/**
 * T28 — SSH transport sanitizer (mask-first).
 * Version-line fingerprint; host-key / signature mask; unknown phase → opaque mask
 * (never encrypted-preserved without per-direction NEWKEYS + proven confidentiality).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage, SanitizationPolicy } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

const SSH_MSG_KEXINIT = 20
const SSH_MSG_NEWKEYS = 21
const SSH_MSG_KEX_ECDH_REPLY = 31

export function looksLikeSsh(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  // Banner
  if (
    data[offset] === 0x53
    && data[offset + 1] === 0x53
    && data[offset + 2] === 0x48
    && data[offset + 3] === 0x2d
  ) {
    return true
  }
  // Binary packet: uint32 length + byte padding + payload (msg type)
  if (length >= 6) {
    const pktLen = readU32be(data, offset)
    if (pktLen >= 2 && pktLen + 4 <= length && pktLen < 0x40000) {
      const pad = data[offset + 4]!
      const msg = data[offset + 5]!
      // Reject Annex J / XML / HTTP mistaken for SSH binary (padding byte must not be '<').
      if (pad === 0x3c /* < */ || msg === 0x3f /* '?' of <?xml */) return false
      // RFC 4253: padding_length is at least 4 when block=8; keep lower bound modest.
      if (pad >= 4 && pad < pktLen && msg >= 1 && msg <= 100) return true
    }
  }
  return false
}

export function sanitizeSsh(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  policy: SanitizationPolicy,
): AppLayerResult | null {
  if (!looksLikeSsh(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = offset
  const end = offset + length

  if (
    buffer[offset] === 0x53
    && buffer[offset + 1] === 0x53
    && buffer[offset + 2] === 0x48
  ) {
    const nl = findCrLf(buffer, offset, end)
    if (nl < 0) {
      maskSpan(collector, intents, packetIndex, offset, length, 'ssh-banner-trunc')
      coverage.push({ protocol: 'ssh', offset, length, status: 'malformed' })
      return { coverage, issues: ['ssh-banner-incomplete'] }
    }
    const lineLen = nl - offset
    sanitizeVersionLine(
      buffer,
      offset,
      lineLen,
      collector,
      intents,
      packetIndex,
      policy,
      coverage,
    )
    pos = nl + (buffer[nl] === 0x0d && nl + 1 < end && buffer[nl + 1] === 0x0a ? 2 : 1)
  }

  let sawNewkeys = false
  while (pos + 6 <= end) {
    const pktLen = readU32be(buffer, pos)
    if (pktLen < 2 || pos + 4 + pktLen > end) {
      const rem = end - pos
      if (rem > 0) {
        maskSpan(collector, intents, packetIndex, pos, rem, 'ssh-phase-unknown')
        coverage.push({ protocol: 'ssh', offset: pos, length: rem, status: 'redacted' })
        issues.push('ssh-phase-unknown')
      }
      break
    }
    const msgType = buffer[pos + 5]!
    const payloadStart = pos + 6
    const payloadEnd = pos + 4 + pktLen
    const padLen = buffer[pos + 4]!
    const msgEnd = Math.max(payloadStart, payloadEnd - padLen)

    if (msgType === SSH_MSG_KEXINIT) {
      coverage.push({ protocol: 'ssh-kexinit', offset: pos, length: 4 + pktLen, status: 'covered' })
    } else if (msgType === SSH_MSG_KEX_ECDH_REPLY) {
      if (msgEnd > payloadStart) {
        maskSpan(
          collector,
          intents,
          packetIndex,
          payloadStart,
          msgEnd - payloadStart,
          'ssh-host-key',
        )
      }
      // Length/pad/type framing preserved; only host-key body masked. Split so T63
      // statusInvariant does not remask the framing over the host-key patch.
      coverage.push({
        protocol: 'ssh-kex-reply',
        offset: pos,
        length: Math.min(6, 4 + pktLen),
        status: 'covered',
      })
      if (msgEnd > payloadStart) {
        coverage.push({
          protocol: 'ssh-kex-reply',
          offset: payloadStart,
          length: msgEnd - payloadStart,
          status: 'redacted',
        })
      }
      const trailer = payloadEnd - msgEnd
      if (trailer > 0) {
        coverage.push({
          protocol: 'ssh-kex-reply',
          offset: msgEnd,
          length: trailer,
          status: 'covered',
        })
      }
      issues.push('crypto-integrity-modified:ssh')
    } else if (msgType === SSH_MSG_NEWKEYS) {
      sawNewkeys = true
      coverage.push({ protocol: 'ssh-newkeys', offset: pos, length: 4 + pktLen, status: 'covered' })
    } else if (sawNewkeys) {
      maskSpan(collector, intents, packetIndex, pos, 4 + pktLen, 'ssh-post-newkeys-unproven')
      coverage.push({ protocol: 'ssh', offset: pos, length: 4 + pktLen, status: 'redacted' })
      issues.push('ssh-confidentiality-unproven')
    } else {
      coverage.push({ protocol: 'ssh', offset: pos, length: 4 + pktLen, status: 'covered' })
    }
    pos = payloadEnd
  }

  if (coverage.length === 0) {
    maskSpan(collector, intents, packetIndex, offset, length, 'ssh-opaque')
    coverage.push({ protocol: 'ssh', offset, length, status: 'redacted' })
  }
  return { coverage, issues }
}

function sanitizeVersionLine(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
): void {
  const text = new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
  const m = /^(SSH-[0-9.]+-)([^\s]+)(?: (.*))?$/.exec(text)
  if (!m) {
    maskSpan(collector, intents, packetIndex, offset, length, 'ssh-banner')
    coverage.push({ protocol: 'ssh-banner', offset, length, status: 'redacted' })
    return
  }
  const prefix = m[1]!
  const software = m[2]!
  const comment = m[3]
  const softOff = offset + prefix.length
  if (policy.preset === 'high-privacy') {
    maskSpan(collector, intents, packetIndex, softOff, software.length, 'ssh-software')
  }
  if (comment != null && comment.length > 0) {
    const commentOff = softOff + software.length + 1
    maskSpan(collector, intents, packetIndex, commentOff, comment.length, 'ssh-banner-comment')
  }
  // Banner framing + software string stay (diagnostic); only comment/HP software are
  // patched. Whole-span `redacted` would trip T63 statusInvariant into wiping OpenSSH_*.
  coverage.push({ protocol: 'ssh-banner', offset, length, status: 'covered' })
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'ssh')
}

function findCrLf(buf: Uint8Array, start: number, end: number): number {
  for (let i = start; i < end; i++) {
    if (buf[i] === 0x0a) return i > start && buf[i - 1] === 0x0d ? i - 1 : i
  }
  return -1
}

function readU32be(buf: Uint8Array, off: number): number {
  return (
    ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0
  )
}
