/**
 * T37 — MSRP (RFC 4975): map path hosts/session; mask message body; preserve transaction framing.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { AppLayerResult, LayerCoverage } from './types'

const MSRP_START = /^MSRP\s+(\S+)\s+(\S+)/i

export function looksLikeMsrp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const head = new TextDecoder('ascii', { fatal: false }).decode(
    data.subarray(offset, offset + Math.min(length, 64)),
  )
  return /^MSRP\s+\S+\s+\S+/i.test(head)
}

export function isMsrpPortHint(src: number, dst: number): boolean {
  // Dynamic ports from SDP — content probe is authoritative
  void src
  void dst
  return false
}

export function sanitizeMsrp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeMsrp(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const text = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  const lines = text.split(/\r\n/)
  if (lines.length === 0) return null

  const start = lines[0]!
  const startMatch = MSRP_START.exec(start)
  if (!startMatch) {
    maskSpan(buffer, offset, length, collector, packetIndex, 'msrp-bad-start')
    return {
      coverage: [{ protocol: 'msrp', offset, length, status: 'malformed' }],
      issues: ['msrp-start'],
    }
  }
  const txnId = startMatch[1]!
  coverage.push({ protocol: 'msrp', offset, length: start.length + 2, status: 'covered' })

  // Map txn id as opaque (must match end-line)
  const txnOffInLine = start.indexOf(txnId)
  if (txnOffInLine >= 0) {
    mapOpaqueAscii(buffer, offset + txnOffInLine, txnId.length, collector, mapping, intents, packetIndex)
  }

  let cursor = offset + start.length + 2 // assume CRLF
  let bodyStart = -1
  let contentType: string | null = null

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!
    if (line === '') {
      bodyStart = cursor + 2
      break
    }
    const colon = line.indexOf(':')
    if (colon > 0) {
      const name = line.slice(0, colon).trim().toLowerCase()
      const value = line.slice(colon + 1).trim()
      const valueOff = cursor + colon + 1 + (line.slice(colon + 1).match(/^\s*/)?.[0].length ?? 0)
      if (name === 'to-path' || name === 'from-path') {
        mapMsrpPath(buffer, valueOff, value, collector, mapping, intents, packetIndex)
      } else if (name === 'message-id') {
        mapOpaqueAscii(buffer, valueOff, value.length, collector, mapping, intents, packetIndex)
      } else if (name === 'content-type') {
        contentType = value.toLowerCase()
      }
      // Byte-Range / Success-Report / Failure-Report preserved
    }
    cursor += line.length + 2
  }

  // End line -------txnId$
  const endRe = new RegExp(`^-------${escapeRe(txnId)}[+$#]`)
  let endIdx = -1
  for (let i = lines.length - 1; i >= 0; i--) {
    if (endRe.test(lines[i]!)) {
      endIdx = i
      break
    }
  }

  if (bodyStart >= 0 && endIdx > 0) {
    // Compute body end as start of end-line
    let endLineOff = offset
    for (let i = 0; i < endIdx; i++) endLineOff += lines[i]!.length + 2
    const bodyLen = endLineOff - bodyStart
    if (bodyLen > 0) {
      // CPIM headers before blank line inside body — best-effort map From/To then mask rest
      sanitizeMsrpBody(
        buffer,
        bodyStart,
        bodyLen,
        contentType,
        collector,
        mapping,
        intents,
        packetIndex,
      )
      coverage.push({
        protocol: 'msrp-body',
        offset: bodyStart,
        length: bodyLen,
        status: 'covered',
      })
    }
    // Remap end-line txn id to same opaque alias
    const endLine = lines[endIdx]!
    const endTxnOff = endLineOff + endLine.indexOf(txnId)
    if (endTxnOff >= endLineOff) {
      mapOpaqueAscii(buffer, endTxnOff, txnId.length, collector, mapping, intents, packetIndex)
    }
  } else {
    issues.push('msrp-framing')
  }

  coverage.push({ protocol: 'msrp', offset, length, status: 'covered' })
  return { coverage, issues: issues.length ? issues : undefined }
}

function sanitizeMsrpBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  contentType: string | null,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  if (contentType?.includes('message/cpim') || text.includes('\nFrom:') || text.includes('\nTo:')) {
    const headerEnd = text.indexOf('\r\n\r\n')
    if (headerEnd >= 0) {
      const headers = text.slice(0, headerEnd).split(/\r\n/)
      let cur = offset
      for (const line of headers) {
        const m = /^(From|To):\s*(.+)$/i.exec(line)
        if (m) {
          const val = m[2]!
          const valOff = cur + line.indexOf(val)
          mapOpaqueAscii(buffer, valOff, val.length, collector, mapping, intents, packetIndex, 'sip-user')
        }
        cur += line.length + 2
      }
      maskSpan(buffer, offset + headerEnd + 4, length - headerEnd - 4, collector, packetIndex, 'msrp-cpim-body')
      return
    }
  }
  maskSpan(buffer, offset, length, collector, packetIndex, 'msrp-body')
}

function mapMsrpPath(
  buffer: Uint8Array,
  valueOff: number,
  value: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // msrp://host:port/session;tcp
  const m = /^msrp:\/\/([^/:]+)(?::(\d+))?\/([^;]+)/i.exec(value)
  if (!m) {
    mapOpaqueAscii(buffer, valueOff, value.length, collector, mapping, intents, packetIndex)
    return
  }
  const host = m[1]!
  const session = m[3]!
  const hostOff = valueOff + value.toLowerCase().indexOf(host.toLowerCase())
  const sessOff = valueOff + value.indexOf(session)
  mapHost(buffer, hostOff, host, collector, mapping, intents, packetIndex)
  mapOpaqueAscii(buffer, sessOff, session.length, collector, mapping, intents, packetIndex)
}

function mapHost(
  buffer: Uint8Array,
  abs: number,
  host: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const cat = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? 'ipv4' : 'hostname'
  const constraint = { kind: 'text-ascii' as const, byteLength: host.length }
  intents?.recordEntityReplacement(packetIndex, abs, cat, host, host.length, constraint, host)
  collector.addDeferred(abs, host.length, ({ mapping: live }) => {
    return computeFixedLengthAsciiBytes(abs, host.length, live.aliasFor(cat, host, constraint, host))
  }, { fallbackKind: 'text-x', protocol: 'msrp', category: cat, packetIndex })
  void buffer
  void mapping
}

function mapOpaqueAscii(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  category: 'opaque-id' | 'sip-user' = 'opaque-id',
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
  const canon = canonicalizeIdentity(category, raw) ?? raw
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    return computeFixedLengthAsciiBytes(abs, len, live.aliasFor(category, canon, constraint, raw))
  }, { fallbackKind: 'text-x', protocol: 'msrp', category, packetIndex })
  void mapping
}

function maskSpan(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  try {
    collector.maskRangeDeferred(abs, len, () =>
      createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }),
    )
  } catch {
    /* overlap */
  }
  void buffer
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
