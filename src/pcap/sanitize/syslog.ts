/**
 * T20 — Syslog (RFC 3164 / 5424) sanitizer: time-shift, hostname map, MSG via T15.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage, SanitizationPolicy } from './types'
import { sanitizeTextPayload } from '../protocols/application/textproto'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec'

const SYSLOG_PORTS = new Set([514, 601, 6514])

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
}

export function isSyslogPortHint(src: number, dst: number): boolean {
  return SYSLOG_PORTS.has(src) || SYSLOG_PORTS.has(dst)
}

export function looksLikeSyslog(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  const head = new TextDecoder('latin1').decode(data.subarray(offset, offset + Math.min(length, 64)))
  return /^<\d{1,3}>/.test(head) || /^\d{4}-\d{2}-\d{2}T/.test(head)
}

export function sanitizeSyslog(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  policy: SanitizationPolicy,
  payloadTime?: PayloadTimeSession,
): AppLayerResult | null {
  if (!looksLikeSyslog(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const slice = buffer.subarray(offset, offset + length)
  const text = new TextDecoder('latin1').decode(slice)

  // Octet-counting framing: leading digits + space (RFC 6587) — leave count, sanitize body.
  let bodyRel = 0
  const oc = /^(\d+) /.exec(text)
  if (oc) {
    const declared = Number(oc[1])
    const prefixLen = oc[0].length
    if (Number.isFinite(declared) && prefixLen + declared <= length) {
      bodyRel = prefixLen
    }
  }

  const body = text.slice(bodyRel)
  const bodyAbs = offset + bodyRel
  const highPrivacy = policy.preset === 'high-privacy'

  const priMatch = /^<(\d{1,3})>/.exec(body)
  if (!priMatch) {
    // Bare text without PRI: free text, masked like MSG below.
    const r = sanitizeTextPayload({
      buffer,
      absoluteOffset: bodyAbs,
      byteLength: length - bodyRel,
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy: true,
      protocolId: 'syslog',
    })
    coverage.push({ protocol: 'syslog', offset, length, status: r.coverageStatus })
    return { coverage, issues }
  }

  let cursor = priMatch[0].length
  // VERSION (5424) optional single digit + space
  let is5424 = false
  const verCh = body[cursor]
  if (verCh !== undefined && verCh >= '1' && verCh <= '9' && body[cursor + 1] === ' ') {
    is5424 = true
    cursor += 2
  }

  if (is5424) {
    cursor = sanitize5424(body, cursor, bodyAbs, collector, mapping, intents, packetIndex, highPrivacy, payloadTime, issues)
  } else {
    cursor = sanitize3164(body, cursor, bodyAbs, collector, mapping, intents, packetIndex, highPrivacy, payloadTime, issues)
  }

  if (cursor < body.length) {
    const msgAbs = bodyAbs + cursor
    const msgLen = body.length - cursor
    // Free MSG text is masked in both levels: text detectors cannot recognise custom identifiers
    // (user names known from SIP, device names, …), so detector-only treatment would leak them.
    // Masking here (not via the export boundary) keeps the 'redacted' status true on every path,
    // including TCP reassembly overlays. Readable logs belong to the text mode.
    const r = sanitizeTextPayload({
      buffer,
      absoluteOffset: msgAbs,
      byteLength: msgLen,
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy: true,
      protocolId: 'syslog',
    })
    if (msgAbs > offset) coverage.push({ protocol: 'syslog', offset, length: msgAbs - offset, status: 'covered' })
    coverage.push({ protocol: 'syslog', offset: msgAbs, length: msgLen, status: r.coverageStatus })
  } else {
    coverage.push({ protocol: 'syslog', offset, length, status: 'covered' })
  }

  return { coverage, issues }
}

function sanitize3164(
  body: string,
  start: number,
  bodyAbs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): number {
  // TIMESTAMP: Mmm dd hh:mm:ss (15 or 16 chars with space padding day)
  const tsRe = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}) /
  const m = tsRe.exec(body.slice(start))
  if (!m) {
    issues.push('syslog-3164-time-ambiguous')
    return start
  }
  const tsText = m[0]!.slice(0, -1) // without trailing space
  rewrite3164Timestamp(tsText, bodyAbs + start, collector, packetIndex, payloadTime, intents)
  let cursor = start + m[0]!.length

  const hostEnd = body.indexOf(' ', cursor)
  if (hostEnd < 0) return cursor
  mapAsciiToken(body, cursor, hostEnd, bodyAbs, collector, mapping, intents, packetIndex, 'hostname')
  cursor = hostEnd + 1
  void highPrivacy
  return cursor
}

function sanitize5424(
  body: string,
  start: number,
  bodyAbs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): number {
  // TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
  const parts: string[] = []
  let cursor = start
  for (let i = 0; i < 5; i++) {
    if (cursor >= body.length) return cursor
    if (body[cursor] === '[') break // structured-data early
    const sp = body.indexOf(' ', cursor)
    if (sp < 0) {
      // Fewer than five header fields: nothing was mapped yet — let the MSG path mask the rest.
      issues.push('syslog-5424-truncated')
      return start
    }
    parts.push(body.slice(cursor, sp))
    cursor = sp + 1
  }
  if (parts.length < 5) {
    issues.push('syslog-5424-truncated')
    return start
  }

  const [ts, host, app, procid, msgid] = parts as [string, string, string, string, string]
  rewrite5424Timestamp(ts, bodyAbs + start, collector, packetIndex, payloadTime, intents)
  const hostOff = start + ts.length + 1
  mapAsciiToken(body, hostOff, hostOff + host.length, bodyAbs, collector, mapping, intents, packetIndex, 'hostname')

  // APP-NAME / PROCID / MSGID: preserve NILVALUE and short schema tokens; else map as opaque-id
  let off = hostOff + host.length + 1
  for (const token of [app, procid, msgid]) {
    if (token !== '-' && token.length > 0) {
      mapAsciiToken(body, off, off + token.length, bodyAbs, collector, mapping, intents, packetIndex, 'opaque-id')
    }
    off += token.length + 1
  }
  cursor = off

  // STRUCTURED-DATA: '-' or [sd-id param="value"...]
  if (body[cursor] === '-') {
    cursor += 1
    if (body[cursor] === ' ') cursor++
  } else if (body[cursor] === '[') {
    const sdEnd = findStructuredDataEnd(body, cursor)
    if (sdEnd > cursor) {
      sanitizeStructuredData(body, cursor, sdEnd, bodyAbs, collector, mapping, intents, packetIndex, highPrivacy)
      cursor = sdEnd
      if (body[cursor] === ' ') cursor++
    }
  }
  return cursor
}

function findStructuredDataEnd(body: string, start: number): number {
  let i = start
  while (i < body.length && body[i] === '[') {
    i++
    while (i < body.length) {
      if (body[i] === '\\' && i + 1 < body.length) {
        i += 2
        continue
      }
      if (body[i] === ']') {
        i++
        break
      }
      i++
    }
  }
  return i
}

/** RFC 5424 STRUCTURED-DATA: one or more `[SD-ID *(SP PARAM-NAME="PARAM-VALUE")]`. */
const SD_GRAMMAR = /^(?:\[[^\s=\]"]+(?: [^\s=\]"]+="(?:[^"\\]|\\.)*")*\])+$/

function sanitizeStructuredData(
  body: string,
  start: number,
  end: number,
  bodyAbs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
): void {
  void highPrivacy
  const span = body.slice(start, end)
  // RFC 5424 SD-PARAM: name="value" (quoted, with \" \\ \] escapes). ip/host/hostname values are
  // mapped; every other value is masked in both levels — SD-IDs and param names stay for diagnostics.
  const re = /([^\s=\]"[]+)="((?:[^"\\]|\\.)*)"/g
  let m: RegExpExecArray | null
  while ((m = re.exec(span)) !== null) {
    const name = m[1]!.toLowerCase()
    const val = m[2] ?? ''
    if (val.length === 0) continue
    const rel = start + m.index! + m[1]!.length + 2
    if ((name === 'ip' || name === 'host' || name === 'hostname') && !val.includes('\\')) {
      const category = /^\d+\.\d+\.\d+\.\d+$/.test(val) ? 'ipv4' : 'hostname'
      mapAsciiToken(body, rel, rel + val.length, bodyAbs, collector, mapping, intents, packetIndex, category)
    } else {
      maskAbs(collector, intents, packetIndex, bodyAbs + rel, val.length, 'syslog-sd-value')
    }
  }
  // Anything outside the RFC 5424 SD grammar (stray text, unquoted values, …) has no
  // field-level policy — mask the whole block (maskRange replaces the per-value patches above).
  if (!SD_GRAMMAR.test(span)) {
    maskAbs(collector, intents, packetIndex, bodyAbs + start, end - start, 'syslog-sd-unparsed')
  }
}

function rewrite3164Timestamp(
  tsText: string,
  abs: number,
  collector: PatchCollector,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  intents: IntentCollector | undefined,
): void {
  // Without year/TZ — ambiguous unless capture-bound; attempt shift using capture year.
  if (!payloadTime?.isBound) {
    maskAbs(collector, intents, packetIndex, abs, tsText.length, 'syslog-time-unbound')
    return
  }
  const m = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(tsText)
  if (!m) {
    maskAbs(collector, intents, packetIndex, abs, tsText.length, 'syslog-time-unwritable')
    return
  }
  const mon = MONTHS[m[1]!]
  if (mon === undefined) {
    maskAbs(collector, intents, packetIndex, abs, tsText.length, 'syslog-time-unwritable')
    return
  }
  const day = Number(m[2])
  const hh = Number(m[3])
  const mm = Number(m[4])
  const ss = Number(m[5])
  // Use UTC year from shifted "now" reference — approximate via epoch 0 shift probe.
  const probe = payloadTime.shiftAbsoluteEpochMs(Date.UTC(2020, mon, day, hh, mm, ss))
  if (probe === null) {
    maskAbs(collector, intents, packetIndex, abs, tsText.length, 'syslog-time-unwritable')
    return
  }
  const d = new Date(probe)
  const monName = m[1]!
  const dayStr = String(d.getUTCDate()).padStart(m[2]!.length === 1 ? 1 : 2, ' ')
  // Preserve original day field width (space-padded vs zero-padded variants).
  const dayField = m[2]!.length === 1
    ? (d.getUTCDate() < 10 ? ` ${d.getUTCDate()}` : String(d.getUTCDate()))
    : String(d.getUTCDate()).padStart(2, '0')
  void dayStr
  const next =
    `${monName} ${dayField} ${String(d.getUTCHours()).padStart(2, '0')}:` +
    `${String(d.getUTCMinutes()).padStart(2, '0')}:${String(d.getUTCSeconds()).padStart(2, '0')}`
  if (next.length !== tsText.length) {
    maskAbs(collector, intents, packetIndex, abs, tsText.length, 'syslog-time-length')
    return
  }
  collector.add(abs, computeFixedLengthAsciiBytes(abs, tsText.length, next))
}

function rewrite5424Timestamp(
  ts: string,
  abs: number,
  collector: PatchCollector,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  intents: IntentCollector | undefined,
): void {
  if (ts === '-') return
  if (!payloadTime?.isBound) {
    maskAbs(collector, intents, packetIndex, abs, ts.length, 'syslog-time-unbound')
    return
  }
  // Partial support: full ISO with Z
  const iso = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(ts)
  if (!iso) {
    maskAbs(collector, intents, packetIndex, abs, ts.length, 'syslog-time-unwritable')
    return
  }
  const ms = Date.parse(ts)
  if (!Number.isFinite(ms)) {
    maskAbs(collector, intents, packetIndex, abs, ts.length, 'syslog-time-unwritable')
    return
  }
  const shifted = payloadTime.shiftAbsoluteEpochMs(ms)
  if (shifted === null) {
    maskAbs(collector, intents, packetIndex, abs, ts.length, 'syslog-time-unwritable')
    return
  }
  // Rebuild preserving fractional / zone spelling length via pad/trunc of fraction.
  const base = new Date(shifted).toISOString().replace(/\.\d{3}Z$/, '')
  let out = base
  if (iso[2]) {
    const frac = iso[2]
    const shiftedFrac = '.' + String(shifted % 1000).padStart(3, '0') + '000000'
    out += shiftedFrac.slice(0, frac.length)
  }
  out += iso[3]
  if (out.length !== ts.length) {
    maskAbs(collector, intents, packetIndex, abs, ts.length, 'syslog-time-length')
    return
  }
  collector.add(abs, computeFixedLengthAsciiBytes(abs, ts.length, out))
}

function mapAsciiToken(
  body: string,
  start: number,
  end: number,
  bodyAbs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  category: 'hostname' | 'ipv4' | 'opaque-id',
): void {
  if (end <= start) return
  const raw = body.slice(start, end)
  if (raw === '-' || raw.length === 0) return
  const abs = bodyAbs + start
  const canon = canonicalizeIdentity(category, raw)
  if (!canon) {
    maskAbs(collector, intents, packetIndex, abs, raw.length, 'syslog-token-opaque')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: raw.length }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, raw.length, constraint, raw)
  collector.addDeferred(abs, raw.length, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor(category, canon, constraint, raw)
      return computeFixedLengthAsciiBytes(abs, raw.length, alias)
    } catch {
      return createProtocolNeutralMaskFill({
        length: raw.length,
        packetIndex,
        offset: abs,
        domain: 'syslog-map-fallback',
      })
    }
  }, { fallbackKind: category === 'ipv4' ? 'digits' : 'text-x', protocol: 'syslog', category, packetIndex })
  void mapping
}

function maskAbs(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  domain: string,
): void {
  if (len <= 0) return
  const fill = createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
  collector.maskRange(abs, fill)
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'syslog')
}
