/**
 * T27 — SMTP / IMAP / POP3 plaintext mail command sanitizers.
 * Commands/status preserved; emails/users mapped; AUTH/passwords and message bodies masked.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { IdentityCategory } from '../../mapping/identityCategories'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import {
  extractTextProtoValues,
  applyPayloadMapHits,
  hitsFromExtractors,
  maskPayloadSpan,
} from '../protocols/application/textproto'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'

const SMTP_PORTS = new Set([25, 587, 465])
const IMAP_PORTS = new Set([143, 993])
const POP3_PORTS = new Set([110, 995])

const SMTP_CMD =
  /^(?:EHLO|HELO|MAIL|RCPT|DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT|SIZE)\b/i
const SMTP_REPLY = /^[1-5]\d\d(?:[ \t-].*)?$/
const IMAP_TAGGED = /^[A-Za-z0-9]+ (?:OK|NO|BAD|BYE|PREAUTH)\b/i
const IMAP_UNTAGGED = /^\* / 
const IMAP_CMD = /^[A-Za-z0-9]+ (?:LOGIN|AUTHENTICATE|SELECT|EXAMINE|FETCH|STORE|LIST|LSUB|CREATE|DELETE|RENAME|APPEND|UID|CAPABILITY|NOOP|LOGOUT|STARTTLS)\b/i
const POP3_CMD = /^(?:\+OK|-ERR|USER|PASS|APOP|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT|TOP|UIDL|CAPA|STLS|AUTH)\b/i

export function isSmtpPortHint(src: number, dst: number): boolean {
  return SMTP_PORTS.has(src) || SMTP_PORTS.has(dst)
}

export function isImapPortHint(src: number, dst: number): boolean {
  return IMAP_PORTS.has(src) || IMAP_PORTS.has(dst)
}

export function isPop3PortHint(src: number, dst: number): boolean {
  return POP3_PORTS.has(src) || POP3_PORTS.has(dst)
}

export function looksLikeSmtp(data: Uint8Array, offset: number, length: number): boolean {
  const head = latin1(data, offset, Math.min(length, 96)).replace(/^\d+ /, '')
  return SMTP_CMD.test(head) || SMTP_REPLY.test(head.trimEnd())
}

export function looksLikeImap(data: Uint8Array, offset: number, length: number): boolean {
  const head = latin1(data, offset, Math.min(length, 96))
  return IMAP_TAGGED.test(head) || IMAP_UNTAGGED.test(head) || IMAP_CMD.test(head)
}

export function looksLikePop3(data: Uint8Array, offset: number, length: number): boolean {
  const head = latin1(data, offset, Math.min(length, 96))
  return POP3_CMD.test(head)
}

export function sanitizeSmtp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeSmtp(buffer, offset, length)) return null
  return sanitizeMailLines(
    buffer, offset, length, collector, mapping, intents, packetIndex, 'smtp', sanitizeSmtpLine,
  )
}

export function sanitizeImap(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeImap(buffer, offset, length)) return null
  return sanitizeMailLines(
    buffer, offset, length, collector, mapping, intents, packetIndex, 'imap', sanitizeImapLine,
  )
}

export function sanitizePop3(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikePop3(buffer, offset, length)) return null
  return sanitizeMailLines(
    buffer, offset, length, collector, mapping, intents, packetIndex, 'pop3', sanitizePop3Line,
  )
}

type LineSanitizer = (
  line: string,
  abs: number,
  rawLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
) => void

function sanitizeMailLines(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  lineFn: LineSanitizer,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const text = latin1(buffer, offset, length)
  let pos = 0
  let inData = false
  while (pos < text.length) {
    const nl = text.indexOf('\n', pos)
    const end = nl < 0 ? text.length : nl + 1
    const rawLine = text.slice(pos, end)
    const line = rawLine.replace(/\r?\n$/, '')
    const abs = offset + pos
    const rawLen = rawLine.length

    if (inData) {
      if (line === '.') {
        inData = false
        coverage.push({ protocol, offset: abs, length: rawLen, status: 'covered' })
      } else if (/^(From|To|Cc|Bcc|Sender|Reply-To|Message-ID|Received):/i.test(line)) {
        const colon = line.indexOf(':')
        const value = line.slice(colon + 1)
        const valueAbs = abs + colon + 1
        const hits = hitsFromExtractors(extractTextProtoValues(value, valueAbs))
        applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, protocol)
        coverage.push({ protocol: `${protocol}-hdr`, offset: abs, length: rawLen, status: 'covered' })
      } else if (/^Subject:/i.test(line)) {
        const colon = line.indexOf(':')
        const valLen = line.length - (colon + 1)
        if (valLen > 0) {
          maskPayloadSpan(collector, abs + colon + 1, valLen, intents, packetIndex, `${protocol}-subject`)
        }
        coverage.push({ protocol: `${protocol}-hdr`, offset: abs, length: rawLen, status: 'redacted' })
      } else {
        maskPayloadSpan(collector, abs, line.length, intents, packetIndex, `${protocol}-body`)
        coverage.push({ protocol: `${protocol}-body`, offset: abs, length: rawLen, status: 'redacted' })
      }
      pos = end
      continue
    }

    lineFn(line, abs, rawLen, collector, mapping, intents, packetIndex, coverage)
    if (protocol === 'smtp' && /^DATA\b/i.test(line)) inData = true
    const lit = /\{(\d+)\+?\}\r?$/.exec(line)
    if (protocol === 'imap' && lit) {
      const litLen = Number(lit[1])
      const litStart = end
      if (Number.isFinite(litLen) && litStart + litLen <= offset + length) {
        maskPayloadSpan(collector, offset + litStart, litLen, intents, packetIndex, 'imap-literal')
        coverage.push({
          protocol: 'imap-literal',
          offset: offset + litStart,
          length: litLen,
          status: 'redacted',
        })
        pos = litStart + litLen
        continue
      }
      issues.push('imap-literal-trunc')
    }
    pos = end
  }
  // One parent span so CF-09 safeExportEnd covers CRLF gaps between per-line rows.
  coverage.unshift({ protocol, offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeSmtpLine(
  line: string,
  abs: number,
  rawLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const auth = /^(AUTH\s+(?:PLAIN|LOGIN)\s+)(\S+)/i.exec(line)
  if (auth) {
    const prefix = auth[1]!.length
    maskPayloadSpan(collector, abs + prefix, auth[2]!.length, intents, packetIndex, 'smtp-auth')
    coverage.push({ protocol: 'smtp-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  if (/^AUTH\s+/i.test(line) && !/^AUTH\s+(?:PLAIN|LOGIN)\s*$/i.test(line)) {
    const sp = line.indexOf(' ', 5)
    if (sp > 0 && sp + 1 < line.length) {
      maskPayloadSpan(collector, abs + sp + 1, line.length - sp - 1, intents, packetIndex, 'smtp-auth')
      coverage.push({ protocol: 'smtp-auth', offset: abs, length: rawLen, status: 'redacted' })
      return
    }
  }
  if (/^[A-Za-z0-9+/=]{8,}$/.test(line) && !SMTP_CMD.test(line) && !SMTP_REPLY.test(line)) {
    maskPayloadSpan(collector, abs, line.length, intents, packetIndex, 'smtp-auth-cont')
    coverage.push({ protocol: 'smtp-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }

  const mailBox = /^(?:MAIL FROM|RCPT TO|VRFY|EXPN):\s*<?([^>\s]+)>?/i.exec(line)
  if (mailBox) {
    mapEmailInLine(line, abs, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'smtp-cmd', offset: abs, length: rawLen, status: 'covered' })
    return
  }

  const ehlo = /^(?:EHLO|HELO)\s+(\S+)/i.exec(line)
  if (ehlo) {
    mapToken(line, abs, ehlo[1]!, 'hostname', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'smtp-cmd', offset: abs, length: rawLen, status: 'covered' })
    return
  }

  const banner = /^(220(?:[ \t-]))(\S+)/.exec(line)
  if (banner) {
    mapToken(line, abs, banner[2]!, 'hostname', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'smtp-cmd', offset: abs, length: rawLen, status: 'covered' })
    return
  }

  const hits = hitsFromExtractors(extractTextProtoValues(line, abs))
  applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'smtp')
  coverage.push({ protocol: 'smtp-cmd', offset: abs, length: rawLen, status: 'covered' })
}

function sanitizeImapLine(
  line: string,
  abs: number,
  rawLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const login = /^([A-Za-z0-9]+)\s+LOGIN\s+(\S+)\s+(\S+)/i.exec(line)
  if (login) {
    mapToken(line, abs, login[2]!, 'user-id', collector, mapping, intents, packetIndex)
    const passStart = line.lastIndexOf(login[3]!)
    if (passStart >= 0) {
      maskPayloadSpan(collector, abs + passStart, login[3]!.length, intents, packetIndex, 'imap-pass')
    }
    coverage.push({ protocol: 'imap-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  const auth = /^([A-Za-z0-9]+)\s+AUTHENTICATE\s+\S+\s+(\S+)/i.exec(line)
  if (auth) {
    maskPayloadSpan(collector, abs + line.indexOf(auth[2]!), auth[2]!.length, intents, packetIndex, 'imap-auth')
    coverage.push({ protocol: 'imap-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  if (/^[A-Za-z0-9+/=]{8,}$/.test(line)) {
    maskPayloadSpan(collector, abs, line.length, intents, packetIndex, 'imap-auth-cont')
    coverage.push({ protocol: 'imap-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  const hits = hitsFromExtractors(extractTextProtoValues(line, abs))
  applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'imap')
  coverage.push({ protocol: 'imap-cmd', offset: abs, length: rawLen, status: 'covered' })
}

function sanitizePop3Line(
  line: string,
  abs: number,
  rawLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const user = /^USER\s+(\S+)/i.exec(line)
  if (user) {
    mapToken(line, abs, user[1]!, 'user-id', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'pop3-cmd', offset: abs, length: rawLen, status: 'covered' })
    return
  }
  const pass = /^PASS\s+(\S+)/i.exec(line)
  if (pass) {
    maskPayloadSpan(collector, abs + line.indexOf(pass[1]!), pass[1]!.length, intents, packetIndex, 'pop3-pass')
    coverage.push({ protocol: 'pop3-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  const apop = /^APOP\s+(\S+)\s+(\S+)/i.exec(line)
  if (apop) {
    mapToken(line, abs, apop[1]!, 'user-id', collector, mapping, intents, packetIndex)
    maskPayloadSpan(collector, abs + line.indexOf(apop[2]!), apop[2]!.length, intents, packetIndex, 'pop3-apop')
    coverage.push({ protocol: 'pop3-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  const hits = hitsFromExtractors(extractTextProtoValues(line, abs))
  applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'pop3')
  coverage.push({ protocol: 'pop3-cmd', offset: abs, length: rawLen, status: 'covered' })
}

function mapEmailInLine(
  line: string,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const hits = hitsFromExtractors(extractTextProtoValues(line, abs)).filter((h) => h.category === 'email')
  if (hits.length > 0) {
    applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'smtp')
    return
  }
  // Angle-addr without domain-dot still treat as mailbox-ish opaque
  const m = /<([^>]+)>/.exec(line)
  if (m) {
    mapToken(line, abs, m[1]!, 'email', collector, mapping, intents, packetIndex)
  }
}

function mapToken(
  line: string,
  abs: number,
  token: string,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const idx = line.indexOf(token)
  if (idx < 0 || token.length === 0) return
  const canon = canonicalizeIdentity(category, token) ?? token
  const constraint = { kind: 'text-ascii' as const, byteLength: token.length }
  intents?.recordEntityReplacement(packetIndex, abs + idx, category, canon, token.length, constraint, token)
  collector.addDeferred(abs + idx, token.length, ({ mapping: live }) => {
    try {
      const mapped = live.aliasFor(category, canon, constraint, token)
      return computeFixedLengthAsciiBytes(abs + idx, token.length, mapped)
    } catch {
      return createProtocolNeutralMaskFill({
        length: token.length, packetIndex, offset: abs + idx, domain: `mail-${category}`,
      })
    }
  }, { fallbackKind: 'text-x', protocol: 'mail', category: String(category), packetIndex })
  void mapping
}

function latin1(buf: Uint8Array, off: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(buf[off + i]!)
  return s
}
