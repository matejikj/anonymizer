/**
 * Single analyze → operations plan for MGCP (T11 / T02 pattern).
 * Discovery and sanitize both consume {@link analyzeMgcpMessages}.
 */

import type { LayerCoverage } from '../../../sanitize/types.ts'
import { parseSdp } from '../sdp/parser.ts'
import { extractSdpEntities } from '../sdp/extract.ts'
import { buildSdpRedactionPlan, SDP_REDACT_MASK_BYTE } from '../sdp/redactPlan.ts'
import { DEFAULT_SDP_REDACTION_POLICY } from '../sdp/types.ts'
import { buildSdpMediaEndpoints } from '../sdp/mediaModel.ts'
import type { SdpSessionBundle } from '../sdp/types.ts'
import type { ByteSpan, MgcpMessage, MgcpParameter } from './types.ts'
import { looksLikeIpv6Host } from './parse.ts'

function callIdFromMessages(messages: readonly MgcpMessage[]): string | null {
  for (const m of messages) {
    for (const p of m.parameters) {
      if (p.name === 'C' && p.valueText.trim()) return p.valueText.trim()
    }
  }
  return null
}

export const MGCP_MASK_BYTE = 0x78 // 'x'

export type MgcpOpAction = 'map' | 'redact' | 'preserve'

export interface MgcpOperation {
  readonly span: ByteSpan
  readonly action: MgcpOpAction
  readonly mappingCategory: string | null
  readonly canonicalText: string
  readonly maskByte: number
  /** When set, session-version style shift is not used — reserved for SDP nested ops. */
  readonly sessionIdForVersion?: string
}

export interface MgcpAnalyzeResult {
  readonly operations: readonly MgcpOperation[]
  readonly coverage: readonly LayerCoverage[]
  readonly issues: readonly string[]
  readonly sdpBundles: readonly SdpSessionBundle[]
}

const KNOWN_PARAM_PRESERVE = new Set([
  'P', // ConnectionParameters QoS
  'M', // Mode
  'Q', // QuarantineHandling
  'R', // RequestedEvents (structure kept; digit literals handled in value walk)
  'T', // DetectEvents
  'E', // ReasonCode
  'RM', // RestartMethod
  'F', // SignalRequests (handled specially for DTMF)
])

/** Local endpoint parts that look like physical port hierarchy — keep structure, map subscriber-ish tokens. */
function localLooksPhysical(local: string): boolean {
  return /^(?:ds|aaln|rtp|trunk|slot)(?:\/|$)/i.test(local)
}

function maskDigitsInPlace(text: string): string {
  return text.replace(/[0-9*#]/g, 'x')
}

/**
 * Plan map/redact ops for one or more MGCP messages (piggyback).
 */
export function analyzeMgcpMessages(
  buffer: Uint8Array,
  messages: readonly MgcpMessage[],
): MgcpAnalyzeResult {
  const operations: MgcpOperation[] = []
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const sdpBundles: SdpSessionBundle[] = []
  const callId = callIdFromMessages(messages)

  for (const message of messages) {
    coverage.push({
      protocol: 'mgcp',
      offset: message.messageSpan.offset,
      length: message.bodySpan
        ? message.bodySpan.offset - message.messageSpan.offset
        : message.messageSpan.length,
      status: 'covered',
    })

    // Free response text — unknown content
    if (message.start.responseTextSpan && message.start.responseTextSpan.length > 0) {
      operations.push({
        span: message.start.responseTextSpan,
        action: 'redact',
        mappingCategory: null,
        canonicalText: '',
        maskByte: MGCP_MASK_BYTE,
      })
    }

    // Endpoint
    const ep = message.start.endpoint
    if (ep) {
      planEndpoint(operations, ep)
    }

    for (const param of message.parameters) {
      planParameter(operations, param, issues)
    }

    if (message.bodySpan && message.bodySpan.length > 0) {
      planNestedSdp(buffer, message.bodySpan, operations, coverage, issues, sdpBundles, callId)
    }
  }

  operations.sort((a, b) => a.span.offset - b.span.offset)
  return {
    operations: dedupeOps(operations),
    coverage,
    issues,
    sdpBundles,
  }
}

function planEndpoint(
  ops: MgcpOperation[],
  ep: NonNullable<MgcpMessage['start']['endpoint']>,
): void {
  const local = ep.localText
  if (local.includes('*') || local === '') {
    // wildcard / empty — preserve
  } else if (localLooksPhysical(local)) {
    // Preserve physical hierarchy tokens; map trailing numeric subscriber if present
    const m = /^(.*\/)(\d+)$/.exec(local)
    if (m && m[2]) {
      const prefixLen = m[1]!.length
      ops.push({
        span: { offset: ep.localSpan.offset + prefixLen, length: m[2].length },
        action: 'map',
        mappingCategory: 'sip-user',
        canonicalText: m[2],
        maskByte: MGCP_MASK_BYTE,
      })
    }
  } else {
    ops.push({
      span: ep.localSpan,
      action: 'map',
      mappingCategory: 'sip-user',
      canonicalText: local,
      maskByte: MGCP_MASK_BYTE,
    })
  }

  if (ep.domainSpan && ep.domainText) {
    ops.push({
      span: ep.domainSpan,
      action: 'map',
      mappingCategory: hostMappingCategory(ep.domainText, ep.domainIsIpv4, ep.domainIsIpv6),
      canonicalText: ep.domainText,
      maskByte: MGCP_MASK_BYTE,
    })
  }
}

function hostMappingCategory(
  host: string,
  isIpv4: boolean,
  isIpv6 = false,
): 'ipv4' | 'ipv6' | 'hostname' {
  if (isIpv4 || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return 'ipv4'
  if (isIpv6 || looksLikeIpv6Host(host)) return 'ipv6'
  return 'hostname'
}

/**
 * Split host[:port] after `@`, honouring `[IPv6]` brackets so the port colon is not
 * confused with address colons (RFC 3435 NotifiedEntity / endpoint forms).
 */
function splitHostPort(hostAndMaybePort: string): { host: string; hostRel: number } {
  let hostRel = 0
  let rest = hostAndMaybePort
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']')
    if (close > 0) {
      const host = rest.slice(1, close)
      return { host, hostRel: 1 }
    }
  }
  // IPv4 or hostname — strip trailing :port (last colon, not inside IPv6)
  if (!looksLikeIpv6Host(rest)) {
    const colon = rest.lastIndexOf(':')
    if (colon > 0) {
      const maybePort = rest.slice(colon + 1)
      if (/^\d{1,5}$/.test(maybePort)) {
        rest = rest.slice(0, colon)
      }
    }
  }
  return { host: rest, hostRel }
}

function planParameter(ops: MgcpOperation[], param: MgcpParameter, issues: string[]): void {
  const name = param.name
  const value = param.valueText
  const span = param.valueSpan
  if (span.length <= 0) return

  switch (name) {
    case 'C': // CallId
      ops.push({
        span,
        action: 'map',
        mappingCategory: 'sip-call-id',
        canonicalText: value.trim(),
        maskByte: MGCP_MASK_BYTE,
      })
      return
    case 'I': // ConnectionId
      ops.push({
        span,
        action: 'map',
        mappingCategory: 'sip-token',
        canonicalText: value.trim(),
        maskByte: MGCP_MASK_BYTE,
      })
      return
    case 'X': // RequestIdentifier
      ops.push({
        span,
        action: 'map',
        mappingCategory: 'sip-token',
        canonicalText: value.trim(),
        maskByte: MGCP_MASK_BYTE,
      })
      return
    case 'N': // NotifiedEntity — host[:port]
      planNotifiedEntity(ops, span, value)
      return
    case 'Z':
    case 'Z2': // SpecificEndpointId
      planSpecificEndpoint(ops, span, value)
      return
    case 'O':
    case 'S': // Observed/Signal events — DTMF digits + caller-id
      planObservedOrSignal(ops, span, value)
      return
    case 'D': // DigitMap — grammar-valid digit mask
      planDigitMap(ops, span, value)
      return
    case 'L': // LocalConnectionOptions
      planLocalConnectionOptions(ops, span, value)
      return
    case 'P':
    case 'M':
    case 'Q':
    case 'T':
    case 'E':
    case 'RM':
      // Preserve known structural parameters
      return
    case 'R':
    case 'F':
      // Keep event names; mask digit literals inside
      planObservedOrSignal(ops, span, value)
      return
    default:
      if (KNOWN_PARAM_PRESERVE.has(name)) return
      // Unknown / vendor package — fail-closed mask of value
      ops.push({
        span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: '',
        maskByte: MGCP_MASK_BYTE,
      })
      issues.push(`mgcp-unknown-param:${name}`)
  }
}

function planNotifiedEntity(ops: MgcpOperation[], span: ByteSpan, value: string): void {
  // Forms: ca@host, ca@[IPv4], ca@[IPv6]:2727, ca@host:2727
  const at = value.indexOf('@')
  if (at < 0) {
    const { host } = splitHostPort(value.trim())
    ops.push({
      span: { offset: span.offset, length: host.length },
      action: 'map',
      mappingCategory: hostMappingCategory(host, false),
      canonicalText: host,
      maskByte: MGCP_MASK_BYTE,
    })
    return
  }
  const afterAt = value.slice(at + 1)
  const { host, hostRel } = splitHostPort(afterAt)
  ops.push({
    span: {
      offset: span.offset + at + 1 + hostRel,
      length: host.length,
    },
    action: 'map',
    mappingCategory: hostMappingCategory(host, false),
    canonicalText: host,
    maskByte: MGCP_MASK_BYTE,
  })
}

function planSpecificEndpoint(ops: MgcpOperation[], span: ByteSpan, value: string): void {
  const at = value.indexOf('@')
  if (at < 0) {
    ops.push({
      span,
      action: 'map',
      mappingCategory: 'sip-user',
      canonicalText: value.trim(),
      maskByte: MGCP_MASK_BYTE,
    })
    return
  }
  const local = value.slice(0, at)
  const afterAt = value.slice(at + 1)
  const { host, hostRel } = splitHostPort(afterAt)
  ops.push({
    span: { offset: span.offset, length: local.length },
    action: 'map',
    mappingCategory: 'sip-user',
    canonicalText: local,
    maskByte: MGCP_MASK_BYTE,
  })
  ops.push({
    span: { offset: span.offset + at + 1 + hostRel, length: host.length },
    action: 'map',
    mappingCategory: hostMappingCategory(host, false),
    canonicalText: host,
    maskByte: MGCP_MASK_BYTE,
  })
}

function planObservedOrSignal(ops: MgcpOperation[], span: ByteSpan, value: string): void {
  // DTMF: D/5, D/*, D/# — mask digit/token keeping D/ prefix
  // caller-id: ci(…, "name", "number") or similar
  const ci = /ci\s*\([^,]*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)/i.exec(value)
  const ciNameSpan: { start: number; end: number } | null = ci
    ? (() => {
        const name = ci[1] ?? ''
        const number = ci[2] ?? ''
        const nameIdx = value.indexOf(`"${name}"`)
        const numIdx = value.indexOf(`"${number}"`, nameIdx + 1)
        if (nameIdx >= 0 && name.length > 0) {
          ops.push({
            span: { offset: span.offset + nameIdx + 1, length: name.length },
            action: 'redact',
            mappingCategory: null,
            canonicalText: '',
            maskByte: MGCP_MASK_BYTE,
          })
        }
        if (numIdx >= 0 && number.length > 0) {
          ops.push({
            span: { offset: span.offset + numIdx + 1, length: number.length },
            action: 'map',
            mappingCategory: 'sip-user',
            canonicalText: number,
            maskByte: MGCP_MASK_BYTE,
          })
        }
        return numIdx >= 0
          ? { start: nameIdx, end: numIdx + number.length + 2 }
          : nameIdx >= 0
            ? { start: nameIdx, end: nameIdx + name.length + 2 }
            : null
      })()
    : null

  // Mask D/<digit> sequences (relative offsets of digit after D/)
  const re = /D\/([0-9*#])/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(value)) != null) {
    const digitRel = m.index + 2
    ops.push({
      span: { offset: span.offset + digitRel, length: 1 },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MGCP_MASK_BYTE,
    })
  }

  // Unknown/vendor package quoted args (may contain commas) — local mask of quote interiors
  // so neighbour event tokens stay intact. Skip spans already handled as caller-id.
  const quoteRe = /"([^"]*)"/g
  let qm: RegExpExecArray | null
  while ((qm = quoteRe.exec(value)) != null) {
    const inner = qm[1] ?? ''
    if (inner.length === 0) continue
    const qStart = qm.index
    const qEnd = qStart + qm[0]!.length
    if (ciNameSpan && qStart >= ciNameSpan.start && qEnd <= ciNameSpan.end) continue
    ops.push({
      span: { offset: span.offset + qStart + 1, length: inner.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MGCP_MASK_BYTE,
    })
  }
}

function planDigitMap(ops: MgcpOperation[], span: ByteSpan, value: string): void {
  // Mask concrete digit literals outside character classes; keep [2-9] ranges,
  // ()| . T S X wildcards and grammar punctuation (RFC 3435 DigitMap).
  let inClass = false
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]!
    if (ch === '[') {
      inClass = true
      continue
    }
    if (ch === ']') {
      inClass = false
      continue
    }
    if (inClass) continue
    if (/[0-9]/.test(ch)) {
      ops.push({
        span: { offset: span.offset + i, length: 1 },
        action: 'redact',
        mappingCategory: null,
        canonicalText: '',
        maskByte: 0x39, // '9' — grammar-valid digit substitute
      })
    }
  }
  void maskDigitsInPlace
}

function planLocalConnectionOptions(ops: MgcpOperation[], span: ByteSpan, value: string): void {
  // k:<key> — mask entire key material; known p:/a:/e:/s: preserve
  const parts = value.split(',')
  let cursor = 0
  for (const part of parts) {
    const trimmed = part.trim()
    const lead = part.length - part.trimStart().length
    const partOff = span.offset + cursor + lead
    const eq = trimmed.indexOf(':')
    if (eq > 0) {
      const key = trimmed.slice(0, eq).trim().toLowerCase()
      const val = trimmed.slice(eq + 1)
      if (key === 'k' && val.length > 0) {
        const valOff = partOff + eq + 1
        ops.push({
          span: { offset: valOff, length: val.length },
          action: 'redact',
          mappingCategory: null,
          canonicalText: '',
          maskByte: MGCP_MASK_BYTE,
        })
      }
    }
    cursor += part.length + 1
  }
}

function planNestedSdp(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
  operations: MgcpOperation[],
  coverage: LayerCoverage[],
  issues: string[],
  sdpBundles: SdpSessionBundle[],
  callId: string | null,
): void {
  const sdp = parseSdp(buffer, { offset: bodySpan.offset, length: bodySpan.length })
  if (sdp.kind !== 'complete') {
    coverage.push({
      protocol: 'sdp',
      offset: bodySpan.offset,
      length: bodySpan.length,
      status: 'malformed',
    })
    issues.push('mgcp-sdp-malformed')
    operations.push({
      span: bodySpan,
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: SDP_REDACT_MASK_BYTE,
    })
    return
  }

  coverage.push({
    protocol: 'sdp',
    offset: bodySpan.offset,
    length: bodySpan.length,
    status: 'covered',
  })

  const extracted = extractSdpEntities(sdp.session, buffer, {
    policy: DEFAULT_SDP_REDACTION_POLICY,
  })
  const plan = buildSdpRedactionPlan(extracted.entities, { maskByte: SDP_REDACT_MASK_BYTE })
  for (const op of plan.operations) {
    operations.push({
      span: op.span,
      action: op.action,
      mappingCategory: op.mappingCategory,
      canonicalText: op.canonicalText,
      maskByte: op.maskByte,
      ...(op.sessionIdForVersion !== undefined
        ? { sessionIdForVersion: op.sessionIdForVersion }
        : {}),
    })
  }

  const endpoints = buildSdpMediaEndpoints(sdp.session, buffer, { callId })
  sdpBundles.push({
    session: sdp.session,
    endpoints,
    callId,
  })
}

function dedupeOps(ops: MgcpOperation[]): MgcpOperation[] {
  const out: MgcpOperation[] = []
  let lastEnd = -1
  for (const op of ops) {
    if (op.action === 'preserve') continue
    const end = op.span.offset + op.span.length
    if (op.span.offset < lastEnd) continue
    out.push(op)
    lastEnd = end
  }
  return out
}
