/**
 * Bounded MGCP tokenizer (RFC 3435 §2–3).
 * Piggyback messages are split on a line that is only `.` — not every dot in SDP.
 * TCP framing is not claimed here (identify-only at the engine).
 */

import type {
  ByteSpan,
  MgcpClassifyResult,
  MgcpEndpointParts,
  MgcpMessage,
  MgcpParameter,
  MgcpStartLine,
  MgcpVerb,
} from './types.ts'

const MGCP_VERBS = new Set<string>([
  'EPCF',
  'CRCX',
  'MDCX',
  'DLCX',
  'RQNT',
  'NTFY',
  'AUEP',
  'AUCX',
  'RSIP',
])

const MGCP_PORTS = new Set([2427, 2727])
const MAX_MESSAGE_BYTES = 64 * 1024
const ASCII_PROBE = 96

export function isMgcpPortHint(srcPort: number, dstPort: number): boolean {
  return MGCP_PORTS.has(srcPort) || MGCP_PORTS.has(dstPort)
}

function decodeLatin1(data: Uint8Array, offset: number, length: number): string {
  let s = ''
  const end = offset + length
  for (let i = offset; i < end; i++) s += String.fromCharCode(data[i]!)
  return s
}

function looksLikeMgcpHead(text: string): boolean {
  const line = text.split(/\r?\n/, 1)[0] ?? ''
  if (/^(?:EPCF|CRCX|MDCX|DLCX|RQNT|NTFY|AUEP|AUCX|RSIP)\s+\d+\s+\S+\s+MGCP\s+1\.[01]/i.test(line)) {
    return true
  }
  // Response: 3-digit code + transaction id (+ optional text)
  if (/^\d{3}\s+\d+(?:\s|$)/.test(line)) return true
  return false
}

export function classifyMgcpPayload(
  data: Uint8Array,
  offset: number,
  length: number,
  options: { readonly portHint?: boolean } = {},
): MgcpClassifyResult {
  if (length <= 0 || length > MAX_MESSAGE_BYTES) {
    return options.portHint ? { kind: 'malformed', reason: 'length' } : { kind: 'not-mgcp' }
  }
  const probe = decodeLatin1(data, offset, Math.min(length, ASCII_PROBE))
  if (!looksLikeMgcpHead(probe)) {
    return options.portHint ? { kind: 'malformed', reason: 'signature' } : { kind: 'not-mgcp' }
  }
  try {
    const messages = parseMgcpDatagram(data, offset, length)
    if (messages.length === 0) {
      return options.portHint ? { kind: 'malformed', reason: 'empty' } : { kind: 'not-mgcp' }
    }
    const last = messages[messages.length - 1]!
    const consumed = last.messageSpan.offset + last.messageSpan.length - offset
    return { kind: 'complete', messages, consumed }
  } catch {
    return options.portHint ? { kind: 'malformed', reason: 'parse' } : { kind: 'not-mgcp' }
  }
}

/**
 * Split a UDP datagram into piggybacked MGCP messages (RFC 3435 §3.5.5).
 * Separator is a line whose only content is `.` (CRLF or LF).
 */
export function parseMgcpDatagram(
  data: Uint8Array,
  offset: number,
  length: number,
): MgcpMessage[] {
  const end = offset + length
  const chunks: ByteSpan[] = []
  let msgStart = offset
  let i = offset
  while (i < end) {
    const lineStart = i
    while (i < end && data[i] !== 0x0a) i++
    const hasLf = i < end && data[i] === 0x0a
    let lineEnd = i
    if (hasLf && lineEnd > lineStart && data[lineEnd - 1] === 0x0d) lineEnd--
    const lineLen = lineEnd - lineStart
    const isDot =
      lineLen === 1 && data[lineStart] === 0x2e /* . */
    if (isDot) {
      if (lineStart > msgStart) {
        chunks.push({ offset: msgStart, length: lineStart - msgStart })
      }
      i = hasLf ? i + 1 : i
      msgStart = i
      continue
    }
    i = hasLf ? i + 1 : i
  }
  if (msgStart < end) {
    // Trim trailing whitespace-only
    let msgEnd = end
    while (msgEnd > msgStart && (data[msgEnd - 1] === 0x0a || data[msgEnd - 1] === 0x0d)) {
      msgEnd--
    }
    if (msgEnd > msgStart) {
      chunks.push({ offset: msgStart, length: end - msgStart })
    }
  }

  const out: MgcpMessage[] = []
  for (const chunk of chunks) {
    out.push(parseSingleMgcpMessage(data, chunk.offset, chunk.length))
  }
  return out
}

function parseSingleMgcpMessage(data: Uint8Array, offset: number, length: number): MgcpMessage {
  const end = offset + length
  // Find blank line (CRLF CRLF or LF LF) separating params from SDP body
  let bodyOffset: number | null = null
  let i = offset
  let lineStart = offset
  let firstLine = true
  let start!: MgcpStartLine
  const parameters: MgcpParameter[] = []

  while (i <= end) {
    const atEnd = i === end
    const isLf = !atEnd && data[i] === 0x0a
    if (!atEnd && !isLf) {
      i++
      continue
    }
    let lineEnd = i
    if (lineEnd > lineStart && data[lineEnd - 1] === 0x0d) lineEnd--
    const lineLen = lineEnd - lineStart
    const next = isLf ? i + 1 : i

    if (firstLine) {
      start = parseStartLine(data, lineStart, lineLen)
      firstLine = false
      lineStart = next
      i = next
      continue
    }

    if (lineLen === 0) {
      // Blank line → body starts after the blank line terminator
      bodyOffset = next
      break
    }

    const param = parseParameterLine(data, lineStart, lineLen)
    if (param) parameters.push(param)
    lineStart = next
    i = next
  }

  if (firstLine) throw new Error('mgcp-missing-start')

  const bodySpan: ByteSpan | null =
    bodyOffset != null && bodyOffset < end
      ? { offset: bodyOffset, length: end - bodyOffset }
      : null

  return {
    start,
    parameters,
    bodySpan,
    messageSpan: { offset, length },
  }
}

function parseStartLine(data: Uint8Array, offset: number, length: number): MgcpStartLine {
  const text = decodeLatin1(data, offset, length)
  const req = /^(EPCF|CRCX|MDCX|DLCX|RQNT|NTFY|AUEP|AUCX|RSIP)\s+(\d+)\s+(\S+)\s+(MGCP\s+1\.[01])$/i.exec(
    text,
  )
  if (req) {
    const verb = req[1]!.toUpperCase() as MgcpVerb
    if (!MGCP_VERBS.has(verb)) throw new Error('mgcp-verb')
    const txid = req[2]!
    const endpointRaw = req[3]!
    const afterVerb = offset + verb.length + 1
    const txidSpan: ByteSpan = { offset: afterVerb, length: txid.length }
    const epOffset = afterVerb + txid.length + 1
    const endpoint = parseEndpoint(epOffset, endpointRaw)
    return {
      kind: 'request',
      span: { offset, length },
      verb,
      transactionIdSpan: txidSpan,
      transactionIdText: txid,
      endpoint,
      responseTextSpan: null,
    }
  }

  const rsp = /^(\d{3})\s+(\d+)(?:\s+(.*))?$/.exec(text)
  if (rsp) {
    const code = Number(rsp[1])
    const txid = rsp[2]!
    const rest = rsp[3] ?? ''
    const afterCode = offset + 4 // "NNN "
    const txidSpan: ByteSpan = { offset: afterCode, length: txid.length }
    let responseTextSpan: ByteSpan | null = null
    if (rest.length > 0) {
      const textOff = afterCode + txid.length + 1
      responseTextSpan = { offset: textOff, length: rest.length }
    }
    return {
      kind: 'response',
      span: { offset, length },
      responseCode: code,
      transactionIdSpan: txidSpan,
      transactionIdText: txid,
      responseTextSpan,
    }
  }

  throw new Error('mgcp-start-line')
}

/** Host looks like IPv6 (hex/colon; not IPv4). */
export function looksLikeIpv6Host(host: string): boolean {
  if (!host.includes(':')) return false
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false
  return /^[0-9a-fA-F:.]+$/.test(host)
}

function parseEndpoint(offset: number, raw: string): MgcpEndpointParts {
  const at = raw.indexOf('@')
  if (at < 0) {
    return {
      localSpan: { offset, length: raw.length },
      localText: raw,
      domainSpan: null,
      domainText: null,
      domainIsIpv4: false,
      domainIsIpv6: false,
    }
  }
  const local = raw.slice(0, at)
  let domain = raw.slice(at + 1)
  let domainOff = offset + at + 1
  let domainLen = domain.length
  let domainIsIpv4 = false
  let domainIsIpv6 = false
  if (domain.startsWith('[')) {
    const close = domain.indexOf(']')
    if (close > 0) {
      domain = domain.slice(1, close)
      domainOff += 1
      domainLen = domain.length
    }
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)) domainIsIpv4 = true
  else if (looksLikeIpv6Host(domain)) domainIsIpv6 = true
  return {
    localSpan: { offset, length: local.length },
    localText: local,
    domainSpan: { offset: domainOff, length: domainLen },
    domainText: domain,
    domainIsIpv4,
    domainIsIpv6,
  }
}

function parseParameterLine(data: Uint8Array, offset: number, length: number): MgcpParameter | null {
  if (length < 2) return null
  const colon = (() => {
    for (let i = 0; i < length; i++) if (data[offset + i] === 0x3a) return i
    return -1
  })()
  if (colon <= 0) return null
  const name = decodeLatin1(data, offset, colon).trim()
  if (!/^[A-Za-z0-9]{1,2}$/.test(name) && !/^[A-Za-z]{1,32}$/.test(name)) {
    // MGCP uses single/double letter codes; also allow longer for vendor packages
  }
  let valueStart = colon + 1
  while (valueStart < length && data[offset + valueStart] === 0x20) valueStart++
  const valueOffset = offset + valueStart
  const valueLength = length - valueStart
  return {
    name: name.toUpperCase(),
    nameSpan: { offset, length: colon },
    valueSpan: { offset: valueOffset, length: Math.max(0, valueLength) },
    valueText: decodeLatin1(data, valueOffset, Math.max(0, valueLength)),
    lineSpan: { offset, length },
  }
}
