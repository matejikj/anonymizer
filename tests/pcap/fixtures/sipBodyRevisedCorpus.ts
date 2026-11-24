/**
 * T02.R6 — synthetic SIP multipart/MIME corpus (quoted boundary, QP CTE, delimiter-in-data,
 * multipart/related, malformed single part, duplicate agreeing Content-Length, TCP boundary split).
 * No real personal data.
 */

import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { SIPREC_SEED } from './voipCorpus'
import { buildEthIpTcp, buildEthIpUdp, envelope } from './voipCorpus'

export const REVISED_BODY_SECRET = {
  sdpSessionId: '9007199254740995',
  mediaIp: '192.168.55.88',
  fakeDelimiterLine: '--fakeDelimT02R6',
} as const

export const REVISED_BODY_LEAK_TOKENS: readonly string[] = [
  REVISED_BODY_SECRET.sdpSessionId,
  REVISED_BODY_SECRET.mediaIp,
  SIPREC_SEED.participantAor,
  SIPREC_SEED.sessionId,
  SIPREC_SEED.mediaIp,
]

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function sipInviteHeaders(
  callId: string,
  contentType: string,
  bodyLength: number,
  extraHeaders: readonly string[] = [],
): string[] {
  return [
    'INVITE sip:recorder@voip.gate.example SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.55.10:5060;branch=z9hG4bKr6',
    'From: <sip:alice@voip.gate.example>;tag=r6-from',
    'To: <sip:recorder@voip.gate.example>',
    `Call-ID: ${callId}`,
    `Content-Type: ${contentType}`,
    ...extraHeaders,
    `Content-Length: ${bodyLength}`,
  ]
}

function completeInvite(headers: string[], body: string): Uint8Array {
  return latin1(`${headers.join('\r\n')}\r\n\r\n${body}`)
}

function validSdpBlock(sessionId = REVISED_BODY_SECRET.sdpSessionId): string {
  return [
    'v=0',
    `o=- ${sessionId} ${sessionId} IN IP4 ${REVISED_BODY_SECRET.mediaIp}`,
    's=-',
    `c=IN IP4 ${REVISED_BODY_SECRET.mediaIp}`,
    't=0 0',
    'm=audio 49100 RTP/AVP 0',
  ].join('\r\n') + '\r\n'
}

function siprecXmlMinimal(): string {
  return (
    `<?xml version="1.0"?>\r\n`
    + `<recording xmlns="urn:ietf:params:xml:ns:recording:1">\r\n`
    + `<session session_id="${SIPREC_SEED.sessionId}">\r\n`
    + `<nameID aor="${SIPREC_SEED.participantAor}"/>\r\n`
    + `</session></recording>\r\n`
  )
}

/** Quoted boundary parameter in Content-Type (RFC 2046). */
export function buildQuotedBoundaryMultipart(): Uint8Array {
  const boundary = 'quotedBndT02R6'
  const body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + validSdpBlock()
    + `\r\n--${boundary}--\r\n`
  const headers = sipInviteHeaders(
    'quoted-boundary@r6',
    `multipart/mixed; boundary="${boundary}"`,
    body.length,
  )
  return completeInvite(headers, body)
}

/** multipart/related top-level (not nested) with SDP + SIPREC metadata. */
export function buildMultipartRelatedSiprec(): Uint8Array {
  const boundary = 'relatedT02R6'
  const body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + validSdpBlock('9007199254740996')
    + `\r\n--${boundary}\r\n`
    + 'Content-Type: application/rs-metadata+xml\r\n\r\n'
    + siprecXmlMinimal()
    + `\r\n--${boundary}--\r\n`
  const headers = sipInviteHeaders(
    'multipart-related@r6',
    `multipart/related;boundary=${boundary}`,
    body.length,
  )
  return completeInvite(headers, body)
}

/** Similar delimiter bytes inside part data must not terminate the part early. */
export function buildDelimiterInDataMultipart(): Uint8Array {
  const boundary = 'realDelimT02R6'
  const decoy = REVISED_BODY_SECRET.fakeDelimiterLine
  const textPart =
    `Line one\r\n`
    + `${decoy}\r\n`
    + `Still same part\r\n`
  const body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + validSdpBlock()
    + `\r\n--${boundary}\r\n`
    + 'Content-Type: text/plain\r\n\r\n'
    + textPart
    + `\r\n--${boundary}--\r\n`
  const headers = sipInviteHeaders(
    'delimiter-in-data@r6',
    `multipart/mixed;boundary=${boundary}`,
    body.length,
  )
  return completeInvite(headers, body)
}

/** quoted-printable CTE → physical mask (no SDP parse on wire bytes). */
export function buildQuotedPrintableCtePart(): Uint8Array {
  const boundary = 'qpCteT02R6'
  const qpBody =
    'v=3D0=0D=0Ao=3D-20390190019001=20390190019001=20IN=20IP4=20192.168.55.88=0D=0A'
  const body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n'
    + 'Content-Transfer-Encoding: quoted-printable\r\n\r\n'
    + qpBody
    + `\r\n--${boundary}--\r\n`
  const headers = sipInviteHeaders(
    'qp-cte@r6',
    `multipart/mixed;boundary=${boundary}`,
    body.length,
  )
  return completeInvite(headers, body)
}

/** One valid SDP part and one malformed SDP part — sibling must still map. */
export function buildMalformedSiblingSdpPart(): Uint8Array {
  const boundary = 'malPartT02R6'
  const badSdp = 'not-sdp-payload-without-typed-lines\r\n'
  const body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + validSdpBlock('9007199254740997')
    + `\r\n--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + badSdp
    + `\r\n--${boundary}--\r\n`
  const headers = sipInviteHeaders(
    'malformed-sdp-part@r6',
    `multipart/mixed;boundary=${boundary}`,
    body.length,
  )
  return completeInvite(headers, body)
}

/** Duplicate agreeing Content-Length must not break multipart body framing. */
export function buildDuplicateAgreeingContentLength(): Uint8Array {
  const boundary = 'dupClT02R6'
  const body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + validSdpBlock('9007199254740998')
    + `\r\n--${boundary}--\r\n`
  const headers = sipInviteHeaders(
    'dup-cl@r6',
    `multipart/mixed;boundary=${boundary}`,
    body.length,
    [`Content-Length: ${body.length}`],
  )
  return completeInvite(headers, body)
}

export interface SipBodyRevisedCase {
  readonly id: string
  readonly payload: Uint8Array
  readonly transport: 'udp' | 'tcp'
  readonly packets: readonly PacketEnvelope[]
}

function udpPackets(payload: Uint8Array): readonly PacketEnvelope[] {
  return [envelope(buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload), 0)]
}

function tcpPacketsSplitAt(payload: Uint8Array, splitIndex: number): readonly PacketEnvelope[] {
  const a = payload.subarray(0, splitIndex)
  const b = payload.subarray(splitIndex)
  return [
    envelope(buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, 3000, a), 0),
    envelope(buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, 3000 + splitIndex, b), 1),
  ]
}

/** TCP split exactly on `\r\n--boundary` between two parts. */
export function buildTcpBoundarySplitMultipart(): SipBodyRevisedCase {
  const payload = buildDelimiterInDataMultipart()
  const boundary = 'realDelimT02R6'
  const needle = latin1(`\r\n--${boundary}\r\n`)
  let splitIndex = -1
  for (let i = 0; i + needle.length <= payload.length; i++) {
    let match = true
    for (let j = 0; j < needle.length; j++) {
      if (payload[i + j] !== needle[j]) {
        match = false
        break
      }
    }
    if (match && i > 200) {
      splitIndex = i + 2
      break
    }
  }
  if (splitIndex < 0) throw new Error('boundary split anchor not found in corpus payload')
  return {
    id: 'tcp-boundary-split',
    payload,
    transport: 'tcp',
    packets: tcpPacketsSplitAt(payload, splitIndex),
  }
}

function udpCase(id: string, build: () => Uint8Array): SipBodyRevisedCase {
  const payload = build()
  return { id, payload, transport: 'udp', packets: udpPackets(payload) }
}

export function sipBodyRevisedCases(): readonly SipBodyRevisedCase[] {
  return [
    udpCase('quoted-boundary', buildQuotedBoundaryMultipart),
    udpCase('multipart-related', buildMultipartRelatedSiprec),
    udpCase('delimiter-in-data', buildDelimiterInDataMultipart),
    udpCase('qp-cte-part', buildQuotedPrintableCtePart),
    udpCase('malformed-sdp-sibling', buildMalformedSiblingSdpPart),
    udpCase('duplicate-cl-agree', buildDuplicateAgreeingContentLength),
    buildTcpBoundarySplitMultipart(),
  ]
}
