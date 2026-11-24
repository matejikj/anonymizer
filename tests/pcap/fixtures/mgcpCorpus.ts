/**
 * Synthetic MGCP (RFC 3435) corpus for T11 — no real personal data.
 */

import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { buildEthIpUdp, envelope } from './voipCorpus'

export const MGCP_SEED = {
  gwHost: 'mgcp-gw.lab.example',
  caHost: 'call-agent.lab.example',
  gwIp: '10.55.66.77',
  caIpv6: '2001:db8:55::ca',
  callId: 'MgcpCallId-AABBCCDDEEFF',
  connectionId: '1A2B3C4D',
  requestId: 'RqntId-998877',
  cryptoKey: 'MgcpSecretCryptoKeyMaterial99',
  dtmfPin: '5',
  callerName: 'MgcpCallerSecretName',
  callerNumber: '420777000111',
  digitMapCanary: '420123456789',
  mediaIp: '10.55.66.78',
  mediaPort: 16000,
  quotedPackageCanary: 'QuotedPkgSecret,WithComma',
} as const

export const MGCP_SEED_TOKENS: readonly string[] = [
  MGCP_SEED.gwHost,
  MGCP_SEED.caHost,
  MGCP_SEED.gwIp,
  MGCP_SEED.caIpv6,
  MGCP_SEED.callId,
  MGCP_SEED.connectionId,
  MGCP_SEED.requestId,
  MGCP_SEED.cryptoKey,
  MGCP_SEED.callerName,
  MGCP_SEED.callerNumber,
  MGCP_SEED.digitMapCanary,
  MGCP_SEED.mediaIp,
  MGCP_SEED.quotedPackageCanary,
]

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

const SDP_BODY = [
  'v=0',
  `o=- 3902468012 3902468013 IN IP4 ${MGCP_SEED.mediaIp}`,
  's=-',
  `c=IN IP4 ${MGCP_SEED.mediaIp}`,
  't=0 0',
  `m=audio ${MGCP_SEED.mediaPort} RTP/AVP 0`,
  'a=rtpmap:0 PCMU/8000',
  '',
].join('\r\n')

export function buildMgcpCrcxWithSdp(): string {
  return [
    `CRCX 1001 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `C: ${MGCP_SEED.callId}`,
    `I: ${MGCP_SEED.connectionId}`,
    `L: p:20, a:PCMU, k:${MGCP_SEED.cryptoKey}`,
    `N: ca@${MGCP_SEED.caHost}:2727`,
    '',
    SDP_BODY,
  ].join('\r\n')
}

export function buildMgcpNtfyDtmf(): string {
  return [
    `NTFY 2002 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `X: ${MGCP_SEED.requestId}`,
    `O: D/${MGCP_SEED.dtmfPin}`,
    '',
  ].join('\r\n')
}

export function buildMgcpSignalCallerId(): string {
  return [
    `RQNT 3003 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `X: ${MGCP_SEED.requestId}`,
    `S: ci(10/22/99/12:30, "${MGCP_SEED.callerName}", "${MGCP_SEED.callerNumber}")`,
    '',
  ].join('\r\n')
}

export function buildMgcpDigitMap(): string {
  return [
    `RQNT 4004 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `X: ${MGCP_SEED.requestId}`,
    `D: (${MGCP_SEED.digitMapCanary}|[2-9]xxxxxxx)`,
    '',
  ].join('\r\n')
}

export function buildMgcpPiggyback(): string {
  const a = [
    `CRCX 5005 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `C: ${MGCP_SEED.callId}`,
    '',
  ].join('\r\n')
  const b = [
    `200 5005 OK`,
    `I: ${MGCP_SEED.connectionId}`,
    '',
  ].join('\r\n')
  return `${a}.\r\n${b}`
}

export function buildMgcpResponseWithText(): string {
  return `200 6006 Transaction succeeded with canary ${MGCP_SEED.gwHost}\r\n`
}

/** Wildcard endpoint — local part must stay structure-preserving (no map). */
export function buildMgcpWildcardEndpoint(): string {
  return [
    `AUEP 7007 *@${MGCP_SEED.gwHost} MGCP 1.0`,
    '',
  ].join('\r\n')
}

/** IPv6 NotifiedEntity with port after bracketed address. */
export function buildMgcpIpv6NotifiedEntity(): string {
  return [
    `CRCX 8008 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `C: ${MGCP_SEED.callId}`,
    `N: ca@[${MGCP_SEED.caIpv6}]:2727`,
    '',
  ].join('\r\n')
}

/** Quoted package argument containing a comma (must not break neighbour params). */
export function buildMgcpQuotedPackageComma(): string {
  return [
    `RQNT 9009 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `X: ${MGCP_SEED.requestId}`,
    `S: G/rt("${MGCP_SEED.quotedPackageCanary}")`,
    `R: D/[0-9*#]`,
    '',
  ].join('\r\n')
}

/** Unknown vendor package — local mask; known neighbour params preserved. */
export function buildMgcpUnknownVendorParam(): string {
  return [
    `MDCX 9010 aaln/1@${MGCP_SEED.gwHost} MGCP 1.0`,
    `C: ${MGCP_SEED.callId}`,
    `I: ${MGCP_SEED.connectionId}`,
    `M: recvonly`,
    `XY: vendor-secret-${MGCP_SEED.cryptoKey}`,
    '',
  ].join('\r\n')
}

export function mgcpPacket(
  payloadText: string,
  packetNumber: number,
  srcPort = 2727,
  dstPort = 2427,
): PacketEnvelope {
  const payload = latin1(payloadText)
  const frame = buildEthIpUdp([10, 55, 66, 77], [10, 0, 0, 1], srcPort, dstPort, payload)
  return envelope(frame, packetNumber)
}

export const mgcpCorpusScenarios = {
  crcxSdp: () => mgcpPacket(buildMgcpCrcxWithSdp(), 1),
  ntfyDtmf: () => mgcpPacket(buildMgcpNtfyDtmf(), 1),
  callerId: () => mgcpPacket(buildMgcpSignalCallerId(), 1),
  digitMap: () => mgcpPacket(buildMgcpDigitMap(), 1),
  piggyback: () => mgcpPacket(buildMgcpPiggyback(), 1),
  responseText: () => mgcpPacket(buildMgcpResponseWithText(), 1, 2427, 2727),
  wildcard: () => mgcpPacket(buildMgcpWildcardEndpoint(), 1),
  ipv6Notified: () => mgcpPacket(buildMgcpIpv6NotifiedEntity(), 1),
  quotedComma: () => mgcpPacket(buildMgcpQuotedPackageComma(), 1),
  unknownVendor: () => mgcpPacket(buildMgcpUnknownVendorParam(), 1),
} as const
