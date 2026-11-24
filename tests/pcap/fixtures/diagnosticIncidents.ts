/**
 * Golden diagnostic incidents (step 10) — identity-agnostic root-cause fixtures.
 */

import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import type { DiagnosticRootCauseCategory } from '../../../src/pcap/diagnostics'
import { buildEthIpTcp, buildEthIpUdp, envelope } from './voipCorpus'

export const DIAGNOSTIC_SEED = {
  ipClient: '10.55.66.77',
  ipServer: '10.55.66.1',
  hostname: 'diag-gate.secret.example',
  phone: 'DiagGatePhone9900',
  callId: 'diag-gate-call@10.55.66.77',
  mac: 'aa:bb:cc:dd:ee:11',
} as const

export const DIAGNOSTIC_SEED_TOKENS: readonly string[] = [
  DIAGNOSTIC_SEED.ipClient,
  DIAGNOSTIC_SEED.ipServer,
  DIAGNOSTIC_SEED.hostname,
  DIAGNOSTIC_SEED.phone,
  DIAGNOSTIC_SEED.callId,
  DIAGNOSTIC_SEED.mac,
  `sip:${DIAGNOSTIC_SEED.phone}@`,
]

function ipParts(ip: string): number[] {
  return ip.split('.').map((p) => Number.parseInt(p, 10))
}

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function buildDnsNxdomain(hostname: string, id = 0x2345): Uint8Array {
  const labels = hostname.split('.')
  let qnameLen = 1
  for (const l of labels) qnameLen += 1 + l.length
  const dns = new Uint8Array(12 + qnameLen + 4)
  dns[0] = (id >> 8) & 0xff
  dns[1] = id & 0xff
  dns[2] = 0x81
  dns[3] = 0x83 // QR + NXDOMAIN
  dns[5] = 1
  let pos = 12
  for (const label of labels) {
    dns[pos++] = label.length
    for (let i = 0; i < label.length; i++) dns[pos++] = label.charCodeAt(i)
  }
  dns[pos++] = 0
  dns[pos + 1] = 1
  dns[pos + 3] = 1
  return dns
}

function buildDnsQueryOnly(hostname: string, id = 0x1111): Uint8Array {
  const labels = hostname.split('.')
  let qnameLen = 1
  for (const l of labels) qnameLen += 1 + l.length
  const dns = new Uint8Array(12 + qnameLen + 4)
  dns[0] = (id >> 8) & 0xff
  dns[1] = id & 0xff
  dns[2] = 0x01
  dns[5] = 1
  let pos = 12
  for (const label of labels) {
    dns[pos++] = label.length
    for (let i = 0; i < label.length; i++) dns[pos++] = label.charCodeAt(i)
  }
  dns[pos++] = 0
  dns[pos + 1] = 1
  dns[pos + 3] = 1
  return dns
}

function buildDhcpDiscover(): Uint8Array {
  const buf = new Uint8Array(300)
  buf[0] = 1
  buf[1] = 1
  buf[2] = 6
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11], 28)
  buf[236] = 99
  buf[237] = 130
  buf[238] = 83
  buf[239] = 99
  let pos = 240
  buf[pos++] = 53
  buf[pos++] = 1
  buf[pos++] = 1 // Discover
  buf[pos++] = 12
  buf[pos++] = DIAGNOSTIC_SEED.hostname.length
  for (let i = 0; i < DIAGNOSTIC_SEED.hostname.length; i++) {
    buf[pos++] = DIAGNOSTIC_SEED.hostname.charCodeAt(i)
  }
  buf[pos++] = 255
  return buf
}

function buildDhcpOffer(): Uint8Array {
  const buf = buildDhcpDiscover()
  buf[0] = 2
  // message type Offer (2)
  for (let i = 240; i < buf.length - 2; i++) {
    if (buf[i] === 53 && buf[i + 1] === 1) {
      buf[i + 2] = 2
      break
    }
  }
  return buf
}

function buildSipStatus(status: number, methodHint = 'REGISTER'): Uint8Array {
  const body = [
    `SIP/2.0 ${status} Failure`,
    `Via: SIP/2.0/UDP ${DIAGNOSTIC_SEED.ipClient}:5060;branch=z9hG4bKdiag`,
    `From: <sip:${DIAGNOSTIC_SEED.phone}@${DIAGNOSTIC_SEED.hostname}>;tag=from-diag`,
    `To: <sip:${DIAGNOSTIC_SEED.phone}@${DIAGNOSTIC_SEED.hostname}>`,
    `Call-ID: ${DIAGNOSTIC_SEED.callId}`,
    `CSeq: 1 ${methodHint}`,
    'Content-Length: 0',
    '',
    '',
  ].join('\r\n')
  return latin1(body)
}

function buildSipRegister(): Uint8Array {
  return latin1(
    [
      `REGISTER sip:${DIAGNOSTIC_SEED.hostname} SIP/2.0`,
      `Via: SIP/2.0/UDP ${DIAGNOSTIC_SEED.ipClient}:5060;branch=z9hG4bKreg`,
      `From: <sip:${DIAGNOSTIC_SEED.phone}@${DIAGNOSTIC_SEED.hostname}>;tag=reg`,
      `To: <sip:${DIAGNOSTIC_SEED.phone}@${DIAGNOSTIC_SEED.hostname}>`,
      `Call-ID: ${DIAGNOSTIC_SEED.callId}`,
      'CSeq: 1 REGISTER',
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n'),
  )
}

function buildEthIpTcpFlags(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  flags: number,
  window: number,
  seq = 1000,
): Uint8Array {
  const buf = buildEthIpTcp(srcIp, dstIp, srcPort, dstPort, seq, new Uint8Array(0))
  buf[47] = flags
  buf[48] = (window >> 8) & 0xff
  buf[49] = window & 0xff
  return buf
}

function buildRtp(seq: number, pt = 0, ssrc = 0x11223344): Uint8Array {
  const buf = new Uint8Array(32)
  buf[0] = 0x80
  buf[1] = pt & 0x7f
  buf[2] = (seq >> 8) & 0xff
  buf[3] = seq & 0xff
  buf[8] = (ssrc >>> 24) & 0xff
  buf[9] = (ssrc >>> 16) & 0xff
  buf[10] = (ssrc >>> 8) & 0xff
  buf[11] = ssrc & 0xff
  return buf
}

function buildRtcpRr(fractionLost: number, jitter: number): Uint8Array {
  const buf = new Uint8Array(32)
  buf[0] = 0x81
  buf[1] = 201 // RR
  buf[2] = 0
  buf[3] = 7
  buf[12] = fractionLost & 0xff
  buf[20] = (jitter >>> 24) & 0xff
  buf[21] = (jitter >>> 16) & 0xff
  buf[22] = (jitter >>> 8) & 0xff
  buf[23] = jitter & 0xff
  return buf
}

export interface DiagnosticIncident {
  readonly id: string
  readonly rootCauseCategory: DiagnosticRootCauseCategory
  readonly packets: readonly PacketEnvelope[]
  readonly seeds: readonly string[]
}

export function diagnosticIncidents(): readonly DiagnosticIncident[] {
  const src = ipParts(DIAGNOSTIC_SEED.ipClient)
  const dst = ipParts(DIAGNOSTIC_SEED.ipServer)

  return [
    {
      id: 'dns-nxdomain',
      rootCauseCategory: 'dns-nxdomain',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 53000, 53, buildDnsNxdomain(DIAGNOSTIC_SEED.hostname)), 0),
      ],
    },
    {
      id: 'dns-timeout',
      rootCauseCategory: 'dns-timeout',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 53001, 53, buildDnsQueryOnly(DIAGNOSTIC_SEED.hostname, 0x2222)), 0),
      ],
    },
    {
      id: 'dhcp-no-ack',
      rootCauseCategory: 'dhcp-no-ack',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, [255, 255, 255, 255], 68, 67, buildDhcpDiscover()), 0),
        envelope(buildEthIpUdp(dst, src, 67, 68, buildDhcpOffer()), 1),
      ],
    },
    {
      id: 'sip-401-auth',
      rootCauseCategory: 'sip-401-auth',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 5060, 5060, buildSipRegister()), 0),
        envelope(buildEthIpUdp(dst, src, 5060, 5060, buildSipStatus(401)), 1),
      ],
    },
    {
      id: 'sip-register-failure',
      rootCauseCategory: 'sip-register-failure',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 5060, 5060, buildSipRegister()), 0),
        envelope(buildEthIpUdp(dst, src, 5060, 5060, buildSipStatus(403)), 1),
      ],
    },
    {
      // One-way audio: RTP only client→server with seq gap (same root-cause class as rtp-loss).
      id: 'rtp-one-way',
      rootCauseCategory: 'rtp-loss',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(1)), 0),
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(5)), 1),
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(6)), 2),
      ],
    },
    {
      id: 'sip-5xx',
      rootCauseCategory: 'sip-5xx',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 5060, 5060, buildSipRegister()), 0),
        envelope(buildEthIpUdp(dst, src, 5060, 5060, buildSipStatus(503, 'REGISTER')), 1),
      ],
    },
    {
      id: 'tcp-reset',
      rootCauseCategory: 'tcp-reset',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [envelope(buildEthIpTcpFlags(src, dst, 40000, 80, 0x14 /* ACK+RST */, 8192), 0)],
    },
    {
      id: 'tcp-zero-window',
      rootCauseCategory: 'tcp-zero-window',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [envelope(buildEthIpTcpFlags(src, dst, 40001, 80, 0x10 /* ACK */, 0), 0)],
    },
    {
      id: 'tcp-retransmission',
      rootCauseCategory: 'tcp-retransmission',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpTcp(src, dst, 40002, 80, 5000, latin1('GET /diag-gate HTTP/1.0\r\n\r\n')), 0),
        envelope(buildEthIpTcp(src, dst, 40002, 80, 5000, latin1('GET /diag-gate HTTP/1.0\r\n\r\n')), 1),
      ],
    },
    {
      id: 'rtp-loss',
      rootCauseCategory: 'rtp-loss',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(1)), 0),
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(4)), 1),
      ],
    },
    {
      id: 'rtp-out-of-order',
      rootCauseCategory: 'rtp-out-of-order',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(20)), 0),
        envelope(buildEthIpUdp(src, dst, 5004, 5004, buildRtp(18)), 1),
      ],
    },
    {
      id: 'rtp-jitter',
      rootCauseCategory: 'rtp-jitter',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(dst, src, 5005, 5005, buildRtcpRr(10, 9000)), 0),
      ],
    },
    {
      id: 'rtcp-quality-degrade',
      rootCauseCategory: 'rtcp-quality-degrade',
      seeds: DIAGNOSTIC_SEED_TOKENS,
      packets: [
        envelope(buildEthIpUdp(dst, src, 5005, 5005, buildRtcpRr(200, 100)), 0),
      ],
    },
  ]
}
