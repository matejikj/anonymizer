/**
 * Synthetic VoIP golden corpus seeds (step 10) — no real personal data.
 */

import type { PacketEnvelope } from '../../../src/pcap/domain/types';

export const VOIP_SEED = {
  ip: '192.168.55.10',
  hostname: 'alice.voip.gate.example',
  callId: 'dialog-voip-gate@192.168.55.10',
  phone: 'VoipGateSecretPhone-7700',
  userAgent: 'VoipGateSecretUA/1.0',
  iceUfrag: 'VoipGateUfrag99',
  icePwd: 'VoipGatePwdSecret42',
  digestRealm: 'voip-gate-realm.example',
  digestUser: 'voip-gate-user',
  mediaPort: 55000,
} as const;

export const VOIP_SEED_TOKENS: readonly string[] = [
  VOIP_SEED.ip,
  VOIP_SEED.hostname,
  VOIP_SEED.callId,
  VOIP_SEED.phone,
  VOIP_SEED.userAgent,
  VOIP_SEED.iceUfrag,
  VOIP_SEED.icePwd,
  VOIP_SEED.digestRealm,
  VOIP_SEED.digestUser,
  `sip:${VOIP_SEED.phone}@`,
  `INVITE sip:${VOIP_SEED.phone}@`,
];

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
}

export function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length;
  const buf = new Uint8Array(total);
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  const ipTotalLen = 20 + 8 + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[23] = 17;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  const udpStart = 34;
  buf[udpStart] = (srcPort >> 8) & 0xff;
  buf[udpStart + 1] = srcPort & 0xff;
  buf[udpStart + 2] = (dstPort >> 8) & 0xff;
  buf[udpStart + 3] = dstPort & 0xff;
  const udpTotalLen = 8 + payload.length;
  buf[udpStart + 4] = (udpTotalLen >> 8) & 0xff;
  buf[udpStart + 5] = udpTotalLen & 0xff;
  buf.set(payload, udpStart + 8);
  return buf;
}

export function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  seq: number,
  payload: Uint8Array,
): Uint8Array {
  const tcpLen = 20;
  const total = 14 + 20 + tcpLen + payload.length;
  const buf = new Uint8Array(total);
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  const ipTotalLen = 20 + tcpLen + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[23] = 6;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  const tcpStart = 34;
  buf[tcpStart] = (srcPort >> 8) & 0xff;
  buf[tcpStart + 1] = srcPort & 0xff;
  buf[tcpStart + 2] = (dstPort >> 8) & 0xff;
  buf[tcpStart + 3] = dstPort & 0xff;
  buf[tcpStart + 4] = (seq >> 24) & 0xff;
  buf[tcpStart + 5] = (seq >> 16) & 0xff;
  buf[tcpStart + 6] = (seq >> 8) & 0xff;
  buf[tcpStart + 7] = seq & 0xff;
  buf[tcpStart + 12] = 0x50;
  buf.set(payload, tcpStart + 20);
  return buf;
}

function ipParts(ip: string): number[] {
  return ip.split('.').map((p) => Number.parseInt(p, 10));
}

export function buildSipInviteWithSdp(options: {
  readonly transport?: 'udp' | 'tcp';
  readonly withDigest?: boolean;
  readonly withIce?: boolean;
} = {}): Uint8Array {
  const sdp = [
    'v=0',
    `o=- 1 2 IN IP4 ${VOIP_SEED.ip}`,
    `c=IN IP4 ${VOIP_SEED.ip}`,
    `m=audio ${VOIP_SEED.mediaPort} RTP/AVP 0`,
    options.withIce
      ? `a=ice-ufrag:${VOIP_SEED.iceUfrag}\r\na=ice-pwd:${VOIP_SEED.icePwd}\r\na=candidate:1 1 UDP 2130706431 ${VOIP_SEED.ip} ${VOIP_SEED.mediaPort} typ host`
      : '',
  ].filter(Boolean).join('\r\n');

  const headers = [
    `INVITE sip:${VOIP_SEED.phone}@${VOIP_SEED.hostname} SIP/2.0`,
    `Via: SIP/2.0/${options.transport === 'tcp' ? 'TCP' : 'UDP'} ${VOIP_SEED.ip}:5060;branch=z9hG4bKvoipgate`,
    `From: <sip:${VOIP_SEED.phone}@${VOIP_SEED.hostname}>;tag=from-voip-gate`,
    `To: <sip:bob@${VOIP_SEED.hostname}>`,
    `Call-ID: ${VOIP_SEED.callId}`,
    `User-Agent: ${VOIP_SEED.userAgent}`,
    'Content-Type: application/sdp',
    options.withDigest
      ? `Authorization: Digest username="${VOIP_SEED.digestUser}", realm="${VOIP_SEED.digestRealm}", nonce="abc", response="deadbeef"`
      : '',
    `Content-Length: ${sdp.length}`,
  ].filter(Boolean);

  return latin1(`${headers.join('\r\n')}\r\n\r\n${sdp}`);
}

/** Synthetic SIPREC INVITE: multipart SDP + rs-metadata+xml (T02). */
export const SIPREC_SEED = {
  participantAor: 'sip:siprec-alice@voip.gate.example',
  sessionId: 'siprec-session-id-77001',
  mediaIp: '192.168.55.77',
} as const;

export const SIPREC_SEED_TOKENS: readonly string[] = [
  SIPREC_SEED.participantAor,
  SIPREC_SEED.sessionId,
  SIPREC_SEED.mediaIp,
  'siprec-alice',
];

export function buildSiprecInvite(options: {
  readonly transport?: 'udp' | 'tcp';
  readonly dualSdp?: boolean;
} = {}): Uint8Array {
  const boundary = 'siprecboundT02';
  const sdp = [
    'v=0',
    `o=- 9007199254740993 9007199254740993 IN IP4 ${SIPREC_SEED.mediaIp}`,
    's=-',
    `c=IN IP4 ${SIPREC_SEED.mediaIp}`,
    't=0 0',
    'm=audio 49000 RTP/AVP 0',
  ].join('\r\n') + '\r\n';
  const sdp2 = options.dualSdp
    ? [
      'v=0',
      `o=- 9007199254740994 9007199254740994 IN IP4 ${SIPREC_SEED.mediaIp}`,
      's=-',
      `c=IN IP4 ${SIPREC_SEED.mediaIp}`,
      't=0 0',
      'm=audio 49002 RTP/AVP 0',
    ].join('\r\n') + '\r\n'
    : null;
  const xml =
    `<?xml version="1.0"?>\r\n`
    + `<recording xmlns="urn:ietf:params:xml:ns:recording:1">\r\n`
    + `<session session_id="${SIPREC_SEED.sessionId}">\r\n`
    + `<participant participant_id="1">\r\n`
    + `<nameID aor="${SIPREC_SEED.participantAor}"/>\r\n`
    + `</participant>\r\n`
    + `</session>\r\n`
    + `</recording>\r\n`;

  let body =
    `--${boundary}\r\n`
    + 'Content-Type: application/sdp\r\n\r\n'
    + sdp
    + `\r\n--${boundary}\r\n`
    + 'Content-Type: application/rs-metadata+xml\r\n\r\n'
    + xml;
  if (sdp2) {
    body +=
      `\r\n--${boundary}\r\n`
      + 'Content-Type: application/sdp\r\n\r\n'
      + sdp2;
  }
  body += `\r\n--${boundary}--\r\n`;

  const headers = [
    `INVITE sip:recorder@${VOIP_SEED.hostname} SIP/2.0`,
    `Via: SIP/2.0/${options.transport === 'tcp' ? 'TCP' : 'UDP'} ${VOIP_SEED.ip}:5060;branch=z9hG4bKsiprec`,
    `From: <sip:${VOIP_SEED.phone}@${VOIP_SEED.hostname}>;tag=siprec-from`,
    `To: <sip:recorder@${VOIP_SEED.hostname}>`,
    `Call-ID: ${VOIP_SEED.callId}-siprec`,
    `User-Agent: ${VOIP_SEED.userAgent}`,
    `Content-Type: multipart/mixed;boundary=${boundary}`,
    `Content-Length: ${body.length}`,
  ];
  return latin1(`${headers.join('\r\n')}\r\n\r\n${body}`);
}

export function buildRtpPayload(payloadType = 0): Uint8Array {
  const buf = new Uint8Array(32);
  buf[0] = 0x80;
  buf[1] = payloadType & 0x7f;
  return buf;
}

export function buildRtcpSdes(cname = `${VOIP_SEED.phone}@${VOIP_SEED.ip}`): Uint8Array {
  const cnameBytes = latin1(cname);
  const chunkLen = 4 + 2 + cnameBytes.length + 1;
  const padded = chunkLen + (4 - (chunkLen % 4)) % 4;
  const buf = new Uint8Array(4 + padded);
  buf[0] = 0x81;
  buf[1] = 202;
  const words = padded / 4;
  buf[2] = (words >> 8) & 0xff;
  buf[3] = words & 0xff;
  buf[8] = 1;
  buf[9] = cnameBytes.length;
  buf.set(cnameBytes, 10);
  return buf;
}

export function envelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index,
    timestamp: { ticks: BigInt(index) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  };
}

export interface VoipCorpusScenario {
  readonly id: string;
  readonly packets: readonly PacketEnvelope[];
  readonly expectMediaDropped?: boolean;
}

export function voipCorpusScenarios(): readonly VoipCorpusScenario[] {
  const src = ipParts(VOIP_SEED.ip);
  const dst = [10, 0, 0, 2];

  const invite = buildSipInviteWithSdp({ withIce: true, withDigest: true });
  const udpCall = [
    envelope(buildEthIpUdp(src, dst, 5060, 5060, invite), 0),
    envelope(buildEthIpUdp(src, dst, VOIP_SEED.mediaPort, 40000, buildRtpPayload(0)), 1),
    envelope(buildEthIpUdp(src, dst, VOIP_SEED.mediaPort + 1, 40001, buildRtcpSdes()), 2),
  ];

  const tcpInvite = buildSipInviteWithSdp({ transport: 'tcp' });
  const mid = Math.floor(tcpInvite.length / 2);
  const tcpSegmented = [
    envelope(buildEthIpTcp(src, dst, 5060, 5060, 1000, tcpInvite.subarray(0, mid)), 0),
    envelope(buildEthIpTcp(src, dst, 5060, 5060, 1000 + mid, tcpInvite.subarray(mid)), 1),
  ];

  const folded = latin1([
    'INVITE sip:folded@example SIP/2.0\r\n',
    'Via: SIP/2.0/UDP 1.1.1.1:5060;\r\n',
    ' branch=folded\r\n',
    `Call-ID: ${VOIP_SEED.callId}-folded\r\n`,
    'Content-Length: 0\r\n',
    '\r\n',
  ].join(''));
  const compactHeaders = envelope(buildEthIpUdp(src, dst, 5060, 5060, folded), 0);

  const tlsClientHello = (() => {
    // Minimal ClientHello with SNI = VOIP_SEED.hostname for CF-10 regression on 5061/TCP.
    const sni = VOIP_SEED.hostname;
    const sniBytes = Array.from(sni, (c) => c.charCodeAt(0) & 0xff);
    const serverNameEntry = [0x00, (sniBytes.length >> 8) & 0xff, sniBytes.length & 0xff, ...sniBytes];
    const serverNameList = [(serverNameEntry.length >> 8) & 0xff, serverNameEntry.length & 0xff, ...serverNameEntry];
    const ext = [0x00, 0x00, (serverNameList.length >> 8) & 0xff, serverNameList.length & 0xff, ...serverNameList];
    const body = [
      0x03, 0x03, ...new Array(32).fill(0), 0x00,
      0x00, 0x02, 0xc0, 0x2f, 0x01, 0x00,
      (ext.length >> 8) & 0xff, ext.length & 0xff, ...ext,
    ];
    const hs = [0x01, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
    return new Uint8Array([0x16, 0x03, 0x03, (hs.length >> 8) & 0xff, hs.length & 0xff, ...hs]);
  })();
  const tls5061 = envelope(buildEthIpTcp(src, dst, 5060, 5061, 1000, tlsClientHello), 0);

  const malformed = latin1('INVITE sip:bad@example SIP/2.0\r\nContent-Length: 999\r\n\r\nshort');
  const malformedPkt = envelope(buildEthIpUdp(src, dst, 5060, 5060, malformed), 0);

  const siprec = buildSiprecInvite();
  const siprecUdp = [envelope(buildEthIpUdp(src, dst, 5060, 5060, siprec), 0)];
  const siprecMid = Math.floor(siprec.length / 2);
  const siprecTcp = [
    envelope(buildEthIpTcp(src, dst, 5060, 5060, 2000, siprec.subarray(0, siprecMid)), 0),
    envelope(buildEthIpTcp(src, dst, 5060, 5060, 2000 + siprecMid, siprec.subarray(siprecMid)), 1),
  ];

  return [
    { id: 'udp-invite-sdp-rtp-rtcp', packets: udpCall, expectMediaDropped: false },
    { id: 'tcp-segmented-invite', packets: tcpSegmented },
    { id: 'compact-folded-via', packets: [compactHeaders] },
    { id: 'sip-tls-port-hint', packets: [tls5061] },
    { id: 'malformed-content-length', packets: [malformedPkt] },
    { id: 'udp-siprec-multipart', packets: siprecUdp },
    { id: 'tcp-siprec-multipart', packets: siprecTcp },
  ];
}
