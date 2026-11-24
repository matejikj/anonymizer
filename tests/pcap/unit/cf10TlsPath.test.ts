/**
 * CF-10 acceptance — unified TLS path; handshake is never marked encrypted.
 */

import { describe, expect, it } from 'vitest';
import {
  sanitizePacket,
  DIAGNOSTIC_POLICY,
  type PacketInput,
} from '../../../src/pcap/sanitize';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';
import { resolveExportBoundary } from '../../../src/pcap/sanitize/exportBoundary';

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const tcpLen = 20;
  const total = 14 + 20 + tcpLen + payload.length;
  const buf = new Uint8Array(total);
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
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
  buf[tcpStart + 12] = 0x50;
  buf.set(payload, tcpStart + 20);
  return buf;
}

function buildTlsClientHello(sni: string, sessionId?: Uint8Array): Uint8Array {
  const sniBytes = Array.from(sni, (c) => c.charCodeAt(0));
  const serverNameEntry = [0x00, (sniBytes.length >> 8) & 0xff, sniBytes.length & 0xff, ...sniBytes];
  const serverNameList = [(serverNameEntry.length >> 8) & 0xff, serverNameEntry.length & 0xff, ...serverNameEntry];
  const serverNameExtension = [0x00, 0x00, (serverNameList.length >> 8) & 0xff, serverNameList.length & 0xff, ...serverNameList];
  const random = new Array(32).fill(0x11);
  const sid = sessionId ? Array.from(sessionId) : [];
  const cipherSuites = [0xc0, 0x2f];
  const compressionMethods = [0x00];
  const handshakeBody = [
    0x03, 0x03,
    ...random,
    sid.length, ...sid,
    (cipherSuites.length >> 8) & 0xff, cipherSuites.length & 0xff, ...cipherSuites,
    compressionMethods.length, ...compressionMethods,
    (serverNameExtension.length >> 8) & 0xff, serverNameExtension.length & 0xff, ...serverNameExtension,
  ];
  const handshakeMessage = [
    0x01,
    (handshakeBody.length >> 16) & 0xff, (handshakeBody.length >> 8) & 0xff, handshakeBody.length & 0xff,
    ...handshakeBody,
  ];
  return new Uint8Array([
    0x16, 0x03, 0x03,
    (handshakeMessage.length >> 8) & 0xff, handshakeMessage.length & 0xff,
    ...handshakeMessage,
  ]);
}

function buildCertificateRecord(canary: string): Uint8Array {
  const canaryBytes = Array.from(canary, (c) => c.charCodeAt(0));
  // Minimal fake certificate handshake: type + 3-byte length + opaque body containing canary
  const body = [0x00, 0x00, ...canaryBytes];
  const handshake = [
    0x0b,
    (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff,
    ...body,
  ];
  return new Uint8Array([
    0x16, 0x03, 0x03,
    (handshake.length >> 8) & 0xff, handshake.length & 0xff,
    ...handshake,
  ]);
}

/** Minimal ServerHello handshake body: server_version(2)+random(32)+session_id(0)+cipher(2)+compression(1). */
function buildServerHelloMessage(): number[] {
  const body = [0x03, 0x03, ...new Array(32).fill(0x22), 0x00, 0xc0, 0x2f, 0x00];
  return [0x02, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
}

/** Certificate handshake message wrapping one fake DER cert body containing `certBody`. */
function buildCertificateMessage(certBody: number[]): number[] {
  const certList = [(certBody.length >> 16) & 0xff, (certBody.length >> 8) & 0xff, certBody.length & 0xff, ...certBody];
  const body = [(certList.length >> 16) & 0xff, (certList.length >> 8) & 0xff, certList.length & 0xff, ...certList];
  return [0x0b, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
}

function wrapHandshakeRecord(messages: number[]): Uint8Array {
  return new Uint8Array([0x16, 0x03, 0x03, (messages.length >> 8) & 0xff, messages.length & 0xff, ...messages]);
}

/** DER SAN iPAddress GeneralName (tag 0x87, length 4) followed by the raw IP bytes — the exact
 * byte pattern a certificate SAN IP leak would show up as in a hex dump. */
function sanIpAddressDer(ip: number[]): number[] {
  return [0x87, 0x04, ...ip];
}

function applyExport(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) out.set(patch.data.slice(0, len - patch.offset), patch.offset);
  }
  return out;
}

describe('CF-10 unified TLS path', () => {
  it('sanitizes ClientHello SNI on SIP TLS port 5061 (no sip-tls/encrypted shortcut)', () => {
    const sni = 'sip-secret.gateway.example';
    const hello = buildTlsClientHello(sni);
    const pkt = buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5061, hello);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());

    expect(result.coverage.some((c) => c.protocol === 'sip-tls' && c.status === 'encrypted')).toBe(false);
    expect(result.coverage.some((c) => c.protocol === 'tls-clienthello')).toBe(true);
    expect(result.coverage.some((c) => c.status === 'encrypted')).toBe(false);

    const exported = applyExport(pkt, result);
    const text = new TextDecoder('latin1').decode(exported);
    expect(text).not.toContain('sip-secret');
    expect(text).not.toContain(sni);
  });

  it('redacts ClientHello session_id', () => {
    const sessionId = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
    const hello = buildTlsClientHello('example.com', sessionId);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 2], 40000, 443, hello);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
    const exported = applyExport(pkt, result);
    const tcpPayloadOffset = 14 + 20 + 20;
    const payload = exported.subarray(tcpPayloadOffset);
    expect(Array.from(payload).join(',')).not.toContain('222,173,190,239'); // 0xde,0xad,0xbe,0xef as decimal
    // session id bytes should be zeroed
    expect(payload.includes(0xde) && payload.includes(0xad) && payload.includes(0xbe) && payload.includes(0xef)).toBe(false);
  });

  it('marks TLS 1.2 Certificate plaintext as tls-certificate/covered with DER masked', () => {
    const canary = 'CN=CanaryOrgSecretCorp';
    const record = buildCertificateRecord(canary);
    const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());

    const cert = result.coverage.find((c) => c.protocol === 'tls-certificate');
    expect(cert).toBeDefined();
    expect(cert!.status).toBe('covered');
    expect(result.coverage.some((c) => c.status === 'encrypted')).toBe(false);

    const boundary = resolveExportBoundary(result.coverage, DIAGNOSTIC_POLICY, pkt.length);
    expect(boundary.safeExportEnd).toBe(pkt.length);
    const exported = applyExport(pkt, result);
    expect(new TextDecoder('latin1').decode(exported)).not.toContain(canary);
  });

  it('marks Application Data as tls-encrypted-payload/encrypted', () => {
    const appData = new Uint8Array([0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 2], 40000, 443, appData);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
    const span = result.coverage.find((c) => c.protocol === 'tls-encrypted-payload');
    expect(span).toBeDefined();
    expect(span!.status).toBe('encrypted');
  });

  it('processes multiple TLS records in one TCP segment', () => {
    const hello = buildTlsClientHello('multi.record.example');
    const appData = new Uint8Array([0x17, 0x03, 0x03, 0x00, 0x02, 0x11, 0x22]);
    const combined = new Uint8Array(hello.length + appData.length);
    combined.set(hello, 0);
    combined.set(appData, hello.length);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 2], 40000, 443, combined);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
    expect(result.coverage.some((c) => c.protocol === 'tls-clienthello')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'tls-encrypted-payload' && c.status === 'encrypted')).toBe(true);
    const text = new TextDecoder('latin1').decode(applyExport(pkt, result));
    expect(text).not.toContain('multi.record');
  });

  describe('multiple handshake messages coalesced in one record (step 3)', () => {
    it('sanitizes a Certificate message that follows a ServerHello in the same record (SAN IP canary masked)', () => {
      const originalSanIp = [172, 16, 100, 32];
      const certBody = [...sanIpAddressDer(originalSanIp), ...Array.from('CN=CanarySecretCorp', (c) => c.charCodeAt(0))];
      const record = wrapHandshakeRecord([...buildServerHelloMessage(), ...buildCertificateMessage(certBody)]);
      const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record);
      const input: PacketInput = {
        index: 0,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      };
      const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());

      // Both messages must be individually recognized — not just the first one.
      const serverHello = result.coverage.find((c) => c.protocol === 'tls-serverhello');
      const certificate = result.coverage.find((c) => c.protocol === 'tls-certificate');
      expect(serverHello).toBeDefined();
      expect(serverHello!.status).toBe('covered');
      expect(certificate).toBeDefined();
      expect(certificate!.status).toBe('covered');
      // The two spans must not overlap and must not gap — no bytes fall in between unclaimed.
      expect(certificate!.offset).toBe(serverHello!.offset + serverHello!.length);

      const boundary = resolveExportBoundary(result.coverage, DIAGNOSTIC_POLICY, pkt.length);
      expect(boundary.safeExportEnd).toBe(pkt.length);

      const exported = applyExport(pkt, result);
      const tcpPayloadOffset = 14 + 20 + 20;
      const certPayload = exported.subarray(tcpPayloadOffset);
      // The original SAN IP bytes and the DER SAN tag+length must not survive intact.
      const ipBytesPresent = certPayload.some((_, i) =>
        i + 4 <= certPayload.length
        && certPayload[i] === originalSanIp[0] && certPayload[i + 1] === originalSanIp[1]
        && certPayload[i + 2] === originalSanIp[2] && certPayload[i + 3] === originalSanIp[3]);
      expect(ipBytesPresent).toBe(false);
      expect(new TextDecoder('latin1').decode(exported)).not.toContain('CanarySecretCorp');
    });

    it('sanitizes a Certificate with multiple certificates after a ServerHello in the same record', () => {
      const cert1 = Array.from('FIRST-CERT-CANARY', (c) => c.charCodeAt(0));
      const cert2 = Array.from('SECOND-CERT-CANARY', (c) => c.charCodeAt(0));
      const certList = [
        (cert1.length >> 16) & 0xff, (cert1.length >> 8) & 0xff, cert1.length & 0xff, ...cert1,
        (cert2.length >> 16) & 0xff, (cert2.length >> 8) & 0xff, cert2.length & 0xff, ...cert2,
      ];
      const certBody = [(certList.length >> 16) & 0xff, (certList.length >> 8) & 0xff, certList.length & 0xff, ...certList];
      const certMessage = [0x0b, (certBody.length >> 16) & 0xff, (certBody.length >> 8) & 0xff, certBody.length & 0xff, ...certBody];
      const record = wrapHandshakeRecord([...buildServerHelloMessage(), ...certMessage]);
      const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record);
      const input: PacketInput = {
        index: 0,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      };
      const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
      const text = new TextDecoder('latin1').decode(applyExport(pkt, result));
      expect(text).not.toContain('FIRST-CERT-CANARY');
      expect(text).not.toContain('SECOND-CERT-CANARY');
    });

    it('redacts an unknown handshake message type that follows a ServerHello in the same record', () => {
      const unknownBody = Array.from('UNKNOWN-HANDSHAKE-CANARY', (c) => c.charCodeAt(0));
      const unknownMessage = [0x32, (unknownBody.length >> 16) & 0xff, (unknownBody.length >> 8) & 0xff, unknownBody.length & 0xff, ...unknownBody];
      const record = wrapHandshakeRecord([...buildServerHelloMessage(), ...unknownMessage]);
      const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record);
      const input: PacketInput = {
        index: 0,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      };
      const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
      const unsupported = result.coverage.find((c) => c.protocol === 'tls-handshake-unsupported');
      expect(unsupported).toBeDefined();
      expect(unsupported!.status).toBe('redacted');
      const text = new TextDecoder('latin1').decode(applyExport(pkt, result));
      expect(text).not.toContain('UNKNOWN-HANDSHAKE-CANARY');
    });

    it('marks a truncated second handshake message as requires-reassembly without discarding the first', () => {
      const serverHello = buildServerHelloMessage();
      // Declares a 200-byte body but the record only has 10 bytes left — cannot be
      // fully verified from this record alone (may continue in the next TLS record).
      const truncatedSecond = [0x0b, 0x00, 0x00, 200, ...new Array(10).fill(0xaa)];
      const record = wrapHandshakeRecord([...serverHello, ...truncatedSecond]);
      const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record);
      const input: PacketInput = {
        index: 0,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      };
      const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());

      const serverHelloSpan = result.coverage.find((c) => c.protocol === 'tls-serverhello');
      expect(serverHelloSpan).toBeDefined();
      expect(serverHelloSpan!.status).toBe('covered');
      const tail = result.coverage.find((c) => c.protocol === 'tls' && c.status === 'requires-reassembly');
      expect(tail).toBeDefined();
      expect(tail!.offset).toBe(serverHelloSpan!.offset + serverHelloSpan!.length);
      expect(tail!.offset + tail!.length).toBe(14 + 20 + 20 + record.length);
    });

    it('never leaves a coverage gap across a multi-message record', () => {
      const record = wrapHandshakeRecord([...buildServerHelloMessage(), ...buildCertificateMessage(sanIpAddressDer([172, 16, 100, 33]))]);
      const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record);
      const input: PacketInput = {
        index: 0,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      };
      const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
      const tlsSpans = result.coverage
        .filter((c) => c.protocol.startsWith('tls'))
        .sort((a, b) => a.offset - b.offset);
      expect(tlsSpans.length).toBeGreaterThanOrEqual(2);
      let cursor = tlsSpans[0]!.offset;
      for (const span of tlsSpans) {
        expect(span.offset).toBe(cursor);
        cursor += span.length;
      }
      expect(cursor).toBe(14 + 20 + 20 + record.length);
    });
  });
});
