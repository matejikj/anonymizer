/**
 * CF-09 acceptance — safe export boundary must not follow risky coverage spans.
 */

import { describe, expect, it } from 'vitest';
import {
  sanitizePacket,
  HIGH_PRIVACY_POLICY,
  DIAGNOSTIC_POLICY,
  resolveExportBoundary,
  blockingSpanCapsSafeEnd,
  type PacketInput,
  type LayerCoverage,
  type SanitizationPolicy,
} from '../../../src/pcap/sanitize';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const ethLen = 14;
  const ipLen = 20;
  const tcpLen = 20;
  const total = ethLen + ipLen + tcpLen + payload.length;
  const buf = new Uint8Array(total);

  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  buf[12] = 0x08;
  buf[13] = 0x00;

  buf[14] = 0x45;
  const ipTotalLen = ipLen + tcpLen + payload.length;
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

function buildEthIpUdp(
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

function buildEthIpGre(payload: Uint8Array, greProtocol = 0x6558): Uint8Array {
  const ethLen = 14;
  const ipLen = 20;
  const greLen = 4;
  const total = ethLen + ipLen + greLen + payload.length;
  const buf = new Uint8Array(total);

  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  buf[12] = 0x08;
  buf[13] = 0x00;

  buf[14] = 0x45;
  const ipTotalLen = ipLen + greLen + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff;
  buf[17] = ipTotalLen & 0xff;
  buf[23] = 47;
  buf.set([192, 168, 1, 1], 26);
  buf.set([10, 0, 0, 1], 30);

  const greStart = 34;
  buf[greStart] = 0;
  buf[greStart + 1] = 0;
  buf[greStart + 2] = (greProtocol >> 8) & 0xff;
  buf[greStart + 3] = greProtocol & 0xff;
  buf.set(payload, greStart + 4);
  return buf;
}

function exportBytes(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const len = result.truncatedLength ?? original.length;
  const out = original.slice(0, len);
  for (const patch of result.patches) {
    if (patch.offset < len) {
      const slice = patch.data.slice(0, len - patch.offset);
      out.set(slice, patch.offset);
    }
  }
  return out;
}

describe('CF-09 export boundary', () => {
  it('masks HTTP POST body in place for both levels (step 2 TCP MASK preference)', () => {
    const secret = 'CANARY-SECRET-POST-BODY';
    const text = `POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: ${secret.length}\r\n\r\n${secret}`;
    const payload = new Uint8Array(Array.from(text, (c) => c.charCodeAt(0)));
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };

    const safe = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping());
    expect(safe.truncatedLength).toBeUndefined();
    expect(exportBytes(pkt, safe).length).toBe(pkt.length);
    const safeText = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, safe));
    expect(safeText).not.toContain(secret);
    expect(safeText).not.toContain('CANARY-SECRET');
    expect(safe.coverage.find((c) => c.protocol === 'http-body')?.status).toBe('redacted');

    const diagnostic = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
    expect(diagnostic.truncatedLength).toBeUndefined();
    const diagnosticText = new TextDecoder('ascii', { fatal: false }).decode(exportBytes(pkt, diagnostic));
    expect(diagnosticText).not.toContain(secret);
    expect(diagnosticText).not.toContain('CANARY-SECRET');
    expect(exportBytes(pkt, diagnostic).length).toBe(pkt.length);
  });

  it('diagnostic keeps covered TLS ServerHello at full length', () => {
    const body = new Uint8Array(38);
    body[0] = 0x03;
    body[1] = 0x03;
    const handshake = new Uint8Array(4 + body.length);
    handshake[0] = 0x02;
    handshake[3] = body.length;
    handshake.set(body, 4);
    const record = new Uint8Array(5 + handshake.length);
    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = (handshake.length >> 8) & 0xff;
    record[4] = handshake.length & 0xff;
    record.set(handshake, 5);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 443, 54321, record);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());

    expect(result.truncatedLength).toBeUndefined();
    expect(exportBytes(pkt, result).length).toBe(pkt.length);
    expect(result.coverage.some((c) => c.protocol === 'tls-serverhello' && c.status === 'covered')).toBe(true);
    const boundary = resolveExportBoundary(result.coverage, DIAGNOSTIC_POLICY, pkt.length);
    expect(boundary.safeExportEnd).toBe(pkt.length);
  });

  it('safe truncates unsupported TLS Alert record bytes from export', () => {
    const record = new Uint8Array([0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 443, 54321, record);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping());

    expect(result.truncatedLength).toBeDefined();
    expect(result.truncatedLength!).toBeLessThan(pkt.length);
    expect(exportBytes(pkt, result).length).toBe(result.truncatedLength);
  });

  it('truncates GRE non-IP payload from export', () => {
    const grePayload = new Uint8Array(Array.from('GRE-CANARY-PAYLOAD-SECRET', (c) => c.charCodeAt(0)));
    const pkt = buildEthIpGre(grePayload);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping());

    expect(result.truncatedLength).toBeDefined();
    const exported = exportBytes(pkt, result);
    const text = new TextDecoder('ascii', { fatal: false }).decode(exported);
    expect(text).not.toContain('GRE-CANARY-PAYLOAD-SECRET');
  });

  it('diagnostic keeps generic unsupported payload length (mask-in-place)', () => {
    const payload = new Uint8Array(32).fill(0xab);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 5], 54321, 33060, payload);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());

    expect(result.truncatedLength).toBeUndefined();
    expect(result.coverage.some((c) => c.protocol === 'heuristic')).toBe(false);
    expect(result.coverage.some((c) => c.status === 'redacted' || c.status === 'unsupported')).toBe(true);
    const boundary = resolveExportBoundary(result.coverage, DIAGNOSTIC_POLICY, pkt.length);
    // After mask application coverage includes redacted span; disposition may be keep.
    expect(exportBytes(pkt, result).length).toBe(pkt.length);
    const exported = exportBytes(pkt, result);
    expect([...exported.subarray(54)].every((b) => b !== 0xab)).toBe(true);
    void boundary;
  });

  describe('malformed disposition matrix (drop propagation, step 2)', () => {
    function assertDropMatrix(pkt: Uint8Array, label: string): void {
      const input: PacketInput = {
        index: 0,
        data: pkt,
        capturedLength: pkt.length,
        originalLength: pkt.length,
        linkType: 1,
      };

      const highPrivacy = sanitizePacket(input, HIGH_PRIVACY_POLICY, new SessionMapping());
      const hpBoundary = resolveExportBoundary(highPrivacy.coverage, HIGH_PRIVACY_POLICY, pkt.length);
      // The regression this guards: resolveExportBoundary() computing 'drop' must never be
      // silently ignored by sanitizePacket() — that was the exact bug (P0-2) that let SIP
      // MESSAGE plaintext survive byte-for-byte in the high-privacy export.
      expect(hpBoundary.disposition, `${label}: expected export boundary disposition 'drop'`).toBe('drop');
      expect(highPrivacy.drop, `${label}: disposition was 'drop' but result.drop was false`).toBe(true);

      const diagnostic = sanitizePacket(input, DIAGNOSTIC_POLICY, new SessionMapping());
      expect(diagnostic.drop, `${label}: diagnostic must keep the record`).toBe(false);
      const diagBoundary = resolveExportBoundary(diagnostic.coverage, DIAGNOSTIC_POLICY, pkt.length);
      expect(diagBoundary.disposition).toBe('mask-application-in-place');
      const exported = exportBytes(pkt, diagnostic);
      expect(exported.length).toBe(pkt.length);
      // Masked region must differ from the original bytes (no original-payload fallback).
      const maskStart = diagBoundary.safeExportEnd;
      expect(maskStart).toBeLessThan(pkt.length);
      let anyByteChanged = false;
      for (let i = maskStart; i < pkt.length; i++) {
        if (exported[i] !== pkt[i]) { anyByteChanged = true; break; }
      }
      expect(anyByteChanged, `${label}: masked span must not equal original bytes`).toBe(true);
    }

    it('malformed SIP: high-privacy drops the record, diagnostic masks it in place', () => {
      const text = 'INVITE sip:a@b.c;=value SIP/2.0\r\nContent-Length: 0\r\n\r\n';
      const payload = new Uint8Array(Array.from(text, (c) => c.charCodeAt(0)));
      const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 5], 5060, 5060, payload);
      assertDropMatrix(pkt, 'SIP');
    });

    it('malformed DNS (too short for a header): high-privacy drops, diagnostic masks in place', () => {
      const payload = new Uint8Array([0x00, 0x01, 0x02, 0x03]); // < 12 bytes
      const pkt = buildEthIpUdp([192, 168, 1, 1], [8, 8, 8, 8], 33333, 53, payload);
      assertDropMatrix(pkt, 'DNS');
    });

    it('malformed DHCPv4 (missing magic cookie): high-privacy drops, diagnostic masks in place', () => {
      const payload = new Uint8Array(64).fill(0x11); // < 240 bytes required
      const pkt = buildEthIpUdp([0, 0, 0, 0], [255, 255, 255, 255], 68, 67, payload);
      assertDropMatrix(pkt, 'DHCPv4');
    });

    it('malformed TLS handshake (declared body length overruns record): high-privacy drops, diagnostic masks in place', () => {
      const body = new Uint8Array(10); // handshake declares 100 bytes but record only has 10
      const handshake = new Uint8Array(4 + body.length);
      handshake[0] = 0x02; // ServerHello
      handshake[1] = 0x00;
      handshake[2] = 0x00;
      handshake[3] = 100;
      handshake.set(body, 4);
      const record = new Uint8Array(5 + handshake.length);
      record[0] = 0x16;
      record[1] = 0x03;
      record[2] = 0x03;
      record[3] = (handshake.length >> 8) & 0xff;
      record[4] = handshake.length & 0xff;
      record.set(handshake, 5);
      const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 443, 54321, record);
      assertDropMatrix(pkt, 'TLS');
    });
  });

  it('property: blocking spans never extend safeExportEnd past their start', () => {
    const blocking: LayerCoverage['status'][] = [
      'unsupported',
      'malformed',
      'requires-reassembly',
      'heuristic',
    ];
    const exportable: LayerCoverage['status'][] = ['covered', 'redacted', 'encrypted', 'preserved-unsafe'];

    for (let trial = 0; trial < 200; trial++) {
      const packetLength = 64 + Math.floor(Math.random() * 192);
      const coverage: LayerCoverage[] = [];
      let cursor = 0;

      while (cursor < packetLength && Math.random() > 0.15) {
        const len = 4 + Math.floor(Math.random() * 24);
        const end = Math.min(cursor + len, packetLength);
        const pool = Math.random() > 0.4 ? exportable : blocking;
        coverage.push({
          protocol: 'test',
          offset: cursor,
          length: end - cursor,
          status: pool[Math.floor(Math.random() * pool.length)]!,
        });
        cursor = end + Math.floor(Math.random() * 8);
      }

      const boundary = resolveExportBoundary(
        coverage,
        {
          truncateUnsupported: true,
          unsupportedPayloadPolicy: 'truncate',
          malformedPayloadPolicy: 'drop',
        } as SanitizationPolicy,
        packetLength,
      );
      expect(boundary.safeExportEnd).toBeLessThanOrEqual(packetLength);
      expect(blockingSpanCapsSafeEnd(coverage, packetLength)).toBe(true);

      for (const span of coverage) {
        if (!blocking.includes(span.status)) continue;
        expect(span.offset).toBeGreaterThanOrEqual(boundary.safeExportEnd);
      }
    }
  });
});
