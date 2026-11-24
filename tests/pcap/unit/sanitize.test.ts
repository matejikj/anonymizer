import { describe, it, expect } from 'vitest';
import { sanitizePacket, policyFromPreset, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize';
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector';
import { sanitizeDns } from '../../../src/pcap/sanitize/dns';
import { sanitizeDhcpv4 } from '../../../src/pcap/sanitize/dhcp';
import { sanitizeSip } from '../../../src/pcap/sanitize/sip';
import { sanitizeIcmpEmbedded } from '../../../src/pcap/sanitize/tunnel';
import { patchFixedLengthAscii } from '../../../src/pcap/sanitize/textPatch';
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping';
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector';
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession';
import type { PacketInput } from '../../../src/pcap/sanitize';
import { sanitizeStun } from '../../../src/pcap/sanitize/stun';
import { STUN_ATTR, STUN_MAGIC_COOKIE } from '../../../src/pcap/protocols/application/stun/classify';

function buildStunXorMappedIpv4(ip: number[], port: number): Uint8Array {
  const xPort = (port ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff;
  const xorIp = new Uint8Array([
    ip[0]! ^ ((STUN_MAGIC_COOKIE >>> 24) & 0xff),
    ip[1]! ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xff),
    ip[2]! ^ ((STUN_MAGIC_COOKIE >>> 8) & 0xff),
    ip[3]! ^ (STUN_MAGIC_COOKIE & 0xff),
  ]);
  const attrValue = new Uint8Array(8);
  attrValue[1] = 0x01;
  attrValue[2] = (xPort >> 8) & 0xff;
  attrValue[3] = xPort & 0xff;
  attrValue.set(xorIp, 4);
  const bodyLen = 4 + 8;
  const msg = new Uint8Array(20 + bodyLen);
  msg[0] = 0x01;
  msg[1] = 0x01;
  msg[2] = (bodyLen >> 8) & 0xff;
  msg[3] = bodyLen & 0xff;
  msg[4] = (STUN_MAGIC_COOKIE >>> 24) & 0xff;
  msg[5] = (STUN_MAGIC_COOKIE >>> 16) & 0xff;
  msg[6] = (STUN_MAGIC_COOKIE >>> 8) & 0xff;
  msg[7] = STUN_MAGIC_COOKIE & 0xff;
  msg[8] = 0x01;
  msg[20] = (STUN_ATTR.XOR_MAPPED_ADDRESS >> 8) & 0xff;
  msg[21] = STUN_ATTR.XOR_MAPPED_ADDRESS & 0xff;
  msg[22] = 0x00;
  msg[23] = 0x08;
  msg.set(attrValue, 24);
  return msg;
}

/** Build a minimal Ethernet + IPv4 + UDP packet with given payload */
function buildEthIpUdp(srcIp: number[], dstIp: number[], srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const ethLen = 14;
  const ipLen = 20;
  const udpLen = 8;
  const total = ethLen + ipLen + udpLen + payload.length;
  const buf = new Uint8Array(total);

  // Ethernet: dst=ff:ff:ff:ff:ff:ff src=aa:bb:cc:dd:ee:ff type=0x0800
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  buf[12] = 0x08; buf[13] = 0x00;

  // IPv4
  buf[14] = 0x45; // version + IHL
  buf[15] = 0x00; // DSCP
  const ipTotalLen = ipLen + udpLen + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff; buf[17] = ipTotalLen & 0xff;
  buf[23] = 17; // protocol = UDP
  buf.set(srcIp, 26); // src IP
  buf.set(dstIp, 30); // dst IP

  // UDP
  const udpStart = 34;
  buf[udpStart] = (srcPort >> 8) & 0xff; buf[udpStart + 1] = srcPort & 0xff;
  buf[udpStart + 2] = (dstPort >> 8) & 0xff; buf[udpStart + 3] = dstPort & 0xff;
  const udpTotalLen = udpLen + payload.length;
  buf[udpStart + 4] = (udpTotalLen >> 8) & 0xff; buf[udpStart + 5] = udpTotalLen & 0xff;

  buf.set(payload, udpStart + 8);
  return buf;
}

function buildEthIpTcp(srcIp: number[], dstIp: number[], srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const ethLen = 14;
  const ipLen = 20;
  const tcpLen = 20;
  const total = ethLen + ipLen + tcpLen + payload.length;
  const buf = new Uint8Array(total);

  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  buf[12] = 0x08; buf[13] = 0x00;

  buf[14] = 0x45;
  const ipTotalLen = ipLen + tcpLen + payload.length;
  buf[16] = (ipTotalLen >> 8) & 0xff; buf[17] = ipTotalLen & 0xff;
  buf[23] = 6; // TCP
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);

  const tcpStart = 34;
  buf[tcpStart] = (srcPort >> 8) & 0xff; buf[tcpStart + 1] = srcPort & 0xff;
  buf[tcpStart + 2] = (dstPort >> 8) & 0xff; buf[tcpStart + 3] = dstPort & 0xff;
  buf[tcpStart + 12] = 0x50; // data offset = 5 (20 bytes)

  buf.set(payload, tcpStart + 20);
  return buf;
}

describe('PatchCollector', () => {
  it('rejects overlapping patches', () => {
    const c = new PatchCollector(100);
    c.add(10, new Uint8Array([1, 2, 3]));
    expect(() => c.add(11, new Uint8Array([4, 5]))).toThrow(/overlap/i);
  });

  it('rejects out-of-bounds patches', () => {
    const c = new PatchCollector(10);
    expect(() => c.add(8, new Uint8Array([1, 2, 3]))).toThrow(/out of bounds/i);
  });

  it('returns sorted patches', () => {
    const c = new PatchCollector(100);
    c.add(50, new Uint8Array([1]));
    c.add(10, new Uint8Array([2]));
    const patches = c.getPatches();
    expect(patches[0]!.offset).toBe(10);
    expect(patches[1]!.offset).toBe(50);
  });

  // Real-45MB-capture regression: a deferred patch's compute() is keyed by offset in an
  // internal Map. If a later maskRange() evicts that patch (because a broader mask at the
  // same start offset wins), the old Map entry must not survive to be wrongly reattached to
  // whatever unrelated patch ends up at that same offset — otherwise resolveDeferred() throws
  // "length-mismatch" (or worse, silently applies the wrong bytes) even though nothing about
  // the winning patch was ever deferred.
  it('drops an evicted deferred patch\'s compute instead of reattaching it to the winning mask', () => {
    const c = new PatchCollector(600);
    const mapping = new SessionMapping();
    const fingerprints = new FingerprintSession();

    // A small deferred patch (e.g. a 4-byte binary IPv4 field) reserved first at offset 42.
    c.addDeferred(42, 4, () => new Uint8Array([9, 9, 9, 9]));
    // A much larger immediate mask at the same start offset wins later (e.g. the whole
    // payload turned out to be unsupported/opaque and got masked in one shot), evicting the
    // small deferred patch.
    const maskBytes = new Uint8Array(556).fill(0x2a);
    c.maskRange(42, maskBytes);

    expect(() => c.resolveDeferred({ mapping, fingerprints })).not.toThrow();
    const patches = c.getPatches();
    expect(patches).toHaveLength(1);
    expect(patches[0]!.offset).toBe(42);
    expect(patches[0]!.data).toEqual(maskBytes);
  });

  it('still resolves a deferred patch normally when nothing evicts it', () => {
    const c = new PatchCollector(100);
    const mapping = new SessionMapping();
    const fingerprints = new FingerprintSession();
    c.addDeferred(10, 3, () => new Uint8Array([7, 8, 9]));
    c.resolveDeferred({ mapping, fingerprints });
    const patches = c.getPatches();
    expect(patches).toHaveLength(1);
    expect(patches[0]).toEqual({ offset: 10, data: new Uint8Array([7, 8, 9]) });
  });

  it('mirrors protocol-neutral mask ops from maskRangeDeferred meta', () => {
    const c = new PatchCollector(96)
    c.maskRangeDeferred(
      24,
      12,
      () => new Uint8Array(12).fill(0x2a),
      {
        fallbackKind: 'binary-mask',
        protocol: 'dns',
        packetIndex: 1,
        maskDomain: 'dns-txt-value',
        maskFillKind: 'protocol-neutral',
        reasonCode: 'dns-txt-value',
      },
    )
    const maskOps = c.getSymbolicMaskOps()
    expect(maskOps).toHaveLength(1)
    expect(maskOps[0]).toMatchObject({
      kind: 'mask',
      packetIndex: 1,
      offset: 24,
      length: 12,
      fillKind: 'protocol-neutral',
      domain: 'dns-txt-value',
    })
    expect(c.isDeferredFullySymbolized()).toBe(true)
  })

  it('mirrors structured map ops when deferred meta carries journal wire fields', () => {
    const c = new PatchCollector(128)
    c.addDeferred(
      40,
      4,
      () => new Uint8Array([1, 2, 3, 4]),
      {
        fallbackKind: 'binary-mask',
        protocol: 'dns',
        category: 'ipv4',
        packetIndex: 3,
        canonical: '192.168.1.50',
        constraint: { kind: 'ipv4-wire' },
        encoder: 'ipv4-octets',
      },
    )
    const ops = c.getSymbolicMapOps()
    expect(ops).toHaveLength(1)
    expect(ops[0]).toMatchObject({
      kind: 'map',
      packetIndex: 3,
      offset: 40,
      length: 4,
      category: 'ipv4',
      encoder: 'ipv4-octets',
    })
    c.maskRange(40, new Uint8Array(8).fill(0x2a))
    expect(c.getSymbolicMapOps()).toHaveLength(0)
  })

  it('mirrors fixed-ascii text map ops via deferredTextMapMeta', () => {
    const c = new PatchCollector(64)
    c.addDeferred(
      8,
      11,
      () => new Uint8Array(11).fill(0x78),
      {
        fallbackKind: 'text-x',
        protocol: 'ldap',
        category: 'hostname',
        packetIndex: 2,
        canonical: 'host.example.com',
        constraint: { kind: 'text-ascii', byteLength: 11 },
        encoder: 'fixed-ascii',
        originalSpelling: 'host.example.com',
      },
    )
    const ops = c.getSymbolicMapOps()
    expect(ops).toHaveLength(1)
    expect(ops[0]).toMatchObject({
      kind: 'map',
      packetIndex: 2,
      encoder: 'fixed-ascii',
      category: 'hostname',
    })
  })

  it('STUN XOR-MAPPED IPv4 deferred map mirrors journal wire fields', () => {
    const stun = buildStunXorMappedIpv4([203, 0, 113, 50], 54320)
    const c = new PatchCollector(stun.length)
    const mapping = new SessionMapping()
    sanitizeStun(stun, 0, stun.length, c, mapping, undefined, 4, [])
    const ops = c.getSymbolicMapOps()
    const ipv4Op = ops.find((o) => o.kind === 'map' && o.category === 'ipv4')
    expect(ipv4Op).toMatchObject({
      kind: 'map',
      packetIndex: 4,
      category: 'ipv4',
      encoder: 'ipv4-octets',
      constraint: { kind: 'ipv4-wire' },
    })
    expect(ops.some((o) => o.kind === 'map' && o.category === 'port')).toBe(true)
  })

  it('a later deferred patch at an evicted offset resolves with its own compute, not a stale one', () => {
    const c = new PatchCollector(600);
    const mapping = new SessionMapping();
    const fingerprints = new FingerprintSession();

    c.addDeferred(42, 4, () => new Uint8Array([1, 2, 3, 4]));
    c.maskRange(42, new Uint8Array(556).fill(0x2a)); // evicts the 4-byte deferred patch
    // A brand new deferred patch later reuses offset 42 with a different length — must not
    // pick up the long-evicted 4-byte compute above.
    c.maskRangeDeferred(42, 8, () => new Uint8Array([5, 6, 7, 8, 9, 10, 11, 12]));

    c.resolveDeferred({ mapping, fingerprints });
    const patches = c.getPatches();
    expect(patches).toHaveLength(1);
    expect(patches[0]!.offset).toBe(42);
    expect(patches[0]!.data).toEqual(new Uint8Array([5, 6, 7, 8, 9, 10, 11, 12]));
  });
});

describe('sanitizePacket — high-privacy level', () => {
  it('patches IP addresses in a simple ethernet/ipv4/udp packet', () => {
    const payload = new Uint8Array(10); // unknown payload
    const pkt = buildEthIpUdp([192, 168, 1, 100], [10, 0, 0, 1], 12345, 80, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    expect(result.drop).toBe(false);
    expect(result.patches.length).toBeGreaterThan(0);
    // IP addresses should be patched (src at 26, dst at 30)
    const ipPatches = result.patches.filter(p => p.offset === 26 || p.offset === 30);
    expect(ipPatches.length).toBe(2);
  });

  it('permutes ephemeral TCP/UDP ports on the wire when mapping policy is permute', () => {
    const payload = new Uint8Array(10);
    const pkt = buildEthIpUdp([192, 168, 1, 100], [10, 0, 0, 1], 12345, 80, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    const udpStart = 34;
    const srcPort = (result.patches.find((p) => p.offset === udpStart)?.data[0]! << 8)
      | (result.patches.find((p) => p.offset === udpStart)?.data[1] ?? pkt[udpStart + 1]!);
    const dstPort = (result.patches.find((p) => p.offset === udpStart + 2)?.data[0]! << 8)
      | (result.patches.find((p) => p.offset === udpStart + 2)?.data[1] ?? pkt[udpStart + 3]!);

    expect(srcPort).not.toBe(12345);
    expect(srcPort).toBeGreaterThanOrEqual(1024);
    expect(dstPort).toBe(80);
  });

  it('truncates unsupported payload', () => {
    const payload = new Uint8Array(50);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 12345, 9999, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    expect(result.truncatedLength).toBeDefined();
    expect(result.truncatedLength!).toBeLessThan(pkt.length);
  });

  it('marks fragments as requires-reassembly', () => {
    const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 53, 53, new Uint8Array(20));
    // Set fragment offset to non-zero
    pkt[20] = 0x00; // flags=0, offset high bits
    pkt[21] = 0x08; // fragment offset = 8
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    const fragCoverage = result.coverage.find(c => c.status === 'requires-reassembly');
    expect(fragCoverage).toBeDefined();
  });

  it('drops SPB packets when policy.dropMalformed is true', () => {
    const pkt = new Uint8Array(100);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: 100, originalLength: 100, linkType: 1, isSimple: true };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    expect(result.drop).toBe(true);
  });
});

describe('sanitizePacket — diagnostic preset', () => {
  it('processes DNS payload', () => {
    // Build a minimal DNS query for "test.example.com" → A record
    const dnsPayload = buildDnsQuery('test.example.com');
    const pkt = buildEthIpUdp([192, 168, 1, 1], [8, 8, 8, 8], 12345, 53, dnsPayload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    expect(result.drop).toBe(false);
    const dnsCoverage = result.coverage.find(c => c.protocol === 'dns');
    expect(dnsCoverage).toBeDefined();
    expect(dnsCoverage!.status).toBe('covered');
  });
});

describe('sanitizePacket — diagnostic level (no truncate)', () => {
  it('does not truncate unsupported payload', () => {
    const payload = new Uint8Array(50);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 12345, 9999, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    expect(result.truncatedLength).toBeUndefined();
  });

  it('does not drop SPB packets', () => {
    const pkt = new Uint8Array(100);
    pkt[0] = 0x45; // IPv4
    const input: PacketInput = { index: 0, data: pkt, capturedLength: 100, originalLength: 100, linkType: 101, isSimple: true };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    expect(result.drop).toBe(false);
  });
});

describe('must-not-leak canaries', () => {
  it('original IP does not appear in patched output', () => {
    const srcIp = [192, 168, 42, 99];
    const dstIp = [10, 20, 30, 40];
    const pkt = buildEthIpUdp(srcIp, dstIp, 12345, 80, new Uint8Array(0));
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    // Apply patches to buffer
    const output = new Uint8Array(pkt);
    for (const patch of result.patches) {
      output.set(patch.data, patch.offset);
    }

    // Check src IP canary — full 4-byte sequence must differ
    const origSrc = [192, 168, 42, 99];
    const patchedSrc = [output[26], output[27], output[28], output[29]];
    expect(patchedSrc).not.toEqual(origSrc);
    // Check dst IP canary
    const origDst = [10, 20, 30, 40];
    const patchedDst = [output[30], output[31], output[32], output[33]];
    expect(patchedDst).not.toEqual(origDst);
  });

  it('original MAC does not appear in patched output', () => {
    const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 1234, 80, new Uint8Array(0));
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) {
      output.set(patch.data, patch.offset);
    }

    // src MAC was aa:bb:cc:dd:ee:ff — should be mapped
    expect(output[6]).not.toBe(0xaa);
  });

  it('DNS hostname canary does not appear in diagnostic output', () => {
    const hostname = 'secret.internal.corp';
    const dnsPayload = buildDnsQuery(hostname);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [8, 8, 8, 8], 12345, 53, dnsPayload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) {
      output.set(patch.data, patch.offset);
    }

    // Search for the original hostname in the output
    const outputStr = new TextDecoder('ascii', { fatal: false }).decode(output);
    expect(outputStr).not.toContain('secret');
    expect(outputStr).not.toContain('internal');
  });

  it('TLS SNI canary does not appear in diagnostic output', () => {
    const hello = buildTlsClientHello('secret-vpn-gateway.internal');
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 443, hello);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) output.set(patch.data, patch.offset);
    const outputStr = new TextDecoder('ascii', { fatal: false }).decode(output);
    expect(outputStr).not.toContain('secret-vpn-gateway');
  });

  it('HTTP Host/Cookie canary does not appear in diagnostic output', () => {
    const payload = buildHttpRequest('secret-internal.example', 'sessionid=letmein123');
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) output.set(patch.data, patch.offset);
    const outputStr = new TextDecoder('ascii', { fatal: false }).decode(output);
    expect(outputStr).not.toContain('secret-internal');
    expect(outputStr).not.toContain('letmein123');
  });
});

describe('TLS ClientHello/SNI', () => {
  it('patches SNI hostname in ClientHello', () => {
    const hello = buildTlsClientHello('secret.internal.example');
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 443, hello);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const tlsCoverage = result.coverage.find(c => c.protocol === 'tls-clienthello');
    expect(tlsCoverage).toBeDefined();
    expect(tlsCoverage!.status).toBe('covered');
  });

  it('reports requires-reassembly for a ClientHello record split across the segment boundary', () => {
    const hello = buildTlsClientHello('example.com');
    const truncated = hello.slice(0, hello.length - 5); // record header still claims the full length
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 443, truncated);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const tlsCoverage = result.coverage.find(c => c.protocol === 'tls');
    expect(tlsCoverage).toBeDefined();
    expect(tlsCoverage!.status).toBe('requires-reassembly');
    // Diagnostic masks the incomplete TLS span in-place (step 4) — never truncates,
    // and never applies a partial ClientHello/SNI rewrite.
    const tcpPayloadOffset = 14 + 20 + 20;
    expect(result.truncatedLength).toBeUndefined();
    expect(result.patches.some(p => p.offset >= tcpPayloadOffset)).toBe(true);
    expect(result.issues.some((i) => i.startsWith('masked-in-place:'))).toBe(true);
  });

  it('marks ServerHello as tls-serverhello/covered after session_id redaction', () => {
    // ServerHello (handshake type 0x02) — plaintext metadata, not ciphertext
    // version(2)+random(32)+session_id_len(1)=0 + cipher(2)+comp(1) = 38 body bytes
    const body = new Uint8Array(38)
    body[0] = 0x03
    body[1] = 0x03
    const handshake = new Uint8Array(4 + body.length)
    handshake[0] = 0x02
    handshake[1] = 0
    handshake[2] = 0
    handshake[3] = body.length
    handshake.set(body, 4)
    const record = new Uint8Array(5 + handshake.length)
    record[0] = 0x16
    record[1] = 0x03
    record[2] = 0x03
    record[3] = (handshake.length >> 8) & 0xff
    record[4] = handshake.length & 0xff
    record.set(handshake, 5)
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 443, 54321, record);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const tlsCoverage = result.coverage.find(c => c.protocol === 'tls-serverhello');
    expect(tlsCoverage).toBeDefined();
    expect(tlsCoverage!.status).toBe('covered');
    expect(result.coverage.some(c => c.status === 'encrypted')).toBe(false);
  });
});

describe('HTTP headers', () => {
  it('maps Host and redacts Cookie', () => {
    const payload = buildHttpRequest('secret-internal.example', 'sessionid=abc123');
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const headerCoverage = result.coverage.find(c => c.protocol === 'http-headers');
    expect(headerCoverage).toBeDefined();
    expect(headerCoverage!.status).toBe('covered');
  });

  it('marks the body beyond headers as redacted (fail-closed MASK), not silently covered or passthrough', () => {
    const text = `POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world`;
    const payload = new Uint8Array(Array.from(text, c => c.charCodeAt(0)));
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const bodyCoverage = result.coverage.find(c => c.protocol === 'http-body');
    expect(bodyCoverage).toBeDefined();
    expect(bodyCoverage!.status).toBe('redacted');
    const out = new Uint8Array(pkt);
    for (const patch of result.patches) out.set(patch.data, patch.offset);
    expect(new TextDecoder('ascii', { fatal: false }).decode(out)).not.toContain('hello world');
  });

  it('does not match non-HTTP payload', () => {
    const payload = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const pkt = buildEthIpTcp([192, 168, 1, 1], [93, 184, 216, 34], 54321, 80, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    expect(result.coverage.some(c => c.protocol === 'http-headers')).toBe(false);
  });
});

describe('generic heuristic scanner', () => {
  it('maps embedded hostname/IPv4 and redacts credential-like fields on an unrecognized protocol', () => {
    const text = 'PROPRIETARY-DB-HELLO host=db-internal.example ip=10.20.30.40 password=hunter2\n';
    const payload = new Uint8Array(Array.from(text, c => c.charCodeAt(0)));
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 5], 54321, 33060, payload); // arbitrary DB-ish port
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    // T74 proprietary-light may claim the payload; identities must still be gone.
    const lightOrHeuristic = result.coverage.find(
      (c) => c.protocol === 'heuristic' || c.protocol.includes('proprietary') || c.protocol === 'unknown',
    ) ?? result.coverage.find((c) => c.status === 'covered' || c.status === 'heuristic' || c.status === 'preserved-for-diagnostics')
    expect(lightOrHeuristic).toBeDefined()

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) output.set(patch.data, patch.offset);
    const outputStr = new TextDecoder('ascii', { fatal: false }).decode(output);
    expect(outputStr).not.toContain('db-internal.example');
    expect(outputStr).not.toContain('10.20.30.40');
    expect(outputStr).not.toContain('hunter2');
  });

  it('is disabled under the high-privacy level', () => {
    const text = 'PROPRIETARY-DB-HELLO password=hunter2\n';
    const payload = new Uint8Array(Array.from(text, c => c.charCodeAt(0)));
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 5], 54321, 33060, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    expect(result.coverage.some(c => c.protocol === 'heuristic')).toBe(false);
  });

  it('PF-01: does not scan opaque binary payloads for FQDN-shaped noise', () => {
    // Deterministic pseudo-random bytes across the full 0-255 range — the kind of payload
    // an unrecognized proprietary binary protocol produces. Before PF-01 this was decoded as
    // ASCII/windows-1252 and searched anyway, letting arbitrary byte values coincidentally
    // form alnum-dot-alnum runs that matched FQDN_CANDIDATE.
    const payload = new Uint8Array(2000);
    let x = 12345;
    for (let i = 0; i < payload.length; i++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      payload[i] = x % 256;
    }
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 5], 54321, 33061, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    expect(result.coverage.some(c => c.protocol === 'heuristic')).toBe(false);
  });

  it('PF-06: deferPatchResolution produces identical patches to immediate resolution', () => {
    const text = 'PROPRIETARY-DB-HELLO host=db-internal.example ip=10.20.30.40 password=hunter2\n';
    const payload = new Uint8Array(Array.from(text, c => c.charCodeAt(0)));
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 5], 54321, 33060, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();

    // Same explicit seed for both paths — fingerprint fields (TCP seq/IPv4-id/etc.) are
    // randomized per FingerprintSession instance, so a fair byte-for-byte comparison needs
    // the same seed, matching how the real pipeline uses one shared, seeded session.
    const immediate = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping, { fingerprints: new FingerprintSession('pf06-test-seed') });

    const deferred = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping, { deferPatchResolution: true });
    expect(deferred.resolvePatches).toBeDefined();
    const resolved = deferred.resolvePatches!({ mapping, fingerprints: new FingerprintSession('pf06-test-seed') });

    const sortByOffset = (a: { offset: number }, b: { offset: number }) => a.offset - b.offset;
    const immediateSorted = [...immediate.patches].sort(sortByOffset);
    const resolvedSorted = [...resolved].sort(sortByOffset);
    expect(resolvedSorted.length).toBe(immediateSorted.length);
    for (let i = 0; i < immediateSorted.length; i++) {
      expect(resolvedSorted[i]!.offset).toBe(immediateSorted[i]!.offset);
      expect([...resolvedSorted[i]!.data]).toEqual([...immediateSorted[i]!.data]);
    }
    expect(immediate.coverage).toEqual(deferred.coverage);
    expect(immediate.drop).toBe(deferred.drop);
  });

  it('PF-01: does not record hostname intents for dotted source-code identifiers or version strings', () => {
    // Real proprietary application/debug log content (verbatim shape from a production
    // capture that triggered PF-01): Java-style package.ClassName references and a dotted
    // version string both structurally match FQDN_CANDIDATE but are not hostnames. Once the
    // heuristic finds *any* real match, the payload's remaining span is masked anyway by the
    // unsupported-payload policy (a separate, pre-existing mechanism) — so the bug is not
    // visible in the output bytes. It is visible in entity/intent creation (PF-02/PF-03's
    // input), which is what this asserts directly via the IntentCollector.
    const text =
      'cz.example.radio.rgw.gateways.tetra.TetraComp - ProtocolVersion: RadioProtocol-1.8.0 ' +
      'Content-Type: application/vnd.example.radioprotocol host=db-internal.example\n';
    const payload = new Uint8Array(Array.from(text, c => c.charCodeAt(0)));
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 5], 54321, 33062, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const intents = new IntentCollector();
    sanitizePacket(input, DIAGNOSTIC_POLICY, mapping, { intents });

    const hostnameIntents = intents.intents.filter((i) => i.kind === 'entity-replacement' && i.category === 'hostname');
    const canonicals = hostnameIntents.map((i) => (i as { canonical: string }).canonical);
    expect(canonicals.some((c) => c.includes('tetracomp') || c.includes('radioprotocol-1'))).toBe(false);
    // Genuine hostname must not survive export (intent and/or T74 free-text path).
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping, { intents: new IntentCollector() });
    const out = new Uint8Array(pkt);
    for (const p of result.patches) out.set(p.data, p.offset);
    expect(new TextDecoder('ascii', { fatal: false }).decode(out)).not.toContain('db-internal.example');
  });
});

describe('patchFixedLengthAscii length preservation', () => {
  it('throws when replacement length differs from the original span', () => {
    const collector = new PatchCollector(20);
    expect(() => patchFixedLengthAscii(collector, 2, 8, 'short')).toThrow(/length/i);
  });

  it('accepts exact-length replacements from aliasFor', () => {
    const mapping = new SessionMapping();
    const original = 'nb.local';
    const mapped = mapping.aliasFor(
      'hostname',
      original,
      { kind: 'text-ascii', byteLength: original.length },
      original,
    );
    expect(mapped.length).toBe(original.length);

    const collector = new PatchCollector(original.length + 4);
    patchFixedLengthAscii(collector, 2, original.length, mapped);
    const patches = collector.getPatches();
    expect(patches.length).toBe(1);
    expect(patches[0]!.data.length).toBe(original.length);
  });
});

describe('DMR (Homebrew/MMDVM)', () => {
  function buildDmrdPacket(srcId: number, dstId: number, voicePayload: Uint8Array): Uint8Array {
    const buf = new Uint8Array(20 + voicePayload.length);
    buf.set([0x44, 0x4d, 0x52, 0x44], 0); // "DMRD"
    buf[4] = 0x00; // seq
    buf[5] = (srcId >> 16) & 0xff; buf[6] = (srcId >> 8) & 0xff; buf[7] = srcId & 0xff;
    buf[8] = (dstId >> 16) & 0xff; buf[9] = (dstId >> 8) & 0xff; buf[10] = dstId & 0xff;
    // repeaterId (11-14), flags (15), streamId (16-19) left zero
    buf.set(voicePayload, 20);
    return buf;
  }

  it('maps srcId/dstId and strips/masks AMBE voice (T68)', () => {
    const voice = new Uint8Array(33).fill(0xab); // fake AMBE payload
    const dmrd = buildDmrdPacket(3100123, 91, voice);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [192, 168, 1, 2], 62031, 62031, dmrd);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const dmrCoverage = result.coverage.find(c => c.protocol === 'dmr');
    expect(dmrCoverage).toBeDefined();
    expect(['covered', 'redacted']).toContain(dmrCoverage!.status);

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) output.set(patch.data, patch.offset);

    const udpPayloadOffset = 14 + 20 + 8;
    const srcId = (output[udpPayloadOffset + 5]! << 16) | (output[udpPayloadOffset + 6]! << 8) | output[udpPayloadOffset + 7]!;
    const dstId = (output[udpPayloadOffset + 8]! << 16) | (output[udpPayloadOffset + 9]! << 8) | output[udpPayloadOffset + 10]!;
    expect(srcId).not.toBe(3100123);
    expect(dstId).not.toBe(91);

    const voiceOut = output.slice(udpPayloadOffset + 20, udpPayloadOffset + 20 + voice.length);
    expect(Array.from(voiceOut)).not.toEqual(Array.from(voice));
  });

  it('preserves reserved radio IDs (0 and all-call 0xFFFFFF)', () => {
    const voice = new Uint8Array(10).fill(0xcd);
    const dmrd = buildDmrdPacket(0, 0xffffff, voice);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [192, 168, 1, 2], 62031, 62031, dmrd);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) output.set(patch.data, patch.offset);
    const udpPayloadOffset = 14 + 20 + 8;
    const srcId = (output[udpPayloadOffset + 5]! << 16) | (output[udpPayloadOffset + 6]! << 8) | output[udpPayloadOffset + 7]!;
    const dstId = (output[udpPayloadOffset + 8]! << 16) | (output[udpPayloadOffset + 9]! << 8) | output[udpPayloadOffset + 10]!;
    expect(srcId).toBe(0);
    expect(dstId).toBe(0xffffff);
  });
});

describe('MOTOTRBO IPSC (best-effort)', () => {
  it('redacts the whole payload and reports redacted on a recognized port, without truncating it away', () => {
    const payload = new Uint8Array(16).fill(0x7a);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [192, 168, 1, 2], 50000, 50000, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    const cov = result.coverage.find(c => c.protocol === 'mototrbo-ipsc');
    expect(cov).toBeDefined();
    expect(cov!.status).toBe('redacted');
    expect(result.truncatedLength).toBeUndefined();

    const output = new Uint8Array(pkt);
    for (const patch of result.patches) output.set(patch.data, patch.offset);
    const udpPayloadOffset = 14 + 20 + 8;
    const payloadOut = output.slice(udpPayloadOffset, udpPayloadOffset + payload.length);
    expect(Array.from(payloadOut).every(b => b === 0)).toBe(true);
  });

  it('does not match on an unrelated port', () => {
    const payload = new Uint8Array(16).fill(0x7a);
    const pkt = buildEthIpUdp([192, 168, 1, 1], [192, 168, 1, 2], 12345, 9999, payload);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, DIAGNOSTIC_POLICY, mapping);

    expect(result.coverage.some(c => c.protocol === 'mototrbo-ipsc')).toBe(false);
  });
});

describe('SIP/SDP hardening (Krok 3)', () => {
  function buildSipText(lines: string[]): Uint8Array {
    const blankIdx = lines.indexOf('');
    if (blankIdx >= 0) {
      const headers = lines.slice(0, blankIdx);
      const body = lines.slice(blankIdx + 1).join('\r\n');
      const headerLines = [...headers];
      if (!headerLines.some((h) => /^Content-Type:/i.test(h))) {
        headerLines.push('Content-Type: application/sdp');
      }
      if (!headerLines.some((h) => /^Content-Length:/i.test(h))) {
        headerLines.push(`Content-Length: ${body.length}`);
      }
      const text = `${headerLines.join('\r\n')}\r\n\r\n${body}`;
      return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0)));
    }
    const headers = [...lines, 'Content-Length: 0'];
    const text = `${headers.join('\r\n')}\r\n\r\n`;
    return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0)));
  }

  function applyPatches(buf: Uint8Array, collector: PatchCollector): string {
    const output = new Uint8Array(buf);
    for (const patch of collector.getPatches()) output.set(patch.data, patch.offset);
    return new TextDecoder('ascii', { fatal: false }).decode(output);
  }

  it('maps the User-Agent header value', () => {
    const buf = buildSipText([
      'REGISTER sip:example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK776asdhds',
      'User-Agent: SecretPhoneModel-X1 v2.3.4',
      'Call-ID: abc123@192.168.1.10',
    ]);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeSip(buf, 0, buf.length, collector, mapping)).toBe(true);
    expect(applyPatches(buf, collector)).not.toContain('SecretPhoneModel-X1');
  });

  it('maps the Server header value', () => {
    const buf = buildSipText([
      'SIP/2.0 200 OK',
      'Server: SecretPBX/9.9',
      'Call-ID: abc123@192.168.1.10',
    ]);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    sanitizeSip(buf, 0, buf.length, collector, mapping);
    expect(applyPatches(buf, collector)).not.toContain('SecretPBX');
  });

  it('maps the host in a Contact URI with no user part', () => {
    const buf = buildSipText([
      'SIP/2.0 200 OK',
      'Contact: <sip:192.0.2.10:5060>',
      'Call-ID: abc123@192.168.1.10',
    ]);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    sanitizeSip(buf, 0, buf.length, collector, mapping);
    expect(applyPatches(buf, collector)).not.toContain('192.0.2.10');
  });

  it('maps the SDP media port on the m= line', () => {
    const buf = buildSipText([
      'INVITE sip:bob@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.168.1.10:5060',
      'Call-ID: abc123@192.168.1.10',
      '',
      'v=0',
      'o=- 123 456 IN IP4 192.168.1.10',
      'c=IN IP4 192.168.1.10',
      'm=audio 54400 RTP/AVP 0',
    ]);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    sanitizeSip(buf, 0, buf.length, collector, mapping);
    expect(applyPatches(buf, collector)).not.toContain('54400');
  });

  it('maps the address and port on an SDP a=candidate (ICE) line', () => {
    const buf = buildSipText([
      'INVITE sip:bob@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 192.168.1.10:5060',
      'Call-ID: abc123@192.168.1.10',
      '',
      'v=0',
      'o=- 123 456 IN IP4 192.168.1.10',
      'c=IN IP4 192.168.1.10',
      'm=audio 54400 RTP/AVP 0',
      'a=candidate:1 1 UDP 2130706431 192.168.1.55 54401 typ host',
    ]);
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    sanitizeSip(buf, 0, buf.length, collector, mapping);
    const outputStr = applyPatches(buf, collector);
    expect(outputStr).not.toContain('192.168.1.55');
    expect(outputStr).not.toContain('54401');
  });
});

describe('ICMP embedded headers', () => {
  it('patches IPs in ICMP embedded IPv4 header', () => {
    // Simulate an embedded IPv4 header
    const embedded = new Uint8Array(28); // 20 IP + 8 payload
    embedded[0] = 0x45; // version=4, IHL=5
    embedded.set([172, 16, 0, 99], 12); // src
    embedded.set([10, 0, 0, 50], 16); // dst

    const collector = new PatchCollector(embedded.length);
    const mapping = new SessionMapping();
    const coverage = sanitizeIcmpEmbedded(embedded, 0, embedded.length, collector, mapping);

    expect(coverage.length).toBeGreaterThan(0);
    expect(coverage[0]!.status).toBe('covered');
    expect(collector.count).toBe(2); // src + dst IP (proto 0 → no port mapping)
    expect(coverage.some((c) => c.protocol === 'icmp-embedded-payload' && c.status === 'unsupported')).toBe(true);
  });
});

describe('coverage rules', () => {
  it('unsupported link type gets unsupported coverage', () => {
    const pkt = new Uint8Array(50);
    const input: PacketInput = { index: 0, data: pkt, capturedLength: 50, originalLength: 50, linkType: 999 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    expect(result.coverage.some(c => c.status === 'unsupported')).toBe(true);
  });

  it('unknown IP protocol gets unsupported coverage', () => {
    const pkt = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 0, 0, new Uint8Array(0));
    // Change IP protocol to unknown (200)
    pkt[23] = 200;
    const input: PacketInput = { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);

    expect(result.coverage.some(c => c.status === 'unsupported')).toBe(true);
  });
});

describe('policyFromPreset', () => {
  it('returns correct policies for the two built-in levels', () => {
    expect(policyFromPreset('diagnostic')).toEqual(DIAGNOSTIC_POLICY);
    expect(policyFromPreset('high-privacy')).toEqual(HIGH_PRIVACY_POLICY);
    expect(policyFromPreset('high-privacy').mediaPolicy).toBe('drop');
  });
});

// Helper to build a minimal DNS query
function buildDnsQuery(hostname: string): Uint8Array {
  const labels = hostname.split('.');
  let qnameLen = 0;
  for (const l of labels) qnameLen += 1 + l.length;
  qnameLen += 1; // null terminator

  const dns = new Uint8Array(12 + qnameLen + 4);
  // Header: ID=0x1234, QR=0, QDCOUNT=1
  dns[0] = 0x12; dns[1] = 0x34;
  dns[5] = 1; // QDCOUNT = 1

  let pos = 12;
  for (const label of labels) {
    dns[pos++] = label.length;
    for (let i = 0; i < label.length; i++) {
      dns[pos++] = label.charCodeAt(i);
    }
  }
  dns[pos++] = 0; // null terminator
  // QTYPE=A(1), QCLASS=IN(1)
  dns[pos + 1] = 1;
  dns[pos + 3] = 1;

  return dns;
}

/** Build a minimal TLS record containing a ClientHello with a single SNI (server_name) extension. */
function buildTlsClientHello(sni: string): Uint8Array {
  const sniBytes = Array.from(sni, (c) => c.charCodeAt(0));
  const serverNameEntry = [0x00, (sniBytes.length >> 8) & 0xff, sniBytes.length & 0xff, ...sniBytes];
  const serverNameList = [(serverNameEntry.length >> 8) & 0xff, serverNameEntry.length & 0xff, ...serverNameEntry];
  const serverNameExtension = [0x00, 0x00, (serverNameList.length >> 8) & 0xff, serverNameList.length & 0xff, ...serverNameList];
  const extensions = serverNameExtension;
  const random = new Array(32).fill(0);
  const cipherSuites = [0xc0, 0x2f];
  const compressionMethods = [0x00];

  const handshakeBody = [
    0x03, 0x03, // client_version
    ...random,
    0x00, // session_id_len = 0
    (cipherSuites.length >> 8) & 0xff, cipherSuites.length & 0xff, ...cipherSuites,
    compressionMethods.length, ...compressionMethods,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  ];
  const handshakeMessage = [
    0x01, // ClientHello
    (handshakeBody.length >> 16) & 0xff, (handshakeBody.length >> 8) & 0xff, handshakeBody.length & 0xff,
    ...handshakeBody,
  ];
  const record = [
    0x16, 0x03, 0x03, // content type = Handshake, version 3.3
    (handshakeMessage.length >> 8) & 0xff, handshakeMessage.length & 0xff,
    ...handshakeMessage,
  ];
  return new Uint8Array(record);
}

/** Build a minimal HTTP/1.1 request with a Host and Cookie header, no body. */
function buildHttpRequest(host: string, cookie: string): Uint8Array {
  const text = `GET /path HTTP/1.1\r\nHost: ${host}\r\nCookie: ${cookie}\r\nUser-Agent: test\r\n\r\n`;
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0)));
}
