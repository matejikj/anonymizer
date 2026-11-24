/**
 * CF-11 / CF-12 / CF-14 — fingerprint coverage, timestamps, port classes.
 */

import { describe, expect, it } from 'vitest';
import {
  SessionMapping,
  DEFAULT_MAPPING_CONFIG,
} from '../../../src/pcap/anonymization/mapping';
import {
  TimestampMapping,
  timestampModeFromConfig,
} from '../../../src/pcap/anonymization/timestampMapping';
import {
  classifyPort,
  isPreservedServicePort,
  DYNAMIC_PORT_MIN,
} from '../../../src/pcap/anonymization/portPolicy';
import {
  sanitizePacket,
  HIGH_PRIVACY_POLICY,
  DIAGNOSTIC_POLICY,
  type PacketInput,
} from '../../../src/pcap/sanitize';
import type { PacketTimestamp } from '../../../src/pcap/domain/types';

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  ttl = 128,
  window = 0xabcd,
): Uint8Array {
  const buf = new Uint8Array(14 + 20 + 20);
  buf[12] = 0x08;
  buf[13] = 0x00;
  buf[14] = 0x45;
  buf[16] = 0;
  buf[17] = 40;
  buf[22] = ttl;
  buf[23] = 6;
  buf.set(srcIp, 26);
  buf.set(dstIp, 30);
  const tcp = 34;
  buf[tcp] = (srcPort >> 8) & 0xff;
  buf[tcp + 1] = srcPort & 0xff;
  buf[tcp + 2] = (dstPort >> 8) & 0xff;
  buf[tcp + 3] = dstPort & 0xff;
  buf[tcp + 12] = 0x50;
  buf[tcp + 14] = (window >> 8) & 0xff;
  buf[tcp + 15] = window & 0xff;
  return buf;
}

describe('CF-14 port classes', () => {
  it('preserves SIP/DNS/mDNS service ports under permute', () => {
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    expect(mapping.map('port', 'udp/5060')).toBe('udp/5060');
    expect(mapping.map('port', 'tcp/5061')).toBe('tcp/5061');
    expect(mapping.map('port', 'udp/53')).toBe('udp/53');
    expect(mapping.map('port', 'udp/5353')).toBe('udp/5353');
    expect(isPreservedServicePort(5060)).toBe(true);
    expect(classifyPort(5060)).toBe('registered-service');
  });

  it('permutes dynamic client ports into dynamic range only', () => {
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    const mapped = mapping.map('port', 'udp/54400');
    const port = Number.parseInt(mapped.slice(mapped.indexOf('/') + 1), 10);
    expect(port).toBeGreaterThanOrEqual(DYNAMIC_PORT_MIN);
    expect(port).toBeLessThanOrEqual(65535);
    expect(isPreservedServicePort(port)).toBe(false);
  });

  it('does not allocate permute aliases onto preserved service ports', () => {
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' });
    const seen = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const mapped = mapping.map('port', `udp/${52000 + (i % 1000)}`);
      const port = Number.parseInt(mapped.slice(mapped.indexOf('/') + 1), 10);
      expect(isPreservedServicePort(port)).toBe(false);
      seen.add(port);
    }
    expect(seen.size).toBeGreaterThan(50);
  });
});

describe('CF-12 timestamp modes', () => {
  it('uses distinct anchors for distinct plan seeds', () => {
    const ts: PacketTimestamp = {
      ticks: 1_700_050_000_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    };
    const a = new TimestampMapping({
      mode: 'relative-exact',
      anchorSeconds: 1_600_000_000n + 1n,
    }).mapTicks(ts).ticks;
    const b = new TimestampMapping({
      mode: 'relative-exact',
      anchorSeconds: 1_600_000_000n + 2n,
    }).mapTicks(ts).ticks;
    expect(a === b).toBe(false);
  });

  it('is deterministic with an explicit anchor', () => {
    const ts: PacketTimestamp = {
      ticks: 1_700_050_000_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    };
    const opts = { mode: 'relative-exact' as const, anchorSeconds: 1_650_000_000n };
    const a = new TimestampMapping(opts).mapTicks(ts).ticks;
    const b = new TimestampMapping(opts).mapTicks(ts).ticks;
    expect(a).toBe(b);
    expect(a).toBe(1_650_000_000_000_000n);
  });

  it('bucket mode never reverses order and coarsens deltas', () => {
    const tm = new TimestampMapping({
      mode: 'relative-bucketed',
      anchorSeconds: 1_700_000_000n,
      bucketTicks: 10_000n,
    });
    const t0: PacketTimestamp = { ticks: 100n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };
    const t1: PacketTimestamp = { ticks: 100n + 3_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };
    const t2: PacketTimestamp = { ticks: 100n + 25_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };
    const m0 = tm.mapTicks(t0).ticks;
    const m1 = tm.mapTicks(t1).ticks;
    const m2 = tm.mapTicks(t2).ticks;
    expect(m1).toBeGreaterThanOrEqual(m0);
    expect(m2).toBeGreaterThanOrEqual(m1);
    // 3ms delta falls into same 10ms bucket → equal mapped times
    expect(m1).toBe(m0);
    expect(m2 - m0).toBe(20_000n);
  });

  it('maps profile config relative → relative-exact', () => {
    expect(timestampModeFromConfig('relative')).toBe('relative-exact');
    expect(timestampModeFromConfig('relative-bucketed')).toBe('relative-bucketed');
  });
});

describe('CF-11 network fingerprint', () => {
  it('high-privacy normalizes TTL and TCP window', () => {
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 2], 5060, 5060, 128, 0xabcd);
    const input: PacketInput = {
      index: 0,
      data: pkt,
      capturedLength: pkt.length,
      originalLength: pkt.length,
      linkType: 1,
    };
    const mapping = new SessionMapping();
    const result = sanitizePacket(input, HIGH_PRIVACY_POLICY, mapping);
    expect(HIGH_PRIVACY_POLICY.networkFingerprint.ttl).toBe('normalize');
    const out = pkt.slice();
    for (const p of result.patches) out.set(p.data, p.offset);
    expect(out[22]).toBe(64);
    expect((out[48]! << 8) | out[49]!).toBe(0x2000);
    expect(result.coverage.some((c) => c.protocol === 'ipv4-ttl' && c.status === 'covered')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'tcp-window' && c.status === 'covered')).toBe(true);
  });

  it('diagnostic preserves fingerprint fields as preserved-for-diagnostics', () => {
    const pkt = buildEthIpTcp([192, 168, 1, 1], [10, 0, 0, 2], 5060, 5060, 128, 0xabcd);
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    );
    expect(result.coverage.some((c) => c.protocol === 'ipv4-ttl' && c.status === 'preserved-for-diagnostics')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'tcp-window' && c.status === 'preserved-for-diagnostics')).toBe(true);
    expect(result.coverage.some((c) => c.protocol === 'tcp-seq' && c.status === 'covered')).toBe(true);
    expect(result.issues.some((i) => i.includes('fingerprint:ipv4-ttl'))).toBe(true);
    // Must not truncate the whole packet solely due to fingerprint residual
    expect(result.truncatedLength).toBeUndefined();
    const out = pkt.slice();
    for (const p of result.patches) out.set(p.data, p.offset);
    expect(out[22]).toBe(128);
  });
});
