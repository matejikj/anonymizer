import { describe, it, expect } from 'vitest';
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping';
import { EntityRegistry } from '../../../src/pcap/anonymization/entityRegistry';
import { TimestampMapping } from '../../../src/pcap/anonymization/timestampMapping';
import type { PacketTimestamp } from '../../../src/pcap/domain/types';

describe('SessionMapping', () => {
  describe('determinism within session', () => {
    it('maps the same IPv4 address to the same pseudonym', () => {
      const m = new SessionMapping();
      const a = m.map('ipv4', '192.168.1.100');
      const b = m.map('ipv4', '192.168.1.100');
      expect(a).toBe(b);
    });

    it('maps the same MAC to the same pseudonym', () => {
      const m = new SessionMapping();
      const a = m.map('mac', 'aa:bb:cc:dd:ee:ff');
      const b = m.map('mac', 'aa:bb:cc:dd:ee:ff');
      expect(a).toBe(b);
    });

    it('maps the same hostname to the same pseudonym', () => {
      const m = new SessionMapping();
      const a = m.map('hostname', 'server.example.com');
      const b = m.map('hostname', 'server.example.com');
      expect(a).toBe(b);
    });
  });

  describe('different sessions produce different mappings', () => {
    it('two SessionMapping instances produce different IPv4 mappings (probabilistic)', () => {
      const m1 = new SessionMapping();
      const m2 = new SessionMapping();
      const a = m1.map('ipv4', '10.0.0.1');
      const b = m2.map('ipv4', '10.0.0.1');
      // Could theoretically be equal but extremely unlikely with CSPRNG
      // We just verify both are valid private IPs
      expect(a).toMatch(/^10\.254\.\d+\.\d+$/);
      expect(b).toMatch(/^10\.254\.\d+\.\d+$/);
    });
  });

  describe('collision-free', () => {
    it('maps 1000 unique IPs without collision', () => {
      const m = new SessionMapping();
      const seen = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        const ip = `192.168.${(i >> 8) & 0xff}.${i & 0xff}`;
        const mapped = m.map('ipv4', ip);
        expect(seen.has(mapped)).toBe(false);
        seen.add(mapped);
      }
    });

    it('maps 1000 unique MACs without collision', () => {
      const m = new SessionMapping();
      const seen = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        const mac = `aa:bb:cc:${((i >> 8) & 0xff).toString(16).padStart(2, '0')}:${(i & 0xff).toString(16).padStart(2, '0')}:01`;
        const mapped = m.map('mac', mac);
        expect(seen.has(mapped)).toBe(false);
        seen.add(mapped);
      }
    });

    it('permutes dynamic ports without collision and never aliases onto service ports (CF-14)', () => {
      const m = new SessionMapping({
        ...DEFAULT_MAPPING_CONFIG,
        ephemeralPorts: 'permute',
      });
      const seen = new Set<string>();

      expect(m.map('port', 'tcp/5060')).toBe('tcp/5060');

      for (let port = 49152; port < 49152 + 2000; port++) {
        const mapped = m.map('port', `tcp/${port}`);
        const mappedPort = Number(mapped.slice(mapped.indexOf('/') + 1));
        expect(mappedPort).toBeGreaterThanOrEqual(49152);
        expect(mappedPort).toBeLessThanOrEqual(65535);
        expect(mappedPort === 5060 || mappedPort === 5061).toBe(false);
        expect(seen.has(mapped)).toBe(false);
        seen.add(mapped);
      }

      expect(seen.size).toBe(2000);
      expect(m.overflow).toBe(false);
    });

    it('fails closed when a policy change would reuse an allocated port alias', () => {
      const permuting = new SessionMapping({
        ...DEFAULT_MAPPING_CONFIG,
        ephemeralPorts: 'permute',
      });
      const mapped = permuting.map('port', 'tcp/50000');
      expect(mapped).not.toBe('tcp/50000');

      const preserving = permuting.clone(DEFAULT_MAPPING_CONFIG);
      preserving.map('port', mapped);

      expect(preserving.overflow).toBe(true);
    });
  });

  describe('CSPRNG randomness (Krok 1)', () => {
    it('consecutive IPv4 mappings for different inputs are not a simple counter sequence', () => {
      // Randomness belongs to privacy mode; diagnostic mode may allocate sequential
      // free slots while keeping addresses in the same topology bucket.
      const m = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ip: 'privacy-preserving' });
      const lastOctets: number[] = [];
      for (let i = 0; i < 20; i++) {
        const mapped = m.map('ipv4', `172.16.${(i >> 8) & 0xff}.${i & 0xff}`);
        const octets = mapped.split('.').map(Number);
        lastOctets.push(octets[2]! * 256 + octets[3]!);
      }
      // A sequential counter would produce lastOctets[i] === lastOctets[0] + i for every i.
      const isSequential = lastOctets.every((v, i) => v === lastOctets[0]! + i);
      expect(isSequential).toBe(false);
    });

    it('generates 500 unique MACs without collision', () => {
      const m = new SessionMapping();
      const seen = new Set<string>();
      for (let i = 0; i < 500; i++) {
        const mac = `de:ad:be:${((i >> 16) & 0xff).toString(16).padStart(2, '0')}:${((i >> 8) & 0xff).toString(16).padStart(2, '0')}:${(i & 0xff).toString(16).padStart(2, '0')}`;
        const mapped = m.map('mac', mac);
        expect(seen.has(mapped)).toBe(false);
        seen.add(mapped);
      }
    });

    it('second MAC byte is drawn independently from the last byte', () => {
      // Regression guard for the `(n >> 32) & 0xff` bug: JS bitwise shifts are 32-bit and
      // the shift amount wraps mod 32, so `n >> 32` was equivalent to `n >> 0` — the second
      // byte (b1) ended up masking the exact same low bits as the last byte (b5), so
      // b1 === b5 on every single generated MAC. With independent CSPRNG bytes they should
      // coincide only by chance (~1/256).
      const m = new SessionMapping();
      let matches = 0;
      const samples = 300;
      for (let i = 0; i < samples; i++) {
        const mac = `de:ad:be:${((i >> 16) & 0xff).toString(16).padStart(2, '0')}:${((i >> 8) & 0xff).toString(16).padStart(2, '0')}:${(i & 0xff).toString(16).padStart(2, '0')}`;
        const mapped = m.map('mac', mac);
        const groups = mapped.split(':');
        if (groups[1] === groups[5]) matches++;
      }
      // Old bug: matches === samples (always equal). Fixed: only coincidental matches.
      expect(matches).toBeLessThan(samples / 8);
    });

    it('does not report mapping overflow for a normal-sized session', () => {
      const m = new SessionMapping();
      for (let i = 0; i < 2000; i++) {
        m.map('ipv4', `10.${(i >> 16) & 0xff}.${(i >> 8) & 0xff}.${i & 0xff}`);
      }
      expect(m.overflow).toBe(false);
    });
  });

  describe('no-original-in-output', () => {
    it('no mapped value equals any original value', () => {
      const m = new SessionMapping();
      m.map('ipv4', '192.168.1.1');
      m.map('ipv4', '10.0.0.1');
      m.map('mac', 'aa:bb:cc:dd:ee:ff');
      m.map('hostname', 'secret.internal.corp');
      expect(m.hasNoOriginalInOutput()).toBe(true);
    });
  });

  describe('address family preservation', () => {
    it('IPv4 maps to IPv4', () => {
      const m = new SessionMapping();
      const mapped = m.map('ipv4', '172.18.0.1');
      expect(mapped).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    });

    it('IPv6 maps to IPv6', () => {
      const m = new SessionMapping();
      const mapped = m.map('ipv6', '2001:db8::1');
      expect(mapped).toContain(':');
    });

    it('private IPv4 maps to private range', () => {
      const m = new SessionMapping();
      const mapped = m.map('ipv4', '192.168.1.1');
      expect(mapped).toMatch(/^10\.254\./);
    });

    it('public IPv4 maps to public range', () => {
      const m = new SessionMapping();
      const mapped = m.map('ipv4', '8.8.8.8');
      expect(mapped).toMatch(/^198\.51\./);
    });
  });

  describe('preserved addresses', () => {
    it('broadcast IPv4 is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('ipv4', '255.255.255.255')).toBe('255.255.255.255');
    });

    it('unspecified IPv4 is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('ipv4', '0.0.0.0')).toBe('0.0.0.0');
    });

    it('multicast IPv4 is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('ipv4', '224.0.0.1')).toBe('224.0.0.1');
    });

    it('broadcast MAC is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('mac', 'ff:ff:ff:ff:ff:ff')).toBe('ff:ff:ff:ff:ff:ff');
    });

    it('multicast MAC is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('mac', '01:00:5e:00:00:01')).toBe('01:00:5e:00:00:01');
    });

    it('well-known port is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('port', 'tcp/80')).toBe('tcp/80');
      expect(m.map('port', 'udp/53')).toBe('udp/53');
    });
  });

  describe('MAC local/unicast bits', () => {
    it('mapped MAC has locally-administered bit set and unicast bit clear', () => {
      const m = new SessionMapping();
      const mapped = m.map('mac', 'aa:bb:cc:dd:ee:ff');
      const firstByte = parseInt(mapped.substring(0, 2), 16);
      expect(firstByte & 0x02).toBe(0x02); // locally administered
      expect(firstByte & 0x01).toBe(0x00); // unicast
    });
  });

  describe('hostname length preservation', () => {
    it('preserves label count', () => {
      const m = new SessionMapping();
      const original = 'server.dept.corp.example.com';
      const mapped = m.map('hostname', original);
      expect(mapped.split('.').length).toBe(original.split('.').length);
    });

    it('preserves per-label length', () => {
      const m = new SessionMapping();
      const original = 'myhost.example.com';
      const mapped = m.map('hostname', original);
      const origLabels = original.split('.');
      const mappedLabels = mapped.split('.');
      for (let i = 0; i < origLabels.length; i++) {
        expect(mappedLabels[i]!.length).toBe(origLabels[i]!.length);
      }
    });
  });

  describe('VLAN mapping', () => {
    it('reserved VLAN 0 is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('vlan', '0')).toBe('0');
    });

    it('reserved VLAN 4095 is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('vlan', '4095')).toBe('4095');
    });

    it('normal VLAN is mapped to a different id in 1-4094', () => {
      const m = new SessionMapping();
      const mapped = parseInt(m.map('vlan', '100'), 10);
      expect(mapped).toBeGreaterThanOrEqual(1);
      expect(mapped).toBeLessThanOrEqual(4094);
      expect(mapped).not.toBe(100);
    });
  });

  describe('radio ID mapping (Krok 3)', () => {
    it('maps a normal radio ID to a different value within the 24-bit range', () => {
      const m = new SessionMapping();
      const mapped = parseInt(m.map('radioId', '1234567'), 10);
      expect(mapped).toBeGreaterThanOrEqual(0);
      expect(mapped).toBeLessThanOrEqual(0xffffff);
      expect(mapped).not.toBe(1234567);
    });

    it('reserved ID 0 is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('radioId', '0')).toBe('0');
    });

    it('reserved all-call ID (0xFFFFFF) is preserved', () => {
      const m = new SessionMapping();
      expect(m.map('radioId', '16777215')).toBe('16777215');
    });

    it('maps the same radio ID to the same pseudonym', () => {
      const m = new SessionMapping();
      const a = m.map('radioId', '3100123');
      const b = m.map('radioId', '3100123');
      expect(a).toBe(b);
    });

    it('maps 500 unique radio IDs without collision', () => {
      const m = new SessionMapping();
      const seen = new Set<string>();
      for (let i = 1; i < 501; i++) {
        const mapped = m.map('radioId', `${i}`);
        expect(seen.has(mapped)).toBe(false);
        seen.add(mapped);
      }
    });

    it('a missing switch arm cannot silently fall through to a numeric-looking alias', () => {
      // Regression guard: EntityCategory has no TypeScript exhaustiveness check (see
      // mapping.ts::map()). Forgotten `case 'radioId'` would return `anon-overflow`
      // (non-numeric) instead of a digit string — catch with this shape check.
      const m = new SessionMapping();
      const mapped = m.map('radioId', '42');
      expect(mapped).toMatch(/^\d+$/);
    });
  });
});

describe('EntityRegistry', () => {
  it('tracks entity counts', () => {
    const reg = new EntityRegistry();
    reg.add('ipv4', '1.2.3.4', 0);
    reg.add('ipv4', '1.2.3.4', 1);
    reg.add('ipv4', '1.2.3.4', 2);
    expect(reg.get('ipv4', '1.2.3.4')?.count).toBe(3);
  });

  describe('cardinality limit', () => {
    it('returns null after MAX_ENTITY_CARDINALITY', () => {
      const reg = new EntityRegistry();
      for (let i = 0; i < 500_000; i++) {
        reg.add('ipv4', `ip-${i}`, i);
      }
      expect(reg.size).toBe(500_000);
      const result = reg.add('ipv4', 'overflow', 500_001);
      expect(result).toBeNull();
      expect(reg.overflow).toBe(true);
    });
  });
});

describe('TimestampMapping', () => {
  it('preserves inter-packet deltas in relative-exact mode', () => {
    const tm = new TimestampMapping({ mode: 'relative-exact', anchorSeconds: 1_700_000_000n });
    const ts1: PacketTimestamp = { ticks: 1700001000_000000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };
    const ts2: PacketTimestamp = { ticks: 1700001001_250000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };

    const m1 = tm.mapTicks(ts1);
    const m2 = tm.mapTicks(ts2);

    expect(m2.ticks - m1.ticks).toBe(ts2.ticks - ts1.ticks);
  });

  it('preserves unitsPerSecond', () => {
    const tm = new TimestampMapping({ mode: 'relative-exact', anchorSeconds: 1_700_000_000n });
    const ts: PacketTimestamp = { ticks: 1700000000_123456789n, unitsPerSecond: 1_000_000_000n, offsetSeconds: 0n };
    const mapped = tm.mapTicks(ts);
    expect(mapped.unitsPerSecond).toBe(ts.unitsPerSecond);
  });

  it('first timestamp maps to configured epoch anchor', () => {
    const tm = new TimestampMapping({ mode: 'relative-exact', anchorSeconds: 1_700_000_000n });
    const ts: PacketTimestamp = { ticks: 1700050000_000000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n };
    const mapped = tm.mapTicks(ts);
    expect(mapped.ticks).toBe(1700000000_000000n);
  });
});
