/**
 * Step 4 — protocol-neutral mask fill must never be mistaken for RTP/RTCP/TLS/SIP on an
 * independent re-scan of the exported file (the colleague-audited "26 false-positive RTP
 * classifications on re-analysis" finding).
 */

import { describe, expect, it } from 'vitest';
import { createProtocolNeutralMaskFill, looksLikeDissectorMagic } from '../../../src/pcap/sanitize/maskFill';
import { detectMediaShape } from '../../../src/pcap/protocols/application/rtp/classify';
import { looksLikeTlsRecord } from '../../../src/pcap/sanitize/mediaPolicy';

function isUppercaseAsciiLetter(b: number): boolean {
  return b >= 0x41 && b <= 0x5a;
}

describe('createProtocolNeutralMaskFill (step 4 magic-byte avoidance)', () => {
  it('never produces a fill that looksLikeDissectorMagic', () => {
    const domains = ['export-boundary:mask-application-in-place', 'tls-certificate-der', 'dhcp-client-id', 'dns-rdata-unknown', 'reassembly:limit-exceeded:tcp'];
    const lengths = [1, 2, 4, 8, 12, 16, 24, 32, 48, 64];
    let checked = 0;
    for (let packetIndex = 0; packetIndex < 2000; packetIndex++) {
      for (const domain of domains) {
        for (const length of lengths) {
          for (let offsetStep = 0; offsetStep < 10; offsetStep++) {
            const offset = offsetStep * 7;
            const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain });
            expect(looksLikeDissectorMagic(fill), `packetIndex=${packetIndex} domain=${domain} length=${length} offset=${offset}`).toBe(false);
            checked++;
          }
        }
      }
    }
    expect(checked).toBeGreaterThanOrEqual(1_000_000);
  });

  it('never produces a fill the real RTP/RTCP shape detector accepts', () => {
    const domains = ['export-boundary:mask-application-in-place', 'tls-certificate-der', 'dhcp-client-id'];
    let checked = 0;
    for (let packetIndex = 0; packetIndex < 20_000; packetIndex++) {
      for (const domain of domains) {
        for (const length of [12, 16, 20, 24]) {
          const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset: 0, domain });
          expect(detectMediaShape(fill, 0, fill.length)).toBeNull();
          checked++;
        }
      }
    }
    expect(checked).toBeGreaterThanOrEqual(200_000);
  });

  it('never produces a fill the real TLS record detector accepts', () => {
    let checked = 0;
    for (let packetIndex = 0; packetIndex < 50_000; packetIndex++) {
      const fill = createProtocolNeutralMaskFill({ length: 16, packetIndex, offset: 0, domain: 'tls-handshake-unsupported' });
      expect(looksLikeTlsRecord(fill, 0, fill.length)).toBe(false);
      checked++;
    }
    expect(checked).toBeGreaterThanOrEqual(50_000);
  });

  it('never produces a fill starting with an uppercase ASCII letter (SIP start-line magic)', () => {
    let checked = 0;
    for (let packetIndex = 0; packetIndex < 50_000; packetIndex++) {
      const fill = createProtocolNeutralMaskFill({ length: 8, packetIndex, offset: 0, domain: 'sip-uncovered' });
      expect(isUppercaseAsciiLetter(fill[0]!)).toBe(false);
      checked++;
    }
    expect(checked).toBeGreaterThanOrEqual(50_000);
  });

  it('is empty-safe and deterministic (same inputs -> same output)', () => {
    const a = createProtocolNeutralMaskFill({ length: 20, packetIndex: 5, offset: 3, domain: 'x' });
    const b = createProtocolNeutralMaskFill({ length: 20, packetIndex: 5, offset: 3, domain: 'x' });
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(createProtocolNeutralMaskFill({ length: 0, packetIndex: 0, offset: 0, domain: 'x' }).length).toBe(0);
  });
});
