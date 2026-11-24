/**
 * VoIP export leak scanner (step 10 / CF-07).
 */

import { expect } from 'vitest';

export function voipLeakVariants(seeds: readonly string[]): string[] {
  const out = new Set<string>();
  for (const seed of seeds) {
    if (seed.length === 0) continue;
    out.add(seed);
    out.add(seed.toLowerCase());
    out.add(seed.toUpperCase());
    if (seed.length >= 4) {
      out.add(Buffer.from(seed, 'latin1').toString('base64'));
      out.add(encodeURIComponent(seed));
      // quoted / bracketed forms commonly seen in SIP/SDP
      out.add(`"${seed}"`);
      out.add(`<${seed}>`);
      out.add(`[${seed}]`);
      const hex = Buffer.from(seed, 'latin1').toString('hex');
      if (hex.length >= 8) {
        out.add(hex);
        out.add(hex.toUpperCase());
      }
    }
  }
  return [...out];
}

export function assertBufferHasNoVoipLeaks(data: Uint8Array, seeds: readonly string[]): void {
  const text = Buffer.from(data).toString('latin1');
  const lower = text.toLowerCase();
  for (const variant of voipLeakVariants(seeds)) {
    if (variant.length < 4) continue;
    expect(text, `leaked seed variant: ${variant}`).not.toContain(variant);
    // Case-fold scan for mixed-case SIP headers / hostnames
    if (/[a-zA-Z]/.test(variant) && variant === variant.toLowerCase()) {
      expect(lower, `leaked case-folded seed: ${variant}`).not.toContain(variant.toLowerCase());
    }
  }
}

/** Whole-file scan (container + all packets). */
export function assertCaptureHasNoVoipLeaks(buffer: ArrayBuffer, seeds: readonly string[]): void {
  assertBufferHasNoVoipLeaks(new Uint8Array(buffer), seeds);
}
