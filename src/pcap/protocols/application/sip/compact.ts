/**
 * RFC 3261 compact header names → canonical lowercase names.
 */

const COMPACT_TO_CANONICAL: Readonly<Record<string, string>> = {
  i: 'call-id',
  m: 'contact',
  f: 'from',
  t: 'to',
  v: 'via',
  l: 'content-length',
  c: 'content-type',
  s: 'subject',
  k: 'supported',
  e: 'content-encoding',
  o: 'event',
  y: 'identity',
  z: 'referred-by',
  u: 'allow-events',
  r: 'refer-to',
};

/** Map compact or full header name to canonical lowercase form for lookup. */
export function canonicalizeHeaderName(nameText: string): string {
  const lower = nameText.toLowerCase();
  if (lower.length === 1) {
    return COMPACT_TO_CANONICAL[lower] ?? lower;
  }
  return lower;
}
