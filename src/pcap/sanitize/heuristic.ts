/**
 * Generic best-effort payload scanner — the last fallback in the app-layer dispatch
 * chain, after every structural decoder (DNS/DHCP/SIP/TLS/HTTP) has declined.
 *
 * This is the deliberate, single answer to both "cover database wire protocols" and
 * "cover arbitrary proprietary traffic": rather than writing per-protocol structural
 * parsers (explicitly out of scope — see pcap-implementation-task plan), this does a
 * bounded regex sweep for plaintext identifiers that commonly leak in ad-hoc/proprietary
 * wire formats — embedded hostnames, embedded IPv4 literals, and obvious credential-like
 * key/value pairs.
 *
 * Always reports `status: 'heuristic'` when at least one match was rewritten, never
 * `'covered'`. If the sweep finds nothing, returns empty coverage so the caller can
 * mark the payload `unsupported` (CF-03) — an empty scan must not claim the whole
 * range was safely examined.
 *
 * Match passes run in priority order — credentials first, then IPv4, then hostname —
 * so that if two patterns match overlapping text (e.g. `token=example.com` matches both
 * the credential and the FQDN pattern), the higher-priority redaction claims the byte
 * range first via PatchCollector and the later, lower-priority patch is silently
 * dropped as an overlap (see patchFixedLengthAscii) rather than corrupting anything.
 */

import type { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import type { AppLayerResult } from './types';
import { patchFixedLengthAscii, computeFixedLengthAsciiBytes } from './textPatch';
import type { IntentCollector } from '../discovery/intentCollector';

const GENERIC_SCAN_LIMIT = 65536;
const REDACT_FILLER = 0x2a; // '*'

const CREDENTIAL_KV = /\b(?:pass(?:word)?|pwd|token|secret|auth(?:orization)?)\w*"?\s*[:=]\s*"?([^\s"',;}{]+)/gi;
const IPV4_LITERAL = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const FQDN_CANDIDATE = /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+\b/g;

// PF-01: this scanner is the last-resort fallback for *unrecognized* payloads, so it sees a
// lot of traffic that is not actually plaintext leaking a hostname — proprietary binary
// protocols, and printable-but-structured application/debug logs full of dotted identifiers
// that are not hostnames (Java-style `pkg.ClassName`, version strings like `Foo-1.8.0`). Both
// make FQDN_CANDIDATE fire constantly on large captures, each spurious match adding an entity,
// an intent, and a patch (see PF-02/PF-03) — turning this from a cheap fallback into the
// dominant cost on captures full of unrecognized proprietary traffic.
const MIN_PRINTABLE_RATIO = 0.85;

function isPrintableAsciiByte(b: number): boolean {
  return b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e);
}

/** Skip the whole scan on payloads that are not text-like — random/binary bytes decoded as
 * ASCII regularly contain short alnum-dot-alnum runs that coincidentally match FQDN_CANDIDATE. */
function looksLikeText(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length === 0) return false;
  let printable = 0;
  for (let i = 0; i < length; i++) {
    if (isPrintableAsciiByte(buffer[offset + i]!)) printable += 1;
  }
  return printable / length >= MIN_PRINTABLE_RATIO;
}

/** Reject FQDN-shaped matches that are almost certainly not real hostnames. */
function looksLikeRealHostname(candidate: string): boolean {
  // DNS hostnames are conventionally written all-lowercase in logs/configs/URLs; an
  // uppercase letter is a strong signal this is a source-code identifier instead
  // (`pkg.ClassName`), not a network hostname.
  if (candidate !== candidate.toLowerCase()) return false;
  // ICANN never allocates purely numeric TLDs (to avoid exactly this ambiguity with version
  // numbers like `Foo-1.8.0`), so a numeric last label is never a real hostname.
  const lastDot = candidate.lastIndexOf('.');
  const lastLabel = candidate.slice(lastDot + 1);
  if (/^[0-9]+$/.test(lastLabel)) return false;
  return true;
}

export function sanitizeGenericPayload(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): AppLayerResult {
  const scanLen = Math.min(length, GENERIC_SCAN_LIMIT);

  // CF-03: empty coverage is the correct "found nothing" signal here too — see below.
  if (!looksLikeText(buffer, offset, scanLen)) {
    return { coverage: [] };
  }

  const text = new TextDecoder('ascii', { fatal: false }).decode(buffer.slice(offset, offset + scanLen));

  let match: RegExpExecArray | null;
  let matchCount = 0;

  CREDENTIAL_KV.lastIndex = 0;
  while ((match = CREDENTIAL_KV.exec(text)) !== null) {
    const value = match[1]!;
    const valueStart = match.index + match[0].length - value.length;
    patchFixedLengthAscii(collector, offset + valueStart, value.length, '', REDACT_FILLER);
    matchCount += 1;
  }

  IPV4_LITERAL.lastIndex = 0;
  while ((match = IPV4_LITERAL.exec(text)) !== null) {
    const ip = match[0];
    const matchOffset = offset + match.index;
    intents?.recordEntityReplacement(packetIndex, matchOffset, 'ipv4', ip, ip.length);
    collector.addDeferred(matchOffset, ip.length, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.aliasFor('ipv4', ip, { kind: 'text-ascii', byteLength: ip.length }, ip);
      return computeFixedLengthAsciiBytes(matchOffset, ip.length, mapped);
    });
    matchCount += 1;
  }

  FQDN_CANDIDATE.lastIndex = 0;
  while ((match = FQDN_CANDIDATE.exec(text)) !== null) {
    const candidate = match[0];
    if (!/[a-zA-Z]/.test(candidate)) continue;
    if (!looksLikeRealHostname(candidate)) continue;
    const matchOffset = offset + match.index;
    intents?.recordEntityReplacement(
      packetIndex,
      matchOffset,
      'hostname',
      candidate,
      candidate.length,
    );
    collector.addDeferred(matchOffset, candidate.length, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.aliasFor(
        'hostname',
        candidate,
        { kind: 'text-ascii', byteLength: candidate.length },
        candidate,
      );
      return computeFixedLengthAsciiBytes(matchOffset, candidate.length, mapped);
    });
    matchCount += 1;
  }

  // CF-03: no matches → empty coverage; caller marks unsupported. Never pretend the
  // whole payload was safely scanned when nothing changed.
  if (matchCount === 0) {
    return { coverage: [] };
  }

  return { coverage: [{ protocol: 'heuristic', offset, length: scanLen, status: 'heuristic' }] };
}
