/**
 * Extended privacy leak scan (step 10) — raw / text / hex / base64 / URL + sidecars.
 */

import { expect } from 'vitest'
import { voipLeakVariants, assertBufferHasNoVoipLeaks } from './voipLeakScan'

export function privacyLeakVariants(seeds: readonly string[]): string[] {
  const out = new Set<string>(voipLeakVariants(seeds))
  for (const seed of seeds) {
    if (seed.length < 4) continue
    const bytes = Buffer.from(seed, 'latin1')
    const hex = bytes.toString('hex')
    out.add(hex)
    out.add(hex.toUpperCase())
    // colon / space separated hex commonly seen in dumps
    if (bytes.length <= 32) {
      out.add([...bytes].map((b) => b.toString(16).padStart(2, '0')).join(':'))
      out.add([...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' '))
    }
  }
  return [...out]
}

export function assertBufferHasNoPrivacyLeaks(data: Uint8Array, seeds: readonly string[]): void {
  assertBufferHasNoVoipLeaks(data, seeds)
  const text = Buffer.from(data).toString('latin1')
  const lower = text.toLowerCase()
  for (const variant of privacyLeakVariants(seeds)) {
    if (variant.length < 4) continue
    // Skip pure-hex variants shorter than 8 nybbles to avoid noisy false positives
    if (/^[0-9a-fA-F: ]+$/.test(variant) && variant.replace(/[: ]/g, '').length < 8) continue
    expect(text, `leaked privacy variant: ${variant}`).not.toContain(variant)
    if (/[a-zA-Z]/.test(variant) && variant === variant.toLowerCase()) {
      expect(lower, `leaked case-folded privacy variant: ${variant}`).not.toContain(variant)
    }
  }
}

export function assertCaptureHasNoPrivacyLeaks(buffer: ArrayBuffer, seeds: readonly string[]): void {
  assertBufferHasNoPrivacyLeaks(new Uint8Array(buffer), seeds)
}

export function assertSidecarHasNoPrivacyLeaks(json: string, seeds: readonly string[]): void {
  const lower = json.toLowerCase()
  for (const seed of seeds) {
    if (!seed || seed.length < 4) continue
    expect(lower, `sidecar leaked seed: ${seed}`).not.toContain(seed.toLowerCase())
    const b64 = Buffer.from(seed, 'latin1').toString('base64').toLowerCase()
    if (b64.length >= 8) {
      expect(lower, `sidecar leaked base64 seed: ${seed}`).not.toContain(b64)
    }
    const hex = Buffer.from(seed, 'latin1').toString('hex')
    if (hex.length >= 8) {
      expect(lower, `sidecar leaked hex seed: ${seed}`).not.toContain(hex)
    }
  }
}

/**
 * Step 6 — parser-independent checks. Both of these deliberately do NOT rely on discovery
 * having named an entity: a parser that fails to recognize SIP/TLS/etc. content cannot pass
 * an identity to the entity scanner, so a seed-list-only gate (assertCaptureHasNoPrivacyLeaks)
 * would silently pass over exactly the packets most likely to leak. These instead compare
 * original vs. anonymized bytes directly, span-by-span.
 */

const BLOCKING_COVERAGE_STATUSES = new Set(['malformed', 'unsupported', 'requires-reassembly'])

export interface MinimalCoverageSpan {
  readonly protocol: string
  readonly offset: number
  readonly length: number
  readonly status: string
}

/**
 * Differential unchanged-window scan: flags any run of at least `minRunLength` bytes that is
 * byte-identical between original and anonymized within a span — regardless of whether the
 * exact original value was ever named as a "seed". A genuinely encrypted TLS/SRTP ciphertext
 * span is exempt only when the caller has independently proven (from coverage) that the span
 * is `encrypted` — passing an already-filtered span list is the caller's responsibility.
 *
 * `allowedUnchanged` (T47): absolute packet offsets that may survive as documented structure
 * (TLS record/handshake headers, versions, cipher lists). Not a blanket protocol exemption —
 * random / session_id / unknown extension bodies must not appear in this list.
 */
export function assertNoUnchangedWindow(
  original: Uint8Array,
  anonymized: Uint8Array,
  span: { offset: number; length: number },
  minRunLength: number,
  context: string,
  allowedUnchanged: readonly { readonly offset: number; readonly length: number }[] = [],
): void {
  const end = Math.min(span.offset + span.length, original.length, anonymized.length)
  const allowed = (index: number): boolean => {
    for (const r of allowedUnchanged) {
      if (index >= r.offset && index < r.offset + r.length) return true
    }
    return false
  }
  let runStart = -1
  for (let i = span.offset; i <= end; i++) {
    const same = i < end && original[i] === anonymized[i] && !allowed(i)
    if (same) {
      if (runStart < 0) runStart = i
      continue
    }
    if (runStart >= 0) {
      const runLen = i - runStart
      if (runLen >= minRunLength) {
        expect.fail(
          `${context}: unchanged byte run [${runStart},${i}) length=${runLen} inside a span `
          + 'that should have been anonymized (differential unchanged-window scan)',
        )
      }
      runStart = -1
    }
  }
}

/** Extension types whose *values* may remain as negotiation metadata (mirrors sanitize/tls.ts). */
const TLS_STRUCTURAL_EXT_VALUE_OK = new Set([
  0x000a, // supported_groups
  0x000b, // ec_point_formats
  0x000d, // signature_algorithms
  0x0010, // ALPN
  0x002b, // supported_versions
  0x002d, // psk_key_exchange_modes
])

/**
 * T47 — independent (of the sanitizer) enumeration of TLS Hello bytes that are allowed
 * to stay identical: record + handshake framing, legacy version, cipher/compression lists,
 * extension type+length headers, and preserve-value extension bodies.
 * Does **not** include random(32), session_id body, SNI hostnames, or unknown/key-share bodies.
 */
export function tlsHelloStructuralPreserveRanges(
  original: Uint8Array,
  span: { readonly offset: number; readonly length: number },
  kind: 'client' | 'server',
): Array<{ offset: number; length: number }> {
  const ranges: Array<{ offset: number; length: number }> = []
  const spanEnd = Math.min(span.offset + span.length, original.length)
  let pos = span.offset
  if (pos >= spanEnd) return ranges

  // Optional TLS record header at span start (content_type=handshake).
  if (original[pos] === 0x16 && pos + 5 <= spanEnd) {
    ranges.push({ offset: pos, length: 5 })
    pos += 5
  }

  if (pos + 4 > spanEnd) return ranges
  // handshake type + uint24 length
  ranges.push({ offset: pos, length: 4 })
  const hsType = original[pos]!
  const hsLen = (original[pos + 1]! << 16) | (original[pos + 2]! << 8) | original[pos + 3]!
  pos += 4
  const bodyStart = pos
  const bodyEnd = Math.min(bodyStart + hsLen, spanEnd)
  const expectType = kind === 'client' ? 0x01 : 0x02
  if (hsType !== expectType) return ranges

  // legacy_version(2)
  if (pos + 2 > bodyEnd) return ranges
  ranges.push({ offset: pos, length: 2 })
  pos += 2

  // random(32) — NOT allowed
  if (pos + 32 > bodyEnd) return ranges
  pos += 32

  // session_id_len(1) allowed; body not
  if (pos + 1 > bodyEnd) return ranges
  ranges.push({ offset: pos, length: 1 })
  const sidLen = original[pos]!
  pos += 1
  if (pos + sidLen > bodyEnd) return ranges
  pos += sidLen

  if (kind === 'client') {
    if (pos + 2 > bodyEnd) return ranges
    const csLen = (original[pos]! << 8) | original[pos + 1]!
    ranges.push({ offset: pos, length: 2 + csLen })
    pos += 2 + csLen
    if (pos + 1 > bodyEnd) return ranges
    const compLen = original[pos]!
    ranges.push({ offset: pos, length: 1 + compLen })
    pos += 1 + compLen
  } else {
    if (pos + 3 > bodyEnd) return ranges
    ranges.push({ offset: pos, length: 3 }) // cipher_suite(2)+compression(1)
    pos += 3
  }

  if (pos + 2 > bodyEnd) return ranges
  const extLen = (original[pos]! << 8) | original[pos + 1]!
  ranges.push({ offset: pos, length: 2 })
  pos += 2
  const extEnd = Math.min(pos + extLen, bodyEnd)
  while (pos + 4 <= extEnd) {
    const et = (original[pos]! << 8) | original[pos + 1]!
    const el = (original[pos + 2]! << 8) | original[pos + 3]!
    ranges.push({ offset: pos, length: 4 }) // type+length always structure
    pos += 4
    if (pos + el > extEnd) break
    // SNI (0) hostnames are mapped — do not allow original value bytes.
    // Preserve-list extension bodies may stay; others must be masked.
    if (et !== 0x0000 && TLS_STRUCTURAL_EXT_VALUE_OK.has(et)) {
      ranges.push({ offset: pos, length: el })
    }
    pos += el
  }
  return ranges
}

/**
 * T47 — Certificate handshake framing only (type/length + cert list lengths).
 * DER body must still change where identities were present; this is not a body allowlist.
 */
export function tlsCertificateStructuralPreserveRanges(
  original: Uint8Array,
  span: { readonly offset: number; readonly length: number },
): Array<{ offset: number; length: number }> {
  const ranges: Array<{ offset: number; length: number }> = []
  const spanEnd = Math.min(span.offset + span.length, original.length)
  let pos = span.offset
  if (pos >= spanEnd) return ranges
  if (original[pos] === 0x16 && pos + 5 <= spanEnd) {
    ranges.push({ offset: pos, length: 5 })
    pos += 5
  }
  if (pos + 4 > spanEnd) return ranges
  ranges.push({ offset: pos, length: 4 })
  const hsType = original[pos]!
  const hsLen = (original[pos + 1]! << 16) | (original[pos + 2]! << 8) | original[pos + 3]!
  pos += 4
  if (hsType !== 0x0b) return ranges
  const bodyEnd = Math.min(pos + hsLen, spanEnd)
  if (pos + 3 > bodyEnd) return ranges
  ranges.push({ offset: pos, length: 3 })
  const certsLen = (original[pos]! << 16) | (original[pos + 1]! << 8) | original[pos + 2]!
  pos += 3
  const certsEnd = Math.min(pos + certsLen, bodyEnd)
  while (pos + 3 <= certsEnd) {
    ranges.push({ offset: pos, length: 3 })
    const certLen = (original[pos]! << 16) | (original[pos + 1]! << 8) | original[pos + 2]!
    pos += 3
    if (pos + certLen > certsEnd) break
    pos += certLen
  }
  return ranges
}

/**
 * No coverage span with a blocking status (`malformed`/`unsupported`/`requires-reassembly`)
 * may survive byte-identical to the original in the export, unless the disposition was an
 * explicit `preserve-unsafe` — neither `diagnostic` nor `high-privacy` ever use that
 * disposition, so in practice this must never fire for either fixed level. This check reads
 * directly off `coverage`, not off discovered entities, so it still fires when a parser bug
 * causes structural anonymization to be skipped for content it *did* correctly flag as
 * blocking (the P0-2 "drop computed but never applied" class of bug).
 */
export function assertNoBlockingSpanSurvivesUnchanged(
  original: Uint8Array,
  anonymized: Uint8Array,
  coverage: readonly MinimalCoverageSpan[],
  packetNumber: number,
  allowPreserveUnsafe = false,
): void {
  if (allowPreserveUnsafe) return
  for (const span of coverage) {
    if (!BLOCKING_COVERAGE_STATUSES.has(span.status)) continue
    if (span.length <= 0) continue
    const end = Math.min(span.offset + span.length, original.length, anonymized.length)
    if (end <= span.offset) continue
    let identical = true
    for (let i = span.offset; i < end; i++) {
      if (original[i] !== anonymized[i]) { identical = false; break }
    }
    if (identical) {
      expect.fail(
        `packet ${packetNumber}: blocking span protocol=${span.protocol} status=${span.status} `
        + `offset=${span.offset} length=${span.length} survived byte-identical to the original `
        + 'without an explicit preserve-unsafe disposition',
      )
    }
  }
}
