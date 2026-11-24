/**
 * Deterministic, domain-separated mask fill for in-place payload redaction (step 4).
 * Fill is never the original bytes, not a constant global pattern, and is stable for
 * the same (domain, packetIndex, offset, length) so discovery and plan agree.
 */

const FNV_OFFSET = 0x811c9dc5
const FNV_PRIME = 0x01000193

function fnv1a32(parts: readonly (string | number)[]): number {
  let h = FNV_OFFSET
  for (const part of parts) {
    const text = typeof part === 'number' ? `n:${part}` : part
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i) & 0xff
      h = Math.imul(h, FNV_PRIME)
    }
    h ^= 0xff
    h = Math.imul(h, FNV_PRIME)
  }
  return h >>> 0
}

function xorshift32(state: number): number {
  let x = state >>> 0
  x ^= x << 13
  x ^= x >>> 17
  x ^= x << 5
  return x >>> 0
}

export type MaskFillMode = 'stream' | 'zeros'

export interface MaskFillRequest {
  readonly length: number
  readonly packetIndex: number
  readonly offset: number
  /** Domain tag — separates SIP reassembly masks from generic payload masks, etc. */
  readonly domain: string
  readonly mode?: MaskFillMode
}

/**
 * Build replacement bytes for a masked span.
 * `zeros` is used only when a protocol calls for an obviously empty filler;
 * default is a domain-separated deterministic stream.
 */
export function createMaskFill(request: MaskFillRequest): Uint8Array {
  const { length, packetIndex, offset, domain } = request
  if (length <= 0) return new Uint8Array(0)
  if (request.mode === 'zeros') return new Uint8Array(length)

  const out = new Uint8Array(length)
  let state = fnv1a32(['pcap-mask-v1', domain, packetIndex, offset, length])
  if (state === 0) state = 0x9e3779b9
  for (let i = 0; i < length; i++) {
    state = xorshift32(state)
    out[i] = state & 0xff
  }
  return out
}

function isTlsContentTypeByte(b: number): boolean {
  return b === 0x14 || b === 0x15 || b === 0x16 || b === 0x17
}

/** True when the fill's leading bytes would be misread as one of our own dissectors'
 * framing magic — RTP/RTCP version 2, a TLS record header, or a SIP start-line. */
export function looksLikeDissectorMagic(out: Uint8Array): boolean {
  if (out.length === 0) return false
  if ((out[0]! >> 6) === 0b10) return true // RTP/RTCP version field
  if (out.length >= 2 && isTlsContentTypeByte(out[0]!) && out[1] === 0x03) return true
  if (out[0]! >= 0x41 && out[0]! <= 0x5a) return true // SIP method / "SIP/2.0" start-line
  return false
}

/**
 * Protocol-neutral mask fill for unknown/malformed application payload (step 4).
 * Same deterministic, domain-separated stream as `createMaskFill`, plus a fix-up pass
 * that deterministically rules out the leading-byte magic our own dissectors key on —
 * so a masked span can never be mistaken for RTP/RTCP/TLS/SIP on a later, independent
 * re-scan of the exported file. Never use this for the RTP/RTCP strip-payload path —
 * that payload sits after an already-preserved, already-classified RTP/RTCP header and
 * must keep the plain `createMaskFill` stream unchanged.
 */
export function createProtocolNeutralMaskFill(request: MaskFillRequest): Uint8Array {
  const out = createMaskFill(request)
  if (out.length === 0) return out

  // RTP/RTCP: both require the top 2 bits of byte 0 to read version=2 (binary 10).
  // Clearing that pattern rules out both detectors at their one shared precondition.
  if ((out[0]! >> 6) === 0b10) {
    out[0] = out[0]! & 0b0011_1111
  }

  // TLS record: content-type in {0x14..0x17} followed by major version byte 0x03.
  if (out.length >= 2 && isTlsContentTypeByte(out[0]!) && out[1] === 0x03) {
    out[1] = out[1]! ^ 0x01
  }

  // SIP start-line always begins with an uppercase ASCII letter (method, or "SIP/2.0").
  if (out[0]! >= 0x41 && out[0]! <= 0x5a) {
    out[0] = out[0]! | 0x80
  }

  return out
}
