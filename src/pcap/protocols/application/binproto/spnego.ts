/**
 * T16 — SPNEGO (RFC 4178) NegTokenInit/Resp unwrap → NTLMSSP or fail-closed mask.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import type { IntentCollector } from '../../../discovery/intentCollector'
import type { MappingLike } from '../../../anonymization/mapping'
import { createProtocolNeutralMaskFill } from '../../../sanitize/maskFill'
import { walkBer } from './ber'
import { looksLikeNtlmssp, sanitizeNtlmssp } from './ntlmssp'

/** SPNEGO mech OID 1.3.6.1.5.5.2 */
const SPNEGO_OID = Uint8Array.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])

export function looksLikeSpnego(buffer: Uint8Array, offset = 0, length = buffer.length - offset): boolean {
  if (length < 12) return false
  // Application 0 constructed or SEQUENCE containing mechTypes / mechToken
  const tag = buffer[offset]!
  if (tag !== 0x60 && tag !== 0xa0 && tag !== 0x30) return false
  for (let i = offset; i + SPNEGO_OID.length <= offset + length; i++) {
    let ok = true
    for (let k = 0; k < SPNEGO_OID.length; k++) {
      if (buffer[i + k] !== SPNEGO_OID[k]) {
        ok = false
        break
      }
    }
    if (ok) return true
  }
  return false
}

/**
 * Find NTLMSSP blob inside SPNEGO DER and sanitize it; otherwise mask whole token.
 */
export function sanitizeSpnego(
  buffer: Uint8Array,
  absoluteOffset: number,
  byteLength: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): boolean {
  if (!looksLikeSpnego(buffer, absoluteOffset, byteLength)) return false

  // Scan for embedded NTLMSSP signature (common in mechToken OCTET STRING).
  const end = absoluteOffset + byteLength
  for (let i = absoluteOffset; i + 12 <= end; i++) {
    if (looksLikeNtlmssp(buffer, i, end - i)) {
      // Bound NTLM message to remaining SPNEGO bytes (NTLM length is implicit to end of OCTET STRING —
      // use walkBer when possible; fallback: rest of buffer).
      let ntlmLen = end - i
      const walked = walkBer(buffer, absoluteOffset, byteLength, { maxDepth: 12, maxNodes: 64 })
      for (const root of walked.roots) {
        const stack = [root]
        while (stack.length > 0) {
          const node = stack.pop()!
          if (
            !node.tag.constructed
            && node.contentOffset <= i
            && node.contentOffset + node.contentLength >= i + 8
          ) {
            ntlmLen = Math.min(ntlmLen, node.contentOffset + node.contentLength - i)
          }
          for (const c of node.children) stack.push(c)
        }
      }
      return sanitizeNtlmssp(buffer, i, ntlmLen, collector, mapping, intents, packetIndex)
    }
  }

  // No NTLMSSP — Kerberos or unknown: fail-closed mask entire SPNEGO token.
  const fill = createProtocolNeutralMaskFill({
    length: byteLength,
    packetIndex,
    offset: absoluteOffset,
    domain: 'spnego-non-ntlm',
  })
  collector.maskRange(absoluteOffset, fill)
  intents?.recordMaskRange(packetIndex, absoluteOffset, byteLength, 'spnego-non-ntlm', 'spnego')
  return true
}
