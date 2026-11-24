/**
 * T15 — always-mask encoded auth tokens (Basic, AUTH PLAIN, bare base64 blobs in auth context).
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import { patchFixedLengthAscii } from '../../../sanitize/textPatch'

const MASK_FILLER = 0x2a // '*'

export interface EncodedTokenSpan {
  readonly absoluteOffset: number
  readonly byteLength: number
  readonly kind: 'basic' | 'auth-plain' | 'bearer' | 'base64-auth'
}

/**
 * Find AUTH PLAIN / Basic / Bearer credential payloads in Latin-1 text.
 * Entire token (including scheme prefix value) is masked by the caller.
 */
export function findEncodedAuthTokenSpans(
  text: string,
  absoluteBase: number,
): readonly EncodedTokenSpan[] {
  const spans: EncodedTokenSpan[] = []
  const patterns: Array<{ re: RegExp; kind: EncodedTokenSpan['kind'] }> = [
    { re: /\bBasic\s+([A-Za-z0-9+/=]{8,})\b/gi, kind: 'basic' },
    { re: /\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b/gi, kind: 'bearer' },
    { re: /\bAUTH\s+PLAIN\s+([A-Za-z0-9+/=]{8,})\b/gi, kind: 'auth-plain' },
  ]
  for (const { re, kind } of patterns) {
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const token = m[1]!
      const tokenIndex = m.index + m[0]!.lastIndexOf(token)
      spans.push({
        absoluteOffset: absoluteBase + tokenIndex,
        byteLength: token.length,
        kind,
      })
    }
  }
  return spans
}

export function maskEncodedAuthTokens(
  collector: PatchCollector,
  spans: readonly EncodedTokenSpan[],
): void {
  for (const span of spans) {
    if (span.byteLength <= 0) continue
    patchFixedLengthAscii(collector, span.absoluteOffset, span.byteLength, '', MASK_FILLER)
  }
}
