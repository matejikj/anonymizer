/**
 * T14 — media-description fact → bounded MediaFlowIndex (no second media registry).
 */

import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import type { SipMessage } from '../protocols/application/sip/types'

export const MEDIA_DESCRIPTION_FACT = 'media-description' as const

/**
 * Project a SIP message's SDP media into the shared MediaFlowIndex.
 * Callers already owning a parsed SipMessage reuse this instead of ad-hoc register.
 */
export function projectMediaDescriptionFact(input: {
  readonly index: MediaFlowIndex
  readonly message: SipMessage
  readonly buffer: Uint8Array
  readonly packetIndex: number
  readonly sourceId?: string
}): MediaDescriptionFact {
  input.index.registerFromSipMessage(input.message, input.buffer)
  return {
    kind: MEDIA_DESCRIPTION_FACT,
    packetIndex: input.packetIndex,
    sourceId: input.sourceId,
  }
}

export type MediaDescriptionFact = {
  readonly kind: typeof MEDIA_DESCRIPTION_FACT
  readonly packetIndex: number
  readonly sourceId?: string
}
