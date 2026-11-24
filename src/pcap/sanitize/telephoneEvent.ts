/**
 * RTP telephone-event (DTMF) classification — enterprise step 8.
 * SECRET/MEDIA: diagnostic MASK, high-privacy MASK or DROP; never preserve-unsafe.
 */

import { parseRtpHeader } from '../protocols/application/rtp/classify'

export function isTelephoneEventPayload(
  data: Uint8Array,
  offset: number,
  length: number,
  telephoneEventPayloadTypes: readonly number[],
): boolean {
  if (telephoneEventPayloadTypes.length === 0) return false
  const header = parseRtpHeader(data, offset, length)
  if (!header) return false
  return telephoneEventPayloadTypes.includes(header.payloadType)
}

/** Issue marker when DTMF digits are masked/dropped. */
export const TELEPHONE_EVENT_ISSUE = 'rtp-telephone-event:SECRET'
