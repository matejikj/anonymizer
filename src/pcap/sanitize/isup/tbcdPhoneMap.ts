/**
 * T25 — length-preserving TBCD phone map via MappingAuthority (shared ISUP + SCCP GT paths).
 */

import type { MappingLike } from '../../anonymization/mapping'
import type { IntentCollector } from '../../discovery/intentCollector'
import type { PatchCollector } from '../PatchCollector'
import { createProtocolNeutralMaskFill } from '../maskFill'
import { canonicalizeIdentity } from '../../../mapping/canonicalize'
import {
  decodeTbcd,
  encodeTbcd,
  remapTbcdBytes,
  TBCD_GSM,
} from '../../protocols/application/binproto/tbcd'

export function maskWireSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
  protocol: string,
): void {
  if (length <= 0) return
  intents?.recordMaskRange(packetIndex, offset, length, domain, protocol)
  collector.addDeferred(
    offset,
    length,
    () =>
      createProtocolNeutralMaskFill({
        length,
        packetIndex,
        offset,
        domain,
      }),
    { fallbackKind: 'binary-mask', protocol, packetIndex },
  )
}

export function mapTbcdSipPhoneField(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
  protocol: string,
): void {
  if (len <= 0) return
  const slice = buffer.subarray(abs, abs + len)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits || digits.length < 3) {
    maskWireSpan(collector, intents, packetIndex, abs, len, `${domain}-bad`, protocol)
    return
  }
  const phone = `+${digits.replace(/\D/g, '')}`
  const canon = canonicalizeIdentity('sip-phone', phone) ?? phone
  const constraint = { kind: 'text-ascii' as const, byteLength: digits.length }
  intents?.recordEntityReplacement(packetIndex, abs, 'sip-phone', canon, len, constraint, digits)
  collector.addDeferred(
    abs,
    len,
    ({ mapping: live }) => {
      try {
        const alias = live.aliasFor('sip-phone', canon, constraint, digits)
        const digitAlias = alias.replace(/\D/g, '')
        const use = digitAlias.length === digits.length ? digitAlias : digits.replace(/\d/g, '0')
        return (
          remapTbcdBytes(slice, use, TBCD_GSM)
          ?? encodeTbcd(use, len, TBCD_GSM)
          ?? createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
        )
      } catch {
        return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
      }
    },
    { fallbackKind: 'digits', protocol, category: 'sip-phone', packetIndex },
  )
  void mapping
}

/** Plan-path canonical for TBCD phone (same rules as {@link mapTbcdSipPhoneField}). */
export function canonicalTbcdSipPhone(buffer: Uint8Array, abs: number, len: number): string | null {
  if (len <= 0) return null
  const digits = decodeTbcd(buffer.subarray(abs, abs + len), TBCD_GSM)
  if (!digits || digits.length < 3) return null
  const phone = `+${digits.replace(/\D/g, '')}`
  return canonicalizeIdentity('sip-phone', phone) ?? phone
}
