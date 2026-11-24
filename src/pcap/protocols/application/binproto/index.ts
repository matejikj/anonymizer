/**
 * T16 — binary protocol toolkit (TLV, BER, TBCD, UTF-16, NTLMSSP/SPNEGO).
 */

export { SoftCursor, type BinParseIssue } from './softCursor'

export {
  walkTlv,
  type TlvDescriptor,
  type TlvElement,
  type TlvWalkResult,
} from './tlv'

export {
  readBerTag,
  readBerLength,
  walkBer,
  readAsn1LengthCompat,
  type BerTag,
  type BerLength,
  type BerNode,
  type BerWalkOptions,
  type BerTagClass,
} from './ber'

export {
  decodeTbcd,
  encodeTbcd,
  remapTbcdBytes,
  normalizeImsiDigits,
  normalizeImeiDigits,
  imeiLuhnCheckDigit,
  isValidImeiLuhn,
  finalizeImeiAliasDigits,
  IMSI_PLMN_SCOPE_SEP,
  imsiWireDigits,
  scopeImsiWithPlmn,
  TBCD_GSM,
  BCD_HIGH_FIRST,
  type TbcdCodecOptions,
  type NibbleOrder,
} from './tbcd'

export {
  computeFixedLengthUtf16Bytes,
  patchFixedLengthUtf16,
  decodeUtf16,
  type Utf16Endian,
} from './utf16'

export {
  looksLikeNtlmssp,
  parseNtlmssp,
  sanitizeNtlmssp,
  type NtlmMessageType,
  type NtlmParseResult,
  type NtlmSecurityBuffer,
} from './ntlmssp'

export {
  looksLikeSpnego,
  sanitizeSpnego,
} from './spnego'
