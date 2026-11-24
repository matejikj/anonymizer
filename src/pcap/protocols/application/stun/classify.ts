/**
 * STUN / TURN message shape detection (RFC 8489 / RFC 8656).
 * First two bits must be 00; magic cookie 0x2112A442.
 */

export const STUN_MAGIC_COOKIE = 0x2112a442
export const STUN_HEADER_BYTES = 20
export const STUN_FINGERPRINT_XOR = 0x5354554e

/** Attribute types we sanitize or special-case. */
export const STUN_ATTR = {
  MAPPED_ADDRESS: 0x0001,
  USERNAME: 0x0006,
  MESSAGE_INTEGRITY: 0x0008,
  ERROR_CODE: 0x0009,
  UNKNOWN_ATTRIBUTES: 0x000a,
  CHANNEL_NUMBER: 0x000c,
  LIFETIME: 0x000d,
  XOR_PEER_ADDRESS: 0x0012,
  DATA: 0x0013,
  REALM: 0x0014,
  NONCE: 0x0015,
  XOR_RELAYED_ADDRESS: 0x0016,
  MESSAGE_INTEGRITY_SHA256: 0x001c,
  USERHASH: 0x001e,
  XOR_MAPPED_ADDRESS: 0x0020,
  PRIORITY: 0x0024,
  USE_CANDIDATE: 0x0025,
  SOFTWARE: 0x8022,
  ALTERNATE_SERVER: 0x8023,
  FINGERPRINT: 0x8028,
  ICE_CONTROLLED: 0x8029,
  ICE_CONTROLLING: 0x802a,
  RESPONSE_ORIGIN: 0x802b,
  OTHER_ADDRESS: 0x802c,
} as const

export interface StunHeader {
  readonly messageType: number
  readonly length: number
  readonly magicCookie: number
  readonly transactionId: Uint8Array
  readonly headerLength: number
  readonly messageBytes: number
}

export function looksLikeStun(data: Uint8Array, offset: number, length: number): boolean {
  if (length < STUN_HEADER_BYTES) return false
  // First two bits must be zero (STUN vs RTP version).
  if ((data[offset]! & 0xc0) !== 0) return false
  const magic =
    ((data[offset + 4]! << 24) >>> 0)
    + (data[offset + 5]! << 16)
    + (data[offset + 6]! << 8)
    + data[offset + 7]!
  if (magic !== STUN_MAGIC_COOKIE) return false
  const msgLen = (data[offset + 2]! << 8) | data[offset + 3]!
  if (msgLen % 4 !== 0) return false
  if (STUN_HEADER_BYTES + msgLen > length) return false
  return true
}

export function parseStunHeader(
  data: Uint8Array,
  offset: number,
  length: number,
): StunHeader | null {
  if (!looksLikeStun(data, offset, length)) return null
  const messageType = (data[offset]! << 8) | data[offset + 1]!
  const msgLen = (data[offset + 2]! << 8) | data[offset + 3]!
  const magic =
    ((data[offset + 4]! << 24) >>> 0)
    + (data[offset + 5]! << 16)
    + (data[offset + 6]! << 8)
    + data[offset + 7]!
  return {
    messageType,
    length: msgLen,
    magicCookie: magic,
    transactionId: data.subarray(offset + 8, offset + 20),
    headerLength: STUN_HEADER_BYTES,
    messageBytes: STUN_HEADER_BYTES + msgLen,
  }
}

export function isXorAddressAttr(type: number): boolean {
  return (
    type === STUN_ATTR.XOR_MAPPED_ADDRESS
    || type === STUN_ATTR.XOR_PEER_ADDRESS
    || type === STUN_ATTR.XOR_RELAYED_ADDRESS
  )
}

export function isPlainAddressAttr(type: number): boolean {
  return (
    type === STUN_ATTR.MAPPED_ADDRESS
    || type === STUN_ATTR.RESPONSE_ORIGIN
    || type === STUN_ATTR.OTHER_ADDRESS
    || type === STUN_ATTR.ALTERNATE_SERVER
  )
}

export function isMessageIntegrityAttr(type: number): boolean {
  return type === STUN_ATTR.MESSAGE_INTEGRITY || type === STUN_ATTR.MESSAGE_INTEGRITY_SHA256
}
