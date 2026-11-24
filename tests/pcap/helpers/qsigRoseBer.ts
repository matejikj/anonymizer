/**
 * Synthetic BER encoders for QSIG Facility ROSE tests (ECMA-165 implicit tags).
 */

import { QSIG_OP } from '../../../src/pcap/protocols/application/qsig/index.ts'

export function berLength(n: number): number[] {
  if (n < 0x80) return [n]
  if (n < 0x100) return [0x81, n]
  return [0x82, (n >> 8) & 0xff, n & 0xff]
}

function berInteger(value: number): number[] {
  if (value === 0) return [0x02, 0x01, 0x00]
  if (value > 0 && value < 0x80) return [0x02, 0x01, value & 0xff]
  return [0x02, 0x01, value & 0xff]
}

/** IA5String (UNIVERSAL 22). */
export function berIa5String(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text)
  return Uint8Array.from([0x16, ...berLength(bytes.length), ...bytes])
}

/** OCTET STRING (UNIVERSAL 4). */
export function berOctetString(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from([0x04, ...berLength(bytes.length), ...bytes])
}

/** ROSE invoke [1] with local opcode INTEGER and optional argument TLV bytes. */
export function encodeQsigRoseInvoke(opcode: number, argumentTlv?: Uint8Array): Uint8Array {
  const body: number[] = []
  body.push(...berInteger(1)) // invokeId
  body.push(...berInteger(opcode))
  if (argumentTlv && argumentTlv.length > 0) {
    body.push(...argumentTlv)
  }
  return Uint8Array.from([0xa1, ...berLength(body.length), ...body])
}

export function buildCallingNameInvoke(canaryName: string): Uint8Array {
  const arg = berIa5String(canaryName)
  return encodeQsigRoseInvoke(QSIG_OP.CALLING_NAME, arg)
}

export function buildUnknownOpInvoke(opcode: number, secret: string): Uint8Array {
  const arg = berOctetString(new TextEncoder().encode(secret))
  return encodeQsigRoseInvoke(opcode, arg)
}
