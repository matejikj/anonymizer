/**
 * T31 pilot — RND Dispatch Lite (project-owned synthetic proprietary dialect).
 *
 * Not a vendor protocol: authored here so the descriptor framework has a legally
 * usable schema + synthetic corpus. MOTOTRBO/Hytera remain mask-only until a
 * licensed vendor schema exists.
 *
 * Wire (UDP): magic "RND1" + 24-byte header; body masked (GPS / text / unknown).
 */

import type { WireProtocolDescriptor } from './types.ts'
import { DESCRIPTOR_SCHEMA_VERSION } from './types.ts'

export const RND_DISPATCH_LITE_UDP_PORT = 49_992
export const RND_DISPATCH_LITE_MAGIC = [0x52, 0x4e, 0x44, 0x31] as const // RND1

const HEADER_FIELDS = [
  {
    name: 'magic',
    offset: 0,
    length: 4,
    disposition: { kind: 'preserve' as const, reason: 'framing magic RND1' },
  },
  {
    name: 'version',
    offset: 4,
    length: 1,
    disposition: { kind: 'preserve' as const, reason: 'protocol version enum' },
  },
  {
    name: 'msgType',
    offset: 5,
    length: 1,
    disposition: { kind: 'preserve' as const, reason: 'message type discriminator' },
  },
  {
    name: 'flags',
    offset: 6,
    length: 1,
    disposition: { kind: 'preserve' as const, reason: 'bit flags without identity' },
  },
  {
    name: 'reserved',
    offset: 7,
    length: 1,
    disposition: { kind: 'mask' as const },
  },
  {
    name: 'srcRadioId',
    offset: 8,
    length: 3,
    disposition: { kind: 'map' as const, category: 'radioId' as const, format: 'u24' as const },
  },
  {
    name: 'dstRadioId',
    offset: 11,
    length: 3,
    disposition: { kind: 'map' as const, category: 'radioId' as const, format: 'u24' as const },
  },
  {
    name: 'siteId',
    offset: 14,
    length: 4,
    disposition: { kind: 'map' as const, category: 'opaque-id' as const, format: 'bytes' as const },
  },
  {
    name: 'seq',
    offset: 18,
    length: 4,
    disposition: {
      kind: 'preserve' as const,
      reason: 'diagnostic sequence counter (not a subscriber identity)',
    },
  },
  {
    name: 'pad',
    offset: 22,
    length: 2,
    disposition: { kind: 'mask' as const },
  },
] as const

export const rndDispatchLiteDescriptor: WireProtocolDescriptor = {
  schemaVersion: DESCRIPTOR_SCHEMA_VERSION,
  id: 'rnd-dispatch-lite',
  title: 'RND Dispatch Lite (synthetic proprietary pilot)',
  profileVersion: '1.0.0',
  specRefs: [
    'synthetic proprietary pilot — see descriptor module + unit tests',
  ],
  transport: { udpPorts: [RND_DISPATCH_LITE_UDP_PORT] },
  framing: {
    kind: 'fixed-magic',
    endian: 'be',
    magic: RND_DISPATCH_LITE_MAGIC,
    headerLength: 24,
  },
  variants: [
    {
      when: { fieldOffset: 5, fieldLength: 1, equals: 0 },
      fields: HEADER_FIELDS,
      trailing: { kind: 'mask' },
    },
    {
      when: { fieldOffset: 5, fieldLength: 1, equals: 1 },
      fields: HEADER_FIELDS,
      trailing: { kind: 'mask' }, // GPS / location body
    },
    {
      when: { fieldOffset: 5, fieldLength: 1, equals: 2 },
      fields: HEADER_FIELDS,
      trailing: { kind: 'mask' }, // text page body
    },
  ],
  unknownVariant: {
    headerFields: HEADER_FIELDS,
    trailing: { kind: 'mask' },
  },
}

/** Build a synthetic RND Dispatch Lite datagram for tests/corpus. */
export function buildRndDispatchLiteDatagram(options: {
  readonly msgType: 0 | 1 | 2
  readonly srcRadioId: number
  readonly dstRadioId: number
  readonly siteId: number
  readonly seq?: number
  readonly body?: Uint8Array
}): Uint8Array {
  const body = options.body ?? new Uint8Array(0)
  const out = new Uint8Array(24 + body.byteLength)
  out[0] = 0x52
  out[1] = 0x4e
  out[2] = 0x44
  out[3] = 0x31
  out[4] = 1
  out[5] = options.msgType
  out[6] = 0
  out[7] = 0xaa
  const src = options.srcRadioId & 0xffffff
  out[8] = (src >>> 16) & 0xff
  out[9] = (src >>> 8) & 0xff
  out[10] = src & 0xff
  const dst = options.dstRadioId & 0xffffff
  out[11] = (dst >>> 16) & 0xff
  out[12] = (dst >>> 8) & 0xff
  out[13] = dst & 0xff
  const site = options.siteId >>> 0
  out[14] = (site >>> 24) & 0xff
  out[15] = (site >>> 16) & 0xff
  out[16] = (site >>> 8) & 0xff
  out[17] = site & 0xff
  const seq = (options.seq ?? 1) >>> 0
  out[18] = (seq >>> 24) & 0xff
  out[19] = (seq >>> 16) & 0xff
  out[20] = (seq >>> 8) & 0xff
  out[21] = seq & 0xff
  out[22] = 0
  out[23] = 0
  out.set(body, 24)
  return out
}
