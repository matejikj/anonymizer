/**
 * T31 — apply a validated wire-protocol descriptor to a UDP/TCP payload (length-preserving).
 */

import type { PatchCollector } from '../../sanitize/PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { AppLayerResult } from '../../sanitize/types.ts'
import type {
  DescriptorField,
  DescriptorMessageVariant,
  WireProtocolDescriptor,
} from './types.ts'

function matchesMagic(
  buffer: Uint8Array,
  offset: number,
  length: number,
  magic: readonly number[],
): boolean {
  if (length < magic.length) return false
  for (let i = 0; i < magic.length; i++) {
    if (buffer[offset + i] !== magic[i]) return false
  }
  return true
}

function pickVariant(
  buffer: Uint8Array,
  offset: number,
  length: number,
  desc: WireProtocolDescriptor,
): DescriptorMessageVariant | null {
  if (length < desc.framing.headerLength) return null
  for (const variant of desc.variants) {
    const { fieldOffset, fieldLength, equals } = variant.when
    if (fieldOffset + fieldLength > length) continue
    let value = 0
    for (let i = 0; i < fieldLength; i++) {
      value = (value << 8) | buffer[offset + fieldOffset + i]!
    }
    if (value === equals) return variant
  }
  return null
}

function readUIntBE(buffer: Uint8Array, offset: number, length: number): number {
  let v = 0
  for (let i = 0; i < length; i++) v = (v << 8) | buffer[offset + i]!
  return v >>> 0
}

function writeUIntBE(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = length - 1; i >= 0; i--) {
    out[i] = value & 0xff
    value = value >>> 8
  }
  return out
}

function applyField(
  buffer: Uint8Array,
  base: number,
  field: DescriptorField,
  collector: PatchCollector,
  _mapping: MappingLike,
  protocolId: string,
): void {
  void _mapping
  const abs = base + field.offset
  const { disposition, length } = field
  if (disposition.kind === 'preserve') return
  if (disposition.kind === 'mask' || disposition.kind === 'secret') {
    try {
      collector.add(abs, new Uint8Array(length))
    } catch {
      /* overlap */
    }
    return
  }
  if (disposition.kind === 'time') {
    // Without PayloadTimeSession in this path, fail-closed mask (never leak wall-clock).
    try {
      collector.add(abs, new Uint8Array(length))
    } catch {
      /* overlap */
    }
    return
  }
  // map
  const format = disposition.format
  const category = disposition.category
  if (format === 'ascii' || format === 'bytes') {
    const raw = buffer.subarray(abs, abs + length)
    const canonical =
      format === 'ascii'
        ? new TextDecoder('utf-8', { fatal: false }).decode(raw).replace(/\0+$/, '')
        : Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join('')
    try {
      collector.addDeferred(abs, length, ({ mapping: live }) => {
        const alias = live.map(category, canonical)
        if (format === 'ascii') {
          const enc = new TextEncoder().encode(alias)
          const out = new Uint8Array(length)
          out.set(enc.subarray(0, Math.min(enc.length, length)))
          return out
        }
        // hex bytes — map returns opaque string; pad/truncate to length
        const hex = alias.replace(/[^0-9a-f]/gi, '').padEnd(length * 2, '0')
        const out = new Uint8Array(length)
        for (let i = 0; i < length; i++) {
          out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16) & 0xff
        }
        return out
      }, { fallbackKind: 'binary-mask', protocol: protocolId, category })
    } catch {
      /* overlap */
    }
    return
  }

  const width =
    format === 'u8' ? 1 : format === 'u16' ? 2 : format === 'u24' ? 3 : format === 'u32' ? 4 : length
  const span = Math.min(width, length)
  const value = readUIntBE(buffer, abs, span)
  try {
    collector.addDeferred(abs, span, ({ mapping: live }) => {
      const mapped = Number.parseInt(live.map(category, String(value)), 10)
      if (!Number.isFinite(mapped)) return new Uint8Array(span)
      return writeUIntBE(mapped >>> 0, span)
    }, { fallbackKind: 'binary-mask', protocol: protocolId, category })
  } catch {
    /* overlap */
  }
}

function applyFields(
  buffer: Uint8Array,
  base: number,
  fields: readonly DescriptorField[],
  collector: PatchCollector,
  mapping: MappingLike,
  protocolId: string,
): void {
  for (const field of fields) {
    applyField(buffer, base, field, collector, mapping, protocolId)
  }
}

function applyTrailing(
  base: number,
  headerLength: number,
  messageLength: number,
  trailing: { readonly kind: 'mask' } | { readonly kind: 'preserve'; readonly reason: string } | undefined,
  collector: PatchCollector,
): 'covered' | 'preserved-unsafe' | 'redacted' {
  const bodyLen = messageLength - headerLength
  if (bodyLen <= 0) return 'covered'
  if (trailing?.kind === 'preserve') {
    return 'preserved-unsafe'
  }
  try {
    collector.add(base + headerLength, new Uint8Array(bodyLen))
  } catch {
    /* overlap */
  }
  return 'redacted'
}

/**
 * Sanitize one message using a descriptor. Returns null when magic does not match.
 */
export function sanitizeFromDescriptor(
  desc: WireProtocolDescriptor,
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
): AppLayerResult | null {
  if (!matchesMagic(buffer, offset, length, desc.framing.magic)) return null
  if (length < desc.framing.headerLength) {
    return {
      coverage: [
        {
          protocol: desc.id,
          offset,
          length,
          status: 'malformed',
        },
      ],
    }
  }

  const variant = pickVariant(buffer, offset, length, desc)
  const fields = variant?.fields ?? desc.unknownVariant.headerFields
  const trailing = variant?.trailing ?? desc.unknownVariant.trailing

  applyFields(buffer, offset, fields, collector, mapping, desc.id)
  const trailStatus = applyTrailing(
    offset,
    desc.framing.headerLength,
    length,
    trailing,
    collector,
  )

  const headerStatus = variant ? 'covered' : 'unsupported'
  return {
    coverage: [
      {
        protocol: desc.id,
        offset,
        length: desc.framing.headerLength,
        status: headerStatus,
      },
      ...(length > desc.framing.headerLength
        ? [
            {
              protocol: `${desc.id}-body`,
              offset: offset + desc.framing.headerLength,
              length: length - desc.framing.headerLength,
              status: trailStatus === 'preserved-unsafe' ? ('preserved-unsafe' as const) : ('redacted' as const),
            },
          ]
        : []),
    ],
  }
}

/** True when destination port is listed on the descriptor (hint only; magic decides claim). */
export function descriptorPortHint(
  desc: WireProtocolDescriptor,
  dstPort: number,
  transport: 'udp' | 'tcp',
): boolean {
  const ports = transport === 'udp' ? desc.transport.udpPorts : desc.transport.tcpPorts
  if (!ports || ports.length === 0) return true
  return ports.includes(dstPort)
}
