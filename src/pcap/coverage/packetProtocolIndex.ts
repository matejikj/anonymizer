import type { PacketDiscoveryResult } from '../discovery/types'

/** CSR membership: two flat transferable columns, with no retained objects per span. */
export interface PackedPacketProtocols {
  readonly offsets: Uint32Array
  readonly protocolIds: Uint32Array
  readonly protocols: readonly string[]
}

export function buildPacketProtocolIndex(
  packetCount: number,
  summaries: readonly { readonly protocols: readonly string[] }[],
  discovery: readonly PacketDiscoveryResult[],
  sanitizerKinds: readonly { readonly protocol: string; readonly status: string }[],
): PackedPacketProtocols {
  const offsets = new Uint32Array(packetCount + 1)
  const table = new Map<string, number>()
  const packet = new Set<string>()
  const kinds = new Set(sanitizerKinds.map(k => `${k.protocol}\u0000${k.status}`))
  const collect = (i: number) => {
    packet.clear()
    for (const protocol of summaries[i]?.protocols ?? []) packet.add(protocol)
    for (const span of discovery[i]?.coverage ?? []) {
      // Use the same bounded labels as the sanitizer rollup, including its overflow bucket.
      packet.add(kinds.has(`${span.protocol}\u0000${span.status}`) ? span.protocol : 'other')
    }
  }
  for (let i = 0; i < packetCount; i++) {
    collect(i)
    offsets[i + 1] = offsets[i]! + packet.size
    for (const protocol of packet) {
      if (!table.has(protocol)) table.set(protocol, table.size)
    }
  }
  const protocolIds = new Uint32Array(offsets[packetCount]!)
  for (let i = 0; i < packetCount; i++) {
    collect(i)
    let at = offsets[i]!
    for (const protocol of packet) protocolIds[at++] = table.get(protocol)!
  }
  return { offsets, protocolIds, protocols: [...table.keys()] }
}

export function indexedPacketProtocols(index: PackedPacketProtocols | undefined, packetIndex: number): readonly string[] {
  if (!index || packetIndex < 0 || packetIndex + 1 >= index.offsets.length) return []
  const out: string[] = []
  for (let at = index.offsets[packetIndex]!; at < index.offsets[packetIndex + 1]!; at++) {
    out.push(index.protocols[index.protocolIds[at]!]!)
  }
  return out
}
