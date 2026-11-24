/**
 * Minimal, self-contained L2/L3/L4 address extraction for recovery-session counterpart bytes.
 *
 * The packet list's Source/Destination columns and display-filter context normally read
 * precomputed entity values from `session.analysis` — built once for whichever file was loaded.
 * In a recovery session that file is the *anonymized* capture, so those precomputed values are
 * the anonymized addresses; running them through the app's usual alias-mapping
 * (`viewFilterContext.ts`) for the "anonymized" pane would just produce a further, unrelated
 * pseudonym, not the true original. This module re-derives the addressing fields directly from
 * the restored bytes instead (fixed-offset header reads, not a full protocol dissection), so the
 * "anonymized" pane in a recovery session can show the real original endpoints.
 */

const ETHERTYPE_VLAN = 0x8100
const ETHERTYPE_QINQ = 0x88a8
const ETHERTYPE_IPV4 = 0x0800
const ETHERTYPE_ARP = 0x0806
const ETHERTYPE_IPV6 = 0x86dd
const LINK_TYPE_ETHERNET = 1

export interface CounterpartEndpointFields {
  readonly srcIpv4?: string
  readonly dstIpv4?: string
  readonly srcIpv6?: string
  readonly dstIpv6?: string
  readonly srcMac?: string
  readonly dstMac?: string
  readonly srcPort?: number
  readonly dstPort?: number
  readonly l4Proto?: 'tcp' | 'udp'
}

function macAt(data: Uint8Array, offset: number): string | undefined {
  if (offset + 6 > data.byteLength) return undefined
  return Array.from(data.subarray(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
}

function ipv4At(data: Uint8Array, offset: number): string | undefined {
  if (offset + 4 > data.byteLength) return undefined
  return `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`
}

function ipv6At(data: Uint8Array, offset: number): string | undefined {
  if (offset + 16 > data.byteLength) return undefined
  const groups: string[] = []
  for (let i = 0; i < 16; i += 2) {
    groups.push(((data[offset + i]! << 8) | data[offset + i + 1]!).toString(16))
  }
  return groups.join(':')
}

function readPorts(data: Uint8Array, l4Offset: number, protocol: number): Pick<CounterpartEndpointFields, 'srcPort' | 'dstPort' | 'l4Proto'> {
  if (protocol !== 6 && protocol !== 17) return {}
  if (l4Offset + 4 > data.byteLength) return {}
  const srcPort = (data[l4Offset]! << 8) | data[l4Offset + 1]!
  const dstPort = (data[l4Offset + 2]! << 8) | data[l4Offset + 3]!
  return { srcPort, dstPort, l4Proto: protocol === 6 ? 'tcp' : 'udp' }
}

function extractFromIpv4(data: Uint8Array, ipOffset: number): CounterpartEndpointFields {
  if (ipOffset + 20 > data.byteLength) return {}
  const ihl = (data[ipOffset]! & 0x0f) * 4
  const protocol = data[ipOffset + 9]!
  const srcIpv4 = ipv4At(data, ipOffset + 12)
  const dstIpv4 = ipv4At(data, ipOffset + 16)
  const ports = readPorts(data, ipOffset + Math.max(ihl, 20), protocol)
  return { srcIpv4, dstIpv4, ...ports }
}

function extractFromIpv6(data: Uint8Array, ipOffset: number): CounterpartEndpointFields {
  if (ipOffset + 40 > data.byteLength) return {}
  const nextHeader = data[ipOffset + 6]!
  const srcIpv6 = ipv6At(data, ipOffset + 8)
  const dstIpv6 = ipv6At(data, ipOffset + 24)
  const ports = readPorts(data, ipOffset + 40, nextHeader)
  return { srcIpv6, dstIpv6, ...ports }
}

function extractFromArp(data: Uint8Array, arpOffset: number): CounterpartEndpointFields {
  // Standard Ethernet/IPv4 ARP: hwType(2) protoType(2) hwLen(1) protoLen(1) opcode(2) = 8 bytes,
  // then senderMac(6) senderIp(4) targetMac(6) targetIp(4).
  if (arpOffset + 8 + 6 + 4 + 6 + 4 > data.byteLength) return {}
  const senderMac = macAt(data, arpOffset + 8)
  const senderIp = ipv4At(data, arpOffset + 14)
  const targetIp = ipv4At(data, arpOffset + 24)
  return { srcMac: senderMac, srcIpv4: senderIp, dstIpv4: targetIp }
}

/** Reads Ethernet (+ up to one VLAN/QinQ tag) then dispatches on ethertype. */
export function extractEndpointFields(data: Uint8Array, linkType: number): CounterpartEndpointFields {
  if (linkType !== LINK_TYPE_ETHERNET || data.byteLength < 14) return {}
  const dstMac = macAt(data, 0)
  const srcMac = macAt(data, 6)
  let cursor = 12
  let ethertype = (data[cursor]! << 8) | data[cursor + 1]!
  cursor += 2
  for (let i = 0; i < 2 && (ethertype === ETHERTYPE_VLAN || ethertype === ETHERTYPE_QINQ); i++) {
    if (cursor + 4 > data.byteLength) return { srcMac, dstMac }
    cursor += 2 // skip VLAN tag control info, ethertype/length field follows
    ethertype = (data[cursor]! << 8) | data[cursor + 1]!
    cursor += 2
  }
  if (ethertype === ETHERTYPE_IPV4) return { srcMac, dstMac, ...extractFromIpv4(data, cursor) }
  if (ethertype === ETHERTYPE_IPV6) return { srcMac, dstMac, ...extractFromIpv6(data, cursor) }
  if (ethertype === ETHERTYPE_ARP) return { srcMac, dstMac, ...extractFromArp(data, cursor) }
  return { srcMac, dstMac }
}

export function counterpartEndpointPair(
  fields: CounterpartEndpointFields | undefined,
): { source: string; dest: string } {
  if (fields?.srcIpv4) return { source: fields.srcIpv4, dest: fields.dstIpv4 ?? fields.srcIpv4 }
  if (fields?.srcMac) return { source: fields.srcMac, dest: fields.dstMac ?? fields.srcMac }
  return { source: '—', dest: '—' }
}
