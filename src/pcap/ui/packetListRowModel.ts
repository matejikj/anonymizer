/**
 * Wireshark-like packet list row display model (step 1).
 */

import type { PacketRecordDescriptor } from '../domain/types'
import { protocolLabel } from './formatters'
import type { PacketRowMeta } from './pcapSession'
import type { UnifiedLayerCoverage } from '../coverage/types'

/** Highest-signal protocol for packet list (app layer before transport). */
const DISPLAY_PROTOCOL_PRIORITY = [
  'sip',
  'sdp',
  'sip-tls',
  'tls-clienthello',
  'tls-serverhello',
  'tls-certificate',
  'tls-handshake-unsupported',
  'tls-encrypted-payload',
  'tls-1.2',
  'tls-1.3',
  'tls-ech',
  'rtp',
  'rtcp',
  'srtp',
  'dns',
  'mdns',
  'dhcp',
  'dhcpv6',
  'http',
  'tls',
  'heuristic',
  'dmr',
  'mototrbo',
  'tcp',
  'udp',
  'icmpv4',
  'icmpv6',
  'ipv4',
  'ipv6',
  'arp',
  'ethernet',
  'vlan',
] as const

export interface EndpointPair {
  readonly source: string
  readonly dest: string
}

export function endpointsFromBytes(data: Uint8Array, linkType: number): EndpointPair {
  if (linkType === 1 && data.length >= 34 && data[12] === 0x08 && data[13] === 0x00) {
    return {
      source: `${data[26]}.${data[27]}.${data[28]}.${data[29]}`,
      dest: `${data[30]}.${data[31]}.${data[32]}.${data[33]}`,
    }
  }
  if (linkType === 1 && data.length >= 14) {
    const fmt = (off: number) =>
      Array.from(data.slice(off, off + 6))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(':')
    return { source: fmt(6), dest: fmt(0) }
  }
  return { source: '—', dest: '—' }
}

export function highestProtocol(protocols: readonly string[] | undefined): string {
  if (!protocols?.length) return '—'
  const lower = new Set(protocols.map((p) => p.toLowerCase()))
  for (const p of DISPLAY_PROTOCOL_PRIORITY) {
    if (lower.has(p)) return protocolLabel(p)
  }
  return protocolLabel(protocols[protocols.length - 1]!)
}

export function relativeTimeSeconds(
  descriptor: PacketRecordDescriptor,
  base: PacketRecordDescriptor | null,
): string {
  if (!base) return '0.000000'
  const delta =
    descriptor.timestamp.ticks -
    base.timestamp.ticks +
    (descriptor.timestamp.offsetSeconds - base.timestamp.offsetSeconds) *
      descriptor.timestamp.unitsPerSecond
  const seconds = Number(delta) / Number(descriptor.timestamp.unitsPerSecond)
  if (!Number.isFinite(seconds)) return '—'
  return seconds.toFixed(6)
}

export function deltaFromPrevious(
  descriptor: PacketRecordDescriptor,
  previous: PacketRecordDescriptor | null,
): string {
  if (!previous) return '0.000000'
  const delta = descriptor.timestamp.ticks - previous.timestamp.ticks
  const seconds = Number(delta) / Number(descriptor.timestamp.unitsPerSecond)
  if (!Number.isFinite(seconds)) return '—'
  return seconds.toFixed(6)
}

export function packetMark(meta: PacketRowMeta, spans: readonly UnifiedLayerCoverage[]): string {
  if (meta.drop) return 'D'
  if (spans.some((s) => s.status === 'requires-reassembly')) return '~'
  if (meta.discovery?.issues.length || meta.summary?.issues.length) return '!'
  if (meta.changed) return 'M'
  return ''
}

export function packetInfoWithPatches(
  meta: PacketRowMeta,
  patchCount: number,
  protocols?: readonly string[],
): string {
  if (meta.drop) return 'Dropped'
  const issues = meta.discovery?.issues ?? meta.summary?.issues ?? []
  if (issues.length > 0) return issues[0]!
  if (meta.changed) return patchCount > 0 ? `Changed (${patchCount} fields)` : 'Changed'
  return highestProtocol(protocols ?? meta.summary?.protocols)
}
