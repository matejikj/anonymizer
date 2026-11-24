/**
 * Single registry for sanitizer protocol coverage contributions (Stage 10 checklist).
 * New app-layer sanitizers register here — Coverage tab, filter, and labels stay in sync.
 */

export const SANITIZER_PROTOCOL_IDS = [
  'dns',
  'mdns',
  'dhcp',
  'dhcpv6',
  'sip',
  'sdp',
  'rtp',
  'rtcp',
  'srtp',
  'sip-tls',
  'tls',
  'tls-clienthello',
  'tls-serverhello',
  'tls-certificate',
  'tls-handshake-unsupported',
  'tls-encrypted-payload',
  'tls-1.2',
  'tls-1.3',
  'tls-ech',
  'http',
  'heuristic',
  'dmr',
  'mototrbo',
  'ssh',
  'ssh-banner',
  'ssh-kexinit',
  'ssh-kex-reply',
  'ssh-newkeys',
  'quic',
  'quic-initial',
  'quic-handshake',
  'quic-vn',
  'quic-retry',
  'quic-0rtt',
  'ike',
  'ike-header',
  'ike-sk',
  'ike-notify',
  'ike-natt-marker',
  'wireguard',
  'wireguard-handshake',
  'wireguard-cookie',
  'esp',
  'ah',
  'tunnel',
  // CF-11 fingerprint coverage tokens (filterable / registry-synced)
  'ipv4-id',
  'ipv4-ttl',
  'ipv6-flow',
  'ipv6-hop',
  'tcp-seq',
  'tcp-window',
  'tcp-options',
] as const

export type SanitizerProtocolId = (typeof SANITIZER_PROTOCOL_IDS)[number]

const SANITIZER_SET = new Set<string>(SANITIZER_PROTOCOL_IDS)

export function isSanitizerProtocol(protocol: string): boolean {
  return SANITIZER_SET.has(protocol)
}

export function allKnownProtocols(structuralIds: Iterable<string>, sanitizerIds: Iterable<string>): string[] {
  const set = new Set<string>()
  for (const id of structuralIds) set.add(id)
  for (const id of sanitizerIds) set.add(id)
  for (const id of SANITIZER_PROTOCOL_IDS) set.add(id)
  return [...set].sort()
}
