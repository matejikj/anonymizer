/**
 * T33 — IPv6 address-form helpers (solicited-node, embedded IPv4, EUI-64 shape).
 * Used by SessionMapping and shared IPv6 canonicalization. No original values in errors.
 */

/** Expand compressed IPv6 text to 8 lowercase hextets (no `::`). */
export function expandIpv6Canonical(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase().replace(/\s+/g, '')
  if (!trimmed.includes(':')) return null
  if (trimmed === '::') return '0:0:0:0:0:0:0:0'

  const sides = trimmed.split('::')
  if (sides.length > 2) return null

  const parseGroup = (group: string): number | null => {
    if (group.length === 0 || group.length > 4) return null
    if (!/^[0-9a-f]+$/.test(group)) return null
    return Number.parseInt(group, 16)
  }

  const left = sides[0]!.length === 0 ? [] : sides[0]!.split(':')
  const right = sides.length === 2 ? (sides[1]!.length === 0 ? [] : sides[1]!.split(':')) : []

  // IPv4-mapped / IPv4-compatible tail: last group may be dotted-quad.
  const expandDotted = (groups: string[]): string[] | null => {
    if (groups.length === 0) return groups
    const last = groups[groups.length - 1]!
    if (!last.includes('.')) return groups
    const parts = last.split('.')
    if (parts.length !== 4) return null
    const nums: number[] = []
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return null
      const n = Number(p)
      if (n > 255) return null
      nums.push(n)
    }
    const hi = ((nums[0]! << 8) | nums[1]!).toString(16)
    const lo = ((nums[2]! << 8) | nums[3]!).toString(16)
    return [...groups.slice(0, -1), hi, lo]
  }

  const leftExpanded = expandDotted(left)
  const rightExpanded = expandDotted(right)
  if (leftExpanded === null || rightExpanded === null) return null

  if (sides.length === 1 && leftExpanded.length !== 8) return null
  if (sides.length === 2 && leftExpanded.length + rightExpanded.length >= 8) return null

  const groups: number[] = []
  for (const g of leftExpanded) {
    const v = parseGroup(g)
    if (v === null) return null
    groups.push(v)
  }
  if (sides.length === 2) {
    const missing = 8 - leftExpanded.length - rightExpanded.length
    for (let i = 0; i < missing; i++) groups.push(0)
    for (const g of rightExpanded) {
      const v = parseGroup(g)
      if (v === null) return null
      groups.push(v)
    }
  }
  if (groups.length !== 8) return null
  return groups.map((g) => g.toString(16)).join(':')
}

export function ipv6Groups(expanded: string): readonly number[] | null {
  const parts = expanded.split(':')
  if (parts.length !== 8) return null
  const out: number[] = []
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(p)) return null
    out.push(Number.parseInt(p, 16) & 0xffff)
  }
  return out
}

export function formatIpv6Groups(groups: readonly number[]): string {
  return groups.map((g) => (g & 0xffff).toString(16)).join(':')
}

/** Well-known / link-scoped multicast constants safe to preserve (not identity-bearing suffixes). */
const PRESERVED_IPV6_MULTICAST = new Set<string>([
  'ff01:0:0:0:0:0:0:1', // all nodes (interface-local)
  'ff01:0:0:0:0:0:0:2', // all routers
  'ff02:0:0:0:0:0:0:1', // all nodes
  'ff02:0:0:0:0:0:0:2', // all routers
  'ff02:0:0:0:0:0:0:16', // MLDv2
  'ff02:0:0:0:0:0:0:fb', // mDNS
  'ff02:0:0:0:0:0:1:2', // DHCPv6 / All_DHCP_Relay_Agents_and_Servers
  'ff02:0:0:0:0:0:1:3', // LLMNR
  'ff05:0:0:0:0:0:1:3', // DHCP site
])

export function isPreservedIpv6Multicast(expanded: string): boolean {
  return PRESERVED_IPV6_MULTICAST.has(expanded)
}

/** Solicited-node: ff02:0:0:0:0:1:ffXX:XXXX (RFC 4291). */
export function isSolicitedNodeIpv6(expanded: string): boolean {
  const g = ipv6Groups(expanded)
  if (!g) return false
  return (
    g[0] === 0xff02 &&
    g[1] === 0 &&
    g[2] === 0 &&
    g[3] === 0 &&
    g[4] === 0 &&
    g[5] === 1 &&
    (g[6]! & 0xff00) === 0xff00
  )
}

export function solicitedNodeLow24(expanded: string): number | null {
  if (!isSolicitedNodeIpv6(expanded)) return null
  const g = ipv6Groups(expanded)!
  return ((g[6]! & 0xff) << 16) | (g[7]! & 0xffff)
}

export function formatSolicitedNodeIpv6(low24: number): string {
  const n = low24 & 0xffffff
  const g6 = 0xff00 | ((n >>> 16) & 0xff)
  const g7 = n & 0xffff
  return formatIpv6Groups([0xff02, 0, 0, 0, 0, 1, g6, g7])
}

export function unicastLow24(expanded: string): number | null {
  const g = ipv6Groups(expanded)
  if (!g) return null
  if ((g[0]! & 0xff00) === 0xff00) return null // multicast
  if (g.every((x) => x === 0)) return null
  return ((g[6]! & 0xff) << 16) | (g[7]! & 0xffff)
}

export function isIpv6Multicast(expanded: string): boolean {
  const g = ipv6Groups(expanded)
  if (!g) return false
  return (g[0]! & 0xff00) === 0xff00
}

/** IPv6 multicast Ethernet: 33:33 + low 32 bits of IPv6 (RFC 2464). */
export function isIpv6MulticastMac(mac: string): boolean {
  const m = mac.toLowerCase()
  return m.startsWith('33:33:')
}

export function isSolicitedNodeMac(mac: string): boolean {
  const m = mac.toLowerCase()
  return /^33:33:ff:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/.test(m)
}

export function solicitedNodeMacLow24(mac: string): number | null {
  if (!isSolicitedNodeMac(mac)) return null
  const parts = mac.toLowerCase().split(':')
  return (
    ((Number.parseInt(parts[3]!, 16) & 0xff) << 16) |
    ((Number.parseInt(parts[4]!, 16) & 0xff) << 8) |
    (Number.parseInt(parts[5]!, 16) & 0xff)
  )
}

export function formatSolicitedNodeMac(low24: number): string {
  const n = low24 & 0xffffff
  const b3 = ((n >>> 16) & 0xff).toString(16).padStart(2, '0')
  const b4 = ((n >>> 8) & 0xff).toString(16).padStart(2, '0')
  const b5 = (n & 0xff).toString(16).padStart(2, '0')
  return `33:33:ff:${b3}:${b4}:${b5}`
}

export function macLow32FromIpv6Multicast(expanded: string): number | null {
  const g = ipv6Groups(expanded)
  if (!g || !isIpv6Multicast(expanded)) return null
  return ((g[6]! & 0xffff) << 16) | (g[7]! & 0xffff)
}

export function formatIpv6MulticastMac(low32: number): string {
  const n = low32 >>> 0
  const b = [
    0x33,
    0x33,
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ]
  return b.map((x) => x.toString(16).padStart(2, '0')).join(':')
}

export type EmbeddedIpv4Kind =
  | { readonly kind: 'ipv4-mapped'; readonly ipv4: string }
  | { readonly kind: 'nat64-well-known'; readonly ipv4: string }
  | { readonly kind: '6to4'; readonly ipv4: string; readonly rest: readonly number[] }
  | { readonly kind: 'isatap'; readonly ipv4: string; readonly prefix: readonly number[] }
  | { readonly kind: 'teredo'; readonly serverIpv4: string; readonly clientIpv4: string; readonly udpPort: number }

export function classifyEmbeddedIpv4(expanded: string): EmbeddedIpv4Kind | null {
  const g = ipv6Groups(expanded)
  if (!g) return null

  // ::ffff:a.b.c.d
  if (
    g[0] === 0 &&
    g[1] === 0 &&
    g[2] === 0 &&
    g[3] === 0 &&
    g[4] === 0 &&
    g[5] === 0xffff
  ) {
    return { kind: 'ipv4-mapped', ipv4: hextetsToIpv4(g[6]!, g[7]!) }
  }

  // 64:ff9b::/96 (RFC 6052 well-known)
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return { kind: 'nat64-well-known', ipv4: hextetsToIpv4(g[6]!, g[7]!) }
  }

  // 2002:AABB:CCDD::/48 (6to4)
  if (g[0] === 0x2002) {
    const ipv4 = hextetsToIpv4(g[1]!, g[2]!)
    return { kind: '6to4', ipv4, rest: g.slice(3) }
  }

  // ISATAP IID 0000:5EFE:a.b.c.d (RFC 5214) — hextets g[4]=0, g[5]=0x5efe, g[6..7]=IPv4
  if (g[4] === 0 && g[5] === 0x5efe) {
    return {
      kind: 'isatap',
      ipv4: hextetsToIpv4(g[6]!, g[7]!),
      prefix: g.slice(0, 4),
    }
  }

  // Teredo 2001:0::/32
  if (g[0] === 0x2001 && g[1] === 0) {
    const server = hextetsToIpv4(g[2]!, g[3]!)
    const flags = g[4]!
    void flags
    const udpPort = (g[5]! ^ 0xffff) & 0xffff
    const clientRaw = ((g[6]! << 16) | g[7]!) >>> 0
    const clientXor = (clientRaw ^ 0xffffffff) >>> 0
    const client = [
      (clientXor >>> 24) & 0xff,
      (clientXor >>> 16) & 0xff,
      (clientXor >>> 8) & 0xff,
      clientXor & 0xff,
    ].join('.')
    return { kind: 'teredo', serverIpv4: server, clientIpv4: client, udpPort }
  }

  return null
}

function hextetsToIpv4(hi: number, lo: number): string {
  return [
    (hi >> 8) & 0xff,
    hi & 0xff,
    (lo >> 8) & 0xff,
    lo & 0xff,
  ].join('.')
}

export function ipv4ToHextets(ipv4: string): readonly [number, number] | null {
  const parts = ipv4.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null
  return [((parts[0]! << 8) | parts[1]!) & 0xffff, ((parts[2]! << 8) | parts[3]!) & 0xffff]
}

export function formatIpv4Mapped(ipv4: string): string | null {
  const h = ipv4ToHextets(ipv4)
  if (!h) return null
  return formatIpv6Groups([0, 0, 0, 0, 0, 0xffff, h[0], h[1]])
}

export function formatNat64WellKnown(ipv4: string): string | null {
  const h = ipv4ToHextets(ipv4)
  if (!h) return null
  return formatIpv6Groups([0x64, 0xff9b, 0, 0, 0, 0, h[0], h[1]])
}

export function format6to4(ipv4: string, rest: readonly number[]): string | null {
  const h = ipv4ToHextets(ipv4)
  if (!h || rest.length !== 5) return null
  return formatIpv6Groups([0x2002, h[0], h[1], rest[0]!, rest[1]!, rest[2]!, rest[3]!, rest[4]!])
}

export function formatIsatap(prefix: readonly number[], ipv4: string): string | null {
  const h = ipv4ToHextets(ipv4)
  if (!h || prefix.length !== 4) return null
  return formatIpv6Groups([prefix[0]!, prefix[1]!, prefix[2]!, prefix[3]!, 0, 0x5efe, h[0], h[1]])
}

export function formatTeredo(serverIpv4: string, clientIpv4: string, udpPort: number): string | null {
  const s = ipv4ToHextets(serverIpv4)
  const cParts = clientIpv4.split('.').map(Number)
  if (!s || cParts.length !== 4) return null
  const clientRaw =
    (((cParts[0]! & 0xff) << 24) |
      ((cParts[1]! & 0xff) << 16) |
      ((cParts[2]! & 0xff) << 8) |
      (cParts[3]! & 0xff)) >>>
    0
  const clientXor = (clientRaw ^ 0xffffffff) >>> 0
  const portXor = (udpPort ^ 0xffff) & 0xffff
  return formatIpv6Groups([
    0x2001,
    0,
    s[0],
    s[1],
    0, // flags preserved as 0 (obfuscation flags not identity for our purpose)
    portXor,
    (clientXor >>> 16) & 0xffff,
    clientXor & 0xffff,
  ])
}

/**
 * Modified EUI-64 IID (RFC 4291): MAC with U/L flipped and `ff:fe` inserted
 * after the first three octets → hextets `uulb:bbff:febb:bbbb`.
 */
export function macFromEui64Ipv6(expanded: string): string | null {
  const g = ipv6Groups(expanded)
  if (!g || isIpv6Multicast(expanded)) return null
  // Bytes: [b0 b1 | b2 ff | fe b3 | b4 b5]
  if ((g[5]! & 0xff) !== 0xff || (g[6]! >> 8) !== 0xfe) return null
  const b0 = (g[4]! >> 8) & 0xff
  const b1 = g[4]! & 0xff
  const b2 = (g[5]! >> 8) & 0xff
  const b3 = g[6]! & 0xff
  const b4 = (g[7]! >> 8) & 0xff
  const b5 = g[7]! & 0xff
  const mac0 = b0 ^ 0x02
  return [mac0, b1, b2, b3, b4, b5].map((x) => x.toString(16).padStart(2, '0')).join(':')
}

/** Build modified EUI-64 IID hextets from a unicast MAC. */
export function eui64IidFromMac(mac: string): readonly [number, number, number, number] | null {
  const parts = mac.toLowerCase().split(':')
  if (parts.length !== 6) return null
  const b = parts.map((p) => Number.parseInt(p, 16))
  if (b.some((n) => !Number.isFinite(n))) return null
  const b0 = (b[0]! ^ 0x02) & 0xff
  return [
    ((b0 << 8) | b[1]!) & 0xffff,
    ((b[2]! << 8) | 0xff) & 0xffff,
    ((0xfe << 8) | b[3]!) & 0xffff,
    ((b[4]! << 8) | b[5]!) & 0xffff,
  ]
}

export function applyEui64Iid(expandedPrefix64: string, mac: string): string | null {
  const g = ipv6Groups(expandedPrefix64)
  const iid = eui64IidFromMac(mac)
  if (!g || !iid) return null
  return formatIpv6Groups([g[0]!, g[1]!, g[2]!, g[3]!, iid[0], iid[1], iid[2], iid[3]])
}
