/**
 * IPv6 text ↔ 16-byte wire conversion with correct `::` expansion.
 */

export function ipv6TextToBytes16(ip: string): Uint8Array | null {
  const trimmed = ip.trim().toLowerCase()
  if (trimmed.length === 0) return null
  if (trimmed === '::') return new Uint8Array(16)

  const sides = trimmed.split('::')
  if (sides.length > 2) return null

  const parseGroup = (group: string): number | null => {
    if (group.length === 0 || group.length > 4) return null
    if (!/^[0-9a-f]+$/.test(group)) return null
    return Number.parseInt(group, 16)
  }

  const left = sides[0]!.length === 0 ? [] : sides[0]!.split(':')
  const right = sides.length === 2 ? (sides[1]!.length === 0 ? [] : sides[1]!.split(':')) : []

  if (sides.length === 1 && left.length !== 8) return null
  if (sides.length === 2 && left.length + right.length >= 8) return null

  const groups: number[] = []
  for (const g of left) {
    const v = parseGroup(g)
    if (v === null) return null
    groups.push(v)
  }
  if (sides.length === 2) {
    const missing = 8 - left.length - right.length
    for (let i = 0; i < missing; i++) groups.push(0)
    for (const g of right) {
      const v = parseGroup(g)
      if (v === null) return null
      groups.push(v)
    }
  }
  if (groups.length !== 8) return null

  const out = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (groups[i]! >> 8) & 0xff
    out[i * 2 + 1] = groups[i]! & 0xff
  }
  return out
}

export function ipv6Bytes16ToText(bytes: Uint8Array, offset = 0): string {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[offset + i]! << 8) | bytes[offset + i + 1]!).toString(16))
  }
  return parts.join(':')
}
