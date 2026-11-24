/**
 * Enterprise step 5 — in-memory leak scanner for export artifacts.
 *
 * Originals may be held only in RAM for the scan. Public findings never include
 * originalValue / hostname / phone / path — only category + hits + packetNumbers.
 */

export const LEAK_CATEGORIES = [
  'PHONE',
  'IPV4',
  'IPV6',
  'MAC',
  'EMAIL',
  'HOSTNAME',
  'SIP_URI',
  'PATH',
  'CREDENTIAL',
  'OTHER',
] as const

export type LeakCategory = (typeof LEAK_CATEGORIES)[number]

export interface LeakScanOriginal {
  readonly category: string
  readonly value: string
  readonly packetNumber: number
}

export interface LeakScanFinding {
  readonly category: LeakCategory
  readonly hits: number
  readonly packetNumbers: readonly number[]
}

export interface LeakScanResult {
  readonly findings: readonly LeakScanFinding[]
  readonly leakHits: number
}

const MAX_PACKET_NUMBERS = 32

/** Map entity / protocol categories onto leak-report buckets. */
export function mapEntityCategoryToLeak(category: string): LeakCategory {
  const c = category.toLowerCase()
  if (c.includes('phone') || c === 'tel' || c === 'msisdn') return 'PHONE'
  if (c === 'ipv4' || c === 'ip' || c === 'ip-address') return 'IPV4'
  if (c === 'ipv6') return 'IPV6'
  if (c === 'mac' || c === 'ethernet') return 'MAC'
  if (c.includes('email') || c.includes('mail')) return 'EMAIL'
  if (c.includes('host') || c === 'dns' || c === 'fqdn' || c === 'domain') return 'HOSTNAME'
  if (c.includes('sip') || c.includes('uri')) return 'SIP_URI'
  if (c.includes('path') || c.includes('file')) return 'PATH'
  if (
    c.includes('password')
    || c.includes('auth')
    || c.includes('credential')
    || c.includes('token')
    || c.includes('secret')
  ) {
    return 'CREDENTIAL'
  }
  return 'OTHER'
}

function normalizeCanary(value: string): string | null {
  const v = value.trim()
  if (v.length < 3) return null
  // Skip trivial placeholders / already-masked forms.
  if (/^x+$/i.test(v) || /^0+(\.0+){3}$/.test(v) || v === '::') return null
  return v
}

/**
 * Search artifact bytes/text for original canaries (memory-only).
 * Result is export-safe: no original values.
 */
export function scanArtifactForOriginalLeaks(input: {
  readonly artifact: string | Uint8Array
  readonly originals: readonly LeakScanOriginal[]
}): LeakScanResult {
  const text =
    typeof input.artifact === 'string'
      ? input.artifact
      : new TextDecoder('latin1', { fatal: false }).decode(input.artifact)

  const lower = text.toLowerCase()
  const byCategory = new Map<LeakCategory, { hits: number; packets: Set<number> }>()

  for (const orig of input.originals) {
    const canary = normalizeCanary(orig.value)
    if (!canary) continue
    const needle = canary.toLowerCase()
    if (!lower.includes(needle)) continue

    const category = mapEntityCategoryToLeak(orig.category)
    let bucket = byCategory.get(category)
    if (!bucket) {
      bucket = { hits: 0, packets: new Set() }
      byCategory.set(category, bucket)
    }
    bucket.hits += 1
    if (bucket.packets.size < MAX_PACKET_NUMBERS) {
      bucket.packets.add(orig.packetNumber)
    }
  }

  const findings: LeakScanFinding[] = [...byCategory.entries()]
    .map(([category, b]) => ({
      category,
      hits: b.hits,
      packetNumbers: [...b.packets].sort((a, b) => a - b),
    }))
    .sort((a, b) => a.category.localeCompare(b.category))

  const leakHits = findings.reduce((n, f) => n + f.hits, 0)
  return { findings, leakHits }
}

/** Empty scan result for exports without entity originals. */
export function emptyLeakScanResult(): LeakScanResult {
  return { findings: [], leakHits: 0 }
}
