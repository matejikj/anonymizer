/**
 * Enterprise step 5 / T65 — in-memory leak scanner for export artifacts.
 *
 * Originals may be held only in RAM for the scan. Public findings never include
 * originalValue / hostname / phone / path — only category + hits + packetNumbers
 * (and T65 positions for remediation).
 */

import { MAX_ENTITY_CARDINALITY } from '../../domain/capabilityContract'
import { buildAhoCorasick } from './ahoCorasick'
import { buildLeakNeedles, type LeakNeedle, type LeakNeedleKind } from './leakVariants'

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

/** T65 — concrete hit location for auto-remediation (no original value). */
export interface LeakHitPosition {
  readonly packetIndex: number
  readonly packetNumber: number
  readonly offset: number
  readonly length: number
  readonly category: LeakCategory
  readonly kind: LeakNeedleKind
}

export interface LeakScanResult {
  readonly findings: readonly LeakScanFinding[]
  readonly leakHits: number
  /** T65 — positions for remediation; empty when scanning opaque report JSON. */
  readonly positions?: readonly LeakHitPosition[]
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
  if (/^x+$/i.test(v) || /^0+(\.0+){3}$/.test(v) || v === '::') return null
  return v
}

/**
 * Search artifact bytes/text for original canaries (memory-only).
 * Result is export-safe: no original values.
 * String artifacts keep the legacy latin1 includes() path (report JSON).
 */
export function scanArtifactForOriginalLeaks(input: {
  readonly artifact: string | Uint8Array
  readonly originals: readonly LeakScanOriginal[]
}): LeakScanResult {
  if (typeof input.artifact === 'string') {
    return scanTextArtifact(input.artifact, input.originals)
  }
  return scanBytesForLeaks({
    packets: [{ packetIndex: 0, packetNumber: 0, bytes: input.artifact }],
    originals: input.originals,
  })
}

function scanTextArtifact(
  text: string,
  originals: readonly LeakScanOriginal[],
): LeakScanResult {
  const lower = text.toLowerCase()
  const byCategory = new Map<LeakCategory, { hits: number; packets: Set<number> }>()

  for (const orig of originals) {
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

function overlapsPatch(
  offset: number,
  length: number,
  patches: readonly { readonly offset: number; readonly data: Uint8Array }[],
): boolean {
  const end = offset + length
  for (const p of patches) {
    const pEnd = p.offset + p.data.length
    if (offset < pEnd && end > p.offset) return true
  }
  return false
}

/**
 * T65 — scan anonymized packet bytes with encoding variants + Aho-Corasick.
 *
 * Binary needles that fall inside existing plan patches (map/mask/derived) are
 * treated as false positives and dropped. Text needles always count.
 */
export function scanBytesForLeaks(input: {
  readonly packets: readonly {
    readonly packetIndex: number
    readonly packetNumber: number
    readonly bytes: Uint8Array
    readonly patches?: readonly { readonly offset: number; readonly data: Uint8Array }[]
  }[]
  readonly originals: readonly LeakScanOriginal[]
}): LeakScanResult {
  const capped = input.originals.slice(0, MAX_ENTITY_CARDINALITY)
  const needles = buildLeakNeedles(capped)
  if (needles.length === 0) return emptyLeakScanResult()

  const automaton = buildAhoCorasick(
    needles.map((n) => ({ id: n.id, bytes: n.bytes })),
  )
  const byId = new Map<number, LeakNeedle>()
  for (const n of needles) byId.set(n.id, n)

  const positions: LeakHitPosition[] = []
  const byCategory = new Map<LeakCategory, { hits: number; packets: Set<number> }>()

  for (const pkt of input.packets) {
    automaton.findAll(pkt.bytes, (patternId, start) => {
      const needle = byId.get(patternId)
      if (!needle) return
      const length = needle.bytes.length
      if (start + length > pkt.bytes.length) return

      // FP filter: binary hits inside already-patched spans are alias/mask bytes.
      if (
        needle.kind === 'binary'
        && pkt.patches
        && overlapsPatch(start, length, pkt.patches)
      ) {
        return
      }

      const category = mapEntityCategoryToLeak(needle.category)
      positions.push({
        packetIndex: pkt.packetIndex,
        packetNumber: pkt.packetNumber,
        offset: start,
        length,
        category,
        kind: needle.kind,
      })

      let bucket = byCategory.get(category)
      if (!bucket) {
        bucket = { hits: 0, packets: new Set() }
        byCategory.set(category, bucket)
      }
      bucket.hits += 1
      if (bucket.packets.size < MAX_PACKET_NUMBERS) {
        bucket.packets.add(pkt.packetNumber)
      }
    })
  }

  const findings: LeakScanFinding[] = [...byCategory.entries()]
    .map(([category, b]) => ({
      category,
      hits: b.hits,
      packetNumbers: [...b.packets].sort((a, b) => a - b),
    }))
    .sort((a, b) => a.category.localeCompare(b.category))

  const leakHits = findings.reduce((n, f) => n + f.hits, 0)
  return { findings, leakHits, positions }
}

/** Empty scan result for exports without entity originals. */
export function emptyLeakScanResult(): LeakScanResult {
  return { findings: [], leakHits: 0, positions: [] }
}
