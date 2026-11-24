/**
 * Step 8 — per-packet plan disposition and change-category accounting.
 * Derived from sanitizer coverage; never embeds original entity values.
 */

import type { LayerCoverage, PacketSanitizationResult } from '../sanitize/types'

/** Why a packet record was kept or removed from the export plan. */
export type PlanDispositionReason =
  | 'exported'
  | 'user-requested-drop'
  | 'blocked'

/**
 * Auditable change categories on the immutable plan (step 8).
 * Counts are span occurrences (not bytes), except masked bytes tracked separately.
 */
export type PlanChangeCategory =
  | 'mapped'
  | 'redacted'
  | 'masked-content'
  | 'preserved-encrypted'
  | 'preserved-for-diagnostics'
  | 'user-requested-drop'
  | 'blocked'

export type PlanChangeCounts = Readonly<Record<PlanChangeCategory, number>>

const MASKED_CONTENT_PROTOCOLS = new Set([
  'payload',
  'application',
  'rtp',
  'rtcp',
  'srtp',
  'icmp-echo-payload',
  'icmp-payload',
  'icmpv6-echo-payload',
  'http-body',
  'tls-encrypted-payload',
])

/** Protocols whose `covered` spans represent identity/structure remapping. */
const MAPPED_PROTOCOLS = new Set([
  'ethernet',
  'vlan',
  'arp',
  'ipv4',
  'ipv4-id',
  'ipv6',
  'ipv6-flow',
  'udp',
  'tcp',
  'tcp-seq',
  'dns',
  'mdns',
  'dhcp',
  'dhcpv6',
  'sip',
  'sdp',
  'tls',
  'tls-clienthello',
  'tls-serverhello',
  'tls-certificate',
  'tls-1.2',
  'tls-ech',
  'http',
  'ssrc',
])

export function emptyPlanChangeCounts(): PlanChangeCounts {
  return {
    mapped: 0,
    redacted: 0,
    'masked-content': 0,
    'preserved-encrypted': 0,
    'preserved-for-diagnostics': 0,
    'user-requested-drop': 0,
    blocked: 0,
  }
}

/** Defaults for hand-built plan snapshots in tests. */
export function emptyPlanAuditFields(): {
  changeCategoryTotals: PlanChangeCounts
  maskedByteCount: number
  dropsByReason: Readonly<Record<PlanDispositionReason, number>>
  dropsByProtocol: Readonly<Record<string, number>>
} {
  return {
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

export function addPlanChangeCounts(a: PlanChangeCounts, b: PlanChangeCounts): PlanChangeCounts {
  return {
    mapped: a.mapped + b.mapped,
    redacted: a.redacted + b.redacted,
    'masked-content': a['masked-content'] + b['masked-content'],
    'preserved-encrypted': a['preserved-encrypted'] + b['preserved-encrypted'],
    'preserved-for-diagnostics': a['preserved-for-diagnostics'] + b['preserved-for-diagnostics'],
    'user-requested-drop': a['user-requested-drop'] + b['user-requested-drop'],
    blocked: a.blocked + b.blocked,
  }
}

function isMaskedContentProtocol(protocol: string): boolean {
  if (MASKED_CONTENT_PROTOCOLS.has(protocol)) return true
  return (
    protocol.includes('mask')
    || protocol.endsWith('-payload')
    || protocol.startsWith('export-boundary')
  )
}

function classifySpan(span: LayerCoverage, counts: { [K in PlanChangeCategory]: number }, maskedBytes: { n: number }): void {
  switch (span.status) {
    case 'covered':
      if (MAPPED_PROTOCOLS.has(span.protocol) || span.protocol.startsWith('tcp-') || span.protocol.startsWith('ipv')) {
        counts.mapped += 1
      }
      break
    case 'redacted':
      if (isMaskedContentProtocol(span.protocol)) {
        counts['masked-content'] += 1
        maskedBytes.n += Math.max(0, span.length)
      } else {
        counts.redacted += 1
      }
      break
    case 'encrypted':
      counts['preserved-encrypted'] += 1
      break
    case 'preserved-for-diagnostics':
      counts['preserved-for-diagnostics'] += 1
      break
    default:
      break
  }
}

export function deriveDispositionReason(sanitization: PacketSanitizationResult): PlanDispositionReason {
  if (!sanitization.drop) return 'exported'
  if (sanitization.issues.some((i) => /block|invariant|unsafe-export|mapping-closure/i.test(i))) {
    return 'blocked'
  }
  return 'user-requested-drop'
}

export function derivePlanPacketAccounting(sanitization: PacketSanitizationResult): {
  dispositionReason: PlanDispositionReason
  changeCounts: PlanChangeCounts
  maskedByteCount: number
} {
  const dispositionReason = deriveDispositionReason(sanitization)
  const mutable = {
    mapped: 0,
    redacted: 0,
    'masked-content': 0,
    'preserved-encrypted': 0,
    'preserved-for-diagnostics': 0,
    'user-requested-drop': 0,
    blocked: 0,
  }
  const maskedBytes = { n: 0 }

  if (dispositionReason === 'blocked') {
    mutable.blocked = 1
    return { dispositionReason, changeCounts: mutable, maskedByteCount: 0 }
  }
  if (dispositionReason === 'user-requested-drop') {
    mutable['user-requested-drop'] = 1
    return { dispositionReason, changeCounts: mutable, maskedByteCount: 0 }
  }

  for (const span of sanitization.coverage) {
    classifySpan(span, mutable, maskedBytes)
  }

  // Issues from in-place mask may not always produce a dedicated span protocol match.
  for (const issue of sanitization.issues) {
    const m = /^masked-in-place:[^:]+:(\d+)\+(\d+)$/.exec(issue)
    if (m) {
      const len = Number(m[2])
      if (Number.isFinite(len) && len > 0 && mutable['masked-content'] === 0) {
        mutable['masked-content'] += 1
        maskedBytes.n += len
      }
    }
  }

  return {
    dispositionReason,
    changeCounts: mutable,
    maskedByteCount: maskedBytes.n,
  }
}

/** Dominant protocol label for a dropped packet (safe — protocol ids only). */
export function primaryProtocolFromCoverage(coverage: readonly LayerCoverage[]): string {
  for (let i = coverage.length - 1; i >= 0; i--) {
    const p = coverage[i]!.protocol
    if (p === 'ethernet' || p === 'ipv4' || p === 'ipv6' || p === 'udp' || p === 'tcp') continue
    return p
  }
  return coverage[0]?.protocol ?? 'unknown'
}
