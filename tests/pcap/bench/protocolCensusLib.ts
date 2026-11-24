/**
 * T13 — local protocol census aggregation (Node/bench only, not product UI).
 * Emits protocol family / unsupported aggregates without original values.
 */

import type { PacketEnvelope } from '../../../src/pcap/domain/types.ts'
import type { CoverageStatus } from '../../../src/pcap/sanitize/types.ts'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets.ts'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline.ts'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase.ts'
import {
  familyForProtocol,
  isUnsupportedProtocolId,
  type ProtocolFamilyId,
} from '../../../src/pcap/coverage/protocolFamilies.ts'
import {
  SEMANTIC_SERVICE_PORTS,
  ianaPortClass,
  type IanaPortClass,
} from '../../../src/pcap/anonymization/portPolicy.ts'

/** Coverage statuses that count as “masked / unusable for analysis” for prioritization. */
const MASKED_STATUSES: ReadonlySet<CoverageStatus> = new Set([
  'redacted',
  'unsupported',
  'heuristic',
  'malformed',
  'processing-failed',
  'encrypted',
  'requires-reassembly',
  'preserved-unsafe',
])

export type PortBucket =
  | `catalog:${number}`
  | `class:${IanaPortClass}`
  | 'unidentified-udp'
  | 'unidentified-tcp'
  | 'unidentified-other'

export interface ProtocolCensusRow {
  readonly key: string
  readonly kind: 'family' | 'unsupported' | 'payload' | 'port-bucket'
  readonly familyId: ProtocolFamilyId | 'n/a'
  readonly protocolId: string | null
  readonly packets: number
  readonly bytes: number
  readonly maskedBytes: number
  readonly flows: number
  readonly capturesPresent: number
  readonly statusCounts: Readonly<Record<string, number>>
  /** Priority score: maskedBytes × capturesPresent (higher = implement sooner). */
  readonly priorityScore: number
}

/** T13 extension — phase-3 telecom families (T49–T61) for separate prioritization rollup. */
export const TELECOM_PHASE3_FAMILY_IDS = [
  'csta',
  'ami-ari',
  'isdn',
  'smpp',
  'emergency-location',
  'mrcp',
  'cwmp-usp',
  'mobile-core',
  'ss7',
] as const satisfies readonly ProtocolFamilyId[]

export interface ProtocolCensusReport {
  readonly version: 1
  readonly generatedAt: string
  readonly captureCount: number
  /** Sanitized capture labels only (basename without private path segments). */
  readonly captureLabels: readonly string[]
  readonly rows: readonly ProtocolCensusRow[]
  readonly unidentifiedTransport: {
    readonly udpFlows: number
    readonly tcpFlows: number
    readonly otherFlows: number
  }
  readonly notes: readonly string[]
}

interface MutableAgg {
  key: string
  kind: ProtocolCensusRow['kind']
  familyId: ProtocolFamilyId | 'n/a'
  protocolId: string | null
  packets: number
  bytes: number
  maskedBytes: number
  flows: Set<string>
  captures: Set<string>
  statusCounts: Record<string, number>
}

function portBucket(canonicalPort: string): PortBucket {
  // canonical: "tcp/80" | "udp/5060"
  const slash = canonicalPort.indexOf('/')
  const proto = slash >= 0 ? canonicalPort.slice(0, slash).toLowerCase() : 'other'
  const port = slash >= 0 ? Number.parseInt(canonicalPort.slice(slash + 1), 10) : NaN
  if (!Number.isFinite(port)) {
    if (proto === 'udp') return 'unidentified-udp'
    if (proto === 'tcp') return 'unidentified-tcp'
    return 'unidentified-other'
  }
  if (SEMANTIC_SERVICE_PORTS.has(port)) return `catalog:${port}`
  const cls = ianaPortClass(port)
  // Never emit the numeric unknown port — only IANA class or unidentified bucket.
  if (cls === 'system' && !SEMANTIC_SERVICE_PORTS.has(port)) {
    if (proto === 'udp') return 'unidentified-udp'
    if (proto === 'tcp') return 'unidentified-tcp'
    return 'unidentified-other'
  }
  return `class:${cls}`
}

function ensureAgg(
  map: Map<string, MutableAgg>,
  key: string,
  kind: ProtocolCensusRow['kind'],
  familyId: ProtocolFamilyId | 'n/a',
  protocolId: string | null,
): MutableAgg {
  let row = map.get(key)
  if (!row) {
    row = {
      key,
      kind,
      familyId,
      protocolId,
      packets: 0,
      bytes: 0,
      maskedBytes: 0,
      flows: new Set(),
      captures: new Set(),
      statusCounts: {},
    }
    map.set(key, row)
  }
  return row
}

/**
 * Aggregate one capture's discovery result into census maps.
 * `captureLabel` must be a safe basename (no path, no PII-bearing names required).
 */
export function accumulateCaptureCensus(
  packets: readonly PacketEnvelope[],
  captureLabel: string,
  into: Map<string, MutableAgg> = new Map(),
): Map<string, MutableAgg> {
  const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY)
  const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, `census-${captureLabel}`, captureLabel, {
    reassemblyContext: reassembly,
  })

  for (const pd of discovery.packetDiscovery) {
    const flowTag = `p${pd.packetIndex}`
    for (const cov of pd.coverage) {
      const ref = familyForProtocol(cov.protocol)
      const masked = MASKED_STATUSES.has(cov.status)
      const familyKey = `family:${ref.familyId}`
      const fam = ensureAgg(into, familyKey, 'family', ref.familyId, null)
      fam.packets += 1
      fam.bytes += cov.length
      if (masked) fam.maskedBytes += cov.length
      fam.flows.add(`${flowTag}:${cov.protocol}`)
      fam.captures.add(captureLabel)
      fam.statusCounts[cov.status] = (fam.statusCounts[cov.status] ?? 0) + 1

      if (isUnsupportedProtocolId(cov.protocol)) {
        // cov.protocol is already `unsupported:<name>`.
        const uKey = cov.protocol
        const u = ensureAgg(into, uKey, 'unsupported', 'identified-unsupported', cov.protocol)
        u.packets += 1
        u.bytes += cov.length
        if (masked) u.maskedBytes += cov.length
        u.flows.add(flowTag)
        u.captures.add(captureLabel)
        u.statusCounts[cov.status] = (u.statusCounts[cov.status] ?? 0) + 1
      } else if (cov.protocol === 'payload' || cov.protocol.startsWith('payload')) {
        const pKey = `payload:${cov.protocol}`
        const p = ensureAgg(into, pKey, 'payload', ref.familyId, cov.protocol)
        p.packets += 1
        p.bytes += cov.length
        if (masked) p.maskedBytes += cov.length
        p.flows.add(flowTag)
        p.captures.add(captureLabel)
        p.statusCounts[cov.status] = (p.statusCounts[cov.status] ?? 0) + 1
      }
    }

    if (pd.portFlowHints) {
      for (const [canonical] of pd.portFlowHints) {
        const bucket = portBucket(canonical)
        const key = `port:${bucket}`
        const row = ensureAgg(into, key, 'port-bucket', 'n/a', null)
        row.packets += 1
        row.flows.add(`${flowTag}:${bucket}`)
        row.captures.add(captureLabel)
      }
    }
  }

  return into
}

export function finalizeCensusReport(
  aggs: Map<string, MutableAgg>,
  captureLabels: readonly string[],
  notes: readonly string[] = [],
): ProtocolCensusReport {
  const rows: ProtocolCensusRow[] = [...aggs.values()]
    .map((a) => {
      const capturesPresent = a.captures.size
      return {
        key: a.key,
        kind: a.kind,
        familyId: a.familyId,
        protocolId: a.protocolId,
        packets: a.packets,
        bytes: a.bytes,
        maskedBytes: a.maskedBytes,
        flows: a.flows.size,
        capturesPresent,
        statusCounts: { ...a.statusCounts },
        priorityScore: a.maskedBytes * Math.max(1, capturesPresent),
      }
    })
    .sort((a, b) => b.priorityScore - a.priorityScore || b.maskedBytes - a.maskedBytes || a.key.localeCompare(b.key))

  let udpFlows = 0
  let tcpFlows = 0
  let otherFlows = 0
  for (const r of rows) {
    if (r.key === 'port:unidentified-udp') udpFlows = r.flows
    else if (r.key === 'port:unidentified-tcp') tcpFlows = r.flows
    else if (r.key === 'port:unidentified-other') otherFlows = r.flows
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    captureCount: captureLabels.length,
    captureLabels: [...captureLabels],
    rows,
    unidentifiedTransport: { udpFlows, tcpFlows, otherFlows },
    notes: [...notes],
  }
}

/** Render Markdown table — aggregates only, no original values. */
export function formatCensusMarkdown(report: ProtocolCensusReport): string {
  const lines: string[] = [
    '# Protocol census (T13)',
    '',
    `Captures: ${report.captureCount} (${report.captureLabels.join(', ') || 'none'})`,
    `Generated: ${report.generatedAt}`,
    '',
    'Sorted by `maskedBytes × capturesPresent`.',
    '',
    '| Priority | Key | Kind | Packets | Bytes | Masked B | Flows | Captures |',
    '|---:|---|---|---:|---:|---:|---:|---:|',
  ]
  for (const r of report.rows) {
    lines.push(
      `| ${r.priorityScore} | \`${r.key}\` | ${r.kind} | ${r.packets} | ${r.bytes} | ${r.maskedBytes} | ${r.flows} | ${r.capturesPresent} |`,
    )
  }
  const telecom = report.rows.filter(
    (r) => r.kind === 'family' && (TELECOM_PHASE3_FAMILY_IDS as readonly string[]).includes(r.familyId),
  )
  if (telecom.length > 0) {
    lines.push('')
    lines.push('## Telecom phase 3 (T49–T61 families)')
    lines.push('')
    lines.push('| Priority | Family | Packets | Masked B | Captures |')
    lines.push('|---:|---|---:|---:|---:|')
    for (const r of telecom) {
      lines.push(
        `| ${r.priorityScore} | \`${r.familyId}\` | ${r.packets} | ${r.maskedBytes} | ${r.capturesPresent} |`,
      )
    }
  }
  lines.push('')
  lines.push('## Unidentified transport (no port numbers)')
  lines.push('')
  lines.push(
    `UDP flows: ${report.unidentifiedTransport.udpFlows}; TCP flows: ${report.unidentifiedTransport.tcpFlows}; other: ${report.unidentifiedTransport.otherFlows}`,
  )
  if (report.notes.length > 0) {
    lines.push('')
    lines.push('## Notes')
    for (const n of report.notes) lines.push(`- ${n}`)
  }
  lines.push('')
  return lines.join('\n')
}

const AGGREGATE_VOCAB = new Set(
  [
    'family',
    'unsupported',
    'payload',
    'port',
    'catalog',
    'class',
    'dynamic',
    'system',
    'user-registered',
    'unidentified',
    'packets',
    'bytes',
    'masked',
    'flows',
    'captures',
    'priority',
    'synthetic',
    'covered',
    'redacted',
    'heuristic',
    'malformed',
    'encrypted',
    'processing-failed',
    'requires-reassembly',
    'preserved-unsafe',
    'preserved-for-diagnostics',
    'network-headers',
    'identified-unsupported',
    'rtp-rtcp',
    'dns-mdns',
    'icmp-ndp',
    'version',
    'generated',
    'transport',
    'protocol',
    'census',
  ].map((s) => s.toLowerCase()),
)

/** High-signal leak seeds: IPv4, hostnames with a dot, emails, long opaque tokens. */
export function extractLeakSeedsFromPackets(packets: readonly PacketEnvelope[], maxSeeds = 64): string[] {
  const seeds = new Set<string>()
  const add = (s: string): void => {
    if (s.length < 8) return
    if (AGGREGATE_VOCAB.has(s.toLowerCase())) return
    if (/^(tcp|udp|sip|sdp|rtp|rtcp|http|tls|dns|dhcp|icmp|ipv4|ipv6)$/i.test(s)) return
    seeds.add(s)
  }
  for (const pkt of packets) {
    const text = Buffer.from(pkt.data).toString('latin1')
    for (const m of text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []) add(m)
    for (const m of text.match(/\b[A-Za-z0-9][A-Za-z0-9-]{1,40}\.[A-Za-z]{2,24}(?:\.[A-Za-z]{2,24})?\b/g) ?? []) {
      add(m)
    }
    for (const m of text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g) ?? []) add(m)
    for (const m of text.match(/\b[A-Za-z0-9]{16,64}\b/g) ?? []) add(m)
    if (seeds.size >= maxSeeds) break
  }
  return [...seeds].slice(0, maxSeeds)
}

export function assertCensusReportHasNoLeaks(
  reportJson: string,
  reportMd: string,
  seeds: readonly string[],
): void {
  const blob = `${reportJson}\n${reportMd}`.toLowerCase()
  for (const seed of seeds) {
    if (!seed || seed.length < 8) continue
    // Catalog port numbers in `catalog:5060` are intentional aggregate labels, not capture values.
    if (/^\d{1,5}$/.test(seed)) continue
    if (AGGREGATE_VOCAB.has(seed.toLowerCase())) continue
    if (blob.includes(seed.toLowerCase())) {
      throw new Error('census-leak: aggregate output contained a capture seed')
    }
  }
}
