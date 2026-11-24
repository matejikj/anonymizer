/**
 * Immutable export plan — shared by preview and export (ARCHITECTURE §29).
 */

import type {
  CaptureFormat,
  ClassicPcapHeader,
  PacketEnvelope,
  PacketTimestamp,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
} from '../domain/types'
import {
  EMPTY_INCIDENT_LOG_SNAPSHOT,
  IncidentLog,
  type IncidentLogSnapshot,
} from '../../domain/anonymizationIncident'
import type { BytePatch } from '../sanitize/types'
import type { PacketSanitizationResult } from '../sanitize/types'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import {
  hashPcapLevelPolicy,
  type DerivedPcapPolicyView,
} from '../profile/presets'
import type { ChecksumReport } from '../checksums/types'
import type { TimestampMappingConfig } from '../anonymization/timestampMapping'
import {
  addPlanChangeCounts,
  derivePlanPacketAccounting,
  emptyPlanChangeCounts,
  primaryProtocolFromCoverage,
  type PlanChangeCounts,
  type PlanDispositionReason,
} from '../plan/planDisposition'
import {
  aggregateDispositionRanges,
  emptyDispositionAggregate,
  finalizePacketDisposition,
  type DispositionLedgerAggregate,
} from './dispositionLedger'

export type { PlanChangeCounts, PlanDispositionReason } from '../plan/planDisposition'
export { emptyPlanAuditFields, emptyPlanChangeCounts } from '../plan/planDisposition'

export interface PcapPlanPacket {
  readonly index: number
  readonly packetNumber: number
  readonly drop: boolean
  readonly patches: readonly BytePatch[]
  readonly truncatedLength?: number
  readonly originalCapturedLength: number
  readonly originalLength: number
  readonly linkType: number
  readonly interfaceId: number
  readonly sectionIndex: number
  readonly originalTimestamp: PacketTimestamp
  /** Step 8 — why this record is kept or dropped. */
  readonly dispositionReason: PlanDispositionReason
  /** Step 8 — per-category change span counts (no original values). */
  readonly changeCounts: PlanChangeCounts
  /** Step 8 — masked application/media bytes for this packet. */
  readonly maskedByteCount: number
  /** Safe protocol id for drop accounting (never an original identity). */
  readonly primaryProtocol?: string
}

export interface PcapPlanSnapshot {
  readonly generationId: string
  /** Active PCAP anonymization level used to build this plan. */
  readonly pcapLevel: PcapAnonymizationLevel
  /** @deprecated Prefer pcapLevel — retained for wire compatibility during transition. */
  readonly profileId: string
  /** Hash of engine version + canonical built-in policy for the level (recovery: policyHash). */
  readonly profileHash: string
  /** Canonical recovery/plan identity hash; equals profileHash. */
  readonly policyHash?: string
  readonly format: CaptureFormat
  readonly fileName: string
  readonly engineVersion: string
  readonly packets: readonly PcapPlanPacket[]
  /**
   * R10 — packets with patches and/or truncation (O(1) status accounting).
   * Avoids scanning `packets` on the UI thread after a large plan transfer.
   */
  readonly packetsWithChanges?: number
  readonly classicHeader?: ClassicPcapHeader
  readonly pcapngSections?: readonly PcapngSectionInfo[]
  readonly pcapngInterfaces?: readonly PcapngInterfaceInfo[]
  readonly droppedPacketNumbers: readonly number[]
  /** CF-12 — timestamp transform mode from level mapping */
  readonly timestamps: TimestampMappingConfig
  /**
   * Opaque per-plan seed for absolute timestamp anchor (step 7).
   * Never copied into plaintext export reports.
   */
  readonly timestampAnchorSeed: string
  /** Step 8 — aggregated change categories across all packets. */
  readonly changeCategoryTotals: PlanChangeCounts
  /** Step 8 — total masked application/media bytes. */
  readonly maskedByteCount: number
  /** Step 8 — drops grouped by disposition reason. */
  readonly dropsByReason: Readonly<Record<PlanDispositionReason, number>>
  /** Step 8 — drops grouped by safe protocol id. */
  readonly dropsByProtocol: Readonly<Record<string, number>>
  /**
   * T04 — value-free anonymization incidents from plan build (field fallback, etc.).
   * Preview and export share this immutable list. Optional for older in-memory fixtures;
   * production builders always set it (default empty snapshot).
   */
  readonly incidents?: IncidentLogSnapshot
  /**
   * T62 — disposition ledger aggregates only (byte counts by disposition / protocol / reason).
   * Full per-packet ranges stay private to plan build and are not stored here.
   */
  readonly dispositionLedger?: DispositionLedgerAggregate
  /**
   * T65 — leak auto-remediation summary (no original values). Present after
   * remediatePlanLeaks; preview and export share the remediated patches.
   */
  readonly leakRemediation?: {
    readonly passes: number
    readonly autoRemediated: import('./leakRemediation').AutoRemediationSummary
    readonly residualLeakHits: number
  }
  /** T66 — cross-protocol identity propagation counts (no originals). */
  readonly identityPropagation?: {
    readonly hits: number
    readonly packets: number
  }
}

export interface BuiltExportPacket {
  readonly envelope: PacketEnvelope
  readonly checksumReport: ChecksumReport
}

/** Bumped for T04 field-fallback / incident plan semantics (feeds profileHash / recovery). */
/** Bumped for T47 — TLS Hello random / unknown-extension masking changes export bytes. */
/** Bumped for T14 — HTTP/SIP absolute Date capture-aligned rewrite. */
/** Bumped for T20 — syslog/SNMP/NTP/TFTP structured handlers. */
/** Bumped for T18 — LLMNR/NBNS/SSDP/WS-Discovery structured handlers. */
/** Bumped for T19 — LLDP/LACP/EAPOL L2 structured handlers. */
/** Bumped for T37 — MCPTT/MSRP/BFCP/ZRTP/T.38 extended VoIP. */
/** Bumped for T34 — NULL/LOOP, PPP/PPPoE, MPLS, Geneve, L2TP, ERSPAN, NFLOG. */
/** Bumped for T21 — NetFlow v5 / IPFIX / sFlow flow-export sanitizers. */
/** Bumped for T23 — LDAP/CLDAP + Kerberos directory/auth sanitizers. */
/** Bumped for T38 — OSPF/BGP/IS-IS/EIGRP/RIP/BFD/HSRP/PIM/IGMP/LDP + TCP MD5/AO. */
/** Bumped for T39 — RDP/VNC/X11/IPMI/Citrix/AMT remote-access sanitizers. */
/** Bumped for T40 — radiotap/802.11, Bluetooth/BLE, GSMTAP wireless captures. */
/** Bumped for T42 — DCE/RPC, iSCSI, portmapper, NFS/ONC RPC storage sanitizers. */
/** Bumped for T59 — NAS EPS/5GS identity and security-phase sanitizer. */
/** Bumped for T60 — PFCP Sx/N4 control-plane sanitizer. */
/** Bumped for T60 — PFCP CP/UP F-SEID endpoint-scoped session graph. */
/** Bumped for T57 — S1AP LTE APER sanitizer (SCTP PPID 18). */
/** Bumped for T58 — NGAP 5G APER sanitizer + typed N2 adapter (SCTP PPID 60). */
/** Bumped for T61 — 5G SBI HTTP/JSON + multipart N1/N2 (REL-18 pinned subset). */
/** Bumped for T25 M2PA (SCTP PPID 5) + T26 GTPv2 piggyback baseline. */
/** Bumped — journal port encoding (mapped ports were written as 0) + SIP/SDP text port wire alias. */
/** Bumped — fail-closed DHCPv4/v6 options, H.225.0 two-octet User-user IE, heuristic syslog MSG. */
/** Bumped for T62 — disposition ledger + residual sweep on unclaimed export bytes. */
/** Bumped for T65 — leak auto-remediation patches on the immutable plan. */
/** Bumped for T66 — cross-protocol identity propagation on plan bytes. */
export const PCAP_ENGINE_VERSION = '2.41.0'

export { EMPTY_INCIDENT_LOG_SNAPSHOT }

export function hashPcapLevel(level: PcapAnonymizationLevel): string {
  return hashPcapLevelPolicy(level, PCAP_ENGINE_VERSION)
}

/** @deprecated Use hashPcapLevel. */
export function hashProfile(profile: DerivedPcapPolicyView | { preset: PcapAnonymizationLevel }): string {
  return hashPcapLevel(profile.preset)
}

/** Cryptographic-quality opaque seed for timestamp anchors — not derived from reported IDs. */
export function createTimestampAnchorSeed(): string {
  const bytes = new Uint8Array(16)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = (Math.random() * 256) | 0
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Deterministic plan entropy from generationId — keeps fingerprint remaps and
 * timestamp anchors stable for the same export generation (pure plan builder).
 * Opaque; never put into the shared privacy/export report JSON.
 */
export function derivePlanEntropySeed(generationId: string): string {
  const material = `${generationId}\0pcap-plan-entropy\0v1`
  const bytes = new Uint8Array(16)
  let h = 2166136261 >>> 0
  for (let i = 0; i < material.length; i++) {
    h ^= material.charCodeAt(i)
    h = Math.imul(h, 16777619) >>> 0
  }
  for (let i = 0; i < bytes.length; i++) {
    h ^= i + 0x9e3779b9
    h = Math.imul(h, 16777619) >>> 0
    h ^= h << 13
    h ^= h >>> 17
    h ^= h << 5
    bytes[i] = h & 0xff
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function buildPlanPacket(
  index: number,
  original: PacketEnvelope,
  sanitization: PacketSanitizationResult,
  overrides?: {
    readonly patches?: readonly BytePatch[]
    readonly truncatedLength?: number
  },
): PcapPlanPacket {
  const accounting = derivePlanPacketAccounting(sanitization)
  return {
    index,
    packetNumber: original.packetNumber,
    drop: sanitization.drop,
    patches: overrides?.patches ? [...overrides.patches] : sanitization.patches,
    truncatedLength: overrides?.truncatedLength ?? sanitization.truncatedLength,
    originalCapturedLength: original.capturedLength,
    originalLength: original.originalLength,
    linkType: original.linkType,
    interfaceId: original.interfaceId,
    sectionIndex: original.sectionIndex,
    originalTimestamp: original.timestamp,
    dispositionReason: accounting.dispositionReason,
    changeCounts: accounting.changeCounts,
    maskedByteCount: accounting.maskedByteCount,
    primaryProtocol: primaryProtocolFromCoverage(sanitization.coverage),
  }
}

export function buildPlanSnapshot(input: {
  generationId: string
  profile: DerivedPcapPolicyView | { id: string; preset: PcapAnonymizationLevel; mapping: { timestamps: TimestampMappingConfig } }
  format: CaptureFormat
  fileName: string
  packets: readonly PacketEnvelope[]
  sanitization: readonly PacketSanitizationResult[]
  classicHeader?: ClassicPcapHeader
  pcapngSections?: readonly PcapngSectionInfo[]
  pcapngInterfaces?: readonly PcapngInterfaceInfo[]
  /** When omitted, derived from generationId for plan purity. */
  timestampAnchorSeed?: string
  /** T04 — incidents collected during plan build (default empty). */
  incidents?: IncidentLogSnapshot
  /** T62 — optional live log for residual-sweep incidents (merged into snapshot). */
  incidentLog?: IncidentLog
  sourceId?: string
}): PcapPlanSnapshot {
  const planPackets: PcapPlanPacket[] = []
  const dropped: number[] = []
  let changeCategoryTotals = emptyPlanChangeCounts()
  let maskedByteCount = 0
  let packetsWithChanges = 0
  const dropsByReason: Record<PlanDispositionReason, number> = {
    exported: 0,
    'user-requested-drop': 0,
    blocked: 0,
  }
  const dropsByProtocol: Record<string, number> = {}
  const level = input.profile.preset
  const residualLog = input.incidentLog ?? new IncidentLog()
  const sourceId = input.sourceId ?? (input.fileName || 'pcap')

  const ledgerAcc = {
    byDisposition: { ...emptyDispositionAggregate().byDisposition },
    byProtocol: {} as Record<string, number>,
    byReason: {} as Record<string, number>,
  }
  let unclaimedBytesBeforeSweep = 0
  let residualMaskedBytes = 0
  let residualTruncatedBytes = 0
  let ledgerPacketCount = 0

  for (let i = 0; i < input.packets.length; i++) {
    const pkt = input.packets[i]!
    const san = input.sanitization[i]!

    // T62 — disposition ledger + residual sweep before freezing plan patches.
    const finalized = finalizePacketDisposition({
      packetIndex: i,
      length: pkt.data.length,
      drop: san.drop,
      truncatedLength: san.truncatedLength,
      patches: san.patches,
      coverage: san.coverage,
      symbolicOps: san.symbolicMapOps,
      level,
      incidentLog: residualLog,
      sourceId,
      packetNumber: pkt.packetNumber,
    })
    unclaimedBytesBeforeSweep += finalized.unclaimedBytesBeforeSweep
    residualMaskedBytes += finalized.residualMaskedBytes
    residualTruncatedBytes += finalized.residualTruncatedBytes
    aggregateDispositionRanges(finalized.ranges, ledgerAcc)
    ledgerPacketCount += 1

    const planPkt = buildPlanPacket(i, pkt, san, {
      patches: finalized.patches,
      truncatedLength: finalized.truncatedLength,
    })
    planPackets.push(planPkt)
    changeCategoryTotals = addPlanChangeCounts(changeCategoryTotals, planPkt.changeCounts)
    maskedByteCount += planPkt.maskedByteCount + finalized.residualMaskedBytes
    if (planPkt.patches.length > 0 || planPkt.truncatedLength !== undefined) {
      packetsWithChanges += 1
    }
    if (san.drop) {
      dropped.push(pkt.packetNumber)
      dropsByReason[planPkt.dispositionReason] =
        (dropsByReason[planPkt.dispositionReason] ?? 0) + 1
      const proto = planPkt.primaryProtocol ?? 'unknown'
      dropsByProtocol[proto] = (dropsByProtocol[proto] ?? 0) + 1
    }
  }

  const priorIncidents = input.incidents ?? EMPTY_INCIDENT_LOG_SNAPSHOT
  // When caller passed a live incidentLog, prefer its snapshot (includes residual).
  // Otherwise merge residual-only records onto the prior snapshot.
  let incidents: IncidentLogSnapshot
  if (input.incidentLog) {
    incidents = residualLog.snapshot()
  } else if (residualLog.snapshot().totalFailures > 0) {
    const merged = new IncidentLog()
    for (const inc of priorIncidents.incidents) merged.record(inc)
    for (const inc of residualLog.snapshot().incidents) merged.record(inc)
    const snap = merged.snapshot()
    incidents = {
      ...snap,
      totalFailures: priorIncidents.totalFailures + residualLog.snapshot().totalFailures,
      truncated: priorIncidents.truncated || snap.truncated,
    }
  } else {
    incidents = priorIncidents
  }

  const dispositionLedger: DispositionLedgerAggregate = {
    byDisposition: ledgerAcc.byDisposition,
    byProtocol: ledgerAcc.byProtocol,
    byReason: ledgerAcc.byReason,
    unclaimedBytesBeforeSweep,
    residualMaskedBytes,
    residualTruncatedBytes,
    packetCount: ledgerPacketCount,
  }

  return {
    generationId: input.generationId,
    pcapLevel: level,
    profileId: input.profile.id,
    profileHash: hashPcapLevel(level),
    policyHash: hashPcapLevel(level),
    format: input.format,
    fileName: input.fileName,
    engineVersion: PCAP_ENGINE_VERSION,
    packets: planPackets,
    packetsWithChanges,
    classicHeader: input.classicHeader,
    pcapngSections: input.pcapngSections,
    pcapngInterfaces: input.pcapngInterfaces,
    droppedPacketNumbers: dropped,
    timestamps: input.profile.mapping.timestamps,
    timestampAnchorSeed:
      input.timestampAnchorSeed ?? derivePlanEntropySeed(input.generationId),
    changeCategoryTotals,
    maskedByteCount,
    dropsByReason,
    dropsByProtocol,
    incidents,
    dispositionLedger,
  }
}
