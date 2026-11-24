/**
 * Transferable packed wire for discover → main-thread (R10 / PF scale).
 *
 * Nested object graphs for 100 MiB captures (~235k packets, ~1.6M coverage rows,
 * ~1.4M intents) are hundreds of MiB and hang Chromium structured-clone during
 * worker postMessage. Parallel typed arrays + string tables transfer by ownership.
 */

import type {
  ClassicPcapHeader,
  PacketRecordDescriptor,
  ParseIssue,
  PcapngInterfaceInfo,
  PcapngSectionInfo,
  SparseCheckpoint,
} from '../domain/types'
import type { PacketDiscoveryResult } from '../discovery/types'

export interface WirePackedCheckpoint {
  readonly packetNumber: number
  readonly fileOffset: number
}

export interface WirePackedTimestampProfile {
  readonly unitsPerSecond: string
  readonly offsetSeconds: string
}

/** Parallel descriptor columns — transferred as ArrayBuffers. */
export interface WirePackedDescriptors {
  readonly count: number
  readonly packetNumber: Uint32Array
  readonly capturedLength: Uint32Array
  readonly originalLength: Uint32Array
  readonly linkType: Uint16Array
  readonly interfaceId: Uint16Array
  readonly sectionIndex: Uint16Array
  readonly fileOffset: Float64Array
  readonly dataOffset: Uint32Array
  readonly ticksLo: Uint32Array
  readonly ticksHi: Uint32Array
  readonly tsProfileId: Uint16Array
  readonly tsProfiles: readonly WirePackedTimestampProfile[]
}

/**
 * Aggregate sanitizer coverage for the main thread (R10).
 * Full per-span coverage stays in the processing worker for plan build; expanding
 * ~1.6M LayerCoverage objects on the UI thread after discover hangs Chromium.
 */
export interface WireCoverageRollup {
  readonly totalUnsupportedSpans: number
  readonly totalTruncatedSpans: number
  readonly totalHeuristicSpans: number
  readonly preservedUnsafeSpans: number
  readonly processingFailedSpans: number
  readonly truncatedPacketCount: number
  readonly discoveryDropCount: number
  readonly discoveryIssueCount: number
}

export interface WirePackedPacketDiscovery {
  readonly count: number
  readonly packetIndex: Uint32Array
  readonly packetNumber: Uint32Array
  /** bit0 = drop, bit1 = has truncatedLength */
  readonly flags: Uint8Array
  readonly truncatedLength: Uint32Array
  /** Deduped issue strings; `issueIds` indexes into this table (0xffff = end of packet's list). */
  readonly issueTable: readonly string[]
  /** Flat list of issue-table ids, grouped by packet in `packetIndex` order, terminated by 0xffff. */
  readonly issueIds: Uint16Array
  readonly coverageRollup: WireCoverageRollup
}

export interface WirePackedContainer {
  readonly descriptors: WirePackedDescriptors
  /** Optional full packed PD — currently unused on UI; rollup carries honesty totals. */
  readonly packetDiscovery?: WirePackedPacketDiscovery
  readonly coverageRollup: WireCoverageRollup
  readonly checkpoints: WirePackedCheckpoint[]
  readonly issues: ParseIssue[]
  readonly classicHeader?: unknown
  readonly pcapngSections?: unknown[]
  readonly pcapngInterfaces?: unknown[]
}

function transferBufferOf(view: ArrayBufferView): ArrayBuffer {
  const buf = view.buffer
  if (buf instanceof ArrayBuffer) return buf
  // Defensive copy if a SharedArrayBuffer ever appears (Transferable list wants ArrayBuffer).
  const copy = new ArrayBuffer(view.byteLength)
  new Uint8Array(copy).set(new Uint8Array(buf, view.byteOffset, view.byteLength))
  return copy
}

function collectTransferBuffers(packed: WirePackedContainer): ArrayBuffer[] {
  const d = packed.descriptors
  const buffers: ArrayBuffer[] = [
    transferBufferOf(d.packetNumber),
    transferBufferOf(d.capturedLength),
    transferBufferOf(d.originalLength),
    transferBufferOf(d.linkType),
    transferBufferOf(d.interfaceId),
    transferBufferOf(d.sectionIndex),
    transferBufferOf(d.fileOffset),
    transferBufferOf(d.dataOffset),
    transferBufferOf(d.ticksLo),
    transferBufferOf(d.ticksHi),
    transferBufferOf(d.tsProfileId),
  ]
  return [...new Set(buffers)]
}

/** Compute rollup without allocating packed PD columns (R10 discover path). */
export function coverageRollupFromDiscovery(
  packetDiscovery: readonly PacketDiscoveryResult[],
): WireCoverageRollup {
  let totalUnsupportedSpans = 0
  let totalTruncatedSpans = 0
  let totalHeuristicSpans = 0
  let preservedUnsafeSpans = 0
  let processingFailedSpans = 0
  let truncatedPacketCount = 0
  let discoveryDropCount = 0
  let discoveryIssueCount = 0
  for (const pd of packetDiscovery) {
    if (pd.drop) discoveryDropCount++
    if (pd.truncatedLength !== undefined) truncatedPacketCount++
    discoveryIssueCount += pd.issues.length
    for (const c of pd.coverage) {
      switch (c.status) {
        case 'unsupported':
          totalUnsupportedSpans++
          break
        case 'truncated':
          totalTruncatedSpans++
          break
        case 'heuristic':
          totalHeuristicSpans++
          break
        case 'preserved-unsafe':
          preservedUnsafeSpans++
          break
        case 'processing-failed':
          processingFailedSpans++
          break
        default:
          break
      }
    }
  }
  return {
    totalUnsupportedSpans,
    totalTruncatedSpans,
    totalHeuristicSpans,
    preservedUnsafeSpans,
    processingFailedSpans,
    truncatedPacketCount,
    discoveryDropCount,
    discoveryIssueCount,
  }
}

export function packDescriptors(descriptors: readonly PacketRecordDescriptor[]): WirePackedDescriptors {
  const n = descriptors.length
  const packetNumber = new Uint32Array(n)
  const capturedLength = new Uint32Array(n)
  const originalLength = new Uint32Array(n)
  const linkType = new Uint16Array(n)
  const interfaceId = new Uint16Array(n)
  const sectionIndex = new Uint16Array(n)
  const fileOffset = new Float64Array(n)
  const dataOffset = new Uint32Array(n)
  const ticksLo = new Uint32Array(n)
  const ticksHi = new Uint32Array(n)
  const tsProfileId = new Uint16Array(n)
  const profileKeys: string[] = []
  const profileIndex = new Map<string, number>()
  const tsProfiles: WirePackedTimestampProfile[] = []

  for (let i = 0; i < n; i++) {
    const d = descriptors[i]!
    packetNumber[i] = d.packetNumber >>> 0
    capturedLength[i] = d.capturedLength >>> 0
    originalLength[i] = d.originalLength >>> 0
    linkType[i] = d.linkType & 0xffff
    interfaceId[i] = d.interfaceId & 0xffff
    sectionIndex[i] = d.sectionIndex & 0xffff
    fileOffset[i] = d.fileOffset
    dataOffset[i] = d.dataOffset >>> 0
    const ticks = d.timestamp.ticks
    ticksLo[i] = Number(ticks & 0xffffffffn)
    ticksHi[i] = Number((ticks >> 32n) & 0xffffffffn)
    const pk = `${d.timestamp.unitsPerSecond}\0${d.timestamp.offsetSeconds}`
    let pid = profileIndex.get(pk)
    if (pid === undefined) {
      pid = tsProfiles.length
      profileIndex.set(pk, pid)
      profileKeys.push(pk)
      tsProfiles.push({
        unitsPerSecond: d.timestamp.unitsPerSecond.toString(),
        offsetSeconds: d.timestamp.offsetSeconds.toString(),
      })
    }
    tsProfileId[i] = pid & 0xffff
  }

  return {
    count: n,
    packetNumber,
    capturedLength,
    originalLength,
    linkType,
    interfaceId,
    sectionIndex,
    fileOffset,
    dataOffset,
    ticksLo,
    ticksHi,
    tsProfileId,
    tsProfiles,
  }
}

export function unpackDescriptors(packed: WirePackedDescriptors): PacketRecordDescriptor[] {
  const n = packed.count
  const out: PacketRecordDescriptor[] = new Array(n)
  const profileBigints = packed.tsProfiles.map((p) => ({
    unitsPerSecond: BigInt(p.unitsPerSecond),
    offsetSeconds: BigInt(p.offsetSeconds),
  }))
  for (let i = 0; i < n; i++) {
    const lo = BigInt(packed.ticksLo[i]!)
    const hi = BigInt(packed.ticksHi[i]!)
    const profile = profileBigints[packed.tsProfileId[i]!]!
    out[i] = {
      packetNumber: packed.packetNumber[i]!,
      timestamp: {
        ticks: (hi << 32n) | lo,
        unitsPerSecond: profile.unitsPerSecond,
        offsetSeconds: profile.offsetSeconds,
      },
      capturedLength: packed.capturedLength[i]!,
      originalLength: packed.originalLength[i]!,
      linkType: packed.linkType[i]!,
      interfaceId: packed.interfaceId[i]!,
      sectionIndex: packed.sectionIndex[i]!,
      fileOffset: packed.fileOffset[i]!,
      dataOffset: packed.dataOffset[i]!,
    }
  }
  return out
}

export function packPacketDiscovery(
  packetDiscovery: readonly PacketDiscoveryResult[],
): WirePackedPacketDiscovery {
  const n = packetDiscovery.length
  const packetIndex = new Uint32Array(n)
  const packetNumber = new Uint32Array(n)
  const flags = new Uint8Array(n)
  const truncatedLength = new Uint32Array(n)

  let issueIdSlots = 0
  for (const pd of packetDiscovery) {
    // one id per issue + one 0xffff terminator per packet
    issueIdSlots += pd.issues.length + 1
  }

  const issueIndex = new Map<string, number>()
  const issueTable: string[] = []
  const issueIds = new Uint16Array(issueIdSlots)

  let totalUnsupportedSpans = 0
  let totalTruncatedSpans = 0
  let totalHeuristicSpans = 0
  let preservedUnsafeSpans = 0
  let processingFailedSpans = 0
  let truncatedPacketCount = 0
  let discoveryDropCount = 0
  let discoveryIssueCount = 0

  let issueAt = 0
  for (let i = 0; i < n; i++) {
    const pd = packetDiscovery[i]!
    packetIndex[i] = pd.packetIndex >>> 0
    packetNumber[i] = pd.packetNumber >>> 0
    let f = 0
    if (pd.drop) {
      f |= 1
      discoveryDropCount++
    }
    if (pd.truncatedLength !== undefined) {
      f |= 2
      truncatedLength[i] = pd.truncatedLength >>> 0
      truncatedPacketCount++
    }
    flags[i] = f
    discoveryIssueCount += pd.issues.length
    for (const iss of pd.issues) {
      let iid = issueIndex.get(iss)
      if (iid === undefined) {
        iid = issueTable.length
        if (iid >= 0xffff) throw new Error('packedCaptureWire: issue table overflow')
        issueIndex.set(iss, iid)
        issueTable.push(iss)
      }
      issueIds[issueAt++] = iid & 0xffff
    }
    issueIds[issueAt++] = 0xffff
    for (const c of pd.coverage) {
      switch (c.status) {
        case 'unsupported':
          totalUnsupportedSpans++
          break
        case 'truncated':
          totalTruncatedSpans++
          break
        case 'heuristic':
          totalHeuristicSpans++
          break
        case 'preserved-unsafe':
          preservedUnsafeSpans++
          break
        case 'processing-failed':
          processingFailedSpans++
          break
        default:
          break
      }
    }
  }

  return {
    count: n,
    packetIndex,
    packetNumber,
    flags,
    truncatedLength,
    issueTable,
    issueIds,
    coverageRollup: {
      totalUnsupportedSpans,
      totalTruncatedSpans,
      totalHeuristicSpans,
      preservedUnsafeSpans,
      processingFailedSpans,
      truncatedPacketCount,
      discoveryDropCount,
      discoveryIssueCount,
    },
  }
}

/**
 * Rebuild lightweight per-packet discovery rows for the UI thread.
 * Coverage spans are intentionally omitted — see {@link WireCoverageRollup}.
 */
export function unpackPacketDiscovery(packed: WirePackedPacketDiscovery): PacketDiscoveryResult[] {
  const n = packed.count
  const out: PacketDiscoveryResult[] = new Array(n)
  let issueAt = 0
  for (let i = 0; i < n; i++) {
    const f = packed.flags[i]!
    const issues: string[] = []
    while (issueAt < packed.issueIds.length) {
      const id = packed.issueIds[issueAt++]!
      if (id === 0xffff) break
      const text = packed.issueTable[id]
      if (text !== undefined) issues.push(text)
    }
    out[i] = {
      packetIndex: packed.packetIndex[i]!,
      packetNumber: packed.packetNumber[i]!,
      drop: (f & 1) !== 0,
      truncatedLength: (f & 2) !== 0 ? packed.truncatedLength[i]! : undefined,
      issues,
      intents: [],
      coverage: [],
    }
  }
  return out
}

export function coverageRollupFromPacked(
  packed: WirePackedContainer | undefined,
): WireCoverageRollup | undefined {
  return packed?.coverageRollup ?? packed?.packetDiscovery?.coverageRollup
}

export function packContainerBody(input: {
  descriptors: readonly PacketRecordDescriptor[]
  checkpoints: readonly SparseCheckpoint[]
  issues: readonly ParseIssue[]
  classicHeader?: ClassicPcapHeader
  pcapngSections?: PcapngSectionInfo[]
  pcapngInterfaces?: PcapngInterfaceInfo[]
  packetDiscovery: readonly PacketDiscoveryResult[]
}): { packed: WirePackedContainer; transfers: ArrayBuffer[] } {
  const packed: WirePackedContainer = {
    descriptors: packDescriptors(input.descriptors),
    coverageRollup: coverageRollupFromDiscovery(input.packetDiscovery),
    checkpoints: input.checkpoints.map((c) => ({ packetNumber: c.packetNumber, fileOffset: c.fileOffset })),
    issues: [...input.issues],
    classicHeader: input.classicHeader,
    pcapngSections: input.pcapngSections ? [...input.pcapngSections] : undefined,
    pcapngInterfaces: input.pcapngInterfaces ? [...input.pcapngInterfaces] : undefined,
  }
  return { packed, transfers: collectTransferBuffers(packed) }
}
