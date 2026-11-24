/**
 * Convert PcapPlanSnapshot to/from wire format for worker responses.
 */

import { CaptureFormat } from '../domain/types'
import type { PcapPlanSnapshot } from '../export/planSnapshot'
import type { WirePackedPatch, WirePlanSnapshot } from '../export/workerProtocol'
import { EMPTY_INCIDENT_LOG_SNAPSHOT, PCAP_ENGINE_VERSION } from '../export/planSnapshot'
import { emptyPlanChangeCounts } from '../plan/planDisposition'
import {
  DEFAULT_PCAP_LEVEL,
  isPcapAnonymizationLevel,
  type PcapAnonymizationLevel,
} from '../profile/pcapAnonymizationLevel'

/**
 * Pack every packet's patches into ONE contiguous buffer instead of one ArrayBuffer per patch.
 * A real capture can carry millions of patches; postMessage()'s transfer list has real
 * per-item overhead, so transferring millions of tiny buffers is catastrophically slower than
 * transferring one buffer of the same total size. Shared by every plan wire producer.
 */
export function packPlanPatches(
  packets: readonly { patches: readonly { offset: number; data: Uint8Array }[] }[],
): { perPacketPatches: WirePackedPatch[][]; patchData: ArrayBuffer } {
  let total = 0
  for (const p of packets) {
    for (const patch of p.patches) total += patch.data.byteLength
  }
  const buf = new Uint8Array(total)
  let cursor = 0
  const perPacketPatches = packets.map((p) =>
    p.patches.map((patch) => {
      const byteOffset = cursor
      buf.set(patch.data, byteOffset)
      cursor += patch.data.byteLength
      return { offset: patch.offset, byteOffset, length: patch.data.byteLength }
    }),
  )
  return { perPacketPatches, patchData: buf.buffer }
}

/** Inverse of `packPlanPatches` — reconstructs per-patch views (no copy) into `patchData`. */
export function unpackPlanPatches(
  wirePatches: readonly WirePackedPatch[],
  patchData: ArrayBuffer,
): Array<{ offset: number; data: Uint8Array }> {
  return wirePatches.map((patch) => ({
    offset: patch.offset,
    data: new Uint8Array(patchData, patch.byteOffset, patch.length),
  }))
}

// `unitsPerSecond`/`offsetSeconds` take only a handful of distinct values across a whole
// capture (one per interface/section) — cache their BigInt conversion so hundreds of thousands
// of packets share the same few instances instead of allocating one pair each.
const sharedTimestampBigIntCache = new Map<string, bigint>()
function sharedBigInt(value: string): bigint {
  let cached = sharedTimestampBigIntCache.get(value)
  if (cached === undefined) {
    cached = BigInt(value)
    sharedTimestampBigIntCache.set(value, cached)
  }
  return cached
}

function tsFromWire(w: WirePlanSnapshot['packets'][0]['originalTimestamp']) {
  return {
    ticks: BigInt(w.ticks),
    unitsPerSecond: sharedBigInt(w.unitsPerSecond),
    offsetSeconds: sharedBigInt(w.offsetSeconds),
  }
}

/** Derive level from deprecated profileId (`pcap-diagnostic` / `pcap-high-privacy`) or raw level. */
export function pcapLevelFromProfileId(profileId: string): PcapAnonymizationLevel {
  if (isPcapAnonymizationLevel(profileId)) return profileId
  if (profileId === 'pcap-high-privacy' || profileId.endsWith('-high-privacy')) return 'high-privacy'
  if (profileId === 'pcap-diagnostic' || profileId.endsWith('-diagnostic')) return 'diagnostic'
  return DEFAULT_PCAP_LEVEL
}

function materializePlanPacket(
  wire: WirePlanSnapshot,
  index: number,
): import('../export/planSnapshot').PcapPlanPacket {
  const p = wire.packets[index]!
  return {
    index: p.index,
    packetNumber: p.packetNumber,
    drop: p.drop,
    patches: unpackPlanPatches(p.patches, wire.patchData),
    truncatedLength: p.truncatedLength,
    originalCapturedLength: p.originalCapturedLength,
    originalLength: p.originalLength,
    linkType: p.linkType,
    interfaceId: p.interfaceId,
    sectionIndex: p.sectionIndex,
    originalTimestamp: tsFromWire(p.originalTimestamp),
    dispositionReason: p.dispositionReason ?? (p.drop ? 'user-requested-drop' : 'exported'),
    changeCounts: p.changeCounts ?? emptyPlanChangeCounts(),
    maskedByteCount: p.maskedByteCount ?? 0,
    primaryProtocol: p.primaryProtocol,
  }
}

/**
 * R10 — lazy plan packets: keep the wire array as the source of truth and materialize
 * only packets the UI actually touches (virtualized grid / selected packet). Eager
 * `.map()` here previously doubled ~235k packet objects on the main thread.
 */
export function planFromWire(wire: WirePlanSnapshot, profileId: string): PcapPlanSnapshot {
  const resolvedProfileId = wire.profileId || profileId
  const pcapLevel =
    wire.pcapLevel && isPcapAnonymizationLevel(wire.pcapLevel)
      ? wire.pcapLevel
      : pcapLevelFromProfileId(resolvedProfileId)
  const policyHash = wire.policyHash || wire.profileHash
  const cache = new Map<number, import('../export/planSnapshot').PcapPlanPacket>()
  const CACHE_MAX = 512
  const getPacket = (i: number) => {
    let hit = cache.get(i)
    if (hit) return hit
    hit = materializePlanPacket(wire, i)
    if (cache.size >= CACHE_MAX) cache.clear()
    cache.set(i, hit)
    return hit
  }
  const packets = new Proxy([] as import('../export/planSnapshot').PcapPlanPacket[], {
    get(_target, prop, receiver) {
      if (prop === 'length') return wire.packets.length
      if (prop === Symbol.iterator) {
        return function* iterate() {
          for (let i = 0; i < wire.packets.length; i++) yield getPacket(i)
        }
      }
      if (typeof prop === 'string' && /^\d+$/.test(prop)) {
        return getPacket(Number(prop))
      }
      if (prop === 'map') {
        return (
          fn: (
            value: import('../export/planSnapshot').PcapPlanPacket,
            index: number,
            array: import('../export/planSnapshot').PcapPlanPacket[],
          ) => unknown,
          thisArg?: unknown,
        ) => {
          const out = new Array(wire.packets.length)
          for (let i = 0; i < wire.packets.length; i++) {
            out[i] = fn.call(thisArg, getPacket(i), i, receiver as import('../export/planSnapshot').PcapPlanPacket[])
          }
          return out
        }
      }
      const value = Reflect.get(_target, prop, receiver)
      return typeof value === 'function' ? value.bind(_target) : value
    },
  })

  let packetsWithChanges = wire.packetsWithChanges
  if (packetsWithChanges === undefined) {
    let n = 0
    for (const p of wire.packets) {
      if (p.patches.length > 0 || p.truncatedLength !== undefined) n++
    }
    packetsWithChanges = n
  }

  const plan: PcapPlanSnapshot = {
    generationId: wire.generationId,
    pcapLevel,
    profileId: resolvedProfileId,
    profileHash: policyHash,
    policyHash,
    format: wire.format as CaptureFormat,
    fileName: wire.fileName,
    engineVersion: wire.engineVersion || PCAP_ENGINE_VERSION,
    packets,
    packetsWithChanges,
    droppedPacketNumbers: [...wire.droppedPacketNumbers],
    classicHeader: wire.classicHeader
      ? {
          format: CaptureFormat.ClassicPcap,
          endian: wire.classicHeader.endian as import('../domain/types').Endian,
          timestampResolution: wire.classicHeader.timestampResolution as import('../domain/types').TimestampResolution,
          versionMajor: wire.classicHeader.versionMajor,
          versionMinor: wire.classicHeader.versionMinor,
          snapLen: wire.classicHeader.snapLen,
          linkType: wire.classicHeader.linkType,
          tzOffset: wire.classicHeader.tzOffset,
          sigfigs: wire.classicHeader.sigfigs,
        }
      : undefined,
    pcapngSections: wire.pcapngSections as PcapPlanSnapshot['pcapngSections'],
    pcapngInterfaces: wire.pcapngInterfaces as PcapPlanSnapshot['pcapngInterfaces'],
    timestamps: wire.timestamps ?? 'relative',
    timestampAnchorSeed:
      wire.timestampAnchorSeed
      ?? `${wire.generationId}:${policyHash}`,
    changeCategoryTotals: wire.changeCategoryTotals ?? emptyPlanChangeCounts(),
    maskedByteCount: wire.maskedByteCount ?? 0,
    dropsByReason: {
      exported: 0,
      'user-requested-drop': 0,
      blocked: 0,
      ...(wire.dropsByReason ?? {}),
    },
    dropsByProtocol: wire.dropsByProtocol ?? {},
    incidents: wire.incidents ?? EMPTY_INCIDENT_LOG_SNAPSHOT,
  }
  // Non-enumerable wire handle for drop-bit scans without materializing patches (R10).
  Object.defineProperty(plan, '__wire', { value: wire, enumerable: false })
  return plan
}

/** Read drop without materializing patch views (uses planFromWire's hidden wire handle). */
export function planPacketDropped(plan: PcapPlanSnapshot, packetIndex: number): boolean {
  const wire = (plan as { __wire?: WirePlanSnapshot }).__wire
  if (wire?.packets[packetIndex]) return wire.packets[packetIndex]!.drop
  return plan.packets[packetIndex]?.drop ?? false
}

export function planToWireExport(plan: PcapPlanSnapshot): { wire: WirePlanSnapshot; transfers: ArrayBuffer[] } {
  const { perPacketPatches, patchData } = packPlanPatches(plan.packets)
  const packets = plan.packets.map((p, i) => {
    return {
      index: p.index,
      packetNumber: p.packetNumber,
      drop: p.drop,
      patches: perPacketPatches[i]!,
      truncatedLength: p.truncatedLength,
      originalCapturedLength: p.originalCapturedLength,
      originalLength: p.originalLength,
      linkType: p.linkType,
      interfaceId: p.interfaceId,
      sectionIndex: p.sectionIndex,
      originalTimestamp: {
        ticks: p.originalTimestamp.ticks.toString(),
        unitsPerSecond: p.originalTimestamp.unitsPerSecond.toString(),
        offsetSeconds: p.originalTimestamp.offsetSeconds.toString(),
      },
      dispositionReason: p.dispositionReason,
      changeCounts: p.changeCounts,
      maskedByteCount: p.maskedByteCount,
      primaryProtocol: p.primaryProtocol,
    }
  })

  return {
    wire: {
      generationId: plan.generationId,
      pcapLevel: plan.pcapLevel,
      profileId: plan.profileId,
      profileHash: plan.profileHash,
      policyHash: plan.policyHash || plan.profileHash,
      format: plan.format,
      fileName: plan.fileName,
      engineVersion: plan.engineVersion,
      packets,
      patchData,
      packetsWithChanges:
        plan.packetsWithChanges
        ?? packets.reduce(
          (n, p) => n + (p.patches.length > 0 || p.truncatedLength !== undefined ? 1 : 0),
          0,
        ),
      droppedPacketNumbers: [...plan.droppedPacketNumbers],
      timestamps: plan.timestamps,
      timestampAnchorSeed: plan.timestampAnchorSeed,
      changeCategoryTotals: plan.changeCategoryTotals,
      maskedByteCount: plan.maskedByteCount,
      dropsByReason: plan.dropsByReason,
      dropsByProtocol: plan.dropsByProtocol,
      incidents: plan.incidents ?? EMPTY_INCIDENT_LOG_SNAPSHOT,
      classicHeader: plan.classicHeader
        ? {
            format: plan.classicHeader.format,
            endian: plan.classicHeader.endian,
            timestampResolution: plan.classicHeader.timestampResolution,
            versionMajor: plan.classicHeader.versionMajor,
            versionMinor: plan.classicHeader.versionMinor,
            snapLen: plan.classicHeader.snapLen,
            linkType: plan.classicHeader.linkType,
            tzOffset: plan.classicHeader.tzOffset,
            sigfigs: plan.classicHeader.sigfigs,
          }
        : undefined,
      pcapngSections: plan.pcapngSections
        ? (plan.pcapngSections as unknown as WirePlanSnapshot['pcapngSections'])
        : undefined,
      pcapngInterfaces: plan.pcapngInterfaces
        ? (plan.pcapngInterfaces as unknown as WirePlanSnapshot['pcapngInterfaces'])
        : undefined,
    },
    transfers: [patchData],
  }
}
