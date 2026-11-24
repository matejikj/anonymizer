/**
 * Step 4 — compact recovery INDEX: seed → typed arenas → encrypted frames.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketRecordDescriptor, type PacketTimestamp } from '../../src/pcap/domain/types'
import { PCAP_ENGINE_VERSION, hashPcapLevel, type PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { bytesEqual, bytesToHex, sha256 } from '../../src/crypto/incrementalSha256'
import { RECOVERY_LOOKUP_CATEGORIES } from '../../src/pcap/recovery/domain/types'
import { RECOVERY_CATEGORY_IDS, toRecoveryLookupCategory } from '../../src/pcap/recovery/codec/categoryIds'
import {
  COMPACT_ENTRY_STRIDE,
  COMPACT_OCC_STRIDE,
  anonymizedPacketNumberFromBitset,
  buildRankCheckpoints,
  compactStringAt,
  entryMatchKind,
  parseCompactIndex,
} from '../../src/pcap/recovery/codec/compactIndexCodec'
import {
  serializeRecoveryIndexSeed,
  buildRecoveryIndexSeedFromDiscovery,
  type RecoveryIndexSeedEntryInput,
} from '../../src/pcap/recovery/export/recoveryIndexSeedPort'
import { buildCompactIndexFromSeed } from '../../src/pcap/recovery/export/compactIndexBuilder'
import {
  restoreOriginalFromDataFrames,
  writeFullLiteralRecoveryBundle,
} from '../../src/pcap/recovery/export/recoveryBundleWriter'


function ts(): PacketTimestamp {
  return { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function makePcapWithMarkers(): {
  buffer: ArrayBuffer
  descriptors: PacketRecordDescriptor[]
  markers: { ipv4: Uint8Array; mac: Uint8Array; host: Uint8Array }
} {
  const ipv4 = new Uint8Array([10, 1, 2, 3])
  const mac = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
  const host = new TextEncoder().encode('sip.example.test')
  const packetData = new Uint8Array(64)
  packetData.set(ipv4, 0)
  packetData.set(mac, 8)
  packetData.set(host, 20)

  const size = 24 + 16 + packetData.length
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, 0xa1b2c3d4, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)
  view.setUint32(24 + 8, packetData.length, true)
  view.setUint32(24 + 12, packetData.length, true)
  new Uint8Array(buf, 40, packetData.length).set(packetData)

  const descriptors: PacketRecordDescriptor[] = [
    {
      packetNumber: 1,
      timestamp: ts(),
      capturedLength: packetData.length,
      originalLength: packetData.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 24,
      dataOffset: 40,
    },
  ]
  return { buffer: buf, descriptors, markers: { ipv4, mac, host } }
}

function minimalPlan(fileName = 'step4.pcap'): PcapPlanSnapshot {
  return {
    generationId: 'gen-step4',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: hashPcapLevel('diagnostic'),
    format: CaptureFormat.ClassicPcap,
    fileName,
    engineVersion: PCAP_ENGINE_VERSION,
    packets: [],
    droppedPacketNumbers: [],
    timestamps: 'relative',
    timestampAnchorSeed: 'seed',
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

function concatChunks(chunks: readonly ArrayBuffer[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const c of chunks) {
    out.set(new Uint8Array(c), o)
    o += c.byteLength
  }
  return out
}

describe('Step 4 — category registry', () => {
  it('assigns stable IDs for all recovery lookup categories', () => {
    const ids = new Set<number>()
    for (const c of RECOVERY_LOOKUP_CATEGORIES) {
      expect(RECOVERY_CATEGORY_IDS[c]).toBeGreaterThan(0)
      ids.add(RECOVERY_CATEGORY_IDS[c])
    }
    expect(ids.size).toBe(RECOVERY_LOOKUP_CATEGORIES.length)
  })

  it('maps registry identity aliases onto recovery categories', () => {
    expect(toRecoveryLookupCategory('ip')).toBe('ipv4')
    expect(toRecoveryLookupCategory('ssrc')).toBe('rtp-ssrc')
    expect(toRecoveryLookupCategory('radioId')).toBe('radio-id')
    expect(toRecoveryLookupCategory('sip-call-id')).toBe('sip-call-id')
    expect(toRecoveryLookupCategory('hostname')).toBe('hostname')
    expect(toRecoveryLookupCategory('vlan')).toBe('vlan')
    expect(toRecoveryLookupCategory('port')).toBe('port')
    expect(toRecoveryLookupCategory('mac')).toBe('mac')
    expect(toRecoveryLookupCategory('sip-user')).toBe('sip-user')
    expect(toRecoveryLookupCategory('sip-token')).toBe('sip-token')
    expect(toRecoveryLookupCategory('user-id')).toBe('user')
    expect(toRecoveryLookupCategory('phone')).toBe('phone')
    expect(RECOVERY_CATEGORY_IDS.phone).toBe(18)
    expect(RECOVERY_CATEGORY_IDS.user).toBe(19)
    expect(RECOVERY_CATEGORY_IDS.email).toBe(7)
    expect(RECOVERY_CATEGORY_IDS['sip-phone']).toBe(10)
  })
})

describe('Step 4 — compact index arenas', () => {
  it('hydrates originals from source spans without per-occurrence objects', async () => {
    const { buffer, markers } = makePcapWithMarkers()
    const entries: RecoveryIndexSeedEntryInput[] = [
      {
        category: 'ipv4',
        matchKind: 'exact',
        anonymizedCanonical: '10.0.0.1',
        anonymizedWire: '10.0.0.1',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 0,
            byteLength: 4,
            protocolId: 1,
            fieldId: 1,
          },
        ],
      },
      {
        category: 'mac',
        matchKind: 'exact',
        anonymizedCanonical: '00:11:22:33:44:55',
        anonymizedWire: '00:11:22:33:44:55',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 8,
            byteLength: 6,
            protocolId: 1,
            fieldId: 2,
          },
        ],
      },
      {
        category: 'hostname',
        matchKind: 'exact',
        anonymizedCanonical: 'anon.host',
        anonymizedWire: 'anon.host',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 20,
            byteLength: markers.host.byteLength,
            protocolId: 2,
            fieldId: 3,
          },
        ],
      },
    ]

    const seed = serializeRecoveryIndexSeed({
      generationId: 'gen-step4',
      mappingRevision: 1,
      originalPacketCount: 1,
      anonymizedPacketCount: 1,
      droppedPacketIndexes: [],
      entries,
    })
    expect(seed.ok).toBe(true)
    if (!seed.ok) return

    const built = await buildCompactIndexFromSeed({
      indexSeed: seed.value,
      sourceBlob: new Blob([buffer]),
      rangeDirectory: [],
    })
    expect(built.ok).toBe(true)
    if (!built.ok) return

    expect(built.value.view.entryCount).toBe(3)
    expect(built.value.view.occurrenceCount).toBe(3)
    expect(built.value.view.arenas.entryU32.length).toBe(3 * COMPACT_ENTRY_STRIDE)
    expect(built.value.view.arenas.occurrenceU32.length).toBe(3 * COMPACT_OCC_STRIDE)

    const roundTrip = parseCompactIndex(built.value.plaintext)
    expect(roundTrip.ok).toBe(true)
    if (!roundTrip.ok) return
    const ipv4Original = compactStringAt(roundTrip.value.arenas, roundTrip.value.arenas.entryU32[4]!)
    expect(ipv4Original).toBe(bytesToHex(markers.ipv4))
    const hostOriginal = compactStringAt(
      roundTrip.value.arenas,
      roundTrip.value.arenas.entryU32[2 * COMPACT_ENTRY_STRIDE + 4]!,
    )
    expect(hostOriginal).toBe('sip.example.test')
  })

  it('marks shared anonymized masks as ambiguous', async () => {
    const { buffer } = makePcapWithMarkers()
    const seed = serializeRecoveryIndexSeed({
      generationId: 'gen-amb',
      mappingRevision: 1,
      originalPacketCount: 1,
      anonymizedPacketCount: 1,
      droppedPacketIndexes: [],
      entries: [
        {
          category: 'other',
          matchKind: 'exact',
          anonymizedCanonical: '********',
          anonymizedWire: '********',
          occurrences: [
            {
              originalPacketNumber: 1,
              anonymizedPacketNumber: 1,
              fileOffset: 24,
              dataOffset: 40,
              byteOffsetInPacket: 0,
              byteLength: 4,
              protocolId: 0,
              fieldId: 0,
            },
          ],
        },
        {
          category: 'other',
          matchKind: 'exact',
          anonymizedCanonical: '********',
          anonymizedWire: '********',
          occurrences: [
            {
              originalPacketNumber: 1,
              anonymizedPacketNumber: 1,
              fileOffset: 24,
              dataOffset: 40,
              byteOffsetInPacket: 8,
              byteLength: 4,
              protocolId: 0,
              fieldId: 0,
            },
          ],
        },
      ],
    })
    expect(seed.ok).toBe(true)
    if (!seed.ok) return
    const built = await buildCompactIndexFromSeed({
      indexSeed: seed.value,
      sourceBlob: new Blob([buffer]),
      rangeDirectory: [],
    })
    expect(built.ok).toBe(true)
    if (!built.ok) return
    expect(entryMatchKind(built.value.view.arenas, 0)).toBe('ambiguous')
    expect(entryMatchKind(built.value.view.arenas, 1)).toBe('ambiguous')
  })

  it('maps dropped packets via bitset + rank checkpoints', () => {
    const originalCount = 4
    const dropped = new Uint8Array(1)
    dropped[0] = 0b0000_0010 // drop index 1
    const checkpoints = buildRankCheckpoints(dropped, originalCount)
    expect(anonymizedPacketNumberFromBitset(dropped, checkpoints, 0, originalCount)).toBe(1)
    expect(anonymizedPacketNumberFromBitset(dropped, checkpoints, 1, originalCount)).toBeNull()
    expect(anonymizedPacketNumberFromBitset(dropped, checkpoints, 2, originalCount)).toBe(2)
  })
})

describe('Step 4 — INDEX frames in bundle', () => {
  it('INDEX hash matches FINAL; restore reads INDEX separately from DATA', async () => {
    const { buffer, descriptors, markers } = makePcapWithMarkers()
    const seed = serializeRecoveryIndexSeed({
      generationId: 'gen-step4',
      mappingRevision: 1,
      originalPacketCount: 1,
      anonymizedPacketCount: 1,
      droppedPacketIndexes: [],
      entries: [
        {
          category: 'ipv4',
          matchKind: 'exact',
          anonymizedCanonical: '10.0.0.1',
          anonymizedWire: '10.0.0.1',
          occurrences: [
            {
              originalPacketNumber: 1,
              anonymizedPacketNumber: 1,
              fileOffset: 24,
              dataOffset: 40,
              byteOffsetInPacket: 0,
              byteLength: 4,
              protocolId: 1,
              fieldId: 1,
            },
          ],
        },
      ],
    })
    expect(seed.ok).toBe(true)
    if (!seed.ok) return

    const anonymizedSha256 = sha256(new TextEncoder().encode('anon-out'))
    const chunks: ArrayBuffer[] = []
    const written = await writeFullLiteralRecoveryBundle({
      sourceBlob: new Blob([buffer]),
      descriptors,
      plan: minimalPlan(),
      anonymizedSha256,
      anonymizedByteLength: 99,
      indexSeed: seed.value,
      onChunk: (b) => {
        chunks.push(b)
      },
    })
    expect(written.ok).toBe(true)
    if (!written.ok) return
    expect(written.value.indexFrameCount).toBeGreaterThanOrEqual(1)
    expect(written.value.lookupEntryCount).toBe(1)
    expect(written.value.occurrenceCount).toBe(1)

    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: concatChunks(chunks),
      anonymizedSha256,
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(bytesEqual(restored.value.original, new Uint8Array(buffer))).toBe(true)
    expect(restored.value.manifest.indexFrameCount).toBe(written.value.indexFrameCount)
    expect(bytesToHex(restored.value.manifest.indexSha256)).toBe(bytesToHex(written.value.indexSha256))
    expect(restored.value.index?.entryCount).toBe(1)
    const originalHex = compactStringAt(
      restored.value.index!.arenas,
      restored.value.index!.arenas.entryU32[4]!,
    )
    expect(originalHex).toBe(bytesToHex(markers.ipv4))
  })
})

describe('Step 4 — production discovery seed', () => {
  it('indexes mapped entities from discovery intents for later lookup', async () => {
    const { buffer, descriptors, markers } = makePcapWithMarkers()
    const plan: PcapPlanSnapshot = {
      ...minimalPlan(),
      packets: [
        {
          index: 0,
          packetNumber: 1,
          drop: false,
          patches: [],
          originalCapturedLength: 64,
          originalLength: 64,
          linkType: 1,
          interfaceId: 0,
          sectionIndex: 0,
          originalTimestamp: ts(),
          dispositionReason: 'exported',
          changeCounts: emptyPlanChangeCounts(),
          maskedByteCount: 0,
        },
      ],
    }
    const seed = buildRecoveryIndexSeedFromDiscovery({
      generationId: 'gen-step4',
      mappingRevision: 1,
      intents: [
        {
          kind: 'entity-replacement',
          packetIndex: 0,
          offset: 0,
          byteLength: 4,
          category: 'ipv4',
          canonical: '10.1.2.3',
          constraint: { kind: 'ipv4-wire' },
        },
      ],
      snapshot: {
        scope: 'session',
        revision: 1,
        mappingRevision: 1,
        canonicalizationVersion: 1,
        generationId: 'gen-step4',
        sourceId: 'src',
        overflow: false,
        entries: [
          {
            identityId: 1,
            category: 'ipv4',
            canonical: '10.1.2.3',
            alias: '198.51.100.24',
            aliases: [
              { alias: '198.51.100.24', constraint: { kind: 'ipv4-wire' }, disposition: 'bijective' },
            ],
            constraint: { kind: 'ipv4-wire' },
            disposition: 'bijective',
            occurrenceCount: 1,
          },
        ],
      },
      plan,
      descriptors,
    })
    expect(seed.ok).toBe(true)
    if (!seed.ok) return
    const built = await buildCompactIndexFromSeed({
      indexSeed: seed.value,
      sourceBlob: new Blob([buffer]),
      rangeDirectory: [],
    })
    expect(built.ok).toBe(true)
    if (!built.ok) return
    expect(built.value.view.entryCount).toBe(1)
    const originalHex = compactStringAt(built.value.view.arenas, built.value.view.arenas.entryU32[4]!)
    expect(originalHex).toBe(bytesToHex(markers.ipv4))
  })
})
