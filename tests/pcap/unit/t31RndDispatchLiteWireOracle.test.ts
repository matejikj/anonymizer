/**
 * T31 — independent wire oracle for rnd-dispatch-lite.
 *
 * Payload bytes are hand-audited hex (see comments per vector). They are NOT produced by
 * `buildRndDispatchLiteDatagram`, which hard-codes flags=0, reserved=0xaa, pad=0x0000.
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { hexToBytes } from '../../../src/crypto/incrementalSha256.ts'
import {
  buildRndDispatchLiteDatagram,
  RND_DISPATCH_LITE_UDP_PORT,
  rndDispatchLiteDescriptor,
  sanitizeFromDescriptor,
} from '../../../src/pcap/protocols/descriptors/index.ts'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping.ts'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession.ts'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector.ts'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'

/** Manual header decode — independent of descriptor sanitizer and project encoder. */
type OracleHeader = {
  readonly msgType: number
  readonly srcRadioId: number
  readonly dstRadioId: number
  readonly siteId: number
  readonly bodyAscii: string
}

function oracleDecodeRndDispatchLite(payload: Uint8Array): OracleHeader | null {
  if (payload.length < 24) return null
  if (
    payload[0] !== 0x52 ||
    payload[1] !== 0x4e ||
    payload[2] !== 0x44 ||
    payload[3] !== 0x31
  ) {
    return null
  }
  const srcRadioId = (payload[8]! << 16) | (payload[9]! << 8) | payload[10]!
  const dstRadioId = (payload[11]! << 16) | (payload[12]! << 8) | payload[13]!
  const siteId =
    (payload[14]! << 24) | (payload[15]! << 16) | (payload[16]! << 8) | payload[17]!
  const body = payload.subarray(24)
  const bodyAscii = new TextDecoder('latin1').decode(body)
  return {
    msgType: payload[5]!,
    srcRadioId,
    dstRadioId,
    siteId,
    bodyAscii,
  }
}

/** Project encoder cannot emit these header tail bytes (fixed in buildRndDispatchLiteDatagram). */
function isIndependentOfProjectEncoder(payload: Uint8Array): boolean {
  return payload[6] !== 0 || payload[7] !== 0xaa || payload[22] !== 0 || payload[23] !== 0
}

const ORACLE_WIRE_VECTORS = [
  {
    id: 'text-page-msg2',
    /** RND1 v1 type2; flags 0x37 reserved 0x5c; ids DEAD01/BEEF02; site CAFEBABE; body ORACLE-T31-PAGE-X */
    hex:
      '524e44310102375cdead01beef02cafebabe00001337f00d' +
      '4f5241434c452d5433312d504147452d58',
    canaries: ['ORACLE-T31-PAGE-X', 'DEAD01', 'BEEF02', 'CAFEBABE'] as const,
    expectMsgType: 2,
    expectSrc: 0xdead01,
    expectDst: 0xbeef02,
  },
  {
    id: 'gps-msg1',
    /** RND1 v1 type1; flags 0x33 reserved 0x05; body GPS-ORACLE-Q + 4 opaque bytes */
    hex:
      '524e4431010133050102030405060a0b0c0d00000042dead' +
      '4750532d4f5241434c452d51' +
      '01020304',
    canaries: ['GPS-ORACLE-Q', '01020304'] as const,
    expectMsgType: 1,
    expectSrc: 0x010203,
    expectDst: 0x040506,
  },
  {
    id: 'unknown-msgType-99',
    /** RND1 v1 type 0x63 (unknown variant); flags 0xa8 reserved 0x77 */
    hex:
      '524e44310163a877112233445566778899aabbccddeeff00' +
      '554e4b4e4f574e2d4d53472d4f5241434c45',
    canaries: ['UNKNOWN-MSG-ORACLE', '112233', '445566'] as const,
    expectMsgType: 0x63,
    expectSrc: 0x112233,
    expectDst: 0x445566,
  },
] as const

function mapping(seed: string): SessionMapping {
  return new SessionMapping(
    {
      ip: 'topology-preserving',
      mac: 'locally-administered',
      timestamps: 'relative',
      ephemeralPorts: 'preserve',
      contentSignalingPorts: 'preserve',
      vlan: 'map',
    },
    { seed },
  )
}

function applyPatches(original: Uint8Array, patches: readonly { offset: number; data: Uint8Array }[]): Uint8Array {
  const out = original.slice()
  for (const p of patches) out.set(p.data, p.offset)
  return out
}

describe('T31 rnd-dispatch-lite wire oracle (independent fixtures)', () => {
  it('oracle payloads are not emitted by buildRndDispatchLiteDatagram', () => {
    const encoderGrid: Array<{
      msgType: 0 | 1 | 2
      srcRadioId: number
      dstRadioId: number
      siteId: number
      body: Uint8Array
    }> = []
    for (const msgType of [0, 1, 2] as const) {
      for (const srcRadioId of [0x010203, 0xdead01, 0x112233]) {
        for (const dstRadioId of [0x040506, 0xbeef02, 0x445566]) {
          for (const siteId of [0x0a0b0c0d, 0xcafebabe, 0x778899aa]) {
            encoderGrid.push({
              msgType,
              srcRadioId,
              dstRadioId,
              siteId,
              body: new TextEncoder().encode('x'),
            })
          }
        }
      }
    }
    const encoderOutputs = new Set(
      encoderGrid.map((g) =>
        Array.from(buildRndDispatchLiteDatagram(g), (b) => b.toString(16).padStart(2, '0')).join(''),
      ),
    )

    for (const vector of ORACLE_WIRE_VECTORS) {
      const payload = hexToBytes(vector.hex)
      expect(isIndependentOfProjectEncoder(payload)).toBe(true)
      expect(encoderOutputs.has(vector.hex)).toBe(false)
    }
  })

  it.each(ORACLE_WIRE_VECTORS)(
    'decode→sanitize ($id): oracle parse + descriptor path redacts canaries',
    (vector) => {
      const payload = hexToBytes(vector.hex)
      const decoded = oracleDecodeRndDispatchLite(payload)
      expect(decoded).not.toBeNull()
      expect(decoded!.msgType).toBe(vector.expectMsgType)
      expect(decoded!.srcRadioId).toBe(vector.expectSrc)
      expect(decoded!.dstRadioId).toBe(vector.expectDst)

      const map = mapping(`t31-oracle-sanitize-${vector.id}`)
      const collector = new PatchCollector(payload.byteLength)
      const result = sanitizeFromDescriptor(
        rndDispatchLiteDescriptor,
        payload,
        0,
        payload.byteLength,
        collector,
        map,
      )
      expect(result).not.toBeNull()
      collector.resolveDeferred({ mapping: map, fingerprints: new FingerprintSession() })
      const sanitized = applyPatches(payload, collector.getPatches())
      const latin1 = new TextDecoder('latin1').decode(sanitized)
      for (const canary of vector.canaries) {
        expect(latin1.includes(canary)).toBe(false)
      }
      expect(String.fromCharCode(sanitized[0]!, sanitized[1]!, sanitized[2]!, sanitized[3]!)).toBe(
        'RND1',
      )
      const srcOut = (sanitized[8]! << 16) | (sanitized[9]! << 8) | sanitized[10]!
      expect(srcOut).not.toBe(vector.expectSrc)
    },
  )

  it.each(ORACLE_WIRE_VECTORS)(
    'decode→sanitize→export ($id): full diagnostic pipeline',
    (vector) => {
      const payload = hexToBytes(vector.hex)
      const frame = buildEthIpUdp(
        [192, 0, 2, 1],
        [192, 0, 2, 2],
        50_000,
        RND_DISPATCH_LITE_UDP_PORT,
        payload,
      )
      const envelope: PacketEnvelope = {
        packetNumber: 0,
        timestamp: { ticks: 1_700_000_000_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
        capturedLength: frame.length,
        originalLength: frame.length,
        linkType: 1,
        interfaceId: 0,
        sectionIndex: 0,
        fileOffset: 24,
        data: frame,
      }
      const { built, discovery } = runDiagnosticExportPipeline(
        [envelope],
        `t31-oracle-${vector.id}.pcap`,
        `t31-oracle-export-${vector.id}`,
        { mappingSeed: `t31-oracle-export-${vector.id}` },
      )
      expect(built.validationValid).toBe(true)
      expect(
        discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'rnd-dispatch-lite'),
      ).toBe(true)

      const exported = built.packets[0]!.data
      const udpStart = 14 + 20 + 8
      const exportedPayload = exported.subarray(udpStart)
      const latin1 = new TextDecoder('latin1').decode(exportedPayload)
      for (const canary of vector.canaries) {
        expect(latin1.includes(canary)).toBe(false)
      }
      expect(String.fromCharCode(exportedPayload[0]!, exportedPayload[1]!, exportedPayload[2]!, exportedPayload[3]!)).toBe(
        'RND1',
      )
    },
  )
})
