/**
 * T51 — ISDN LAPD/Q.931/IUA canaries (numbers, Facility mask, IUA Protocol Data).
 */
import { beforeEach, describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { sctpCrc32c, writeCrc32cLe } from '../../../src/crypto/crc32c'
import { IPPROTO_SCTP } from '../../../src/pcap/protocols/types'
import { LINKTYPE_LINUX_LAPD, PPID_IUA } from '../../../src/pcap/sanitize/isdn'
import { resetProtocolGraphStateRegistryForTests } from '../../../src/pcap/sanitize/protocolGraphState'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import {
  QSIG_FULL_ECM_CATALOG_CLAIM,
  QSIG_PINNED_OPERATION_CODES,
  QSIG_ROSE_SCHEMA_PIN,
  qsigPinnedInventoryMatchesSchema,
} from '../../../src/pcap/protocols/application/qsig/index.ts'
import {
  buildCallingNameInvoke,
  buildUnknownOpInvoke,
} from '../helpers/qsigRoseBer.ts'
import { QSIG_OP } from '../../../src/pcap/protocols/application/qsig/qsigRoseSchema.ts'

function packetInput(data: Uint8Array, linkType = 1) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

/** Minimal Q.931 SETUP with Calling/Called IA5 digits + Display + Facility. */
function buildQ931Setup(): Uint8Array {
  const calling = new TextEncoder().encode('420111222333')
  const called = new TextEncoder().encode('420444555666')
  const display = new TextEncoder().encode('Alice Canary')
  const facility = new TextEncoder().encode('FACILITY-SECRET-CANARY')
  // PD, CR len=1, CR=0x01 (orig), msg=SETUP(0x05)
  const parts: number[] = [0x08, 0x01, 0x01, 0x05]
  // Bearer capability dummy
  parts.push(0x04, 0x03, 0x80, 0x90, 0xa3)
  // Calling party number 0x6c: type/plan 0x81, digits
  parts.push(0x6c, 1 + calling.length, 0x81, ...calling)
  // Called party number 0x70
  parts.push(0x70, 1 + called.length, 0x81, ...called)
  // Display 0x28
  parts.push(0x28, display.length, ...display)
  // Facility 0x1c
  parts.push(0x1c, facility.length, ...facility)
  return Uint8Array.from(parts)
}

function buildLapdIFrame(q931: Uint8Array, tei = 0): Uint8Array {
  // Address: SAPI=0 (call control), C/R=0, EA0=0; TEI, EA1=1
  const a0 = 0x00
  const a1 = ((tei & 0x7f) << 1) | 0x01
  // I-frame control: N(S)=0, N(R)=0 → 0x00, 0x01 (P/F=0)
  const out = new Uint8Array(2 + 2 + q931.length)
  out[0] = a0
  out[1] = a1
  out[2] = 0x00
  out[3] = 0x01
  out.set(q931, 4)
  return out
}

function buildLinuxLapdFrame(lapd: Uint8Array): Uint8Array {
  const cooked = new Uint8Array(16 + lapd.length)
  // minimal cooked header (zeros OK for our parser)
  cooked.set(lapd, 16)
  return cooked
}

function buildEthIpSctp(srcIp: number[], dstIp: number[], sctpPayload: Uint8Array): Uint8Array {
  const total = 14 + 20 + sctpPayload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + sctpPayload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = IPPROTO_SCTP
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  buf.set(sctpPayload, 34)
  return buf
}

function finalizeSctp(packet: Uint8Array): void {
  const crc = sctpCrc32c(packet, 0, packet.length)
  writeCrc32cLe(packet, 8, crc)
}

function buildDataChunk(srcPort: number, dstPort: number, ppid: number, user: Uint8Array): Uint8Array {
  const chunkLen = 16 + user.length
  const padded = (chunkLen + 3) & ~3
  const pkt = new Uint8Array(12 + padded)
  pkt[0] = (srcPort >> 8) & 0xff
  pkt[1] = srcPort & 0xff
  pkt[2] = (dstPort >> 8) & 0xff
  pkt[3] = dstPort & 0xff
  pkt[12] = 0
  pkt[13] = 0x03
  pkt[14] = (chunkLen >> 8) & 0xff
  pkt[15] = chunkLen & 0xff
  pkt[16] = 0
  pkt[17] = 0
  pkt[18] = 0
  pkt[19] = 1
  pkt[24] = (ppid >>> 24) & 0xff
  pkt[25] = (ppid >>> 16) & 0xff
  pkt[26] = (ppid >>> 8) & 0xff
  pkt[27] = ppid & 0xff
  pkt.set(user, 28)
  finalizeSctp(pkt)
  return pkt
}

/** IUA QPTM Data Indication with Protocol Data = bare Q.931. */
function buildIuaProtocolData(
  q931: Uint8Array,
  ifName: string,
  order: 'if-then-pd' | 'pd-then-if' = 'if-then-pd',
): Uint8Array {
  const ifBytes = new TextEncoder().encode(ifName)
  const ifParamLen = 4 + ifBytes.length
  const ifPadded = (ifParamLen + 3) & ~3
  const pdParamLen = 4 + q931.length
  const pdPadded = (pdParamLen + 3) & ~3
  const msgLen = 8 + ifPadded + pdPadded
  const out = new Uint8Array(msgLen)
  out[0] = 1
  out[1] = 0
  out[2] = 5 // QPTM
  out[3] = 2 // Data Indication
  out[4] = (msgLen >>> 24) & 0xff
  out[5] = (msgLen >>> 16) & 0xff
  out[6] = (msgLen >>> 8) & 0xff
  out[7] = msgLen & 0xff
  const writeIf = (at: number) => {
    out[at] = 0x00
    out[at + 1] = 0x03
    out[at + 2] = (ifParamLen >> 8) & 0xff
    out[at + 3] = ifParamLen & 0xff
    out.set(ifBytes, at + 4)
  }
  const writePd = (at: number) => {
    out[at] = 0x00
    out[at + 1] = 0x0e
    out[at + 2] = (pdParamLen >> 8) & 0xff
    out[at + 3] = pdParamLen & 0xff
    out.set(q931, at + 4)
  }
  if (order === 'if-then-pd') {
    writeIf(8)
    writePd(8 + ifPadded)
  } else {
    writePd(8)
    writeIf(8 + pdPadded)
  }
  return out
}

describe('T51 registry', () => {
  it('registers lapd/q931/iua handlers, family, port, and engine 2.36.1', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('lapd')
    expect(ids).toContain('q931')
    expect(ids).toContain('iua')
    expect(familyForProtocol('lapd').familyId).toBe('isdn')
    expect(familyForProtocol('q931').familyId).toBe('isdn')
    expect(familyForProtocol('iua').familyId).toBe('isdn')
    expect(familyForProtocol('q931-number').familyId).toBe('isdn')
    expect(SEMANTIC_SERVICE_PORTS.has(9900)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T51 LAPD + Q.931', () => {
  it('maps calling/called digits and masks Facility on LINUX_LAPD', () => {
    const q931 = buildQ931Setup()
    const lapd = buildLapdIFrame(q931, 5)
    const frame = buildLinuxLapdFrame(lapd)
    const mapping = new SessionMapping(undefined, { seed: 't51-lapd' })
    const result = sanitizePacket(packetInput(frame, LINKTYPE_LINUX_LAPD), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('q931') || c.protocol.startsWith('lapd'))).toBe(
      true,
    )
    const out = latin1(applyPatches(frame, result))
    expect(out.includes('420111222333')).toBe(false)
    expect(out.includes('420444555666')).toBe(false)
    expect(out.includes('FACILITY-SECRET-CANARY')).toBe(false)
    expect(out.includes('Alice Canary')).toBe(false)
    // Message type SETUP preserved
    expect(frame[16 + 2 + 2 + 3]).toBe(0x05) // before patch msg type at fixed offset
    const patched = applyPatches(frame, result)
    expect(patched[16 + 4 + 3]).toBe(0x05)
  })

  it('structured QSIG callingName invoke maps IA5 name and marks facility covered', () => {
    const NAME_CANARY = 'QSIG-Calling-Name-Canary'
    const roseBody = buildCallingNameInvoke(NAME_CANARY)
    const parts: number[] = [0x08, 0x01, 0x01, 0x62]
    parts.push(0x1c, roseBody.length, ...roseBody)
    const q931 = Uint8Array.from(parts)
    const lapd = buildLapdIFrame(q931, 2)
    const frame = buildLinuxLapdFrame(lapd)
    const mapping = new SessionMapping(undefined, { seed: 't51-qsig-rose' })
    const result = sanitizePacket(packetInput(frame, LINKTYPE_LINUX_LAPD), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'q931-qsig-rose-invoke')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'q931-facility' && c.status === 'covered')).toBe(
      true,
    )
    expect(result.issues).not.toContain('q931-facility-mask')
    const out = latin1(applyPatches(frame, result))
    expect(out.includes(NAME_CANARY)).toBe(false)
  })

  it('unknown QSIG opcode masks argument but preserves invoke envelope', () => {
    const SECRET = 'QSIG-UNKNOWN-OP-SECRET!!'
    const roseBody = buildUnknownOpInvoke(99, SECRET)
    const parts: number[] = [0x08, 0x01, 0x01, 0x62, 0x1c, roseBody.length, ...roseBody]
    const q931 = Uint8Array.from(parts)
    const lapd = buildLapdIFrame(q931, 3)
    const frame = buildLinuxLapdFrame(lapd)
    const mapping = new SessionMapping(undefined, { seed: 't51-qsig-unknown' })
    const result = sanitizePacket(packetInput(frame, LINKTYPE_LINUX_LAPD), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues).toContain('q931-qsig-rose-unknown-op')
    const argCov = result.coverage.filter((c) => c.protocol === 'q931-qsig-rose-arg')
    expect(argCov.every((c) => c.status === 'redacted')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'q931-qsig-rose-invoke' && c.status === 'covered')).toBe(
      true,
    )
    const out = latin1(applyPatches(frame, result))
    expect(out.includes(SECRET)).toBe(false)
  })

  it('non-BER Facility payload stays fail-closed mask-only', () => {
    const facility = new TextEncoder().encode('FACILITY-PLAIN-ASCII-SECRET')
    const parts: number[] = [0x08, 0x01, 0x01, 0x62, 0x1c, facility.length, ...facility]
    const q931 = Uint8Array.from(parts)
    const lapd = buildLapdIFrame(q931, 4)
    const frame = buildLinuxLapdFrame(lapd)
    const mapping = new SessionMapping(undefined, { seed: 't51-facility-plain' })
    const result = sanitizePacket(packetInput(frame, LINKTYPE_LINUX_LAPD), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues).toContain('q931-facility-mask')
    const facilityCov = result.coverage.filter((c) => c.protocol === 'q931-facility')
    expect(facilityCov.every((c) => c.status === 'redacted')).toBe(true)
  })

  it('preserves call-ref direction bit across map', () => {
    const q931 = buildQ931Setup()
    // Flip CR to destination bit set (0x81)
    q931[2] = 0x81
    const lapd = buildLapdIFrame(q931, 1)
    const frame = buildLinuxLapdFrame(lapd)
    const mapping = new SessionMapping(undefined, { seed: 't51-cr' })
    const result = sanitizePacket(packetInput(frame, LINKTYPE_LINUX_LAPD), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    const crAbs = 16 + 4 + 2 // cooked + lapd addr/ctrl + PD + CR len → CR value
    expect((out[crAbs]! & 0x80) !== 0).toBe(true)
  })
})

describe('T51 IUA over SCTP', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  it('sanitizes Protocol Data Q.931 and masks interface name canary', () => {
    const q931 = buildQ931Setup()
    const iua = buildIuaProtocolData(q931, 'pri-canary-iface')
    const sctp = buildDataChunk(9900, 9900, PPID_IUA, iua)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't51-iua' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('iua') || c.protocol.startsWith('q931'))).toBe(
      true,
    )
    const out = latin1(applyPatches(frame, result))
    expect(out.includes('420111222333')).toBe(false)
    expect(out.includes('FACILITY-SECRET-CANARY')).toBe(false)
    expect(out.includes('pri-canary-iface')).toBe(false)
  })

  it('resolves Interface ID before Protocol Data even when PD TLV comes first', () => {
    const q931 = buildQ931Setup()
    const iua = buildIuaProtocolData(q931, 'pri-second-iface', 'pd-then-if')
    const sctp = buildDataChunk(9900, 9900, PPID_IUA, iua)
    const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
    const mapping = new SessionMapping(undefined, { seed: 't51-iua-order' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const protos = result.coverage.map((c) => c.protocol)
    expect(protos.some((p) => p.startsWith('iua')), `coverage=${protos.join(',')}`).toBe(true)
    // Bare Q.931 inside Protocol Data — must not be left as unparsed iua-pdata.
    expect(
      protos.some((p) => p.startsWith('q931') || p === 'iua-pdata'),
      `coverage=${protos.join(',')}`,
    ).toBe(true)
    expect(protos.includes('iua-pdata')).toBe(false)
    expect(mapping.get('opaque-id', 'isdn-cr:iua:if-text:pri-second-iface:01')).toBeDefined()
    expect(mapping.get('opaque-id', 'isdn-cr:iua:unknown-link:01')).toBeUndefined()
    expect(mapping.get('opaque-id', 'isdn-cr:iua:unscoped:pkt0:01')).toBeUndefined()
  })

  it('isolates identical call-refs on two IUA interfaces', () => {
    const mapping = new SessionMapping(undefined, { seed: 't51-iua-scope' })
    const q931 = buildQ931Setup()
    for (const ifName of ['pri-a', 'pri-b'] as const) {
      const iua = buildIuaProtocolData(q931, ifName, 'pd-then-if')
      const sctp = buildDataChunk(9900, 9900, PPID_IUA, iua)
      const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
      sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    }
    const a = mapping.get('opaque-id', 'isdn-cr:iua:if-text:pri-a:01')
    const b = mapping.get('opaque-id', 'isdn-cr:iua:if-text:pri-b:01')
    expect(a).toBeDefined()
    expect(b).toBeDefined()
    expect(a).not.toBe(b)
  })

  it('flags multi-link when the same call-ref appears on two IUA interfaces (SCTP path)', () => {
    const mapping = new SessionMapping(undefined, { seed: 't51-iua-multilink' })
    const q931 = buildQ931Setup()
    const frames: { ifName: 'pri-a' | 'pri-b'; index: number }[] = [
      { ifName: 'pri-a', index: 0 },
      { ifName: 'pri-b', index: 1 },
    ]
    const results: ReturnType<typeof sanitizePacket>[] = []
    for (const { ifName, index } of frames) {
      const iua = buildIuaProtocolData(q931, ifName, 'pd-then-if')
      const sctp = buildDataChunk(9900, 9900, PPID_IUA, iua)
      const frame = buildEthIpSctp([10, 0, 0, 1], [10, 0, 0, 2], sctp)
      results.push(
        sanitizePacket({ ...packetInput(frame), index }, DIAGNOSTIC_POLICY, mapping),
      )
    }
    expect(results[0]?.issues?.includes('q931-multi-link-graph')).toBe(false)
    expect(results[1]?.issues).toContain('q931-multi-link-graph')
  })
})

describe('T51 QSIG pinned schema inventory', () => {
  it('pins highest-value GF operations without full ECMA catalog claim', () => {
    expect(qsigPinnedInventoryMatchesSchema()).toBe(true)
    expect(QSIG_PINNED_OPERATION_CODES).toContain(QSIG_OP.CALLING_NAME)
    expect(QSIG_PINNED_OPERATION_CODES).toContain(QSIG_OP.ACTIVATE_DIVERSION)
    expect(QSIG_PINNED_OPERATION_CODES).toContain(QSIG_OP.CALL_TRANSFER_COMPLETE)
    expect(QSIG_FULL_ECM_CATALOG_CLAIM).toBe(false)
    expect(QSIG_ROSE_SCHEMA_PIN.moduleId).toBe('qsig.pisn.facility.rose.pinned')
  })
})

describe('T51 QSIG Facility export regression', () => {
  const FACILITY_CANARY = 'QSIG-Export-Name-Canary'

  /** Facility-only Q.931 with structured callingName ROSE invoke. */
  function buildQ931FacilityOnly(): Uint8Array {
    const facility = buildCallingNameInvoke(FACILITY_CANARY)
    return Uint8Array.from([0x08, 0x01, 0x01, 0x62, 0x1c, facility.length, ...facility])
  }

  /** IUA QPTM with Protocol Data only (no Interface ID opaque-id map). */
  function buildIuaProtocolDataOnly(q931: Uint8Array): Uint8Array {
    const pdParamLen = 4 + q931.length
    const pdPadded = (pdParamLen + 3) & ~3
    const msgLen = 8 + pdPadded
    const out = new Uint8Array(msgLen)
    out[0] = 1
    out[1] = 0
    out[2] = 5
    out[3] = 2
    out[4] = (msgLen >>> 24) & 0xff
    out[5] = (msgLen >>> 16) & 0xff
    out[6] = (msgLen >>> 8) & 0xff
    out[7] = msgLen & 0xff
    out[8] = 0x00
    out[9] = 0x0e
    out[10] = (pdParamLen >> 8) & 0xff
    out[11] = pdParamLen & 0xff
    out.set(q931, 12)
    return out
  }

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`export pipeline sanitizes structured Facility without leak (${level})`, () => {
      const q931 = buildQ931FacilityOnly()
      const lapd = buildLapdIFrame(q931, 9)
      const frame = buildLinuxLapdFrame(lapd)
      const exported = runExportPipeline(
        [
          {
            packetNumber: 1,
            timestamp: { ticks: 1n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
            capturedLength: frame.length,
            originalLength: frame.length,
            linkType: LINKTYPE_LINUX_LAPD,
            interfaceId: 0,
            sectionIndex: 0,
            fileOffset: 0,
            data: frame,
          },
        ],
        level,
        't51-qsig-export.pcap',
        `t51-qsig-export-${level}`,
        { mappingSeed: `t51-qsig-export-${level}` },
      )
      const wire = latin1(exported.built.packets[0]!.data)
      expect(wire.includes(FACILITY_CANARY)).toBe(false)
      assertCaptureHasNoPrivacyLeaks(exported.built.packets, [FACILITY_CANARY])
      const facilityCov =
        exported.discovery.packetDiscovery[0]?.coverage.filter((c) =>
          c.protocol.endsWith('-facility') || c.protocol.includes('qsig-rose'),
        ) ?? []
      expect(facilityCov.length).toBeGreaterThan(0)
      expect(facilityCov.some((c) => c.protocol === 'q931-facility' && c.status === 'covered')).toBe(
        true,
      )
      expect(facilityCov.some((c) => c.protocol === 'q931-qsig-rose-invoke')).toBe(true)
    })
  }
})
