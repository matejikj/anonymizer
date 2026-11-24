/**
 * Step 2 — recovery codec: golden fixtures, tamper, oversize, frame order (v4 plaintext).
 */

import { describe, expect, it } from 'vitest'
import { bytesToHex, sha256 } from '../../src/crypto/incrementalSha256'
import {
  FrameSequenceTracker,
  PCAP_RECOVERY_ERROR,
  buildEmptyDataFrameHeaderVector,
  buildPreambleLayoutVector,
  footerSha256,
  parseFooter,
  parseFrame,
  parseFrameHeader,
  parseManifest,
  parsePreamble,
  writeFooter,
  writeFrameEnvelope,
  writeManifest,
  writePreamble,
  RECOVERY_ENCRYPTED_FORMAT_VERSION,
  RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE,
  RECOVERY_FRAME_TYPE_DATA,
  RECOVERY_FRAME_TYPE_FINAL,
  RECOVERY_FRAME_TYPE_INDEX,
} from '../../src/pcap/recovery'

const ANON_HASH = sha256(new TextEncoder().encode('anonymized-capture-v1'))

function fixedMaterial() {
  const recoveryId = new Uint8Array(16)
  for (let i = 0; i < 16; i++) recoveryId[i] = i
  return { recoveryId, hashPrefix: ANON_HASH.subarray(0, 8) }
}

describe('Step 2 — recovery preamble/footer/manifest codecs', () => {
  it('parses the hand-assembled v4 preamble layout vector', () => {
    const vector = buildPreambleLayoutVector()
    const parsed = parsePreamble(vector)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.value.headerLength).toBe(vector.byteLength)
    expect(bytesToHex(parsed.value.recoveryId)).toBe('000102030405060708090a0b0c0d0e0f')
  })

  it('round-trips preamble deterministically (golden)', () => {
    const m = fixedMaterial()
    const written = writePreamble({
      recoveryId: m.recoveryId,
      anonymizedSha256Prefix64: m.hashPrefix,
    })
    expect(written.ok).toBe(true)
    if (!written.ok) return
    const again = writePreamble({
      recoveryId: m.recoveryId,
      anonymizedSha256Prefix64: m.hashPrefix,
    })
    expect(again.ok).toBe(true)
    if (!again.ok) return
    expect(bytesToHex(written.value)).toBe(bytesToHex(again.value))
    const parsed = parsePreamble(written.value)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(bytesToHex(parsed.value.recoveryId)).toBe(bytesToHex(m.recoveryId))
  })

  it('rejects legacy encrypted v3 with a clear Czech message', () => {
    const vector = buildPreambleLayoutVector()
    const view = new DataView(vector.buffer)
    view.setUint16(8, RECOVERY_ENCRYPTED_FORMAT_VERSION, true)
    view.setUint16(10, RECOVERY_ENCRYPTED_FORMAT_VERSION, true)
    const parsed = parsePreamble(vector)
    expect(parsed.ok).toBe(false)
    if (!parsed.ok) {
      expect(parsed.code).toBe(PCAP_RECOVERY_ERROR.versionUnsupported)
      expect(parsed.message).toBe(RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE)
    }
  })

  it('rejects unknown mandatory flags and non-zero reserved bytes', () => {
    const vector = buildPreambleLayoutVector()
    const badFlag = vector.slice()
    badFlag[14] = 0x01
    expect(parsePreamble(badFlag).ok).toBe(false)
    if (parsePreamble(badFlag).ok === false) {
      expect(parsePreamble(badFlag).code).toBe(PCAP_RECOVERY_ERROR.versionUnsupported)
    }

    const reserved = vector.slice()
    reserved[18] = 0x01
    expect(parsePreamble(reserved).ok).toBe(false)
  })

  it('round-trips footer and verifies CRC', () => {
    const m = fixedMaterial()
    const written = writeFooter({
      recoveryId: m.recoveryId,
      totalByteLength: 1024,
      dataFrameCount: 2,
      indexFrameCount: 1,
      indexDirectoryOffset: 100,
      indexDirectoryLength: 50,
      finalFrameOffset: 900,
      finalFrameLength: 24,
      anonymizedByteLength: 512,
      anonymizedSha256Prefix64: m.hashPrefix,
    })
    expect(written.ok).toBe(true)
    if (!written.ok) return
    const parsed = parseFooter(written.value)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(Number(parsed.value.totalByteLength)).toBe(1024)
    expect(parsed.value.dataFrameCount).toBe(2)

    const flipped = written.value.slice()
    flipped[30] ^= 0x01
    expect(parseFooter(flipped).ok).toBe(false)
  })

  it('round-trips manifest plaintext', () => {
    const m = fixedMaterial()
    const footer = writeFooter({
      recoveryId: m.recoveryId,
      totalByteLength: 200,
      dataFrameCount: 1,
      indexFrameCount: 0,
      indexDirectoryOffset: 0,
      indexDirectoryLength: 0,
      finalFrameOffset: 100,
      finalFrameLength: 50,
      anonymizedByteLength: 100,
      anonymizedSha256Prefix64: m.hashPrefix,
    })
    expect(footer.ok).toBe(true)
    if (!footer.ok) return
    const footerHash = footerSha256(footer.value)
    const written = writeManifest({
      recoveryId: m.recoveryId,
      originalFileName: 'capture.pcap',
      originalFormat: 'pcap',
      originalByteLength: 100n,
      originalSha256: ANON_HASH,
      anonymizedByteLength: 100n,
      anonymizedSha256: ANON_HASH,
      pcapLevel: 'diagnostic',
      policyHash: new TextEncoder().encode('policy'),
      engineVersion: '1',
      restoreEncoding: 'full-literal-frames-v1',
      lookupEncoding: 'compact-index-v1',
      dataFrameCount: 1,
      indexFrameCount: 0,
      lookupEntryCount: 0n,
      occurrenceCount: 0n,
      originalPacketCount: 1n,
      anonymizedPacketCount: 1n,
      indexSha256: ANON_HASH,
      footerSha256: footerHash,
    })
    expect(written.ok).toBe(true)
    if (!written.ok) return
    const parsed = parseManifest(written.value)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.value.originalFileName).toBe('capture.pcap')
    expect(parsed.value.dataFrameCount).toBe(1)
  })

  it('rejects oversize frame plaintext claim', () => {
    const header = buildEmptyDataFrameHeaderVector(0)
    const view = new DataView(header.buffer)
    view.setUint32(8, 0xffffffff, true)
    view.setUint32(12, 0xffffffff, true)
    const parsed = parseFrameHeader(header, 0)
    expect(parsed.ok).toBe(false)
    if (!parsed.ok) expect(parsed.code).toBe(PCAP_RECOVERY_ERROR.oversize)
  })

  it('rejects truncated payload without allocating claimed length', () => {
    const header = buildEmptyDataFrameHeaderVector(0)
    const view = new DataView(header.buffer)
    view.setUint32(8, 1024, true)
    view.setUint32(12, 1024, true)
    const parsed = parseFrame(header, 0)
    expect(parsed.ok).toBe(false)
    if (!parsed.ok) expect(parsed.code).toBe(PCAP_RECOVERY_ERROR.invalidFormat)
  })

  it('tracks frame order and rejects duplicate / reorder / missing FINAL', () => {
    const tracker = new FrameSequenceTracker()
    expect(tracker.accept({
      frameType: RECOVERY_FRAME_TYPE_DATA,
      frameFlags: 0,
      frameIndex: 0,
      plaintextLength: 0,
      payloadLength: 0,
    }).ok).toBe(true)
    expect(tracker.accept({
      frameType: RECOVERY_FRAME_TYPE_DATA,
      frameFlags: 0,
      frameIndex: 0,
      plaintextLength: 0,
      payloadLength: 0,
    }).ok).toBe(false)
    const tracker2 = new FrameSequenceTracker()
    tracker2.accept({
      frameType: RECOVERY_FRAME_TYPE_DATA,
      frameFlags: 0,
      frameIndex: 0,
      plaintextLength: 0,
      payloadLength: 0,
    })
    expect(tracker2.accept({
      frameType: RECOVERY_FRAME_TYPE_INDEX,
      frameFlags: 0,
      frameIndex: 1,
      plaintextLength: 0,
      payloadLength: 0,
    }).ok).toBe(true)
    expect(tracker2.accept({
      frameType: RECOVERY_FRAME_TYPE_DATA,
      frameFlags: 0,
      frameIndex: 2,
      plaintextLength: 0,
      payloadLength: 0,
    }).ok).toBe(false)
    expect(tracker2.finish().ok).toBe(false)

    const tracker3 = new FrameSequenceTracker()
    tracker3.accept({
      frameType: RECOVERY_FRAME_TYPE_FINAL,
      frameFlags: 0,
      frameIndex: 0,
      plaintextLength: 10,
      payloadLength: 10,
    })
    expect(tracker3.finish().ok).toBe(true)
  })

  it('writes and parses a DATA frame envelope, and rejects a length-tampered header', () => {
    const plaintext = new TextEncoder().encode('literal-frame-bytes')
    const frame = writeFrameEnvelope({
      frameType: RECOVERY_FRAME_TYPE_DATA,
      frameIndex: 0,
      plaintext,
    })
    expect(frame.ok).toBe(true)
    if (!frame.ok) return
    expect(frame.value.byteLength).toBe(16 + plaintext.byteLength)

    const again = writeFrameEnvelope({
      frameType: RECOVERY_FRAME_TYPE_DATA,
      frameIndex: 0,
      plaintext,
    })
    expect(again.ok).toBe(true)
    if (!again.ok) return
    expect(bytesToHex(frame.value)).toBe(bytesToHex(again.value))

    const parsed = parseFrame(frame.value, 0)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.value.plaintextLength).toBe(plaintext.byteLength)
    expect(parsed.value.payloadLength).toBe(plaintext.byteLength)
    expect(parsed.value.frameType).toBe(RECOVERY_FRAME_TYPE_DATA)

    const shortened = frame.value.subarray(0, frame.value.byteLength - 1)
    const badLength = parseFrame(shortened, 0)
    expect(badLength.ok).toBe(false)
    if (!badLength.ok) expect(badLength.code).toBe(PCAP_RECOVERY_ERROR.invalidFormat)
  })
})
