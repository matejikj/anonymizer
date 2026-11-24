import { describe, expect, it, vi } from 'vitest'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CaptureFormat, IssueSeverity, MAX_RECORD_SIZE } from '../../../src/pcap/domain/types.ts'
import { readClassicPcap, readClassicPcapFramed, readClassicPcapFromBlob } from '../../../src/pcap/capture/pcapReader.ts'
import { readPcapng, readPcapngFramed, readPcapngFromBlob } from '../../../src/pcap/capture/pcapngReader.ts'
import { parseClassicPcapFraming } from '../../../src/pcap/capture/classicPcapFraming.ts'
import { parsePcapngFraming } from '../../../src/pcap/capture/pcapngFraming.ts'
import { MemoryAsyncCursor, BlobSliceCursor } from '../../../src/pcap/capture/asyncCursor.ts'
import { feedBlobChunks } from '../../../src/pcap/capture/chunkFeeder.ts'
import { ReassemblyBuffer } from '../../../src/pcap/capture/chunkFeeder.ts'
import { readCaptureIncremental } from '../../../src/pcap/capture/incrementalCaptureReader.ts'

const FUZZ_FIXTURE_DIR = join(import.meta.dirname, '../fixtures/fuzz-corpus')

function makeMinimalPcap(packets = 1): ArrayBuffer {
  const packetData = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  const size = 24 + packets * (16 + packetData.length)
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, 0xa1b2c3d4, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)
  let offset = 24
  for (let i = 0; i < packets; i++) {
    view.setUint32(offset + 8, packetData.length, true)
    view.setUint32(offset + 12, packetData.length, true)
    new Uint8Array(buf, offset + 16, packetData.length).set(packetData)
    offset += 16 + packetData.length
  }
  return buf
}

function makeMinimalPcapng(packets = 1): ArrayBuffer {
  const packetData = new Uint8Array([0xca, 0xfe, 0xba, 0xbe])
  const paddedDataLen = (packetData.length + 3) & ~3
  const epbLen = 12 + 20 + paddedDataLen
  const totalSize = 28 + 20 + packets * epbLen
  const buf = new ArrayBuffer(totalSize)
  const view = new DataView(buf)
  let off = 0
  view.setUint32(off, 0x0a0d0d0a, true); off += 4
  view.setUint32(off, 28, true); off += 4
  view.setUint32(off, 0x1a2b3c4d, true); off += 4
  view.setUint16(off, 1, true); off += 2
  view.setUint16(off, 0, true); off += 2
  view.setBigInt64(off, -1n, true); off += 8
  view.setUint32(off, 28, true); off += 4
  view.setUint32(off, 0x00000001, true); off += 4
  view.setUint32(off, 20, true); off += 4
  view.setUint16(off, 1, true); off += 2
  view.setUint16(off, 0, true); off += 2
  view.setUint32(off, 262144, true); off += 4
  view.setUint32(off, 20, true); off += 4
  for (let i = 0; i < packets; i++) {
    view.setUint32(off, 0x00000006, true); off += 4
    view.setUint32(off, epbLen, true); off += 4
    view.setUint32(off, 0, true); off += 4
    view.setUint32(off, 0, true); off += 4
    view.setUint32(off, i * 1000, true); off += 4
    view.setUint32(off, packetData.length, true); off += 4
    view.setUint32(off, packetData.length, true); off += 4
    new Uint8Array(buf, off, packetData.length).set(packetData)
    off += paddedDataLen
    view.setUint32(off, epbLen, true); off += 4
  }
  return buf
}

function descriptorKey(d: {
  packetNumber: number
  capturedLength: number
  originalLength: number
  fileOffset: number
  dataOffset: number
}) {
  return `${d.packetNumber}:${d.capturedLength}:${d.originalLength}:${d.fileOffset}:${d.dataOffset}`
}

describe('Stage 6 — incremental classic PCAP', () => {
  it('BlobSliceCursor parity with sync reference adapter', async () => {
    const buf = makeMinimalPcap(5)
    const ref = readClassicPcap(buf)
    const blob = new Blob([buf])
    const inc = await readClassicPcapFromBlob(blob)
    expect(inc.packets.length).toBe(ref.packets.length)
    expect(inc.descriptors.map(descriptorKey)).toEqual(ref.descriptors.map(descriptorKey))
    expect(inc.packets[0]!.data).toEqual(ref.packets[0]!.data)
  })

  it('MemoryAsyncCursor framing parity with sync reference', async () => {
    const buf = makeMinimalPcap(3)
    const ref = readClassicPcap(buf)
    const framed = await readClassicPcapFramed(buf)
    expect(framed.descriptors.map(descriptorKey)).toEqual(ref.descriptors.map(descriptorKey))
  })

  it('rejects oversized record before payload allocation', async () => {
    const buf = makeMinimalPcap(1)
    const view = new DataView(buf)
    view.setUint32(24 + 8, MAX_RECORD_SIZE + 1, true)
    const result = await parseClassicPcapFraming(new MemoryAsyncCursor(buf))
    expect(result.descriptors).toHaveLength(0)
    expect(result.issues.some((i) => i.code === 'pcap-record-too-large')).toBe(true)
  })

  it('reports truncated global header', async () => {
    const buf = new ArrayBuffer(12)
    new DataView(buf).setUint32(0, 0xa1b2c3d4, true)
    const result = await parseClassicPcapFraming(new MemoryAsyncCursor(buf))
    expect(result.header).toBeNull()
    expect(result.issues[0]?.code).toMatch(/too-small|invalid/)
  })

  it('reports truncated packet record', async () => {
    const buf = new ArrayBuffer(24 + 16 + 2)
    const view = new DataView(buf)
    view.setUint32(0, 0xa1b2c3d4, true)
    view.setUint16(4, 2, true)
    view.setUint16(6, 4, true)
    view.setUint32(16, 65535, true)
    view.setUint32(20, 1, true)
    view.setUint32(24 + 8, 4, true)
    view.setUint32(24 + 12, 4, true)

    const result = await parseClassicPcapFraming(new MemoryAsyncCursor(buf))
    expect(result.descriptors).toHaveLength(0)
    expect(result.issues.some((i) => i.code === 'pcap-truncated')).toBe(true)
  })

  it('BlobSliceCursor batches per-read slices into a single bounded window', async () => {
    // Small file fits in one read-ahead window, so all header-field reads should collapse
    // into a single Blob.slice() call instead of one per u8/u16/u32 read.
    const buf = makeMinimalPcap(3)
    const ref = readClassicPcap(buf)
    const blob = new Blob([buf])
    const sliceSpy = vi.spyOn(blob, 'slice')
    const result = await parseClassicPcapFraming(new BlobSliceCursor(blob))
    expect(sliceSpy.mock.calls.length).toBe(1)
    expect(result.descriptors.map(descriptorKey)).toEqual(ref.descriptors.map(descriptorKey))
    sliceSpy.mockRestore()
  })

  it('BlobSliceCursor parses correctly across read-ahead window boundaries', async () => {
    // 4000 packets * 20 bytes > 64 KiB read-ahead window, forcing multiple window fills;
    // verifies records are still framed correctly when a read spans a window boundary.
    const buf = makeMinimalPcap(4000)
    const ref = readClassicPcap(buf)
    const blob = new Blob([buf])
    const sliceSpy = vi.spyOn(blob, 'slice')
    const result = await parseClassicPcapFraming(new BlobSliceCursor(blob))
    expect(sliceSpy.mock.calls.length).toBeGreaterThan(1)
    expect(result.descriptors.map(descriptorKey)).toEqual(ref.descriptors.map(descriptorKey))
    sliceSpy.mockRestore()
  })

  it('chunk reassembly produces same metadata for various chunk sizes', async () => {
    const buf = makeMinimalPcap(4)
    const ref = readClassicPcap(buf)
    const blob = new Blob([buf])

    for (const chunkSize of [1, 3, 4096, 65536, 17]) {
      const reassembly = new ReassemblyBuffer()
      await feedBlobChunks(blob, (chunk) => {
        reassembly.append(chunk, 0)
      }, { chunkSize, preferStream: false })

      const combined = reassembly.view()
      const framed = await parseClassicPcapFraming(new MemoryAsyncCursor(combined.buffer.slice(
        combined.byteOffset,
        combined.byteOffset + combined.byteLength,
      )))
      expect(framed.descriptors.map(descriptorKey), `chunkSize=${chunkSize}`).toEqual(
        ref.descriptors.map(descriptorKey),
      )
    }
  })

  it('readClassicPcapFromBlob never calls whole-file arrayBuffer', async () => {
    const buf = makeMinimalPcap(2)
    const blob = new Blob([buf])
    vi.spyOn(blob, 'arrayBuffer').mockImplementation(() => {
      throw new Error('whole-file arrayBuffer forbidden')
    })
    const result = await readClassicPcapFromBlob(blob)
    expect(result.packets.length).toBe(2)
  })
})

describe('Stage 6 — incremental PCAPNG', () => {
  it('BlobSliceCursor parity with sync reference adapter', async () => {
    const buf = makeMinimalPcapng(3)
    const ref = readPcapng(buf)
    const blob = new Blob([buf])
    const inc = await readPcapngFromBlob(blob)
    expect(inc.packets.length).toBe(ref.packets.length)
    expect(inc.descriptors.map(descriptorKey)).toEqual(ref.descriptors.map(descriptorKey))
    expect(inc.packets[0]!.data).toEqual(ref.packets[0]!.data)
  })

  it('MemoryAsyncCursor framing parity with sync reference', async () => {
    const buf = makeMinimalPcapng(2)
    const ref = readPcapng(buf)
    const framed = await readPcapngFramed(buf)
    expect(framed.descriptors.map(descriptorKey)).toEqual(ref.descriptors.map(descriptorKey))
  })

  it('readPcapngFromBlob never calls whole-file arrayBuffer', async () => {
    const buf = makeMinimalPcapng(1)
    const blob = new Blob([buf])
    vi.spyOn(blob, 'arrayBuffer').mockImplementation(() => {
      throw new Error('whole-file arrayBuffer forbidden')
    })
    const result = await readPcapngFromBlob(blob)
    expect(result.packets.length).toBe(1)
  })

  it('reports truncated SHB', async () => {
    const buf = new ArrayBuffer(16)
    const view = new DataView(buf)
    view.setUint32(0, 0x0a0d0d0a, true)
    view.setUint32(4, 28, true)
    view.setUint32(8, 0x1a2b3c4d, true)
    const result = await parsePcapngFraming(new MemoryAsyncCursor(buf))
    expect(result.sections).toHaveLength(0)
    expect(result.issues.some((i) => i.code === 'pcapng-truncated-shb')).toBe(true)
  })

  it('reports truncated IDB', async () => {
    const buf = new ArrayBuffer(28 + 12)
    const view = new DataView(buf)
    view.setUint32(0, 0x0a0d0d0a, true)
    view.setUint32(4, 28, true)
    view.setUint32(8, 0x1a2b3c4d, true)
    view.setUint16(12, 1, true)
    view.setUint16(14, 0, true)
    view.setBigInt64(16, -1n, true)
    view.setUint32(24, 28, true)
    view.setUint32(28, 0x00000001, true)
    view.setUint32(32, 20, true)

    const result = await parsePcapngFraming(new MemoryAsyncCursor(buf))
    expect(result.interfaces).toHaveLength(0)
    expect(result.issues.some((i) => i.code === 'pcapng-truncated-block')).toBe(true)
  })

  it('reports truncated EPB payload', async () => {
    const epbLen = 36
    const buf = new ArrayBuffer(28 + 20 + epbLen)
    const view = new DataView(buf)
    let off = 0
    view.setUint32(off, 0x0a0d0d0a, true); off += 4
    view.setUint32(off, 28, true); off += 4
    view.setUint32(off, 0x1a2b3c4d, true); off += 4
    view.setUint16(off, 1, true); off += 2
    view.setUint16(off, 0, true); off += 2
    view.setBigInt64(off, -1n, true); off += 8
    view.setUint32(off, 28, true); off += 4
    view.setUint32(off, 0x00000001, true); off += 4
    view.setUint32(off, 20, true); off += 4
    view.setUint16(off, 1, true); off += 2
    view.setUint16(off, 0, true); off += 2
    view.setUint32(off, 262144, true); off += 4
    view.setUint32(off, 20, true); off += 4
    view.setUint32(off, 0x00000006, true); off += 4
    view.setUint32(off, epbLen, true); off += 4
    view.setUint32(off, 0, true); off += 4
    view.setUint32(off, 0, true); off += 4
    view.setUint32(off, 0, true); off += 4
    view.setUint32(off, 9, true); off += 4
    view.setUint32(off, 9, true); off += 4
    view.setUint32(off, epbLen, true)

    const result = await parsePcapngFraming(new MemoryAsyncCursor(buf))
    expect(result.descriptors).toHaveLength(0)
    expect(result.issues.some((i) => i.code === 'pcapng-epb-truncated')).toBe(true)
  })

  it('reports trailing length mismatch', async () => {
    const buf = new ArrayBuffer(48)
    const view = new DataView(buf)
    view.setUint32(0, 0x0a0d0d0a, true)
    view.setUint32(4, 28, true)
    view.setUint32(8, 0x1a2b3c4d, true)
    view.setUint16(12, 1, true)
    view.setUint16(14, 0, true)
    view.setBigInt64(16, -1n, true)
    view.setUint32(24, 28, true)
    view.setUint32(28, 0x00000001, true)
    view.setUint32(32, 20, true)
    view.setUint16(36, 1, true)
    view.setUint32(40, 262144, true)
    view.setUint32(44, 99, true)

    const result = await parsePcapngFraming(new MemoryAsyncCursor(buf))
    expect(result.issues.some((i) => i.code === 'pcapng-trailing-length-mismatch')).toBe(true)
  })

  it('rejects oversized EPB before payload allocation', async () => {
    const buf = new ArrayBuffer(28 + 20 + 12)
    const view = new DataView(buf)
    let off = 0
    view.setUint32(off, 0x0a0d0d0a, true); off += 4
    view.setUint32(off, 28, true); off += 4
    view.setUint32(off, 0x1a2b3c4d, true); off += 4
    view.setUint16(off, 1, true); off += 2
    view.setUint16(off, 0, true); off += 2
    view.setBigInt64(off, -1n, true); off += 8
    view.setUint32(off, 28, true); off += 4
    view.setUint32(off, 0x00000001, true); off += 4
    view.setUint32(off, 20, true); off += 4
    view.setUint16(off, 1, true); off += 2
    view.setUint16(off, 0, true); off += 2
    view.setUint32(off, 262144, true); off += 4
    view.setUint32(off, 20, true); off += 4
    view.setUint32(off, 0x00000006, true); off += 4
    view.setUint32(off, MAX_RECORD_SIZE + 100, true)

    const result = await parsePcapngFraming(new MemoryAsyncCursor(buf))
    expect(result.descriptors).toHaveLength(0)
    expect(result.issues.some((i) => i.severity === IssueSeverity.Fatal)).toBe(true)
  })
})

describe('Stage 6 — incremental fuzz corpus', () => {
  it('incremental blob readers never throw on fuzz-corpus fixtures', async () => {
    if (!existsSync(FUZZ_FIXTURE_DIR)) return
    const files = readdirSync(FUZZ_FIXTURE_DIR).filter(
      (f) => f.endsWith('.bin') || f.endsWith('.pcap') || f.endsWith('.pcapng'),
    )
    for (const file of files) {
      const raw = readFileSync(join(FUZZ_FIXTURE_DIR, file))
      const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
      const blob = new Blob([buf])
      vi.spyOn(blob, 'arrayBuffer').mockImplementation(() => {
        throw new Error('whole-file arrayBuffer forbidden')
      })
      await expect(readClassicPcapFromBlob(blob)).resolves.toBeDefined()
      await expect(readPcapngFromBlob(blob)).resolves.toBeDefined()
    }
  })

  it('readCaptureIncremental never materializes whole file', async () => {
    const buf = makeMinimalPcap(2)
    const blob = new Blob([buf])
    vi.spyOn(blob, 'arrayBuffer').mockImplementation(() => {
      throw new Error('whole-file arrayBuffer forbidden')
    })
    const classic = await readCaptureIncremental(blob, CaptureFormat.ClassicPcap)
    expect(classic.format).toBe(CaptureFormat.ClassicPcap)
    expect(classic.packets.length).toBe(2)
  })
})
