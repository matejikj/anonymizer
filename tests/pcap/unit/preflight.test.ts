import { describe, expect, it, vi } from 'vitest'
import {
  MAX_PCAP_FILE_BYTES,
  BYTES_PER_MIB,
} from '../../../src/domain/capabilityContract.ts'
import {
  preflightPcapFile,
  PCAP_PREFLIGHT_PREFIX_BYTES,
} from '../../../src/pcap/capture/preflight.ts'
import { CaptureFormat } from '../../../src/pcap/domain/types.ts'
import {
  PCAP_MAGIC_MICRO_LE,
  PCAP_MAGIC_MICRO_BE,
  PCAP_MAGIC_NANO_LE,
  PCAP_MAGIC_NANO_BE,
  PCAPNG_MAGIC,
} from '../../../src/pcap/domain/types.ts'

function prefixWithMagic(magic: number, littleEndian = true): Uint8Array {
  const buf = new Uint8Array(PCAP_PREFLIGHT_PREFIX_BYTES)
  new DataView(buf.buffer).setUint32(0, magic, littleEndian)
  return buf
}

function mockSizedFile(
  size: number,
  prefix: Uint8Array,
  name = 'capture.bin',
): File {
  const blobParts = [prefix]
  const file = new File(blobParts, name, { type: 'application/octet-stream' })
  Object.defineProperty(file, 'size', { value: size, configurable: true })

  let fullArrayBufferCalled = false
  const originalSlice = file.slice.bind(file)
  file.slice = (start?: number, end?: number, contentType?: string) => {
    const slice = originalSlice(start, end, contentType)
    return slice
  }
  file.arrayBuffer = async () => {
    fullArrayBufferCalled = true
    throw new Error('preflight must not read the whole file')
  }

  Object.defineProperty(file, '__fullArrayBufferCalled', {
    get: () => fullArrayBufferCalled,
    configurable: true,
  })

  return file
}

describe('preflightPcapFile', () => {
  it('accepts exactly MAX_PCAP_FILE_BYTES', async () => {
    const file = mockSizedFile(MAX_PCAP_FILE_BYTES, prefixWithMagic(PCAP_MAGIC_MICRO_LE))
    const result = await preflightPcapFile(file)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.byteLength).toBe(MAX_PCAP_FILE_BYTES)
    expect(result.format).toBe(CaptureFormat.ClassicPcap)
    expect(result.limits.maxFileBytes).toBe(MAX_PCAP_FILE_BYTES)
    expect((file as File & { __fullArrayBufferCalled?: boolean }).__fullArrayBufferCalled).toBe(false)
  })

  it('rejects MAX_PCAP_FILE_BYTES + 1 before parsing', async () => {
    const file = mockSizedFile(MAX_PCAP_FILE_BYTES + 1, prefixWithMagic(PCAP_MAGIC_MICRO_LE))
    const result = await preflightPcapFile(file)
    expect(result).toEqual({
      ok: false,
      code: 'too-large',
      byteLength: MAX_PCAP_FILE_BYTES + 1,
      limitBytes: MAX_PCAP_FILE_BYTES,
      message: expect.stringContaining('100.0 MiB'),
    })
    if (result.ok) return
    expect(result.message).toContain('+1 B')
    expect(result.message).toMatch(/Maximum je 100\.0 MiB/)
    expect((file as File & { __fullArrayBufferCalled?: boolean }).__fullArrayBufferCalled).toBe(false)
  })

  it('detects all classic PCAP magic/endian variants', async () => {
    const magics = [
      PCAP_MAGIC_MICRO_LE,
      PCAP_MAGIC_MICRO_BE,
      PCAP_MAGIC_NANO_LE,
      PCAP_MAGIC_NANO_BE,
    ]
    for (const magic of magics) {
      const le = magic === PCAP_MAGIC_MICRO_LE || magic === PCAP_MAGIC_NANO_LE
      const file = mockSizedFile(128, prefixWithMagic(magic, le))
      const result = await preflightPcapFile(file)
      expect(result.ok, `magic 0x${magic.toString(16)}`).toBe(true)
      if (result.ok) expect(result.format).toBe(CaptureFormat.ClassicPcap)
    }
  })

  it('detects PCAPNG from SHB magic regardless of file extension', async () => {
    const file = mockSizedFile(
      4096,
      prefixWithMagic(PCAPNG_MAGIC),
      'definitely-not-pcap.txt',
    )
    const result = await preflightPcapFile(file)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.format).toBe(CaptureFormat.Pcapng)
  })

  it('rejects empty file with stable issue code', async () => {
    const file = mockSizedFile(0, new Uint8Array(0))
    const result = await preflightPcapFile(file)
    expect(result).toMatchObject({ ok: false, code: 'empty', byteLength: 0 })
  })

  it('rejects too-short unknown input', async () => {
    const file = mockSizedFile(2, new Uint8Array([0, 0]))
    const result = await preflightPcapFile(file)
    expect(result).toMatchObject({ ok: false, code: 'too-small', byteLength: 2 })
  })

  it('rejects unknown magic with stable issue code', async () => {
    const file = mockSizedFile(64, prefixWithMagic(0xdeadbeef))
    const result = await preflightPcapFile(file)
    expect(result).toMatchObject({ ok: false, code: 'unknown-format', byteLength: 64 })
    if (result.ok) return
    expect(result.message).toContain('magic bytes')
  })

  it('reads only a bounded prefix', async () => {
    const sliceSpy = vi.spyOn(Blob.prototype, 'slice')
    const file = mockSizedFile(8192, prefixWithMagic(PCAP_MAGIC_MICRO_LE))
    await preflightPcapFile(file)
    expect(sliceSpy).toHaveBeenCalled()
    const firstCall = sliceSpy.mock.calls[0]
    expect(firstCall?.[0]).toBe(0)
    expect(firstCall?.[1]).toBe(PCAP_PREFLIGHT_PREFIX_BYTES)
    sliceSpy.mockRestore()
  })

  it('reports limit in MiB from capability contract', () => {
    expect(MAX_PCAP_FILE_BYTES / BYTES_PER_MIB).toBe(100)
  })
})
