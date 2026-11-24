/**
 * T05 — compression probe + gzip inflate limits.
 */

import { describe, expect, it } from 'vitest'
import {
  detectCompressedFormat,
  decompressGzipToFile,
  DecompressError,
  stripGzipExtension,
  validateGzipHeader,
} from '../../src/correlation/import/decompressInput.ts'
import { probeSourceKind, resolveInputFile } from '../../src/correlation/import'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { defaultOutputFileName } from '../../src/correlation/sourceLimits.ts'

async function gzipBytes(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip')
  const writer = cs.writable.getWriter()
  await writer.write(data)
  await writer.close()
  const reader = cs.readable.getReader()
  const chunks: Uint8Array[] = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
  }
  let total = 0
  for (const c of chunks) total += c.byteLength
  const out = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) {
    out.set(c, offset)
    offset += c.byteLength
  }
  return out
}

describe('T05 detectCompressedFormat', () => {
  it('recognizes gzip/zip/xz/zstd/bzip2 magic', () => {
    expect(detectCompressedFormat(new Uint8Array([0x1f, 0x8b, 0x08]))).toBe('gzip')
    expect(detectCompressedFormat(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))).toBe('zip')
    expect(detectCompressedFormat(new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))).toBe('xz')
    expect(detectCompressedFormat(new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]))).toBe('zstd')
    expect(detectCompressedFormat(new Uint8Array([0x42, 0x5a, 0x68]))).toBe('bzip2')
  })

  it('probeSourceKind prefers PCAP magic over compression', () => {
    const head = new Uint8Array(16)
    new DataView(head.buffer).setUint32(0, 0xa1b2c3d4, true)
    expect(probeSourceKind(head).kind).toBe(SK.Pcap)
  })

  it('probeSourceKind returns compressed before binary NUL scan', () => {
    const head = new Uint8Array([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0])
    const result = probeSourceKind(head)
    expect(result.kind).toBe('compressed')
    if (result.kind === 'compressed') expect(result.format).toBe('gzip')
  })

  it('non-compressed binary stays unsupported binary', () => {
    const result = probeSourceKind(new Uint8Array([0, 1, 2, 3, 4, 5]))
    expect(result.kind).toBe('unsupported')
    if (result.kind === 'unsupported') expect(result.code).toBe('binary')
  })
})

describe('T05 decompressGzipToFile', () => {
  it('inflates gzip text and strips .gz from name', async () => {
    const body = new TextEncoder().encode('contact 10.0.0.1\n')
    const gz = await gzipBytes(body)
    const file = new File([gz], 'sample.log.gz', { type: 'application/gzip' })
    const out = await decompressGzipToFile(file)
    expect(out.file.name).toBe('sample.log')
    expect(out.inflatedBytes).toBe(body.byteLength)
    expect(new TextDecoder().decode(new Uint8Array(await out.file.arrayBuffer()))).toContain('10.0.0.1')
  })

  it('inflates gzip PCAP magic payload', async () => {
    const pcap = new Uint8Array(24)
    new DataView(pcap.buffer).setUint32(0, 0xa1b2c3d4, true)
    const gz = await gzipBytes(pcap)
    const file = new File([gz], 'cap.pcap.gz')
    const out = await decompressGzipToFile(file)
    const head = new Uint8Array(await out.file.slice(0, 4).arrayBuffer())
    expect(probeSourceKind(head).kind).toBe(SK.Pcap)
  })

  it('rejects gzip bomb during streaming before completing', async () => {
    const limit = 8 * 1024
    const huge = new Uint8Array(limit + 32 * 1024) // zeros → tiny gzip, large inflate
    const gz = await gzipBytes(huge)
    expect(gz.byteLength).toBeLessThan(limit)
    const file = new File([gz], 'bomb.log.gz')
    await expect(decompressGzipToFile(file, { maxInflatedBytes: limit })).rejects.toMatchObject({
      name: 'DecompressError',
      code: 'gzip-bomb',
    })
  })

  it('rejects corrupt gzip', async () => {
    const file = new File([new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff])], 'bad.gz')
    await expect(decompressGzipToFile(file)).rejects.toBeInstanceOf(DecompressError)
  })

  it('rejects invalid gzip CM / reserved FLG bits', async () => {
    expect(validateGzipHeader(new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0]))).toBe('ok')
    expect(validateGzipHeader(new Uint8Array([0x1f, 0x8b, 0x00, 0x00, 0, 0, 0, 0, 0, 0]))).toBe(
      'gzip-header-invalid',
    )
    const badCm = new Uint8Array([0x1f, 0x8b, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0])
    await expect(decompressGzipToFile(new File([badCm], 'badcm.gz'))).rejects.toMatchObject({
      code: 'gzip-header-invalid',
    })
  })

  it('inflates concatenated gzip members fully (canary in second member)', async () => {
    const m1 = await gzipBytes(new TextEncoder().encode('MEMBER1-AAA\n'))
    const m2 = await gzipBytes(new TextEncoder().encode('MEMBER2-CANARY-BBB\n'))
    const concat = new Uint8Array(m1.length + m2.length)
    concat.set(m1, 0)
    concat.set(m2, m1.length)
    const out = await decompressGzipToFile(new File([concat], 'multi.log.gz'))
    const text = new TextDecoder().decode(new Uint8Array(await out.file.arrayBuffer()))
    expect(text).toContain('MEMBER1-AAA')
    expect(text).toContain('MEMBER2-CANARY-BBB')
  })

  it('honours AbortSignal', async () => {
    const body = new TextEncoder().encode('x'.repeat(100_000))
    const gz = await gzipBytes(body)
    const file = new File([gz], 'big.log.gz')
    const ac = new AbortController()
    ac.abort()
    await expect(decompressGzipToFile(file, { signal: ac.signal })).rejects.toMatchObject({
      code: 'cancelled',
    })
  })

  it('stripGzipExtension is single-suffix', () => {
    expect(stripGzipExtension('a.log.gz')).toBe('a.log')
    expect(stripGzipExtension('a.pcap.gz')).toBe('a.pcap')
  })
})

describe('T05 resolveInputFile', () => {
  it('resolves .log.gz to text', async () => {
    const body = new TextEncoder().encode('line 10.0.0.2\n')
    const gz = await gzipBytes(body)
    const result = await resolveInputFile(new File([gz], 'obc2.log.gz'))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.kind).toBe(SK.Text)
    expect(result.file.name).toBe('obc2.log')
    expect(result.gzipInflation?.inflatedBytes).toBe(body.byteLength)
    expect(defaultOutputFileName(result.kind, result.file.name)).toBe('obc2.anonym.log')
  })

  it('rejects truncated zip without asking the user to unpack manually (T72/I6)', async () => {
    const zip = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0])
    const result = await resolveInputFile(new File([zip], 'archive.zip'))
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.rejection.code).toBe('compressed-zip')
    expect(result.message).toMatch(/ZIP/i)
    expect(result.message).not.toMatch(/rozbalte ručně|rozdělte|nahrajte jednotlivě/i)
  })

  it('accepts nested gzip within nest depth (T72)', async () => {
    const inner = new TextEncoder().encode('nested\n')
    const innerGz = await gzipBytes(inner)
    const outerGz = await gzipBytes(innerGz)
    const result = await resolveInputFile(new File([outerGz], 'nested.log.gz'))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.kind).toBeDefined()
  })
})
