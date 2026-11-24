/**
 * T72 / T73 — decompress formats + large-input split/merge (I6).
 */

import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  decompressToFile,
  detectCompressedFormat,
  MAX_COMPRESSION_NEST_DEPTH,
} from '../../src/correlation/import/decompressInput.ts'
import { resolveInputFile } from '../../src/correlation/import/resolveInputFile.ts'
import {
  LARGE_INPUT_SPLIT,
  mergeSplitExportBytes,
  needsLargeInputSplit,
  splitLargeInput,
} from '../../src/correlation/import/largeInputSplit.ts'
import { SourceKind as SK } from '../../src/domain/sourceArtifact.ts'
import { MAX_TEXT_FILE_BYTES } from '../../src/domain/capabilityContract.ts'

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
  let n = 0
  for (const c of chunks) n += c.byteLength
  const out = new Uint8Array(n)
  let o = 0
  for (const c of chunks) {
    out.set(c, o)
    o += c.byteLength
  }
  return out
}

function compressWithTool(tool: 'xz' | 'zstd' | 'bzip2', body: Uint8Array): Uint8Array {
  const dir = mkdtempSync(join(tmpdir(), 't72-'))
  const input = join(dir, 'in.log')
  writeFileSync(input, body)
  if (tool === 'xz') {
    return new Uint8Array(execFileSync('xz', ['-c', input], { maxBuffer: 16 * 1024 * 1024 }))
  }
  if (tool === 'zstd') {
    return new Uint8Array(execFileSync('zstd', ['-c', input]))
  }
  return new Uint8Array(execFileSync('bzip2', ['-ck', input]))
}

describe('T72 decompress xz/zstd/bzip2', () => {
  it('detects and inflates offline codecs to text', async () => {
    const body = new TextEncoder().encode('line 10.0.0.9 contact\n')
    for (const [tool, format] of [
      ['xz', 'xz'],
      ['zstd', 'zstd'],
      ['bzip2', 'bzip2'],
    ] as const) {
      const compressed = compressWithTool(tool, body)
      expect(detectCompressedFormat(compressed)).toBe(format)
      const ext = format === 'bzip2' ? 'bz2' : format === 'zstd' ? 'zst' : 'xz'
      const file = new File([compressed], `sample.log.${ext}`)
      const out = await decompressToFile(file, format)
      expect(new TextDecoder().decode(new Uint8Array(await out.file.arrayBuffer()))).toContain('10.0.0.9')
      const resolved = await resolveInputFile(file)
      expect(resolved.ok).toBe(true)
      if (resolved.ok) expect(resolved.mode).toBe('single')
    }
  })

  it('allows nested gzip up to MAX_COMPRESSION_NEST_DEPTH', async () => {
    expect(MAX_COMPRESSION_NEST_DEPTH).toBe(4)
    let bytes = new TextEncoder().encode('nested-ok\n')
    for (let i = 0; i < 2; i++) bytes = await gzipBytes(bytes)
    const result = await resolveInputFile(new File([bytes], 'nested.log.gz'))
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.mode).toBe('single')
    expect(result.kind).toBe(SK.Text)
  })
})

describe('T73 large input split + merge', () => {
  it('splits oversized text on line boundaries and merge restores order', async () => {
    const line = 'x'.repeat(1024) + '\n'
    const target = MAX_TEXT_FILE_BYTES + 64 * 1024
    const parts: string[] = []
    let size = 0
    while (size < target) {
      parts.push(line)
      size += line.length
    }
    const text = parts.join('')
    const file = new File([new TextEncoder().encode(text)], 'big.log')
    expect(needsLargeInputSplit(file.size, SK.Text)).toBe(true)
    const split = await splitLargeInput(file, SK.Text)
    expect(split.ok).toBe(true)
    if (!split.ok) return
    expect(split.segments.length).toBeGreaterThan(1)
    expect(split.aggregateBytes).toBeLessThanOrEqual(LARGE_INPUT_SPLIT.maxAggregateBytes)
    for (const seg of split.segments) {
      expect(seg.file.size).toBeLessThanOrEqual(LARGE_INPUT_SPLIT.textMaxSegmentBytes)
    }
    const resolved = await resolveInputFile(file)
    expect(resolved.ok).toBe(true)
    if (resolved.ok) expect(resolved.mode).toBe('split')

    const exported = split.segments.map((s) => ({
      bytes: new Uint8Array(s.file.size), // placeholder sizes
      uniquePayloadStart: s.uniquePayloadStart,
    }))
    // Real merge of segment payloads
    const realParts = await Promise.all(
      split.segments.map(async (s) => ({
        bytes: new Uint8Array(await s.file.arrayBuffer()),
        uniquePayloadStart: s.uniquePayloadStart,
      })),
    )
    const merged = mergeSplitExportBytes(realParts)
    expect(new TextDecoder().decode(merged)).toBe(text)
    void exported
  })

  it('mergeSplitExportBytes skips overlap prefix on later parts', () => {
    const merged = mergeSplitExportBytes([
      { bytes: new Uint8Array([1, 2, 3, 4, 5, 6]), uniquePayloadStart: 0 },
      { bytes: new Uint8Array([9, 9, 7, 8]), uniquePayloadStart: 2 },
    ])
    expect(Array.from(merged)).toEqual([1, 2, 3, 4, 5, 6, 7, 8])
  })
})
