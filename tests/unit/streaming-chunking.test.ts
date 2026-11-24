import { describe, expect, it } from 'vitest'
import {
  createLineAssembler,
  pushBytes,
  pushText,
  takePackedLineEndings,
  utf8ByteLength,
} from '../../src/features/import-log/streamingDecode.ts'
import {
  splitArrayBuffer,
  splitPasteText,
  readFileByteChunks,
  CHUNK_SIZE,
} from '../../src/features/import-log/chunking.ts'
import {
  adaptChunkSizeFromBenchmark,
  getRecommendedChunkBytes,
  setRecommendedChunkBytes,
} from '../../src/features/import-log/chunkSizing.ts'
import {
  ENDING_CR,
  ENDING_CRLF,
  ENDING_LF,
  ENDING_NONE,
  applyPackedLineEndings,
  packLineEndingsFromText,
} from '../../src/features/export-log/lineEndings.ts'

describe('streamingDecode', () => {
  it('keeps only line tail across UTF-8 chunks (including split CRLF)', () => {
    const state = createLineAssembler()
    const enc = new TextEncoder()
    const a = pushBytes(state, enc.encode('hello\r'), false)
    expect(a.lines).toEqual([])
    expect(a.lfFragment).toBe('')
    expect(state.lineTail).toBe('hello\r')

    const b = pushBytes(state, enc.encode('\nworld\n'), false)
    expect(b.lines.map((l) => l.text)).toEqual(['hello', 'world'])
    expect(b.lfFragment).toBe('hello\nworld\n')
    expect(state.lineTail).toBe('')

    const c = pushBytes(state, enc.encode('tail'), true)
    expect(c.lines.map((l) => l.text)).toEqual(['tail'])
    expect(c.lfFragment).toBe('tail')
    expect(state.lineTail).toBe('')
  })

  it('assigns absolute UTF-16 offsets in canonical LF document', () => {
    const state = createLineAssembler()
    const { lines } = pushText(state, 'ab\ncd\nef', true)
    expect(lines.map((l) => ({ t: l.text, s: l.start, n: l.line }))).toEqual([
      { t: 'ab', s: 0, n: 1 },
      { t: 'cd', s: 3, n: 2 },
      { t: 'ef', s: 6, n: 3 },
    ])
  })

  it('matches CRLF/CR/LF packed endings with packLineEndingsFromText', () => {
    const raw = 'a\r\nb\nc\r'
    const state = createLineAssembler()
    pushText(state, raw, true)
    const packed = takePackedLineEndings(state)
    expect(Array.from(packed)).toEqual(Array.from(packLineEndingsFromText(raw)))
    const lf = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    expect(applyPackedLineEndings(lf, packed)).toBe(raw)
  })

  it('emits canonical LF offsets for CRLF lines', () => {
    const state = createLineAssembler()
    const { lines, lfFragment } = pushText(state, 'x\r\ny\r\n', true)
    expect(lfFragment).toBe('x\ny\n')
    expect(lines[0]?.start).toBe(0)
    expect(lines[1]?.start).toBe(2)
    const endings = takePackedLineEndings(state)
    expect(endings[0]).toBe(ENDING_CRLF)
    expect(endings[1]).toBe(ENDING_CRLF)
  })

  it('handles CR-only line endings', () => {
    const state = createLineAssembler()
    pushText(state, 'a\rb\r', true)
    const endings = takePackedLineEndings(state)
    expect(endings[0]).toBe(ENDING_CR)
    expect(endings[1]).toBe(ENDING_CR)
    expect(endings[2]).toBe(ENDING_NONE)
  })

  it('counts UTF-8 bytes for paste limits', () => {
    expect(utf8ByteLength('a')).toBe(1)
    expect(utf8ByteLength('ž')).toBe(2)
  })
})

describe('chunking', () => {
  it('splits ArrayBuffer into final=true last chunk', () => {
    const buf = new Uint8Array(100).buffer
    const chunks = splitArrayBuffer(buf, CHUNK_SIZE.minBytes)
    expect(chunks.at(-1)?.final).toBe(true)
    expect(chunks.reduce((s, c) => s + c.byteLength, 0)).toBe(100)
  })

  it('does not split UTF-16 surrogate pairs in paste text', () => {
    const text = 'a' + '😀'.repeat(10) + 'b'
    const chunks = splitPasteText(text, 8)
    const joined = chunks.map((c) => c.text).join('')
    expect(joined).toBe(text)
    for (const c of chunks) {
      for (let i = 0; i < c.text.length; i++) {
        const code = c.text.charCodeAt(i)
        if (code >= 0xd800 && code <= 0xdbff) {
          expect(c.text.charCodeAt(i + 1)).toBeGreaterThanOrEqual(0xdc00)
        }
      }
    }
  })

  it('produces chunks whose reported utf8Bytes matches actual encoded length (ASCII, multi-byte, and surrogate pairs)', () => {
    const text = 'plain ascii ' + 'ž'.repeat(5) + '😀'.repeat(5) + ' more'
    const chunks = splitPasteText(text, 6)
    const enc = new TextEncoder()
    for (const c of chunks) {
      expect(c.utf8Bytes).toBe(enc.encode(c.text).byteLength)
    }
  })

  it('splits a large paste (~10 MB) without the per-character TextEncoder blowup regressing', () => {
    const line = 'x'.repeat(199) + '\n'
    const text = line.repeat(50_000)
    const start = performance.now()
    const chunks = splitPasteText(text, CHUNK_SIZE.defaultBytes)
    const elapsedMs = performance.now() - start
    expect(chunks.map((c) => c.text).join('')).toBe(text)
    expect(elapsedMs).toBeLessThan(500)
  })

  it('assembles CRLF split across paste chunks identically to one-shot decode', () => {
    const raw = 'alpha\r\nbeta\r\ngamma\n'
    const chunks = splitPasteText(raw, 3)
    const piecewise = createLineAssembler()
    const lfParts: string[] = []
    for (let i = 0; i < chunks.length; i++) {
      const c = chunks[i]!
      const { lfFragment } = pushText(piecewise, c.text, c.final)
      if (lfFragment) lfParts.push(lfFragment)
    }
    const whole = createLineAssembler()
    pushText(whole, raw, true)
    expect(lfParts.join('')).toBe(raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n'))
    expect(Array.from(takePackedLineEndings(piecewise))).toEqual(
      Array.from(takePackedLineEndings(whole)),
    )
  })

  it('uses bounded slices when Blob.stream is unavailable', async () => {
    const raw = new Uint8Array(CHUNK_SIZE.minBytes + 17)
    raw.fill(65)
    const blob = new Blob([raw])
    const sliceOnlyBlob = {
      size: blob.size,
      slice: blob.slice.bind(blob),
    } as Blob
    const lengths: number[] = []

    for await (const chunk of readFileByteChunks(sliceOnlyBlob, CHUNK_SIZE.minBytes)) {
      lengths.push(chunk.byteLength)
    }

    expect(lengths).toEqual([CHUNK_SIZE.minBytes, 17])
  })
})

describe('chunkSizing', () => {
  it('clamps adaptive size into 512KiB–4MiB', () => {
    setRecommendedChunkBytes(100)
    expect(getRecommendedChunkBytes()).toBe(CHUNK_SIZE.minBytes)
    setRecommendedChunkBytes(99 * 1024 * 1024)
    expect(getRecommendedChunkBytes()).toBe(CHUNK_SIZE.maxBytes)
    const next = adaptChunkSizeFromBenchmark({
      chunkBytes: CHUNK_SIZE.defaultBytes,
      elapsedMs: 10,
      processedBytes: CHUNK_SIZE.defaultBytes,
      targetChunkMs: 40,
    })
    expect(next).toBeGreaterThanOrEqual(CHUNK_SIZE.minBytes)
    expect(next).toBeLessThanOrEqual(CHUNK_SIZE.maxBytes)
  })
})
