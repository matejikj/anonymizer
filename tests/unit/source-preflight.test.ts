import { describe, expect, it } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { CORRELATION_SESSION_LIMITS } from '../../src/domain/capabilityContract'
import {
  buildStagingItemsFromFiles,
  buildStagingSummary,
  fileFingerprint,
  probeSourceKind,
  readFileHead,
} from '../../src/correlation/import'

function textFile(name: string, body: string, lastModified = 1_700_000_000_000): File {
  return new File([body], name, { type: 'text/plain', lastModified })
}

function pcapHeadFile(name: string): File {
  const buf = new Uint8Array(24)
  new DataView(buf.buffer).setUint32(0, 0xa1b2c3d4, true)
  return new File([buf], name, { type: 'application/octet-stream' })
}

describe('Stage 27 source preflight port', () => {
  it('detects text from printable content without pcap magic', () => {
    const head = new TextEncoder().encode('2024-01-01 log line\n')
    expect(probeSourceKind(head).kind).toBe(SK.Text)
  })

  it('prefers pcap when classic magic is present', () => {
    const head = new Uint8Array(16)
    new DataView(head.buffer).setUint32(0, 0xa1b2c3d4, true)
    expect(probeSourceKind(head).kind).toBe(SK.Pcap)
  })

  it('marks unknown binary as unsupported', () => {
    const head = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7])
    const result = probeSourceKind(head)
    expect(result.kind).toBe('unsupported')
    expect(result.code).toBe('binary')
  })

  it('fingerprints files by name size and mtime', () => {
    const a = textFile('a.log', 'x')
    const b = textFile('a.log', 'x')
    expect(fileFingerprint(a)).toBe(fileFingerprint(b))
  })

  it('flags duplicate files in a batch', async () => {
    const file = textFile('dup.log', 'hello 10.0.0.1\n')
    const items = await buildStagingItemsFromFiles([file, file])
    expect(items).toHaveLength(2)
    expect(items[0]?.status).toBe('ready')
    expect(items[1]?.status).toBe('duplicate-warning')
  })

  it('keeps valid files when mixed with invalid binary', async () => {
    const good = textFile('ok.log', 'valid log 10.0.0.2\n')
    const bad = new File([new Uint8Array([0, 0, 0, 1, 2, 3, 4, 5])], 'bad.bin', {
      type: 'application/octet-stream',
    })
    const items = await buildStagingItemsFromFiles([good, bad])
    expect(items.filter((i) => i.status === 'ready')).toHaveLength(1)
    expect(items.filter((i) => i.status === 'error')).toHaveLength(1)
  })

  it('reports aggregate over-limit with bytes to remove', () => {
    const limit = CORRELATION_SESSION_LIMITS.maxAggregateBytes
    const items = [
      {
        id: 'a',
        file: textFile('a.log', 'a'),
        fileName: 'a.log',
        byteLength: limit - 1024,
        status: 'ready' as const,
        kind: SK.Text,
        profileLabel: 'Test',
      },
      {
        id: 'b',
        file: textFile('b.log', 'b'),
        fileName: 'b.log',
        byteLength: 2048,
        status: 'ready' as const,
        kind: SK.Text,
        profileLabel: 'Test',
      },
    ]
    const summary = buildStagingSummary(items)
    expect(summary.aggregateOverLimit).toBe(true)
    expect(summary.bytesToRemove).toBe(1024)
    expect(summary.largestReadyIds[0]).toBe('a')
  })

  it('reads file head without loading entire file', async () => {
    const file = textFile('head.log', 'x'.repeat(1000))
    const head = await readFileHead(file, 8)
    expect(head.byteLength).toBe(8)
  })

  it('detects pcap file name independently of extension via magic', async () => {
    const file = pcapHeadFile('capture.dat')
    const head = await readFileHead(file)
    expect(probeSourceKind(head).kind).toBe(SK.Pcap)
  })

  it('T05: stages gzip text as ready inflated file without .gz in working name', async () => {
    const body = new TextEncoder().encode('ok 10.0.0.9\n')
    const csStream = new CompressionStream('gzip')
    const w = csStream.writable.getWriter()
    await w.write(body)
    await w.close()
    const r = csStream.readable.getReader()
    const chunks: Uint8Array[] = []
    for (;;) {
      const { done, value } = await r.read()
      if (done) break
      chunks.push(value)
    }
    const file = new File(chunks, 'obc2.log.gz', { type: 'application/gzip' })
    const items = await buildStagingItemsFromFiles([file])
    expect(items).toHaveLength(1)
    expect(items[0]?.status).toBe('ready')
    if (items[0]?.status !== 'ready') return
    expect(items[0].file.name).toBe('obc2.log')
    expect(items[0].fileName).toBe('obc2.log.gz')
    expect(items[0].gzipInflation?.format).toBe('gzip')
    expect(items[0].kind).toBe(SK.Text)
  })
})
