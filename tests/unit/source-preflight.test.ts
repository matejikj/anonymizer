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

  it.each([
    '2026-10-22 13:07:55.335 [Thread-19] DEBUG NativeCodeLogger - RX SIP message\nINVITE sip:bob@example.invalid SIP/2.0\nFrom: <sip:alice@example.invalid>\nTo: <sip:bob@example.invalid>\nContent-Type: application/sdp\n\nv=0\n',
    'INVITE sip:bob@example.invalid SIP/2.0\r\nFrom: <sip:alice@example.invalid>\r\nTo: <sip:bob@example.invalid>\r\n\r\n',
    'SIP/2.0 200 OK\nFrom: <sip:alice@example.invalid>\nTo: <sip:bob@example.invalid>\n\n',
    '2026-10-22 DEBUG received payload\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=example\n\n',
    'HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=example\r\n\r\n',
    'X-Trace: request\n2026-10-22 DEBUG received payload\nFrom: source\nTo: destination\n\n',
  ])('keeps protocol headers inside logs and dumps as text (%#)', (body) => {
    expect(probeSourceKind(new TextEncoder().encode(body), 'obc.log').kind).toBe(SK.Text)
  })

  it.each([
    'From: alice@example.invalid\r\nTo: bob@example.invalid\r\nSubject: Test\r\n\r\nbody\r\n',
    'Received: by mail.example.invalid\nX-Trace/ID: test\nFrom: alice@example.invalid\nSubject: A folded\n subject\nMIME-Version: 1.0\n\nbody\n',
    'Content-Type: multipart/mixed;\n boundary=example\n\n--example\n',
  ])('still rejects an email header block even with a .log extension (%#)', (body) => {
    expect(probeSourceKind(new TextEncoder().encode(body), 'message.log')).toEqual({
      kind: 'unsupported', code: 'mime-unsupported',
    })
  })

  it('does not infer email from headers occurring after a blank line', () => {
    expect(probeSourceKind(new TextEncoder().encode('\nFrom: source\nTo: destination\n'), 'trace.log').kind).toBe(SK.Text)
  })

  it('uses content rather than a misleading .eml extension for a plain log', () => {
    expect(probeSourceKind(new TextEncoder().encode('2026-10-22 INFO ready\n'), 'trace.eml').kind).toBe(SK.Text)
    expect(probeSourceKind(new Uint8Array(), 'empty.eml')).toEqual({ kind: 'unsupported', code: 'mime-unsupported' })
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

  it('stages a log containing SIP From/To headers as ready text', async () => {
    const file = textFile('obc.log', '2026-10-22 DEBUG RX SIP\nINVITE sip:b@example.invalid SIP/2.0\nFrom: <sip:a@example.invalid>\nTo: <sip:b@example.invalid>\n\n')
    const items = await buildStagingItemsFromFiles([file])
    expect(items).toHaveLength(1)
    expect(items[0]?.status).toBe('ready')
    expect(items[0]?.kind).toBe(SK.Text)
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
