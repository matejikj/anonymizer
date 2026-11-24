/**
 * T15 — text protocol toolkit: tokenizer, extractors, payload detectors, correlation.
 */
import { describe, expect, it } from 'vitest'
import {
  tokenizeTextProtoMessage,
  extractTextProtoValues,
  detectIdentitiesInPayload,
  dispositionForTextProtoHeader,
  findSqlLiteralSpans,
  findEncodedAuthTokenSpans,
  GENERIC_NOTIFY_CORPUS,
  GENERIC_NOTIFY_HEADER_POLICY,
  matchesGenericNotifyStartLine,
  sanitizeTextPayload,
} from '../../../src/pcap/protocols/application/textproto'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

describe('T15 textproto tokenizer', () => {
  it('parses start-line, folded headers, and Content-Length body', () => {
    const msg = [
      'NOTIFY * HTTP/1.1\r\n',
      'Host: example.com\r\n',
      'X-Note: line1\r\n',
      ' folded\r\n',
      'Content-Length: 5\r\n',
      '\r\n',
      'helloEXTRA',
    ].join('')
    const buf = latin1(msg)
    const parsed = tokenizeTextProtoMessage(buf, 0, buf.length)
    expect(parsed).not.toBeNull()
    expect(matchesGenericNotifyStartLine(parsed!.startLineText)).toBe(true)
    expect(parsed!.headers.some((h) => h.name === 'host')).toBe(true)
    const note = parsed!.headers.find((h) => h.name === 'x-note')
    expect(note?.valueText).toContain('line1')
    expect(note?.valueText).toContain('folded')
    expect(parsed!.body?.length).toBe(5)
  })

  it('accepts LF-only lines and rejects NUL', () => {
    const lf = latin1('GET / HTTP/1.1\nHost: a.example\n\n')
    expect(tokenizeTextProtoMessage(lf, 0, lf.length)?.headers).toHaveLength(1)
    const nul = new Uint8Array([0x41, 0x00, 0x42])
    expect(tokenizeTextProtoMessage(nul, 0, nul.length)).toBeNull()
  })

  it('parses GENERIC_NOTIFY_CORPUS with policy table', () => {
    const buf = latin1(GENERIC_NOTIFY_CORPUS)
    const parsed = tokenizeTextProtoMessage(buf, 0, buf.length)
    expect(parsed).not.toBeNull()
    expect(matchesGenericNotifyStartLine(parsed!.startLineText)).toBe(true)
    expect(dispositionForTextProtoHeader(GENERIC_NOTIFY_HEADER_POLICY, 'NTS')).toEqual({
      kind: 'preserve',
    })
    expect(dispositionForTextProtoHeader(GENERIC_NOTIFY_HEADER_POLICY, 'X-Unknown')).toEqual({
      kind: 'mask',
    })
    const host = parsed!.headers.find((h) => h.name === 'host')
    expect(host).toBeTruthy()
    const extracted = extractTextProtoValues(host!.valueText, host!.valueSpan.offset)
    expect(extracted.some((e) => e.category === 'ipv4')).toBe(true)
  })
})

describe('T15 extractors and literals', () => {
  it('extracts URI host, email, and +phone', () => {
    const text = 'see http://alice@10.1.2.3:8080/x and a@b.example +420777123456'
    const hits = extractTextProtoValues(text, 100)
    expect(hits.some((h) => h.category === 'ipv4' && h.canonical === '10.1.2.3')).toBe(true)
    expect(hits.some((h) => h.category === 'email')).toBe(true)
    expect(hits.some((h) => h.category === 'sip-phone')).toBe(true)
    expect(hits.every((h) => h.absoluteOffset >= 100)).toBe(true)
  })

  it('masks SQL string/number/comment literals with stable spans', () => {
    const sql = latin1("SELECT * FROM t WHERE id=42 AND name='secret' -- leak")
    const spans = findSqlLiteralSpans(sql, 0)
    expect(spans.some((s) => s.kind === 'sql-number')).toBe(true)
    expect(spans.some((s) => s.kind === 'sql-string')).toBe(true)
    expect(spans.some((s) => s.kind === 'sql-comment')).toBe(true)
  })

  it('finds Basic / AUTH PLAIN tokens for always-mask', () => {
    const text = 'Authorization: Basic YWxpY2U6c2VjcmV0 and AUTH PLAIN AGJvYgBwYXNz'
    const spans = findEncodedAuthTokenSpans(text, 0)
    expect(spans.some((s) => s.kind === 'basic')).toBe(true)
    expect(spans.some((s) => s.kind === 'auth-plain')).toBe(true)
  })
})

describe('T15 payload detectors + correlation', () => {
  it('detects the same IP as text-log builtins', () => {
    const body = latin1('peer 10.0.0.77 connected\n')
    const hits = detectIdentitiesInPayload(body, 0, body.length)
    expect(hits.some((h) => h.canonical === '10.0.0.77' || h.originalSpelling === '10.0.0.77')).toBe(true)
  })

  it('shares MappingAuthority alias between text identity and payload hit', () => {
    const authority = new MappingAuthority()
    const correlationOptions = { crossFormatLinking: true as const }
    const ip = '10.0.0.77'

    const textResolved = authority.resolve({
      generationId: 't15',
      sourceId: 'log',
      identities: [{
        category: 'ip',
        canonical: ip,
        constraint: { kind: 'ipv4-wire' },
        originalSpelling: ip,
        source: { detectorId: 'text' },
      }],
      correlationOptions,
    })
    expect(textResolved.ok).toBe(true)
    if (!textResolved.ok) return
    const textAlias = textResolved.snapshot.entries[0]!.alias

    const body = latin1(`status from ${ip} ok\n`)
    const hits = detectIdentitiesInPayload(body, 0, body.length)
    const hit = hits.find((h) => h.originalSpelling === ip || h.canonical === ip)
    expect(hit).toBeTruthy()

    const pcapResolved = authority.resolve({
      generationId: 't15',
      sourceId: 'pcap',
      identities: [{
        category: hit!.category === 'ip' ? 'ipv4' : hit!.category,
        canonical: ip,
        constraint: { kind: 'ipv4-wire' },
        originalSpelling: ip,
        source: { detectorId: 'pcap' },
      }],
      correlationOptions,
    })
    expect(pcapResolved.ok).toBe(true)
    if (!pcapResolved.ok) return
    expect(pcapResolved.snapshot.entries.find((e) => e.canonical === ip)?.alias).toBe(textAlias)
  })

  it('sanitizeTextPayload maps detector hits without changing length', () => {
    const body = latin1('client 10.0.0.9 login\n')
    const collector = new PatchCollector(body.length)
    const mapping = new SessionMapping(
      {
        ip: 'topology-preserving',
        mac: 'locally-administered',
        timestamps: 'relative',
        ephemeralPorts: 'preserve',
        contentSignalingPorts: 'preserve',
        vlan: 'map',
      },
      { seed: 't15-payload' },
    )
    const result = sanitizeTextPayload({
      buffer: body,
      absoluteOffset: 0,
      byteLength: body.length,
      collector,
      mapping,
      packetIndex: 0,
    })
    expect(result.hitCount).toBeGreaterThan(0)
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = new Uint8Array(body)
    for (const p of collector.getPatches()) {
      out.set(p.data, p.offset)
    }
    expect(out.length).toBe(body.length)
    expect(new TextDecoder('latin1').decode(out)).not.toContain('10.0.0.9')
  })
})

describe('T15 engine version', () => {
  it('bumps PCAP_ENGINE_VERSION for text/* body detector path', () => {
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})
