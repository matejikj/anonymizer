/**
 * T43 — text encodings (CP1250 / UTF-16) + NDJSON secret-key masking + binary log reject.
 */
import { describe, expect, it } from 'vitest'
import {
  detectTextEncoding,
  decodeTextBuffer,
  looksLikeEvtx,
  looksLikeSystemdJournal,
} from '../../src/features/import-log/textEncoding.ts'
import { preflightFile } from '../../src/features/import-log/preflight.ts'
import {
  detectStructuredLogFormat,
  sanitizeStructuredLogText,
} from '../../src/engine/structuredLogSanitize.ts'
import { probeSourceKind } from '../../src/correlation/import/sourcePreflightPort.ts'
import { rejectionForUnsupportedCode } from '../../src/correlation/import/inputRejection.ts'

function encodeUtf16Le(text: string, withBom = true): Uint8Array {
  const bom = withBom ? [0xff, 0xfe] : []
  const body: number[] = []
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    body.push(c & 0xff, (c >> 8) & 0xff)
  }
  return new Uint8Array([...bom, ...body])
}

/** Minimal CP1250 bytes for "Novák šťastný" (Czech). */
function cp1250CzechSample(): Uint8Array {
  // N o v á k   š ť a s t n ý
  // á=0xE1 in both; š=0x9A, ť=0x9D, ý=0xFD in CP1250
  return new Uint8Array([
    0x4e, 0x6f, 0x76, 0xe1, 0x6b, 0x20, 0x9a, 0x9d, 0x61, 0x73, 0x74, 0x6e, 0xfd, 0x0a,
  ])
}

describe('T43 encoding detection', () => {
  it('detects UTF-8 BOM and UTF-16 LE BOM', () => {
    expect(detectTextEncoding(new Uint8Array([0xef, 0xbb, 0xbf, 0x61])).label).toBe('utf-8')
    expect(detectTextEncoding(new Uint8Array([0xff, 0xfe, 0x61, 0x00])).label).toBe('utf-16le')
    expect(detectTextEncoding(new Uint8Array([0xfe, 0xff, 0x00, 0x61])).label).toBe('utf-16be')
  })

  it('decodes Windows-1250 Czech without U+FFFD', () => {
    const bytes = cp1250CzechSample()
    const detected = detectTextEncoding(bytes)
    expect(detected.label).toBe('windows-1250')
    const { text, hadReplacement } = decodeTextBuffer(bytes, 'windows-1250')
    expect(hadReplacement).toBe(false)
    expect(text.includes('\uFFFD')).toBe(false)
    expect(text).toMatch(/Nov/)
    expect(text).toMatch(/š|ť|ý/)
  })

  it('decodes UTF-16 LE Czech without U+FFFD and preflight accepts it', async () => {
    const text = 'Novák šťastný\n'
    const bytes = encodeUtf16Le(text, true)
    expect(detectTextEncoding(bytes).label).toBe('utf-16le')
    const decoded = decodeTextBuffer(bytes, 'utf-16le', 0)
    // TextDecoder strips BOM
    expect(decoded.hadReplacement).toBe(false)
    expect(decoded.text.includes('\uFFFD')).toBe(false)
    expect(decoded.text).toContain('Novák')

    const file = new File([bytes], 'utf16.log', { type: 'application/octet-stream' })
    const pre = await preflightFile(file, { encoding: 'utf-16le' })
    expect(pre.ok).toBe(true)
    if (pre.ok) {
      expect(pre.sourceEncoding).toBe('utf-16le')
      expect(pre.hadInvalidUtf8).toBe(false)
    }
  })
})

describe('T43 structured JSON/NDJSON', () => {
  it('masks secret keys and keeps valid JSON', () => {
    const src = [
      '{"user":"alice","password":"s3cret","ip":"10.0.0.1"}',
      '{"token":"abc","hostname":"gw.example"}',
      '',
    ].join('\n')
    expect(detectStructuredLogFormat(src)).toBe('ndjson')
    const out = sanitizeStructuredLogText(src)
    expect(out.stats.secretFieldsMasked).toBeGreaterThanOrEqual(2)
    const lines = out.text.trim().split('\n')
    for (const line of lines) {
      const obj = JSON.parse(line) as Record<string, unknown>
      if ('password' in obj) expect(String(obj.password)).toMatch(/^\*+$/)
      if ('token' in obj) expect(String(obj.token)).toMatch(/^\*+$/)
    }
  })

  it('preserves large integers and duplicate keys (V14 lexeme sanitize)', () => {
    const src = '{"id":9007199254740993,"value":1,"value":2,"password":"x"}\n'
    const out = sanitizeStructuredLogText(src)
    expect(out.text).toContain('9007199254740993')
    expect(out.text).toMatch(/"value"\s*:\s*1/)
    expect(out.text).toMatch(/"value"\s*:\s*2/)
    expect(out.text).not.toContain('"password":"x"')
    expect(out.text).toMatch(/"password"\s*:\s*"\*+"/)
  })
})

describe('T43 structured CSV / CEF / logfmt / HAR / access', () => {
  it('masks secret CSV columns and preserves row/column count', () => {
    const src = [
      'user,email,password,ip',
      'alice,a@example.com,s3cret,10.0.0.1',
      'bob,b@example.com,hunter2,10.0.0.2',
      '',
    ].join('\n')
    expect(detectStructuredLogFormat(src)).toBe('csv')
    const out = sanitizeStructuredLogText(src)
    expect(out.stats.format).toBe('csv')
    expect(out.stats.secretFieldsMasked).toBe(2)
    const rows = out.text.trim().split('\n')
    expect(rows).toHaveLength(3)
    expect(rows[0]).toBe('user,email,password,ip')
    expect(rows[1]).toMatch(/^alice,a@example.com,\*+,10\.0\.0\.1$/)
    expect(rows[1]).not.toContain('s3cret')
  })

  it('masks multiline quoted CSV password fields (V14 record framer)', () => {
    const src = 'user,password,ip\n"alice","line1\nSECRET_CSV_PASS",10.0.0.1\n'
    expect(detectStructuredLogFormat(src)).toBe('csv')
    const out = sanitizeStructuredLogText(src)
    expect(out.stats.format).toBe('csv')
    expect(out.text).not.toContain('SECRET_CSV_PASS')
    expect(out.stats.secretFieldsMasked).toBeGreaterThanOrEqual(1)
  })

  it('masks CEF secret extensions and keeps header pipes', () => {
    const src =
      'CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.1 suser=alice token=abc123 dst=10.0.0.2\n'
    expect(detectStructuredLogFormat(src)).toBe('cef')
    const out = sanitizeStructuredLogText(src)
    expect(out.text).toContain('CEF:0|Vendor|Product|1.0|100|Login|5|')
    expect(out.text).toContain('src=10.0.0.1')
    expect(out.text).toContain('suser=alice')
    expect(out.text).not.toContain('abc123')
    expect(out.text).toMatch(/token=\*+/)
  })

  it('masks logfmt secret values', () => {
    const src = 'level=info user=alice password="s3cret" host=gw.example msg=ok\n'
    expect(detectStructuredLogFormat(src)).toBe('logfmt')
    const out = sanitizeStructuredLogText(src)
    expect(out.text).toContain('user=alice')
    expect(out.text).toContain('host=gw.example')
    expect(out.text).not.toContain('s3cret')
    expect(out.text).toMatch(/password="\*+"/)
  })

  it('masks HAR Authorization / Cookie and keeps valid JSON', () => {
    const har = {
      log: {
        version: '1.2',
        entries: [
          {
            startedDateTime: '2026-01-01T00:00:00.000Z',
            time: 12,
            serverIPAddress: '10.0.0.9',
            request: {
              method: 'GET',
              url: 'https://example.com/',
              headers: [
                { name: 'Authorization', value: 'Bearer SECRETTOKEN' },
                { name: 'Host', value: 'example.com' },
              ],
              cookies: [{ name: 'sid', value: 'cookie-value' }],
              queryString: [{ name: 'token', value: 'q-secret' }],
            },
            response: {
              status: 200,
              headers: [],
              cookies: [],
              content: { text: '{"password":"body-secret"}', mimeType: 'application/json' },
            },
          },
        ],
      },
    }
    const src = JSON.stringify(har)
    expect(detectStructuredLogFormat(src)).toBe('har')
    const out = sanitizeStructuredLogText(src)
    const parsed = JSON.parse(out.text) as typeof har
    expect(parsed.log.entries[0]!.request.headers[0]!.value).toMatch(/^\*+$/)
    expect(parsed.log.entries[0]!.request.cookies[0]!.value).toMatch(/^\*+$/)
    expect(parsed.log.entries[0]!.request.queryString[0]!.value).toMatch(/^\*+$/)
    expect(parsed.log.entries[0]!.serverIPAddress).toBe('10.0.0.9')
    expect(out.text).not.toContain('SECRETTOKEN')
    expect(out.text).not.toContain('body-secret')
  })

  it('masks access-log user and query token params', () => {
    const src =
      '10.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /path?token=abc&id=1 HTTP/1.0" 200 2326 "http://ref.example/" "Mozilla/5.0"\n'
    expect(detectStructuredLogFormat(src)).toBe('access-combined')
    const out = sanitizeStructuredLogText(src)
    expect(out.text).not.toContain('frank')
    expect(out.text).not.toContain('token=abc')
    expect(out.text).toContain('id=1')
    expect(out.text).toContain('10.0.0.1')
  })
})

describe('T43 binary log rejection', () => {
  it('recognizes EVTX and systemd journal magics', async () => {
    const evtx = new Uint8Array([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00])
    expect(looksLikeEvtx(evtx)).toBe(true)
    expect(probeSourceKind(evtx).kind).toBe('unsupported')
    if (probeSourceKind(evtx).kind === 'unsupported') {
      expect(probeSourceKind(evtx).code).toBe('evtx')
    }
    const journal = new TextEncoder().encode('LPKSHHRH....')
    expect(looksLikeSystemdJournal(journal)).toBe(true)
    const rej = rejectionForUnsupportedCode('evtx')
    expect(rej.action).toMatch(/wevtutil/)
    expect(rejectionForUnsupportedCode('systemd-journal').action).toMatch(/journalctl/)

    const evtxFile = new File([evtx], 'events.evtx', { type: 'application/octet-stream' })
    const pre = await preflightFile(evtxFile)
    expect(pre.ok).toBe(false)
    if (!pre.ok) {
      expect(pre.code).toBe('evtx')
      expect(pre.message).toMatch(/wevtutil/)
    }
  })
})
