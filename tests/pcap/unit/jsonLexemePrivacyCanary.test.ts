/**
 * V01 / V08 canaries — SBI + GELF JSON must not retain synthetic secrets in exported bytes.
 * Runs the real discovery → plan → buildCapture path for both anonymization levels.
 */
import { describe, expect, it } from 'vitest'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpTcp, buildEthIpUdp, envelope } from '../fixtures/voipCorpus'
import {
  findJsonLexemeSpans,
  maskJsonNumberRaw,
} from '../../../src/pcap/sanitize/httpBody'

const TEXT_ENC = new TextEncoder()
const TEXT_DEC = new TextDecoder('latin1')

function exportedAscii(built: { packets: readonly { data: Uint8Array }[] }): string {
  return built.packets.map((p) => TEXT_DEC.decode(p.data)).join('\0')
}

describe('JSON lexeme walker', () => {
  it('accounts for keys, numbers, array inheritance, and escapes', () => {
    const body = TEXT_ENC.encode(
      '{"accessToken":123456789012,"privateValues":["AUDIT_ARRAY_SECRET_77319"],"sta\\u0074us":"x"}',
    )
    const lexemes = findJsonLexemeSpans(body, 0)
    expect(lexemes).not.toBeNull()
    const kinds = lexemes!.map((l) => [l.kind, l.decoded, l.precedingKey] as const)
    expect(kinds).toEqual([
      ['key', 'accessToken', null],
      ['number', '123456789012', 'accessToken'],
      ['key', 'privateValues', null],
      ['string', 'AUDIT_ARRAY_SECRET_77319', 'privateValues'],
      ['key', 'status', null],
      ['string', 'x', 'status'],
    ])
    expect(maskJsonNumberRaw('420777123456')).toBe('000000000000')
  })
})

describe('V01 SBI JSON privacy canary', () => {
  const canaries = [
    'AUDIT_PRIVATE_KEY_77319',
    '420777123456',
    'AUDIT_ARRAY_SECRET_77319',
    '123456789012',
  ] as const

  it('export path removes unknown keys, numeric secrets, and array strings (both levels)', () => {
    const body = JSON.stringify({
      supi: 'imsi-262019876543210',
      AUDIT_PRIVATE_KEY_77319: 1,
      privatePhone: 420777123456,
      privateValues: ['AUDIT_ARRAY_SECRET_77319'],
      accessToken: 123456789012,
      status: 'REGISTERED',
      '5qi': 9,
    })
    const http = TEXT_ENC.encode(
      `POST /namf-comm/v1/ue-contexts/test-context/n1-n2-messages HTTP/1.1\r\n` +
        `Host: amf.example.invalid\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `\r\n` +
        body,
    )
    const pkt = envelope(
      buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 8080, 1, http),
      0,
    )

    for (const level of ['diagnostic', 'high-privacy'] as const) {
      const result = runExportPipeline([pkt], level, 'v01-sbi-json.pcap', `v01-sbi-${level}`, {
        mappingSeed: 'v01-sbi-json-canary',
      })
      expect(result.built.validationValid).toBe(true)
      expect(result.built.packets.length).toBe(1)
      const out = exportedAscii(result.built)
      for (const canary of canaries) {
        expect(out.includes(canary), `${level} retained ${canary}`).toBe(false)
      }
      // Schema preserve fields remain (not secrets)
      expect(out.includes('REGISTERED')).toBe(true)
      expect(out.includes('"5qi":9') || out.includes('"5qi": 9')).toBe(true)
    }
  })
})

describe('V08 GELF JSON privacy canary', () => {
  const canaries = [
    'AUDIT_GELF_KEY_77319',
    '420777123456',
    'AUDIT_GELF_ARRAY_77319',
  ] as const

  it('export path removes dynamic keys and numeric/array private values (both levels)', () => {
    const body = JSON.stringify({
      version: '1.1',
      host: 'audit.example.invalid',
      short_message: 'message',
      AUDIT_GELF_KEY_77319: 1,
      privateCounter: 420777123456,
      privateArray: ['AUDIT_GELF_ARRAY_77319'],
    })
    const pkt = envelope(
      buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 12_201, TEXT_ENC.encode(body)),
      0,
    )

    for (const level of ['diagnostic', 'high-privacy'] as const) {
      const result = runExportPipeline([pkt], level, 'v08-gelf-json.pcap', `v08-gelf-${level}`, {
        mappingSeed: 'v08-gelf-json-canary',
      })
      expect(result.built.validationValid).toBe(true)
      expect(result.built.packets.length).toBe(1)
      const out = exportedAscii(result.built)
      for (const canary of canaries) {
        expect(out.includes(canary), `${level} retained ${canary}`).toBe(false)
      }
      expect(out.includes('"version":"1.1"') || out.includes('"version": "1.1"')).toBe(true)
    }
  })
})
