/**
 * T00 / T06 / T12 — guard against known-false claims in the in-app overview docs.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '../..')
const overviewPath = join(rootDir, 'docs/PCAP_ANONYMIZATION_OVERVIEW.md')
const protocolMatrixPath = join(rootDir, 'src/pcap/docs/protocolSupportMatrix.ts')

// Positive overclaims only — "not a finished unified kernel" is the honest wording.
const FINISHED_KERNEL_CLAIM =
  /(?<!not a )finished unified (?:T-01 )?kernel|T-01 (?:je )?dodan[ée]|T-01 jádro \(dodáno\)|dodan[ée] jádro|hotové jádro/i

describe('anonymization overview docs claims (T00/T06/T12)', () => {
  const text = readFileSync(overviewPath, 'utf8')

  it('claims RTP/RTCP port pairing is preserved (T06)', () => {
    expect(text).toMatch(/RTCP\s*=\s*RTP\s*\+\s*1/i)
    expect(text).toMatch(/zůstává zachovaný/i)
    expect(text).toMatch(/permutují po dvojicích/i)
    // Legacy honest-but-negative wording must be gone.
    expect(text).not.toMatch(/nezachovávají\s*—\s*oprava párování/i)
    expect(text).not.toMatch(/implementační task T06/i)
  })

  it('describes SDP session-id length-stable mapping and modular session-version shift (T01)', () => {
    expect(text).not.toMatch(/číslo verze\s+zůstává nedotčené/i)
    expect(text).not.toMatch(/verze\s+zůstává nedotčené/i)
    expect(text).not.toMatch(/dnes mapuje jako samostatná identita/i)
    expect(text).toMatch(/session-id se nahradí číslem stejné\s+délky/i)
    expect(text).toMatch(/Session-version se posouvá o stejnou\s+konstantu/i)
    expect(text).toMatch(/přírůstky v re-INVITE zůstávají\s+čitelné/i)
    expect(text).toMatch(/sdp-session-id/)
  })

  it('does not overclaim AES Crypto-PAn for IPv4 topology (T12 / T48)', () => {
    expect(text).not.toMatch(/Crypto-PAn styl odvození/i)
    expect(text).toMatch(/topology-preserving kandidát/i)
    expect(text).toMatch(/ne standardní AES Crypto-PAn/i)
    expect(text).toMatch(/koliz/i)
  })

  it('documents finite per-category alias domains below the 500k cap (T48)', () => {
    expect(text).toMatch(/Konečné aliasové domény/i)
    expect(text).toMatch(/65\s*536|65536/)
    expect(text).toMatch(/mappingDomainRegistry/)
  })

  it('describes ICE raddr/rport without claiming independent port preservation (T12)', () => {
    expect(text).toMatch(/raddr.*rport|raddr\/rport/i)
    expect(text).toMatch(/permutují \*\*po dvojicích\*\*|permutují po dvojicích/i)
    expect(text).not.toMatch(/zachovaným vztahem „tenhle kandidát je veřejná strana/i)
  })

  it('lists MGCP, SIPREC, maskFill unsupported path, and three-state AI gate (T02/T08/T11/T12)', () => {
    expect(text).toMatch(/MGCP/)
    expect(text).toMatch(/SIPREC|multipart\/mixed/i)
    expect(text).toMatch(/maskFill/)
    expect(text).toMatch(/AI_READY_WITH_GAPS/)
    expect(text).toMatch(/AI_READY/)
    expect(text).toMatch(/NOT_AI_READY/)
  })

  it('documents MGCP IPv6 NotifiedEntity and DigitMap class preservation (T11/T12)', () => {
    expect(text).toMatch(/NotifiedEntity/)
    expect(text).toMatch(/IPv6/)
    expect(text).toMatch(/DigitMap/)
    expect(text).toMatch(/\[2-9\]|znakové třídy/i)
    expect(text).toMatch(/unsupported:mgcp/)
  })

  it('documents gzip inflate limits and archive handling (T05/T12/T44)', () => {
    expect(text).toMatch(/\.gz|gzip/i)
    expect(text).toMatch(/rozbalenou velikost|gzip bomb/i)
    expect(text).toMatch(/ZIP|xz|zstd|bzip2/i)
    expect(text).toMatch(/support bundle|\.zip|\.tar\.gz/i)
  })

  it('states high-privacy drops RTP rather than rewriting payload (D0/T12)', () => {
    expect(text).toMatch(/zahazuje hlasová|zahazuje.*RTP|drop.*RTP|celý paket zahozen/i)
  })

  it('does not claim all IPv6 ff00::/8 multicast is preserved (T33)', () => {
    expect(text).not.toMatch(/multicast \(IPv4 `224\.0\.0\.0\/4`, IPv6 `ff00::\/8`\)\s*\nse \*\*nemapují\*\*/i)
    expect(text).toMatch(/solicited-node/i)
    expect(text).toMatch(/33:33:ff/i)
  })

  it('does not list SSDP/H.248 as unsupported protocol examples (T00 honesty)', () => {
    expect(text).not.toMatch(/nepodporované protokoly\s*\(SSDP,\s*H\.248/i)
    expect(text).toMatch(/SSDP a H\.248 mají strukturovanou podporu/i)
  })
})

describe('T-01 kernel honesty (T12 / R09)', () => {
  const matrixHeader = readFileSync(protocolMatrixPath, 'utf8')

  it('does not claim finished unified T-01 kernel in matrix module header', () => {
    expect(matrixHeader).not.toMatch(FINISHED_KERNEL_CLAIM)
  })

  it('states T-01.F / R09 partial status and 107/108 dispatch registry in matrix module header', () => {
    expect(matrixHeader).toMatch(/T-01\.F|R09/)
    expect(matrixHeader).toMatch(/107\/108/)
    expect(matrixHeader).toMatch(/not a finished unified kernel|R10 browser open/i)
  })
})
