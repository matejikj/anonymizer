/**
 * T27 — FTP control channel (TCP 21): USER/PASS, PORT/PASV/EPRT/EPSV length-stable IP/port map.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import {
  extractTextProtoValues,
  applyPayloadMapHits,
  hitsFromExtractors,
  maskPayloadSpan,
} from '../protocols/application/textproto'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'

const FTP_PORTS = new Set([21])

export function isFtpPortHint(src: number, dst: number): boolean {
  return FTP_PORTS.has(src) || FTP_PORTS.has(dst)
}

export function looksLikeFtp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  const head = latin1(data, offset, Math.min(length, 80))
  return /^(?:220|230|331|227|229|150|125|226|250|200|331|530|USER |PASS |PORT |EPRT |PASV|EPSV|RETR |STOR |CWD |LIST|QUIT|AUTH |PROT )/i.test(
    head,
  )
}

export function sanitizeFtp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeFtp(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const text = latin1(buffer, offset, length)
  let pos = 0
  while (pos < text.length) {
    const nl = text.indexOf('\n', pos)
    const end = nl < 0 ? text.length : nl + 1
    const raw = text.slice(pos, end)
    const line = raw.replace(/\r?\n$/, '')
    const abs = offset + pos
    sanitizeFtpLine(line, abs, raw.length, collector, mapping, intents, packetIndex, coverage, issues)
    pos = end
  }
  // Parent span so CF-09 advances past CRLF between per-line rows.
  coverage.unshift({ protocol: 'ftp', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeFtpLine(
  line: string,
  abs: number,
  rawLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const user = /^USER\s+(\S+)/i.exec(line)
  if (user) {
    mapAscii(line, abs, user[1]!, 'user-id', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'ftp-cmd', offset: abs, length: rawLen, status: 'covered' })
    return
  }
  const pass = /^(?:PASS|ACCT)\s+(\S+)/i.exec(line)
  if (pass) {
    maskPayloadSpan(collector, abs + line.indexOf(pass[1]!), pass[1]!.length, intents, packetIndex, 'ftp-pass')
    coverage.push({ protocol: 'ftp-auth', offset: abs, length: rawLen, status: 'redacted' })
    return
  }

  // PORT h1,h2,h3,h4,p1,p2
  const portCmd = /^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\s*$/i.exec(line)
  if (portCmd) {
    mapPortTuple(line, abs, rawLen, portCmd, collector, mapping, intents, packetIndex, coverage, issues)
    return
  }
  // 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
  const pasv = /^(227\b.*?\()(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)(\).*)/i.exec(line)
  if (pasv) {
    const tuple = [pasv[2]!, pasv[3]!, pasv[4]!, pasv[5]!, pasv[6]!, pasv[7]!]
    const tupleStr = tuple.join(',')
    const tupleIdx = line.indexOf(tupleStr)
    mapCommaTuple(
      line, abs, rawLen, tupleIdx, tuple, collector, mapping, intents, packetIndex, coverage, issues,
    )
    return
  }

  // EPRT |1|ip|port|  or |2|ipv6|port|
  const eprt = /^(EPRT\s+\|)([12])\|([^|]+)\|(\d+)\|/i.exec(line)
  if (eprt) {
    mapEprt(line, abs, rawLen, eprt, collector, mapping, intents, packetIndex, coverage, issues)
    return
  }
  // 229 Entering Extended Passive Mode (|||port|)
  const epsv = /^(229\b.*?\(\|\|\|)(\d+)(\|\).*)/i.exec(line)
  if (epsv) {
    const portStr = epsv[2]!
    const idx = line.indexOf(portStr, epsv[1]!.length)
    mapPortDecimal(line, abs, idx, portStr, collector, mapping, intents, packetIndex, coverage, issues)
    coverage.push({ protocol: 'ftp-data', offset: abs, length: rawLen, status: 'covered' })
    return
  }

  // Paths — detector extract
  if (/^(?:RETR|STOR|CWD|LIST|NLST|DELE|MKD|RMD|RNFR|RNTO)\b/i.test(line)
    || /^257\b/.test(line)) {
    const hits = hitsFromExtractors(extractTextProtoValues(line, abs))
    applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'ftp')
    // Path remainder after command — mask if looks like absolute path with user dirs
    const sp = line.indexOf(' ')
    if (sp > 0 && /[\\/]/.test(line.slice(sp))) {
      maskPayloadSpan(collector, abs + sp + 1, line.length - sp - 1, intents, packetIndex, 'ftp-path')
      coverage.push({ protocol: 'ftp-path', offset: abs, length: rawLen, status: 'redacted' })
      return
    }
    coverage.push({ protocol: 'ftp-cmd', offset: abs, length: rawLen, status: 'covered' })
    return
  }

  const hits = hitsFromExtractors(extractTextProtoValues(line, abs))
  applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'ftp')
  coverage.push({ protocol: 'ftp-cmd', offset: abs, length: rawLen, status: 'covered' })
}

function mapPortTuple(
  line: string,
  abs: number,
  rawLen: number,
  m: RegExpExecArray,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const tuple = [m[1]!, m[2]!, m[3]!, m[4]!, m[5]!, m[6]!]
  const tupleStr = tuple.join(',')
  const idx = line.indexOf(tupleStr)
  mapCommaTuple(line, abs, rawLen, idx, tuple, collector, mapping, intents, packetIndex, coverage, issues)
}

function mapCommaTuple(
  line: string,
  abs: number,
  rawLen: number,
  idx: number,
  tuple: string[],
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (idx < 0) {
    maskPayloadSpan(collector, abs, line.length, intents, packetIndex, 'ftp-port-bad')
    coverage.push({ protocol: 'ftp-data', offset: abs, length: rawLen, status: 'redacted' })
    issues.push('ftp-port-parse')
    return
  }
  const ip = `${tuple[0]}.${tuple[1]}.${tuple[2]}.${tuple[3]}`
  const p1 = Number(tuple[4])
  const p2 = Number(tuple[5])
  const port = (p1 << 8) | p2
  const ipCanon = canonicalizeIdentity('ipv4', ip)
  const portCanon = canonicalizeIdentity('port', `tcp/${port}`)
  if (!ipCanon || !portCanon) {
    maskPayloadSpan(collector, abs + idx, tuple.join(',').length, intents, packetIndex, 'ftp-port-bad')
    coverage.push({ protocol: 'ftp-data', offset: abs, length: rawLen, status: 'redacted' })
    return
  }
  const tupleStr = tuple.join(',')
  intents?.recordEntityReplacement(packetIndex, abs + idx, 'ipv4', ipCanon, tupleStr.length)
  intents?.recordEntityReplacement(packetIndex, abs + idx, 'port', portCanon, tupleStr.length)
  collector.addDeferred(abs + idx, tupleStr.length, ({ mapping: live }) => {
    try {
      const mappedIp = live.map('ipv4', ipCanon)
      const mappedPortStr = live.map('port', portCanon)
      const slash = mappedPortStr.indexOf('/')
      const mappedPort = Number.parseInt(mappedPortStr.slice(slash + 1), 10)
      const parts = mappedIp.split('.').map((x) => Number(x))
      if (parts.length !== 4 || !Number.isInteger(mappedPort)) {
        return createProtocolNeutralMaskFill({
          length: tupleStr.length, packetIndex, offset: abs + idx, domain: 'ftp-port',
        })
      }
      const outParts = [
        String(parts[0]), String(parts[1]), String(parts[2]), String(parts[3]),
        String((mappedPort >> 8) & 0xff), String(mappedPort & 0xff),
      ]
      // Length-stable per decimal field: pad/truncate each field to original digit count
      const rebuilt: string[] = []
      for (let i = 0; i < 6; i++) {
        const want = tuple[i]!.length
        let s = outParts[i]!
        if (s.length > want) {
          // Cannot preserve length without changing value semantics → mask whole tuple
          return createProtocolNeutralMaskFill({
            length: tupleStr.length, packetIndex, offset: abs + idx, domain: 'ftp-port-len',
          })
        }
        s = s.padStart(want, '0')
        rebuilt.push(s)
      }
      return computeFixedLengthAsciiBytes(abs + idx, tupleStr.length, rebuilt.join(','))
    } catch {
      return createProtocolNeutralMaskFill({
        length: tupleStr.length, packetIndex, offset: abs + idx, domain: 'ftp-port',
      })
    }
  }, { fallbackKind: 'digits', protocol: 'ftp', category: 'ipv4', packetIndex })
  coverage.push({ protocol: 'ftp-data', offset: abs, length: rawLen, status: 'covered' })
  void mapping
  void line
}

function mapEprt(
  line: string,
  abs: number,
  rawLen: number,
  m: RegExpExecArray,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const fam = m[2]!
  const host = m[3]!
  const portStr = m[4]!
  const hostIdx = line.indexOf(host)
  const portIdx = line.indexOf(`|${portStr}|`, hostIdx)
  const cat = fam === '2' ? 'ipv6' as const : 'ipv4' as const
  const hostCanon = canonicalizeIdentity(cat, host)
  if (hostCanon && hostIdx >= 0) {
    mapAscii(line, abs, host, cat, collector, mapping, intents, packetIndex)
  } else if (hostIdx >= 0) {
    maskPayloadSpan(collector, abs + hostIdx, host.length, intents, packetIndex, 'ftp-eprt-host')
  }
  if (portIdx >= 0) {
    mapPortDecimal(line, abs, portIdx + 1, portStr, collector, mapping, intents, packetIndex, coverage, issues)
  }
  coverage.push({ protocol: 'ftp-data', offset: abs, length: rawLen, status: 'covered' })
}

function mapPortDecimal(
  line: string,
  abs: number,
  idx: number,
  portStr: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  void coverage
  void issues
  void line
  const port = Number(portStr)
  const canon = canonicalizeIdentity('port', `tcp/${port}`)
  if (!canon || idx < 0) {
    maskPayloadSpan(collector, abs + Math.max(0, idx), portStr.length, intents, packetIndex, 'ftp-epsv-port')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: portStr.length }
  intents?.recordEntityReplacement(packetIndex, abs + idx, 'port', canon, portStr.length, constraint, portStr)
  collector.addDeferred(abs + idx, portStr.length, ({ mapping: live }) => {
    try {
      const mapped = live.map('port', canon)
      const slash = mapped.indexOf('/')
      const n = Number.parseInt(mapped.slice(slash + 1), 10)
      let s = String(n)
      if (s.length > portStr.length) {
        return createProtocolNeutralMaskFill({
          length: portStr.length, packetIndex, offset: abs + idx, domain: 'ftp-epsv-len',
        })
      }
      s = s.padStart(portStr.length, '0')
      return computeFixedLengthAsciiBytes(abs + idx, portStr.length, s)
    } catch {
      return createProtocolNeutralMaskFill({
        length: portStr.length, packetIndex, offset: abs + idx, domain: 'ftp-epsv',
      })
    }
  }, { fallbackKind: 'digits', protocol: 'ftp', category: 'port', packetIndex })
  void mapping
}

function mapAscii(
  line: string,
  abs: number,
  token: string,
  category: 'user-id' | 'ipv4' | 'ipv6' | 'hostname',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const idx = line.indexOf(token)
  if (idx < 0) return
  const canon = canonicalizeIdentity(category, token) ?? token
  const constraint = { kind: 'text-ascii' as const, byteLength: token.length }
  intents?.recordEntityReplacement(packetIndex, abs + idx, category, canon, token.length, constraint, token)
  collector.addDeferred(abs + idx, token.length, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(
        abs + idx, token.length, live.aliasFor(category, canon, constraint, token),
      )
    } catch {
      return createProtocolNeutralMaskFill({
        length: token.length, packetIndex, offset: abs + idx, domain: `ftp-${category}`,
      })
    }
  }, { fallbackKind: 'text-x', protocol: 'ftp', category, packetIndex })
  void mapping
}

function latin1(buf: Uint8Array, off: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(buf[off + i]!)
  return s
}
