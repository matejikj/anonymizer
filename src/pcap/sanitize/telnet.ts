/**
 * T27 — Telnet (TCP 23): preserve IAC negotiation option codes; mask user data / subnegotiation.
 * Port 514/TCP is syslog-capable — require IAC signature, not port alone.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

const TELNET_PORTS = new Set([23, 513]) // telnet + rlogin; rsh 514 needs IAC proof
const IAC = 255
const SB = 250
const SE = 240
const WILL = 251
const WONT = 252
const DO = 253
const DONT = 254

export function isTelnetPortHint(src: number, dst: number): boolean {
  return TELNET_PORTS.has(src) || TELNET_PORTS.has(dst) || src === 514 || dst === 514
}

export function looksLikeTelnet(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  // Must see at least one IAC command (negotiation) — distinguishes from syslog on 514/TCP
  for (let i = 0; i + 1 < length && i < 64; i++) {
    if (data[offset + i] === IAC) {
      const cmd = data[offset + i + 1]!
      if (cmd === IAC || cmd === SB || cmd === SE || (cmd >= WILL && cmd <= DONT) || cmd === 249) {
        return true
      }
    }
  }
  return false
}

export function sanitizeTelnet(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeTelnet(buffer, offset, length)) return null
  void mapping
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let i = 0
  let dataStart = -1
  const flushData = (end: number): void => {
    if (dataStart < 0 || end <= dataStart) return
    const abs = offset + dataStart
    const len = end - dataStart
    mask(collector, intents, packetIndex, abs, len, 'telnet-data')
    coverage.push({ protocol: 'telnet-data', offset: abs, length: len, status: 'redacted' })
    dataStart = -1
  }

  while (i < length) {
    if (buffer[offset + i] !== IAC) {
      if (dataStart < 0) dataStart = i
      i++
      continue
    }
    flushData(i)
    // IAC command
    if (i + 1 >= length) {
      mask(collector, intents, packetIndex, offset + i, length - i, 'telnet-iac-trunc')
      coverage.push({ protocol: 'telnet', offset: offset + i, length: length - i, status: 'malformed' })
      issues.push('telnet-iac-trunc')
      break
    }
    const cmd = buffer[offset + i + 1]!
    if (cmd === IAC) {
      // Escaped 0xFF in data stream — mask as data
      mask(collector, intents, packetIndex, offset + i, 2, 'telnet-escaped-ff')
      coverage.push({ protocol: 'telnet-data', offset: offset + i, length: 2, status: 'redacted' })
      i += 2
      continue
    }
    if (cmd === WILL || cmd === WONT || cmd === DO || cmd === DONT) {
      // IAC + cmd + option — preserve all three
      if (i + 2 >= length) {
        mask(collector, intents, packetIndex, offset + i, length - i, 'telnet-opt-trunc')
        coverage.push({ protocol: 'telnet', offset: offset + i, length: length - i, status: 'malformed' })
        break
      }
      coverage.push({ protocol: 'telnet-iac', offset: offset + i, length: 3, status: 'covered' })
      i += 3
      continue
    }
    if (cmd === SB) {
      // Subnegotiation — preserve IAC SB <opt>, mask body until IAC SE
      let j = i + 3 // after IAC SB opt
      if (i + 2 >= length) {
        mask(collector, intents, packetIndex, offset + i, length - i, 'telnet-sb-trunc')
        break
      }
      coverage.push({ protocol: 'telnet-iac', offset: offset + i, length: 3, status: 'covered' })
      while (j + 1 < length) {
        if (buffer[offset + j] === IAC && buffer[offset + j + 1] === SE) {
          if (j > i + 3) {
            mask(collector, intents, packetIndex, offset + i + 3, j - (i + 3), 'telnet-sb-body')
            coverage.push({
              protocol: 'telnet-sb',
              offset: offset + i + 3,
              length: j - (i + 3),
              status: 'redacted',
            })
          }
          coverage.push({ protocol: 'telnet-iac', offset: offset + j, length: 2, status: 'covered' })
          j += 2
          break
        }
        j++
      }
      if (j >= length && !(buffer[offset + length - 2] === IAC && buffer[offset + length - 1] === SE)) {
        // Unterminated SB — mask rest
        mask(collector, intents, packetIndex, offset + i + 3, length - (i + 3), 'telnet-sb-open')
        coverage.push({
          protocol: 'telnet-sb',
          offset: offset + i + 3,
          length: length - (i + 3),
          status: 'redacted',
        })
        issues.push('telnet-sb-open')
        i = length
        break
      }
      i = j
      continue
    }
    // Other IAC commands (GA, EL, EC, …) — 2-byte, preserve
    coverage.push({ protocol: 'telnet-iac', offset: offset + i, length: 2, status: 'covered' })
    i += 2
  }
  flushData(length)
  if (coverage.length === 0) {
    coverage.push({ protocol: 'telnet', offset, length, status: 'covered' })
  }
  return { coverage, issues }
}

function mask(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'telnet')
  collector.addDeferred(offset, length, () => createProtocolNeutralMaskFill({
    length, packetIndex, offset, domain,
  }))
}
