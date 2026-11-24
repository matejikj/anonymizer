/**
 * T21 — sFlow v5 datagram sanitizer: agent address map, raw header recurse, extended samples.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'
import {
  sanitizeLinkedEthernet,
  type InnerTransportHandler,
  MAX_TUNNEL_DEPTH,
} from './tunnel'

const SFLOW_PORTS = new Set([6343])
const HEADER_PROTO_ETHERNET = 1

export function isSflowPortHint(src: number, dst: number): boolean {
  return SFLOW_PORTS.has(src) || SFLOW_PORTS.has(dst)
}

export function looksLikeSflow(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 28) return false
  const ver = readU32(data, offset)
  if (ver !== 5) return false
  const addrType = readU32(data, offset + 4)
  return addrType === 1 || addrType === 2
}

export function sanitizeSflow(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number = 0,
  onInnerTransport?: InnerTransportHandler,
): AppLayerResult | null {
  if (!looksLikeSflow(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (depth >= MAX_TUNNEL_DEPTH) {
    coverage.push({ protocol: 'sflow', offset, length, status: 'unsupported' })
    return { coverage, issues: ['sflow-depth'] }
  }

  const end = offset + length
  let pos = offset
  pos += 4 // version
  const addrType = readU32(buffer, pos)
  pos += 4
  if (addrType === 1) {
    if (pos + 4 > end) {
      coverage.push({ protocol: 'sflow', offset, length, status: 'malformed' })
      return { coverage, issues: ['sflow-trunc'] }
    }
    mapIpv4(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  } else if (addrType === 2) {
    if (pos + 16 > end) {
      coverage.push({ protocol: 'sflow', offset, length, status: 'malformed' })
      return { coverage, issues: ['sflow-trunc'] }
    }
    mapIpv6(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 16
  } else {
    maskRange(collector, intents, packetIndex, pos, end - pos, 'sflow-addr-unknown')
    coverage.push({ protocol: 'sflow', offset, length, status: 'malformed' })
    return { coverage, issues: ['sflow-addr-type'] }
  }

  if (pos + 16 > end) {
    coverage.push({ protocol: 'sflow', offset, length, status: 'malformed' })
    return { coverage, issues: ['sflow-trunc'] }
  }
  // sub_agent, sequence, uptime, num_samples — preserve
  const numSamples = readU32(buffer, pos + 12)
  pos += 16
  coverage.push({ protocol: 'sflow', offset, length: pos - offset, status: 'covered' })

  for (let s = 0; s < numSamples && pos + 8 <= end; s++) {
    const tag = readU32(buffer, pos)
    const sampleLen = readU32(buffer, pos + 4)
    pos += 8
    const enterprise = tag >>> 12
    const format = tag & 0xfff
    if (sampleLen > end - pos) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'sflow-sample-trunc')
      issues.push('sflow-sample-trunc')
      break
    }
    const sampleEnd = pos + sampleLen
    if (enterprise === 0 && (format === 1 || format === 3)) {
      // flow_sample (1) or flow_sample_expanded (3)
      sanitizeFlowSample(
        buffer,
        pos,
        sampleEnd,
        format === 3,
        collector,
        mapping,
        intents,
        packetIndex,
        depth,
        onInnerTransport,
        coverage,
        issues,
      )
    } else if (enterprise === 0 && (format === 2 || format === 4)) {
      // counter_sample — preserve known schema body
      coverage.push({ protocol: 'sflow-counter', offset: pos - 8, length: sampleLen + 8, status: 'covered' })
    } else {
      maskRange(collector, intents, packetIndex, pos, sampleLen, 'sflow-sample-unknown')
      coverage.push({
        protocol: 'sflow-sample',
        offset: pos - 8,
        length: sampleLen + 8,
        status: 'redacted',
      })
    }
    pos = sampleEnd
    // samples are 4-byte aligned in length field already
  }

  return { coverage, issues }
}

function sanitizeFlowSample(
  buffer: Uint8Array,
  off: number,
  end: number,
  expanded: boolean,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number,
  onInnerTransport: InnerTransportHandler | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  let pos = off
  // sequence, source_id[, source_index], sampling_rate, sample_pool, drops, input[, input], output[, output]
  const hdrSkip = expanded ? 4 + 8 + 4 + 4 + 4 + 8 + 8 : 4 + 4 + 4 + 4 + 4 + 4 + 4
  if (pos + hdrSkip + 4 > end) {
    maskRange(collector, intents, packetIndex, off, end - off, 'sflow-flow-trunc')
    issues.push('sflow-flow-trunc')
    return
  }
  pos += hdrSkip
  const recordCount = readU32(buffer, pos)
  pos += 4
  coverage.push({ protocol: 'sflow-flow', offset: off, length: pos - off, status: 'covered' })

  for (let r = 0; r < recordCount && pos + 8 <= end; r++) {
    const rtag = readU32(buffer, pos)
    const rlen = readU32(buffer, pos + 4)
    pos += 8
    const rent = rtag >>> 12
    const rfmt = rtag & 0xfff
    if (rlen > end - pos) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'sflow-record-trunc')
      issues.push('sflow-record-trunc')
      return
    }
    const rend = pos + rlen
    if (rent === 0 && rfmt === 1) {
      sanitizeSampledHeader(
        buffer,
        pos,
        rend,
        collector,
        mapping,
        intents,
        packetIndex,
        depth,
        onInnerTransport,
        coverage,
        issues,
      )
    } else if (rent === 0 && (rfmt === 2 || rfmt === 3 || rfmt === 4)) {
      // extended_switch / router / gateway — map IPs in known layouts
      sanitizeExtended(buffer, pos, rend, rfmt, collector, mapping, intents, packetIndex, coverage)
    } else {
      maskRange(collector, intents, packetIndex, pos, rlen, `sflow-ext-${rfmt}`)
      coverage.push({ protocol: 'sflow-record', offset: pos - 8, length: rlen + 8, status: 'redacted' })
    }
    pos = rend
  }
}

function sanitizeSampledHeader(
  buffer: Uint8Array,
  off: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number,
  onInnerTransport: InnerTransportHandler | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (off + 16 > end) {
    maskRange(collector, intents, packetIndex, off, end - off, 'sflow-header-trunc')
    issues.push('sflow-header-trunc')
    return
  }
  const headerProtocol = readU32(buffer, off)
  // frame_length, stripped preserved
  const headerLength = readU32(buffer, off + 12)
  const hdrOff = off + 16
  const avail = end - hdrOff
  const take = Math.min(headerLength, avail)
  coverage.push({ protocol: 'sflow-header', offset: off, length: 16, status: 'covered' })

  if (headerProtocol === HEADER_PROTO_ETHERNET && take >= 14) {
    const eth = sanitizeLinkedEthernet(
      buffer,
      hdrOff,
      take,
      collector,
      mapping,
      depth + 1,
      onInnerTransport,
      { packetIndex, intents },
      'sflow-ethernet',
      'sflow-payload',
    )
    coverage.push(...eth.coverage)
    if (eth.depthExceeded) issues.push('sflow-depth')
  } else if (take > 0) {
    // truncated / non-ethernet — expected for short samples, not malformed
    maskRange(collector, intents, packetIndex, hdrOff, take, 'sflow-header-opaque')
    coverage.push({
      protocol: 'sflow-header-body',
      offset: hdrOff,
      length: take,
      status: 'redacted',
    })
  }
}

function sanitizeExtended(
  buffer: Uint8Array,
  off: number,
  end: number,
  format: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // extended_router (format 3): nexthop address type + addr
  if (format === 3 && off + 8 <= end) {
    const t = readU32(buffer, off)
    if (t === 1 && off + 8 <= end) {
      mapIpv4(buffer, off + 4, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'sflow-ext-router', offset: off, length: end - off, status: 'covered' })
      return
    }
    if (t === 2 && off + 20 <= end) {
      mapIpv6(buffer, off + 4, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'sflow-ext-router', offset: off, length: end - off, status: 'covered' })
      return
    }
  }
  // extended_gateway / user / url — mask free-form identity
  if (format === 2) {
    coverage.push({ protocol: 'sflow-ext-switch', offset: off, length: end - off, status: 'covered' })
    return
  }
  maskRange(collector, intents, packetIndex, off, end - off, `sflow-ext-${format}`)
  coverage.push({ protocol: 'sflow-ext', offset: off, length: end - off, status: 'redacted' })
}

function mapIpv4(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = `${buffer[abs]!}.${buffer[abs + 1]!}.${buffer[abs + 2]!}.${buffer[abs + 3]!}`
  if (text === '0.0.0.0' || text === '255.255.255.255') return
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', text, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', text)
    return new Uint8Array(mapped.split('.').map(Number))
  }, { fallbackKind: 'binary-mask', protocol: 'sflow', category: 'ipv4', packetIndex })
  void mapping
}

function mapIpv6(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = ipv6Bytes16ToText(buffer.subarray(abs, abs + 16))
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv6', text, 16)
  collector.addDeferred(abs, 16, ({ mapping: live }) => {
    const mapped = live.map('ipv6', text)
    return ipv6TextToBytes16(mapped)
      ?? createProtocolNeutralMaskFill({ length: 16, packetIndex, offset: abs, domain: 'sflow-ipv6' })
  }, { fallbackKind: 'binary-mask', protocol: 'sflow', category: 'ipv6', packetIndex })
  void mapping
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  collector.maskRange(abs, createProtocolNeutralMaskFill({ length, packetIndex, offset: abs, domain }))
  intents?.recordMaskRange(packetIndex, abs, length, domain, 'sflow')
}

function readU32(buf: Uint8Array, off: number): number {
  return (
    ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0
  )
}
