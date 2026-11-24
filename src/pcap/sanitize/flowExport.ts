/**
 * T21 — NetFlow v5 and NetFlow v9 / IPFIX flow-export sanitizers.
 * Addresses/ports share MappingAuthority with L3/L4; unknown IE → mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec'
import { createProtocolNeutralMaskFill } from './maskFill'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'
import { deferredBinaryMapMeta, deferredPortMapMeta } from './deferredMapMeta.ts'

const NETFLOW_V5_PORTS = new Set([2055, 9995, 9996])
const IPFIX_PORTS = new Set([4739])
/** Also accept classic NetFlow collector ports for v9. */
const NETFLOW_V9_PORTS = new Set([2055, 9995, 9996, 4739])

const NF5_HDR = 24
const NF5_REC = 48

/** Max templates cached per mapping session (bounded). */
const MAX_TEMPLATES = 256
const MAX_FIELDS_PER_TEMPLATE = 64

export type IePolicy = 'ipv4' | 'ipv6' | 'mac' | 'port' | 'asn' | 'time-ms' | 'time-sec' | 'preserve' | 'mask'

/** IANA IPFIX / NetFlow v9 field types with structured policy. */
const IE_POLICY: Readonly<Record<number, IePolicy>> = {
  1: 'preserve', // octetDeltaCount
  2: 'preserve', // packetDeltaCount
  4: 'preserve', // protocolIdentifier
  5: 'preserve', // ipClassOfService
  6: 'preserve', // tcpControlBits
  7: 'port', // sourceTransportPort
  8: 'ipv4', // sourceIPv4Address
  9: 'preserve', // sourceIPv4PrefixLength
  10: 'preserve', // ingressInterface
  11: 'port', // destinationTransportPort
  12: 'ipv4', // destinationIPv4Address
  13: 'preserve', // destinationIPv4PrefixLength
  14: 'preserve', // egressInterface
  15: 'ipv4', // ipNextHopIPv4Address
  16: 'asn', // bgpSourceAsNumber
  17: 'asn', // bgpDestinationAsNumber
  18: 'ipv4', // bgpNextHopIPv4Address
  21: 'preserve', // lastSwitched (relative)
  22: 'preserve', // firstSwitched
  27: 'ipv6', // sourceIPv6Address
  28: 'ipv6', // destinationIPv6Address
  56: 'mac', // sourceMacAddress
  57: 'mac', // postDestinationMacAddress
  60: 'preserve', // ipVersion
  62: 'ipv6', // ipNextHopIPv6Address
  80: 'mac', // destinationMacAddress
  150: 'time-sec', // flowStartSeconds
  151: 'time-sec', // flowEndSeconds
  152: 'time-ms', // flowStartMilliseconds
  153: 'time-ms', // flowEndMilliseconds
}

export interface TemplateField {
  readonly type: number
  readonly length: number
  readonly enterprise: number
}

export interface TemplateDef {
  readonly id: number
  readonly fields: readonly TemplateField[]
  readonly domainId: number
}

class TemplateCache {
  private readonly byKey = new Map<string, TemplateDef>()

  get(exporterKey: string, domainId: number, templateId: number): TemplateDef | undefined {
    // V17 — scope by exporter/transport session so two exporters cannot share templates.
    return this.byKey.get(`${exporterKey}/${domainId}/${templateId}`)
  }

  set(exporterKey: string, def: TemplateDef): void {
    if (this.byKey.size >= MAX_TEMPLATES) {
      const first = this.byKey.keys().next().value
      if (first !== undefined) this.byKey.delete(first)
    }
    this.byKey.set(`${exporterKey}/${def.domainId}/${def.id}`, def)
  }
}

/** T21 — processing-generation / source scope for template defs (optional on sanitize API). */
export interface FlowExportSanitizeContext {
  readonly generationId?: string
  readonly sourceId?: string
}

export type FlowExporterEndpoints = {
  readonly srcPort?: number
  readonly dstPort?: number
  readonly srcIp?: string
  readonly dstIp?: string
}

function flowSessionScopeKey(session?: FlowExportSanitizeContext): string {
  const generationId = session?.generationId ?? ''
  const sourceId = session?.sourceId ?? ''
  return `${generationId}\0${sourceId}`
}

/** mapping → (generation/source scope → templates). Weak outer key avoids retaining mappings. */
let cachesByMapping = new WeakMap<object, Map<string, TemplateCache>>()

function cacheFor(mapping: MappingLike, session?: FlowExportSanitizeContext): TemplateCache {
  const mappingKey = mapping as object
  let byScope = cachesByMapping.get(mappingKey)
  if (!byScope) {
    byScope = new Map()
    cachesByMapping.set(mappingKey, byScope)
  }
  const scopeKey = flowSessionScopeKey(session)
  let c = byScope.get(scopeKey)
  if (!c) {
    c = new TemplateCache()
    byScope.set(scopeKey, c)
  }
  return c
}

/**
 * Drop all flow-export template caches for one mapping (e.g. remapped session on same object).
 * Call when a processing generation ends if the mapping instance may be reused.
 */
export function resetFlowExportCachesForMapping(mapping: MappingLike): void {
  cachesByMapping.delete(mapping as object)
}

/** Test-only — clear module template caches without retaining mapping references. */
export function resetFlowExportCachesForTests(): void {
  disposeFlowExportCachesForSession()
}

/**
 * Drop all NetFlow/IPFIX template caches for the active processing session.
 * Call from PCAP/session teardown so a reused MappingLike cannot see prior-generation templates.
 */
export function disposeFlowExportCachesForSession(): void {
  cachesByMapping = new WeakMap()
}

/** Transport-session scope for template isolation (src/dst IP+port when available). */
export function flowExporterScopeKey(input: {
  readonly srcIp?: string
  readonly dstIp?: string
  readonly srcPort?: number
  readonly dstPort?: number
  readonly observationDomainId?: number
}): string {
  const src = input.srcIp ?? '?'
  const dst = input.dstIp ?? '?'
  const sp = input.srcPort ?? 0
  const dp = input.dstPort ?? 0
  const dom = input.observationDomainId ?? 0
  return `${src}:${sp}>${dst}:${dp}@${dom}`
}

export function isNetflowV5PortHint(src: number, dst: number): boolean {
  return NETFLOW_V5_PORTS.has(src) || NETFLOW_V5_PORTS.has(dst)
}

export function isIpfixPortHint(src: number, dst: number): boolean {
  return IPFIX_PORTS.has(src) || IPFIX_PORTS.has(dst) || NETFLOW_V9_PORTS.has(src) || NETFLOW_V9_PORTS.has(dst)
}

export function looksLikeNetflowV5(data: Uint8Array, offset: number, length: number): boolean {
  if (length < NF5_HDR) return false
  const ver = (data[offset]! << 8) | data[offset + 1]!
  if (ver !== 5) return false
  const count = (data[offset + 2]! << 8) | data[offset + 3]!
  return count >= 1 && count <= 30
}

export function looksLikeNetflowV9OrIpfix(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const ver = (data[offset]! << 8) | data[offset + 1]!
  return ver === 9 || ver === 10
}

export function sanitizeNetflowV5(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
): AppLayerResult | null {
  if (!looksLikeNetflowV5(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  coverage.push({ protocol: 'netflow-v5', offset, length: NF5_HDR, status: 'covered' })
  // unix_secs @ +8, unix_nsecs @ +12
  shiftUnixSecsNsecs(buffer, offset + 8, offset + 12, collector, intents, packetIndex, payloadTime, issues)

  const count = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
  let pos = offset + NF5_HDR
  for (let i = 0; i < count; i++) {
    if (pos + NF5_REC > offset + length) {
      maskRange(collector, intents, packetIndex, pos, offset + length - pos, 'netflow-v5-trunc')
      issues.push('netflow-v5-trunc')
      break
    }
    mapIpv4(buffer, pos, collector, mapping, intents, packetIndex) // src
    mapIpv4(buffer, pos + 4, collector, mapping, intents, packetIndex) // dst
    mapIpv4(buffer, pos + 8, collector, mapping, intents, packetIndex) // nexthop
    const proto = buffer[pos + 38]!
    const portKind = proto === 6 ? 'tcp' : 'udp'
    mapPort(buffer, pos + 32, portKind, collector, mapping, intents, packetIndex)
    mapPort(buffer, pos + 34, portKind, collector, mapping, intents, packetIndex)
    mapAsn(buffer, pos + 40, 2, collector, mapping, intents, packetIndex)
    mapAsn(buffer, pos + 42, 2, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'netflow-v5-record', offset: pos, length: NF5_REC, status: 'covered' })
    pos += NF5_REC
  }
  return { coverage, issues }
}

export function sanitizeNetflowV9OrIpfix(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
  exporter?: FlowExporterEndpoints,
  session?: FlowExportSanitizeContext,
): AppLayerResult | null {
  if (!looksLikeNetflowV9OrIpfix(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const ver = (buffer[offset]! << 8) | buffer[offset + 1]!
  const cache = cacheFor(mapping, session)
  const protoName = ver === 10 ? 'ipfix' : 'netflow-v9'

  let domainId = 0
  let setPos = 0
  let end = offset + length
  if (ver === 9) {
    if (length < 20) {
      coverage.push({ protocol: protoName, offset, length, status: 'malformed' })
      return { coverage, issues: [`${protoName}-trunc`] }
    }
    // unix_secs @ +8
    shiftUnixSecsOnly(buffer, offset + 8, collector, intents, packetIndex, payloadTime, issues)
    domainId = readU32(buffer, offset + 16)
    setPos = offset + 20
    coverage.push({ protocol: protoName, offset, length: 20, status: 'covered' })
  } else {
    if (length < 16) {
      coverage.push({ protocol: protoName, offset, length, status: 'malformed' })
      return { coverage, issues: [`${protoName}-trunc`] }
    }
    const msgLen = (buffer[offset + 2]! << 8) | buffer[offset + 3]!
    end = offset + Math.min(length, msgLen > 0 ? msgLen : length)
    shiftUnixSecsOnly(buffer, offset + 4, collector, intents, packetIndex, payloadTime, issues) // export_time
    domainId = readU32(buffer, offset + 12)
    setPos = offset + 16
    coverage.push({ protocol: protoName, offset, length: 16, status: 'covered' })
  }

  const scopeKey = flowExporterScopeKey({
    srcIp: exporter?.srcIp,
    dstIp: exporter?.dstIp,
    srcPort: exporter?.srcPort,
    dstPort: exporter?.dstPort,
    observationDomainId: domainId,
  })

  return walkSets(buffer, setPos, end, ver, domainId, scopeKey, cache, collector, mapping, intents, packetIndex, payloadTime, coverage, issues, protoName)
}

function walkSets(
  buffer: Uint8Array,
  setPos: number,
  end: number,
  ver: number,
  domainId: number,
  scopeKey: string,
  cache: TemplateCache,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  coverage: LayerCoverage[],
  issues: string[],
  protoName: string,
): AppLayerResult {
  while (setPos + 4 <= end) {
    const setId = (buffer[setPos]! << 8) | buffer[setPos + 1]!
    const setLen = (buffer[setPos + 2]! << 8) | buffer[setPos + 3]!
    if (setLen < 4 || setPos + setLen > end) {
      maskRange(collector, intents, packetIndex, setPos, end - setPos, `${protoName}-set-trunc`)
      issues.push(`${protoName}-set-trunc`)
      break
    }
    const bodyOff = setPos + 4
    const bodyEnd = setPos + setLen
    const isTemplate = ver === 9 ? setId === 0 : setId === 2
    const isOptions = ver === 9 ? setId === 1 : setId === 3
    if (isTemplate || isOptions) {
      parseTemplates(buffer, bodyOff, bodyEnd, domainId, scopeKey, isOptions, cache, coverage, issues, protoName)
    } else if (setId >= 256) {
      sanitizeDataSet(
        buffer,
        bodyOff,
        bodyEnd,
        setId,
        domainId,
        scopeKey,
        cache,
        collector,
        mapping,
        intents,
        packetIndex,
        payloadTime,
        coverage,
        issues,
        protoName,
      )
    } else {
      maskRange(collector, intents, packetIndex, bodyOff, bodyEnd - bodyOff, `${protoName}-unknown-set`)
      coverage.push({ protocol: `${protoName}-set`, offset: setPos, length: setLen, status: 'redacted' })
    }
    setPos += setLen
  }
  return { coverage, issues }
}

function parseTemplates(
  buffer: Uint8Array,
  off: number,
  end: number,
  domainId: number,
  scopeKey: string,
  options: boolean,
  cache: TemplateCache,
  coverage: LayerCoverage[],
  issues: string[],
  protoName: string,
): void {
  let pos = off
  while (pos + 4 <= end) {
    const tid = (buffer[pos]! << 8) | buffer[pos + 1]!
    const fieldCount = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    pos += 4
    // IPFIX options template (set 3): Scope Field Count follows Field Count.
    if (options && pos + 2 <= end) {
      pos += 2
    }
    if (fieldCount > MAX_FIELDS_PER_TEMPLATE) {
      issues.push(`${protoName}-template-too-large`)
      break
    }
    const fields: TemplateField[] = []
    const tmplStart = pos
    for (let i = 0; i < fieldCount; i++) {
      if (pos + 4 > end) {
        issues.push(`${protoName}-template-trunc`)
        return
      }
      let type = (buffer[pos]! << 8) | buffer[pos + 1]!
      const flen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
      pos += 4
      let enterprise = 0
      if ((type & 0x8000) !== 0) {
        if (pos + 4 > end) {
          issues.push(`${protoName}-enterprise-trunc`)
          return
        }
        enterprise = readU32(buffer, pos)
        pos += 4
        type = type & 0x7fff
      }
      fields.push({ type, length: flen, enterprise })
    }
    if (tid >= 256) {
      cache.set(scopeKey, { id: tid, fields, domainId })
      coverage.push({
        protocol: `${protoName}-template`,
        offset: tmplStart - (options ? 6 : 4),
        length: pos - (tmplStart - (options ? 6 : 4)),
        status: 'covered',
      })
    }
  }
}

function sanitizeDataSet(
  buffer: Uint8Array,
  off: number,
  end: number,
  templateId: number,
  domainId: number,
  scopeKey: string,
  cache: TemplateCache,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  coverage: LayerCoverage[],
  issues: string[],
  protoName: string,
): void {
  const tmpl = cache.get(scopeKey, domainId, templateId)
  if (!tmpl) {
    maskRange(collector, intents, packetIndex, off, end - off, `${protoName}-missing-template`)
    coverage.push({
      protocol: `${protoName}-data`,
      offset: off,
      length: end - off,
      status: 'requires-reassembly',
    })
    issues.push(`${protoName}-missing-template`)
    return
  }
  let pos = off
  let records = 0
  while (pos < end) {
    const start = pos
    let ok = true
    for (const f of tmpl.fields) {
      let flen = f.length
      if (flen === 0xffff) {
        // IPFIX variable-length
        if (pos >= end) {
          ok = false
          break
        }
        const first = buffer[pos]!
        if (first < 255) {
          flen = first
          pos += 1
        } else {
          if (pos + 3 > end) {
            ok = false
            break
          }
          flen = (buffer[pos + 1]! << 8) | buffer[pos + 2]!
          pos += 3
        }
      }
      if (pos + flen > end) {
        ok = false
        break
      }
      applyIePolicy(buffer, pos, flen, f, collector, mapping, intents, packetIndex, payloadTime, issues)
      pos += flen
    }
    if (!ok || pos === start) {
      if (pos < end) {
        maskRange(collector, intents, packetIndex, pos, end - pos, `${protoName}-record-tail`)
        issues.push(`${protoName}-record-tail`)
      }
      break
    }
    // padding to 4 at end of set is normal — stop if remaining < min field
    records++
    if (records > 10_000) {
      issues.push(`${protoName}-record-budget`)
      maskRange(collector, intents, packetIndex, pos, end - pos, `${protoName}-budget`)
      break
    }
    // skip padding zeros at end
    if (pos < end && end - pos < 4) break
  }
  coverage.push({ protocol: `${protoName}-data`, offset: off, length: end - off, status: 'covered' })
}

function applyIePolicy(
  buffer: Uint8Array,
  abs: number,
  length: number,
  field: TemplateField,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): void {
  if (field.enterprise !== 0) {
    maskRange(collector, intents, packetIndex, abs, length, 'ipfix-enterprise-ie')
    return
  }
  const policy = IE_POLICY[field.type] ?? 'mask'
  switch (policy) {
    case 'preserve':
      return
    case 'ipv4':
      if (length >= 4) mapIpv4(buffer, abs, collector, mapping, intents, packetIndex)
      else maskRange(collector, intents, packetIndex, abs, length, 'ipfix-ipv4-short')
      return
    case 'ipv6':
      if (length >= 16) mapIpv6(buffer, abs, collector, mapping, intents, packetIndex)
      else maskRange(collector, intents, packetIndex, abs, length, 'ipfix-ipv6-short')
      return
    case 'mac':
      if (length >= 6) mapMac(buffer, abs, collector, mapping, intents, packetIndex)
      else maskRange(collector, intents, packetIndex, abs, length, 'ipfix-mac-short')
      return
    case 'port':
      if (length >= 2) mapPort(buffer, abs, 'udp', collector, mapping, intents, packetIndex)
      else maskRange(collector, intents, packetIndex, abs, length, 'ipfix-port-short')
      return
    case 'asn':
      mapAsn(buffer, abs, length >= 4 ? 4 : length >= 2 ? 2 : length, collector, mapping, intents, packetIndex)
      return
    case 'time-sec':
      if (length >= 4) shiftUnixSecsOnly(buffer, abs, collector, intents, packetIndex, payloadTime, issues)
      else maskRange(collector, intents, packetIndex, abs, length, 'ipfix-time-short')
      return
    case 'time-ms':
      if (length >= 8) shiftUnixMs(buffer, abs, collector, intents, packetIndex, payloadTime, issues)
      else maskRange(collector, intents, packetIndex, abs, length, 'ipfix-time-ms-short')
      return
    case 'mask':
    default:
      maskRange(collector, intents, packetIndex, abs, length, `ipfix-ie-${field.type}`)
  }
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
  }, deferredBinaryMapMeta('netflow', packetIndex, 'ipv4', text))
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
      ?? createProtocolNeutralMaskFill({ length: 16, packetIndex, offset: abs, domain: 'ipfix-ipv6' })
  }, deferredBinaryMapMeta('ipfix', packetIndex, 'ipv6', text))
  void mapping
}

function mapMac(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 6; i++) parts.push(buffer[abs + i]!.toString(16).padStart(2, '0'))
  const text = parts.join(':')
  intents?.recordEntityReplacement(packetIndex, abs, 'mac', text, 6)
  collector.addDeferred(abs, 6, ({ mapping: live }) => {
    const mapped = live.map('mac', text)
    const out = new Uint8Array(6)
    const hex = mapped.split(':')
    if (hex.length !== 6) {
      return createProtocolNeutralMaskFill({ length: 6, packetIndex, offset: abs, domain: 'ipfix-mac' })
    }
    for (let i = 0; i < 6; i++) out[i] = Number.parseInt(hex[i]!, 16) & 0xff
    return out
  }, deferredBinaryMapMeta('ipfix', packetIndex, 'mac', text))
  void mapping
}

function mapPort(
  buffer: Uint8Array,
  abs: number,
  kind: 'tcp' | 'udp',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const port = (buffer[abs]! << 8) | buffer[abs + 1]!
  const canonical = `${kind}/${port}`
  intents?.recordEntityReplacement(packetIndex, abs, 'port', canonical, 2)
  collector.addDeferred(abs, 2, ({ mapping: live }) => {
    const mapped = live.map('port', canonical)
    const n = Number.parseInt(String(mapped).replace(/^(tcp|udp)\//, ''), 10)
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
      return createProtocolNeutralMaskFill({ length: 2, packetIndex, offset: abs, domain: 'netflow-port' })
    }
    return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
  }, deferredPortMapMeta('netflow', packetIndex, kind, port))
  void mapping
}

function mapAsn(
  buffer: Uint8Array,
  abs: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (length < 2) {
    maskRange(collector, intents, packetIndex, abs, length, 'netflow-asn-short')
    return
  }
  const value = length >= 4 ? readU32(buffer, abs) : (buffer[abs]! << 8) | buffer[abs + 1]!
  if (value === 0) return
  const canon = `asn/${value}`
  const wireLen = length >= 4 ? 4 : 2
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, wireLen)
  collector.addDeferred(abs, wireLen, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: wireLen,
      packetIndex,
      offset: abs,
      domain: `asn:${alias}`,
    })
  }, { fallbackKind: 'binary-mask', protocol: 'netflow', category: 'opaque-id', packetIndex })
  void mapping
}

function shiftUnixSecsNsecs(
  buffer: Uint8Array,
  secsOff: number,
  nsecsOff: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): void {
  const secs = readU32(buffer, secsOff)
  const nsecs = readU32(buffer, nsecsOff)
  if (!payloadTime?.isBound || secs === 0) return
  const epochMs = secs * 1000 + Math.floor(nsecs / 1_000_000)
  const shifted = payloadTime.shiftAbsoluteEpochMs(epochMs)
  if (shifted === null) {
    issues.push('netflow-time-unbound')
    return
  }
  const newSecs = Math.floor(shifted / 1000) >>> 0
  const newNsecs = ((shifted % 1000) * 1_000_000) >>> 0
  intents?.recordMaskRange(packetIndex, secsOff, 8, 'netflow-unix-time', 'timestamp')
  collector.addDeferred(secsOff, 4, () => u32be(newSecs), {
    fallbackKind: 'binary-mask',
    protocol: 'netflow',
    category: 'timestamp',
    packetIndex,
  })
  collector.addDeferred(nsecsOff, 4, () => u32be(newNsecs), {
    fallbackKind: 'binary-mask',
    protocol: 'netflow',
    category: 'timestamp',
    packetIndex,
  })
  void buffer
}

function shiftUnixSecsOnly(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): void {
  const secs = readU32(buffer, abs)
  if (!payloadTime?.isBound || secs === 0) return
  const shifted = payloadTime.shiftAbsoluteEpochMs(secs * 1000)
  if (shifted === null) {
    issues.push('netflow-time-unbound')
    return
  }
  const newSecs = Math.floor(shifted / 1000) >>> 0
  intents?.recordMaskRange(packetIndex, abs, 4, 'netflow-unix-secs', 'timestamp')
  collector.addDeferred(abs, 4, () => u32be(newSecs), {
    fallbackKind: 'binary-mask',
    protocol: 'netflow',
    category: 'timestamp',
    packetIndex,
  })
  void buffer
}

function shiftUnixMs(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
): void {
  const hi = readU32(buffer, abs)
  const lo = readU32(buffer, abs + 4)
  const ms = hi * 0x1_0000_0000 + lo
  if (!payloadTime?.isBound || ms === 0) return
  const shifted = payloadTime.shiftAbsoluteEpochMs(ms)
  if (shifted === null) {
    issues.push('ipfix-time-ms-unbound')
    return
  }
  const newHi = Math.floor(shifted / 0x1_0000_0000) >>> 0
  const newLo = (shifted % 0x1_0000_0000) >>> 0
  intents?.recordMaskRange(packetIndex, abs, 8, 'ipfix-time-ms', 'timestamp')
  collector.addDeferred(abs, 4, () => u32be(newHi), {
    fallbackKind: 'binary-mask',
    protocol: 'ipfix',
    category: 'timestamp',
    packetIndex,
  })
  collector.addDeferred(abs + 4, 4, () => u32be(newLo), {
    fallbackKind: 'binary-mask',
    protocol: 'ipfix',
    category: 'timestamp',
    packetIndex,
  })
  void buffer
}

function maskRange(
  collector: PatchCollector | undefined,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  length: number,
  domain: string,
): void {
  if (!collector || length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset: abs, domain })
  collector.maskRange(abs, fill)
  intents?.recordMaskRange(packetIndex, abs, length, domain, 'flow-export')
}

function readU32(buf: Uint8Array, off: number): number {
  return (
    ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0
  )
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
}

/** Test helper — seed a template into the mapping-scoped cache. */
export function __testSeedIpfixTemplate(
  mapping: MappingLike,
  domainId: number,
  templateId: number,
  fields: readonly TemplateField[],
  exporter?: FlowExporterEndpoints,
  session?: FlowExportSanitizeContext,
): void {
  const scopeKey = flowExporterScopeKey({
    srcIp: exporter?.srcIp,
    dstIp: exporter?.dstIp,
    srcPort: exporter?.srcPort,
    dstPort: exporter?.dstPort,
    observationDomainId: domainId,
  })
  cacheFor(mapping, session).set(scopeKey, { id: templateId, domainId, fields })
}
