/**
 * Build DissectionNode tree from protocol decode + coverage (step 2).
 */

import { decodeLink } from '../protocols/registry'
import type { DecodedField, DecodedNode } from '../protocols/types'
import type { UnifiedLayerCoverage } from '../coverage/types'
import type { PcapPlanPacket } from '../export/planSnapshot'
import type { DissectionChangeKind, DissectionNode, PacketDissection, ByteSource } from './types'

const LAYER_ORDER: readonly { readonly id: string; readonly label: string; readonly match: (id: string) => boolean }[] = [
  { id: 'frame', label: 'Frame', match: () => true },
  { id: 'link', label: 'Link layer', match: (id) => ['ethernet', 'sll', 'sll2', 'vlan', 'arp'].includes(id) },
  { id: 'network', label: 'Network', match: (id) => ['ipv4', 'ipv6', 'ip-in-ip', 'gre', 'vxlan'].includes(id) },
  { id: 'transport', label: 'Transport', match: (id) => ['tcp', 'udp', 'icmpv4', 'icmpv6'].includes(id) },
  { id: 'application', label: 'Application', match: () => true },
]

export function buildPacketDissection(input: {
  data: Uint8Array
  linkType: number
  packetIndex: number
  capturedLength: number
  unifiedSpans: readonly UnifiedLayerCoverage[]
  planPkt?: PcapPlanPacket
  appProtocols?: readonly string[]
}): PacketDissection {
  const decoded = decodeLink(input.data, input.linkType)
  const flatDecoded: DecodedNode[] = []
  if (decoded) collectDecoded(decoded, flatDecoded)

  const patchRanges = (input.planPkt?.patches ?? []).map((p) => ({
    start: p.offset,
    end: p.offset + p.data.length,
  }))
  const truncatedAt = input.planPkt?.truncatedLength

  const layerBuckets = new Map<string, DissectionNode[]>()
  for (const layer of LAYER_ORDER) layerBuckets.set(layer.id, [])

  for (const node of flatDecoded) {
    const dNode = decodedNodeToDissection(node, input.unifiedSpans, patchRanges, truncatedAt)
    const layer = classifyLayer(node.protocolId)
    layerBuckets.get(layer)!.push(dNode)
  }

  for (const span of input.unifiedSpans) {
    if (['ethernet', 'ipv4', 'tcp', 'udp'].includes(span.protocol)) continue
    layerBuckets.get('application')!.push({
      id: `app-${span.protocol}-${span.offset}`,
      label: span.protocol,
      fieldName: span.protocol,
      offset: span.offset,
      length: span.length,
      coverageStatus: span.status,
      changeKind: changeKindForSpan(span.status, span.offset, span.length, patchRanges, truncatedAt),
      children: [],
    })
  }

  const frameChildren: DissectionNode[] = []
  for (const layer of LAYER_ORDER) {
    if (layer.id === 'frame') continue
    const nodes = layerBuckets.get(layer.id)!
    if (nodes.length === 0) continue
    frameChildren.push({
      id: layer.id,
      label: layer.label,
      offset: nodes[0]!.offset,
      length: nodes.reduce((max, n) => Math.max(max, n.offset + n.length), 0) - nodes[0]!.offset,
      children: nodes,
    })
  }

  const frameNode: DissectionNode = {
    id: 'frame',
    label: 'Frame',
    fieldName: 'frame',
    displayValue: `${input.capturedLength} bytes on wire`,
    offset: 0,
    length: input.data.length,
    children: frameChildren,
  }

  const fieldMap = flattenNodes([frameNode])
  const sources: ByteSource[] = [{
    id: 'frame',
    label: 'Frame',
    bytes: input.data,
    fieldMap,
  }]

  return { roots: [frameNode], sources }
}

function collectDecoded(node: DecodedNode, out: DecodedNode[]): void {
  out.push(node)
  for (const c of node.children) collectDecoded(c, out)
}

function classifyLayer(protocolId: string): string {
  for (const layer of LAYER_ORDER) {
    if (layer.id === 'frame' || layer.id === 'application') continue
    if (layer.match(protocolId)) return layer.id
  }
  return 'application'
}

function decodedNodeToDissection(
  node: DecodedNode,
  spans: readonly UnifiedLayerCoverage[],
  patchRanges: readonly { start: number; end: number }[],
  truncatedAt: number | undefined,
  idPrefix = '',
): DissectionNode {
  const id = idPrefix ? `${idPrefix}-${node.protocolId}` : node.protocolId
  const span = spans.find((s) => s.protocol === node.protocolId && s.offset === node.range.start)
  const fieldChildren = node.fields.map((f, i) => fieldToNode(f, `${id}-f${i}`, spans, patchRanges, truncatedAt))
  const childNodes = node.children.map((c, i) =>
    decodedNodeToDissection(c, spans, patchRanges, truncatedAt, `${id}-c${i}`),
  )
  return {
    id,
    label: node.protocolId,
    fieldName: node.protocolId,
    offset: node.range.start,
    length: node.range.end - node.range.start,
    coverageStatus: span?.status,
    changeKind: changeKindForSpan(span?.status, node.range.start, node.range.end - node.range.start, patchRanges, truncatedAt),
    children: [...fieldChildren, ...childNodes],
  }
}

function fieldToNode(
  field: DecodedField,
  id: string,
  _spans: readonly UnifiedLayerCoverage[],
  patchRanges: readonly { start: number; end: number }[],
  truncatedAt: number | undefined,
): DissectionNode {
  const display = field.display ?? formatFieldValue(field.value)
  const generated = field.name === 'flags' || field.name === 'options'
  return {
    id,
    label: field.name,
    fieldName: field.name,
    value: display,
    displayValue: generated ? `[${display}]` : display,
    offset: field.range.start,
    length: field.range.end - field.range.start,
    generated,
    changeKind: changeKindForSpan(undefined, field.range.start, field.range.end - field.range.start, patchRanges, truncatedAt),
    children: [],
  }
}

function formatFieldValue(value: string | number | bigint | Uint8Array): string {
  if (value instanceof Uint8Array) {
    if (value.length === 4) return `${value[0]}.${value[1]}.${value[2]}.${value[3]}`
    if (value.length === 6) return Array.from(value).map((b) => b.toString(16).padStart(2, '0')).join(':')
    return `(${value.length} bytes)`
  }
  return String(value)
}

function changeKindForSpan(
  status: string | undefined,
  offset: number,
  length: number,
  patchRanges: readonly { start: number; end: number }[],
  truncatedAt: number | undefined,
): DissectionChangeKind {
  if (truncatedAt !== undefined && offset >= truncatedAt) return 'truncated'
  if (status === 'preserved-for-diagnostics') return 'preserved-for-diagnostics'
  if (status === 'redacted') {
    return 'masked'
  }
  if (patchRanges.some((p) => rangesOverlap(p.start, p.end, offset, offset + length))) {
    return status === 'covered' ? 'mapped' : 'rewritten'
  }
  if (status === 'covered') return 'mapped'
  if (status === 'unsupported' || status === 'preserved-unsafe') return 'uncovered'
  return 'none'
}

function rangesOverlap(a0: number, a1: number, b0: number, b1: number): boolean {
  return a0 < b1 && b0 < a1
}

function flattenNodes(nodes: readonly DissectionNode[]): DissectionNode[] {
  const out: DissectionNode[] = []
  const walk = (list: readonly DissectionNode[]) => {
    for (const n of list) {
      if (n.length > 0) out.push(n)
      walk(n.children)
    }
  }
  walk(nodes)
  return out
}
