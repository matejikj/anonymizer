/**
 * T49 — extract CSTA service/event facts from bounded XML (monitor lifecycle, invoke correlation).
 */

import {
  localNameOf,
  parseBoundedXml,
  spanText,
  type XmlElement,
  type XmlNode,
} from './boundedXml.ts'
import type { CstaBodySpan } from './xmlPlan.ts'

const SERVICE_ROOT =
  /^(?:monitorstart|monitorstop|monitorstartresponse|deliveredevent|establishedevent|connectionclearedevent|originatedevent|divertedevent|makecall|makecallresponse)$/i

const FIELD_NAMES = new Set([
  'monitorcrossrefid',
  'invokeid',
  'deviceid',
  'deviceidentifier',
  'callid',
  'connectionid',
])

export type CstaServiceKind =
  | 'monitor-start'
  | 'monitor-stop'
  | 'monitor-start-response'
  | 'monitor-event'
  | 'call-service'
  | 'unknown'

export interface CstaServiceFacts {
  readonly kind: CstaServiceKind
  readonly rootLocalName: string
  readonly monitorCrossRefId: string | null
  readonly invokeId: string | null
  readonly deviceId: string | null
  readonly callId: string | null
}

function classifyRoot(local: string): CstaServiceKind {
  const n = local.toLowerCase()
  if (n === 'monitorstart') return 'monitor-start'
  if (n === 'monitorstop') return 'monitor-stop'
  if (n === 'monitorstartresponse') return 'monitor-start-response'
  if (/event$/i.test(n) || n.endsWith('event')) return 'monitor-event'
  if (n === 'makecall' || n === 'makecallresponse') return 'call-service'
  return 'unknown'
}

function firstFieldText(text: string, root: XmlElement, names: readonly string[]): string | null {
  const want = new Set(names.map((n) => n.toLowerCase()))
  const stack: XmlElement[] = [root]
  while (stack.length > 0) {
    const el = stack.shift()!
    if (want.has(el.localName)) {
      for (const child of el.children) {
        if (child.kind === 'text' || child.kind === 'cdata') {
          const inner = child.kind === 'cdata' ? child.content : child.span
          const v = spanText(text, inner).trim()
          if (v.length > 0) return v
        }
      }
    }
    for (const child of el.children) {
      if (child.kind === 'element') stack.push(child)
    }
  }
  return null
}

function findServiceRoot(nodes: readonly XmlNode[]): XmlElement | null {
  const stack: XmlNode[] = [...nodes]
  while (stack.length > 0) {
    const node = stack.shift()!
    if (node.kind !== 'element') continue
    if (SERVICE_ROOT.test(node.localName)) return node
    for (const child of node.children) stack.push(child)
  }
  return null
}

/** Bounded fact extract for monitor start/stop/event lifecycle (no DTD expansion). */
export function extractCstaServiceFacts(
  buffer: Uint8Array,
  bodySpan: CstaBodySpan,
): CstaServiceFacts | null {
  const text = new TextDecoder('latin1').decode(
    buffer.subarray(bodySpan.offset, bodySpan.offset + bodySpan.length),
  )
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) return null
  const parsed = parseBoundedXml(text)
  if (!parsed.complete) return null
  const root = findServiceRoot(parsed.roots)
  if (!root) return null

  const monitorCrossRefId = firstFieldText(text, root, ['monitorCrossRefID', 'monitorcrossrefid'])
  const invokeId = firstFieldText(text, root, ['invokeID', 'invokeid'])
  const deviceId = firstFieldText(text, root, ['deviceID', 'deviceid', 'deviceIdentifier', 'deviceidentifier'])
  const callId = firstFieldText(text, root, ['callID', 'callid'])

  return {
    kind: classifyRoot(root.localName),
    rootLocalName: root.localName,
    monitorCrossRefId,
    invokeId,
    deviceId,
    callId,
  }
}

/** @internal test helper — local name normalization parity */
export function cstaFieldLocalName(raw: string): string {
  return localNameOf(raw)
}

export function isCstaLifecycleFieldLocalName(local: string): boolean {
  return FIELD_NAMES.has(local.toLowerCase())
}
