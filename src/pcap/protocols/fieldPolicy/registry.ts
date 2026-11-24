/**
 * T63.2 — central field-policy registry for APPLICATION_HANDLER_ORDER + structural layers.
 *
 * Detailed tables (structural / http / sip / dns) declare preserve-safe vs canary-required
 * fields. Every other handler gets a fail-closed default until a dedicated table lands.
 */

import { APPLICATION_HANDLER_ORDER } from '../../kernel/applicationHandlers'
import {
  assertFieldPolicyDictionary,
  fieldPolicyAllowsPreserveSafe,
  type FieldPolicyDescriptor,
} from '../../kernel/fieldPolicy'
import { DEFAULT_HANDLER_FIELD_POLICY } from './defaults'
import { DNS_HANDLER_FIELD_POLICY } from './dns'
import { HTTP_HANDLER_FIELD_POLICY } from './http'
import { SIP_HANDLER_FIELD_POLICY } from './sip'
import { STRUCTURAL_FIELD_POLICIES } from './structural'

export interface HandlerFieldPolicyTable {
  readonly handlerId: string
  /** When true, unpatched covered bytes outside preserve fields are residual-sweep candidates. */
  readonly detailed: boolean
  readonly fields: readonly FieldPolicyDescriptor[]
}

const DETAILED_APP: Readonly<Record<string, readonly FieldPolicyDescriptor[]>> = {
  http: HTTP_HANDLER_FIELD_POLICY,
  http2: HTTP_HANDLER_FIELD_POLICY,
  sip: SIP_HANDLER_FIELD_POLICY,
  dns: DNS_HANDLER_FIELD_POLICY,
}

function buildRegistry(): ReadonlyMap<string, HandlerFieldPolicyTable> {
  const map = new Map<string, HandlerFieldPolicyTable>()

  for (const [protocol, fields] of Object.entries(STRUCTURAL_FIELD_POLICIES)) {
    assertFieldPolicyDictionary(fields)
    map.set(protocol, { handlerId: protocol, detailed: true, fields })
  }

  for (const handler of APPLICATION_HANDLER_ORDER) {
    const detailed = DETAILED_APP[handler.id]
    if (detailed) {
      map.set(handler.id, { handlerId: handler.id, detailed: true, fields: detailed })
    } else {
      map.set(handler.id, {
        handlerId: handler.id,
        detailed: false,
        fields: DEFAULT_HANDLER_FIELD_POLICY,
      })
    }
  }

  return map
}

const REGISTRY = buildRegistry()

/** All registered handler / structural protocol ids. */
export function listFieldPolicyHandlerIds(): readonly string[] {
  return [...REGISTRY.keys()]
}

export function getHandlerFieldPolicy(handlerId: string): HandlerFieldPolicyTable | undefined {
  return REGISTRY.get(handlerId)
}

/**
 * True when this protocol has a detailed field table (not just the fail-closed default).
 * Disposition ledger uses this to stop the transitional "all covered = preserve-safe" rule.
 */
export function hasDetailedFieldPolicy(protocol: string): boolean {
  const bare = protocol.includes(':') ? protocol.slice(protocol.indexOf(':') + 1) : protocol
  return REGISTRY.get(bare)?.detailed === true || REGISTRY.get(protocol)?.detailed === true
}

export function listPreserveSafeFields(
  protocol: string,
  level?: 'diagnostic' | 'high-privacy',
): readonly FieldPolicyDescriptor[] {
  const table = getHandlerFieldPolicy(protocol) ?? getHandlerFieldPolicy(
    protocol.includes(':') ? protocol.slice(protocol.indexOf(':') + 1) : protocol,
  )
  if (!table) return []
  return table.fields.filter((f) => fieldPolicyAllowsPreserveSafe(f, level))
}

/**
 * Architecture / F1 helper: every APPLICATION_HANDLER_ORDER id must be registered.
 * Returns missing ids (empty = OK).
 */
export function missingApplicationHandlerFieldPolicies(): readonly string[] {
  const missing: string[] = []
  for (const handler of APPLICATION_HANDLER_ORDER) {
    if (!REGISTRY.has(handler.id)) missing.push(handler.id)
  }
  return missing
}
