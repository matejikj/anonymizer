/**
 * Discovery intents from the shared MGCP analyze plan (T11 / T02 parity).
 */

import type { IntentCollector } from '../../../discovery/intentCollector.ts'
import { analyzeMgcpMessages } from './analyze.ts'
import type { MgcpMessage } from './types.ts'
import type { IdentityCategory } from '../../../../mapping/identityCategories.ts'

export function recordMgcpDiscoveryIntents(
  intents: IntentCollector,
  buffer: Uint8Array,
  messages: readonly MgcpMessage[],
  transport: 'tcp' | 'udp',
  packetIndex: number,
): void {
  const plan = analyzeMgcpMessages(buffer, messages)
  for (const op of plan.operations) {
    if (op.action === 'redact') {
      intents.recordFixedRedaction(packetIndex, op.span.offset, op.span.length)
      continue
    }
    if (op.action !== 'map' || op.mappingCategory === null) continue
    // session-version: deferred shift, not a MappingAuthority identity
    if (op.sessionIdForVersion !== undefined) continue

    const originalSpelling = (() => {
      let s = ''
      for (let i = 0; i < op.span.length; i++) {
        s += String.fromCharCode(buffer[op.span.offset + i]!)
      }
      return s
    })()

    const category = op.mappingCategory as IdentityCategory
    let rawCanonical = op.canonicalText
    if (category === 'port') {
      rawCanonical = `${transport}/${op.canonicalText}`
    }

    intents.recordEntityReplacement(
      packetIndex,
      op.span.offset,
      category,
      rawCanonical,
      op.span.length,
      { kind: 'text-ascii', byteLength: op.span.length },
      originalSpelling,
    )
  }
}
