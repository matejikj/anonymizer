/**
 * T02.S4 — analytical protocol facts for SIPREC rs-metadata+xml (kernel journal).
 * Projects the same {@link planSipBodyOperations} walker used by discovery and plan.
 */

import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { IdentityCategory } from '../../mapping/identityCategories'
import { decodeLatin1Span } from '../protocols/application/sip/bytes'
import { planSipBodyOperations } from '../protocols/application/sip/bodyOperations'
import type { ByteSpan, SipMessage } from '../protocols/application/sip/types'
import type { LayerCoverage } from '../sanitize/types'
import { createFactWriter } from './factWriter'
import type { SemanticJournalBuilder } from './journal'
import type { SymbolicOperation } from './operations'

export const SIPREC_METADATA_PROTOCOL_ID = 'sip-siprec-metadata' as const

function spanWithin(span: ByteSpan, region: LayerCoverage): boolean {
  const end = span.offset + span.length
  const regionEnd = region.offset + region.length
  return span.offset >= region.offset && end <= regionEnd
}

/**
 * Emit journal facts (and optional symbolic ops) for SIPREC metadata body parts.
 * No-op when the message has no `sip-siprec-metadata` coverage region.
 */
export function emitSiprecMetadataKernelFacts(input: {
  readonly message: SipMessage
  readonly buffer: Uint8Array
  readonly packetIndex: number
  readonly logicalMessageId: number
  readonly journal: SemanticJournalBuilder
  readonly symbolicOps?: SymbolicOperation[]
}): readonly number[] {
  const bodyPlan = planSipBodyOperations(input.message, input.buffer)
  const siprecRegions = bodyPlan.coverage.filter(
    (c) => c.protocol === SIPREC_METADATA_PROTOCOL_ID,
  )
  if (siprecRegions.length === 0) return []

  const ops = input.symbolicOps ?? []
  const out = createFactWriter(input.journal, ops)
  const factIds: number[] = []

  for (const region of siprecRegions) {
    const parentId = out.coverage({
      protocolId: SIPREC_METADATA_PROTOCOL_ID,
      packetIndex: input.packetIndex,
      logicalMessageId: input.logicalMessageId,
      parentFactId: 0,
      spanOffset: region.offset,
      spanLength: region.length,
      status: region.status,
      recognition: region.status === 'malformed' ? 'malformed' : 'recognized',
      reasonCode: region.status === 'redacted' ? 'siprec-body-fallback' : undefined,
    })
    factIds.push(parentId)

    for (const op of bodyPlan.operations) {
      if (!spanWithin(op.span, region)) continue

      if (op.action === 'redact') {
        out.operation({
          kind: 'mask',
          packetIndex: input.packetIndex,
          offset: op.span.offset,
          length: op.span.length,
          fillKind: 'protocol-neutral',
          domain: SIPREC_METADATA_PROTOCOL_ID,
          reasonCode: 'siprec-redact',
        })
        out.structuralField({
          protocolId: SIPREC_METADATA_PROTOCOL_ID,
          packetIndex: input.packetIndex,
          logicalMessageId: input.logicalMessageId,
          parentFactId: parentId,
          spanOffset: op.span.offset,
          spanLength: op.span.length,
          fieldId: 'redacted-leaf',
          recognition: 'recognized',
        })
        continue
      }

      if (op.mappingCategory === null || op.sessionIdForVersion !== undefined) continue

      const category = op.mappingCategory as IdentityCategory
      const originalSpelling = decodeLatin1Span(input.buffer, op.span)
      const canonical = canonicalizeIdentity(category, op.canonicalText) ?? op.canonicalText
      const constraint = { kind: 'text-ascii' as const, byteLength: op.span.length }
      const mapOp = {
        kind: 'map' as const,
        packetIndex: input.packetIndex,
        offset: op.span.offset,
        length: op.span.length,
        category,
        canonical,
        constraint,
        encoder: 'fixed-ascii' as const,
        originalSpelling,
      }
      out.identity({
        protocolId: SIPREC_METADATA_PROTOCOL_ID,
        packetIndex: input.packetIndex,
        logicalMessageId: input.logicalMessageId,
        parentFactId: parentId,
        spanOffset: op.span.offset,
        spanLength: op.span.length,
        identity: { category, canonical, constraint, originalSpelling },
        mapOp,
      })
    }
  }

  return factIds
}
