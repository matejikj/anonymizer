/**
 * Step 9 / T03 — format plan/mapping errors for UI without leaking original values.
 * Category comes from structured error fields, never parsed from message text.
 */

import { cs } from '../../i18n/cs.ts'
import { MappingLookupError } from '../anonymization/mappingErrors.ts'
import {
  PlanInvariantError,
  planInvariantSafeReasonCode,
} from '../plan/planErrors'
import { toSafeWorkerError } from '../../domain/safeWorkerError.ts'

export function formatPlanInvariantForUser(error: PlanInvariantError): string {
  const packet =
    error.packetNumber !== undefined
      ? String(error.packetNumber)
      : error.packetIndex !== undefined
        ? String(error.packetIndex + 1)
        : undefined

  const code = planInvariantSafeReasonCode(error)
  let reason: string
  switch (code) {
    case 'closure':
      reason = cs.pcap.export.mappingReasonClosure.replace(
        '{category}',
        error.category ?? 'identity',
      )
      break
    case 'lookup':
      reason = cs.pcap.export.mappingReasonLookup
      break
    case 'patch':
      reason = cs.pcap.export.mappingReasonPatch
      break
    case 'boundary':
      reason = cs.pcap.export.mappingReasonBoundary
      break
    default:
      reason = cs.pcap.export.mappingReasonGeneric
  }

  const base = packet !== undefined
    ? cs.pcap.export.mappingBlocked
      .replace('{packet}', packet)
      .replace('{reason}', reason)
    : cs.pcap.export.mappingBlockedNoPacket.replace('{reason}', reason)
  // Stable code for ticket copy — never includes identity values.
  return `${base} [${error.code}${error.category ? `/${error.category}` : ''}]`
}

export function formatUnknownPlanErrorForUser(error: unknown): string {
  if (error instanceof PlanInvariantError) return formatPlanInvariantForUser(error)
  if (error instanceof MappingLookupError) {
    return cs.pcap.export.mappingBlockedNoPacket.replace(
      '{reason}',
      cs.pcap.export.mappingReasonClosure.replace('{category}', error.category ?? 'identity'),
    ) + ` [${error.code}]`
  }
  // Worker/unknown errors — never scrub and display raw Error.message.
  return toSafeWorkerError(error, 'unknown').safeMessage
}
