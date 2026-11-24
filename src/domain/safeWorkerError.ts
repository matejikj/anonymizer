/**
 * T03 — sanitize worker-boundary errors so UI never receives original values.
 *
 * Uses structural checks (error.name / code) so `domain/` stays free of pcap imports.
 * Known structured errors map to a stable code + Czech user message.
 * Unknown errors never forward `err.message` over postMessage.
 */

import { cs } from '../i18n/cs.ts'

export type SafeWorkerErrorStage =
  | 'detection'
  | 'export'
  | 'mapping'
  | 'pcap-processing'
  | 'pcap-export'
  | 'pcap-restore'
  | 'unknown'

export interface SafeWorkerError {
  readonly code: string
  readonly stage: SafeWorkerErrorStage
  /** Czech user-facing text — never contains original identity values. */
  readonly safeMessage: string
}

function asRecord(err: unknown): Record<string, unknown> | null {
  if (err && typeof err === 'object') return err as Record<string, unknown>
  return null
}

function logDevOnly(err: unknown, stage: SafeWorkerErrorStage): void {
  try {
    if (import.meta.env?.DEV) {
      console.error(`[${stage}]`, err instanceof Error ? err.name : typeof err)
    }
  } catch {
    // ignore logging failures
  }
}

/**
 * Convert any thrown value into a wire-safe error payload.
 * Never includes `Error.message` from unknown errors.
 */
export function toSafeWorkerError(
  err: unknown,
  stage: SafeWorkerErrorStage,
  fallbackCode = 'internal',
): SafeWorkerError {
  logDevOnly(err, stage)
  const rec = asRecord(err)
  const name = err instanceof Error ? err.name : ''
  const code = typeof rec?.code === 'string' ? rec.code : undefined
  const category = typeof rec?.category === 'string' ? rec.category : undefined
  const packetNumber = typeof rec?.packetNumber === 'number' ? rec.packetNumber : undefined
  const packetIndex = typeof rec?.packetIndex === 'number' ? rec.packetIndex : undefined

  if (name === 'MappingLookupError') {
    const reasonCode = code ?? 'missing-snapshot-alias'
    const cat = category ?? 'identity'
    return {
      code: reasonCode,
      stage,
      safeMessage:
        cs.pcap.export.mappingBlockedNoPacket.replace(
          '{reason}',
          cs.pcap.export.mappingReasonClosure.replace('{category}', cat),
        ) + ` (${reasonCode})`,
    }
  }

  if (name === 'MappingPatchError') {
    const reasonCode = code ?? 'patch-overlap'
    return {
      code: reasonCode,
      stage,
      safeMessage:
        `${cs.pcap.export.mappingBlockedNoPacket.replace(
          '{reason}',
          cs.pcap.export.mappingReasonPatch,
        )} (${reasonCode})`,
    }
  }

  if (name === 'PlanInvariantError') {
    const reasonCode = code ?? 'mapping-closure'
    const packet =
      packetNumber !== undefined
        ? String(packetNumber)
        : packetIndex !== undefined
          ? String(packetIndex + 1)
          : undefined
    let reason: string
    if (reasonCode === 'mapping-closure') {
      reason = cs.pcap.export.mappingReasonClosure.replace('{category}', category ?? 'identity')
    } else if (
      reasonCode === 'mapping-lookup'
      || reasonCode === 'representation-unavailable'
    ) {
      reason = cs.pcap.export.mappingReasonLookup
    } else if (reasonCode === 'patch-overlap') {
      reason = cs.pcap.export.mappingReasonPatch
    } else if (reasonCode === 'unsafe-export-boundary') {
      reason = cs.pcap.export.mappingReasonBoundary
    } else {
      reason = cs.pcap.export.mappingReasonGeneric
    }
    const base = packet !== undefined
      ? cs.pcap.export.mappingBlocked
        .replace('{packet}', packet)
        .replace('{reason}', reason)
      : cs.pcap.export.mappingBlockedNoPacket.replace('{reason}', reason)
    return {
      code: reasonCode,
      stage,
      safeMessage: `${base} (${reasonCode})`,
    }
  }

  if (name === 'PacketParseError') {
    const pkt = packetIndex !== undefined ? String(packetIndex + 1) : '?'
    return {
      code: 'packet-parse',
      stage,
      safeMessage: cs.errors.worker.packetParse
        .replace('{packet}', pkt)
        .replace('{code}', 'packet-parse'),
    }
  }

  if (err instanceof Error) {
    if (err.name === 'CancellationError') {
      return {
        code: 'cancelled',
        stage,
        safeMessage: cs.errors.worker.cancelled,
      }
    }
    const msg = err.message
    if (
      msg === 'cancelled'
      || msg === 'Processing cancelled'
      || msg === 'Plan build cancelled'
      || msg === 'Operation cancelled'
    ) {
      return {
        code: 'cancelled',
        stage,
        safeMessage: cs.errors.worker.cancelled,
      }
    }
    if (msg === 'Invalid protocol version') {
      return {
        code: 'protocol-mismatch',
        stage,
        safeMessage: cs.errors.worker.protocolMismatch,
      }
    }
  }

  return {
    code: fallbackCode,
    stage,
    safeMessage: cs.errors.worker.internal.replace('{code}', fallbackCode),
  }
}
