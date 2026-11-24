/**
 * Correlation session limit validation (Stage 23).
 */

import {
  CORRELATION_PASTE_LIMITS,
  CORRELATION_SESSION_LIMITS,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../domain/capabilityContract'
import type { SourceKind } from '../domain/sourceArtifact'
import { SourceKind as SK } from '../domain/sourceArtifact'
import type { CorrelationError, StagedSourceDescriptor, SourceLimits } from './types'

export function correlationSourceLimits(): SourceLimits {
  return {
    maxFileBytes: Math.max(MAX_TEXT_FILE_BYTES, MAX_PCAP_FILE_BYTES),
    maxSources: CORRELATION_SESSION_LIMITS.maxSources,
    maxAggregateBytes: CORRELATION_SESSION_LIMITS.maxAggregateBytes,
  }
}

export function perKindFileLimit(kind: SourceKind): number {
  if (kind === SK.Pcap) return MAX_PCAP_FILE_BYTES
  return MAX_TEXT_FILE_BYTES
}

export function validateDescriptorCount(count: number): CorrelationError | null {
  if (count <= 0) {
    return { code: 'correlation-empty', message: 'No source descriptors to stage' }
  }
  if (count > CORRELATION_SESSION_LIMITS.maxSources) {
    return {
      code: 'correlation-too-many-sources',
      message: `At most ${CORRELATION_SESSION_LIMITS.maxSources} sources per session`,
    }
  }
  return null
}

export function validateAggregateBytes(totalBytes: number): CorrelationError | null {
  if (totalBytes > CORRELATION_SESSION_LIMITS.maxAggregateBytes) {
    return {
      code: 'correlation-aggregate-too-large',
      message: 'Aggregate source size exceeds correlation session limit',
    }
  }
  return null
}

export function validateUniqueSourceIds(descriptors: readonly StagedSourceDescriptor[]): CorrelationError | null {
  const seen = new Set<string>()
  for (const d of descriptors) {
    if (seen.has(d.sourceId)) {
      return {
        code: 'correlation-duplicate-source-id',
        message: `Duplicate source id: ${d.sourceId}`,
        sourceId: d.sourceId,
      }
    }
    seen.add(d.sourceId)
  }
  return null
}

export function sumDescriptorBytes(descriptors: readonly StagedSourceDescriptor[]): number {
  let total = 0
  for (const d of descriptors) {
    total += d.file.size
  }
  return total
}

export function sumPasteDescriptorBytes(descriptors: readonly StagedSourceDescriptor[]): number {
  let total = 0
  for (const d of descriptors) {
    if (d.inputKind === 'paste') total += d.file.size
  }
  return total
}

export function validatePasteAggregateBytes(totalPasteBytes: number): CorrelationError | null {
  if (totalPasteBytes > CORRELATION_PASTE_LIMITS.maxAggregateBytes) {
    return {
      code: 'correlation-paste-aggregate-too-large',
      message: 'Paste/in-memory aggregate size exceeds correlation session limit',
    }
  }
  return null
}

export function sumExistingSourceBytes(sources: Iterable<{ byteLength: number }>): number {
  let total = 0
  for (const s of sources) total += s.byteLength
  return total
}

export function defaultOutputFileName(kind: SourceKind, fileName: string): string {
  // T05: strip a single .gz so export names stay `obc2.anonym.log`, not `obc2.log.anonym.log`.
  const withoutGz = fileName.replace(/\.gz$/i, '')
  if (kind === SK.Pcap) {
    const base = withoutGz.replace(/\.(pcap|pcapng|cap)$/i, '')
    return `${base}.anonym.pcap`
  }
  const base = withoutGz.replace(/\.(log|txt)$/i, '')
  return `${base}.anonym.log`
}
