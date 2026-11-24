/**
 * T44 — support-bundle archive budgets (zip bomb, entry caps, correlation source cap).
 */

import {
  BYTES_PER_MIB,
  CORRELATION_SESSION_LIMITS,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../domain/capabilityContract.ts'

export const ARCHIVE_LIMITS = {
  /** Declared members walked (including omitted); not the accepted source count. */
  maxEntriesScanned: 256,
  /** Accepted text/PCAP sources — must not exceed correlation session cap. */
  maxAcceptedSources: CORRELATION_SESSION_LIMITS.maxSources,
  /** Aggregate inflated payload across accepted + scanned entry bodies. */
  maxTotalInflatedBytes: CORRELATION_SESSION_LIMITS.maxAggregateBytes,
  maxSingleEntryBytes: Math.max(MAX_TEXT_FILE_BYTES, MAX_PCAP_FILE_BYTES),
  maxPathBytes: 512,
  /** Compressed:inflated ratio ceiling for a single entry (zip bomb). */
  maxInflationRatio: 100,
  /** Nested archive depth: tar.gz is depth 1 (gzip→tar); ZIP-in-ZIP rejected. */
  maxNestDepth: 1,
  /** Minimum compressed size before ratio check (avoid tiny false positives). */
  ratioCheckMinCompressedBytes: 256,
  maxCommentBytes: 4 * 1024,
} as const

export const ARCHIVE_MIN_HEAD_FOR_USTAR = 262

/** Human label for limit errors (no original paths). */
export function archiveLimitMiB(bytes: number): string {
  const mib = bytes / BYTES_PER_MIB
  return `${mib.toLocaleString('cs-CZ', { maximumFractionDigits: 1 })} MiB`
}
