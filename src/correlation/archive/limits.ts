/**
 * T44 / T72 — support-bundle archive budgets (zip bomb, entry caps, nest depth).
 */

import {
  BYTES_PER_MIB,
  CORRELATION_SESSION_LIMITS,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../domain/capabilityContract.ts'
import { MAX_COMPRESSION_NEST_DEPTH } from '../import/decompressInput.ts'

export const ARCHIVE_LIMITS = {
  /** Declared members walked (including omitted); not the accepted source count. */
  maxEntriesScanned: 256,
  /**
   * T72 — accept every supported member within aggregate size; no hard 8-source omit.
   * Cap still equals the correlation session source ceiling (raised with T72).
   */
  maxAcceptedSources: CORRELATION_SESSION_LIMITS.maxSources,
  /** Aggregate inflated payload across accepted + scanned entry bodies. */
  maxTotalInflatedBytes: CORRELATION_SESSION_LIMITS.maxAggregateBytes,
  maxSingleEntryBytes: Math.max(MAX_TEXT_FILE_BYTES, MAX_PCAP_FILE_BYTES),
  maxPathBytes: 512,
  /** Compressed:inflated ratio ceiling for a single entry (zip bomb). */
  maxInflationRatio: 100,
  /** T72 — nested archive / compression layers (gz in tar in zip …). */
  maxNestDepth: MAX_COMPRESSION_NEST_DEPTH,
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
