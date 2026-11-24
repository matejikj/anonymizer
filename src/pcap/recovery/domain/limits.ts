/**
 * Central PCAP recovery limits — writer and reader must use the same table.
 */

import {
  BYTES_PER_MIB,
  MAX_PCAP_FILE_BYTES,
} from '../../../domain/capabilityContract'

export const PCAP_RECOVERY_LIMITS = {
  /**
   * Extension for the plaintext v4 recovery sidecar (not a text ruleset). Ends in the common
   * `.bin` suffix — some real-world Chrome installs silently withhold downloads of files whose
   * *entire* extension is a made-up, never-seen-before string (no console error, no visible
   * warning, no chrome://downloads entry — see the recovery-export bug from 2026-09-08), while
   * `.bin`/`.pcap`/`.json` all download reliably in the same environment. Content is still
   * identified purely by the RECOVERY_MAGIC_BYTES header, never by this suffix, so changing it
   * is safe.
   */
  fileExtension: '.rnd-pcap-recovery.bin',

  /** Hard cap on recovery bundle size on disk / import (original + index + frame overhead). */
  maxBundleBytes: MAX_PCAP_FILE_BYTES + 32 * BYTES_PER_MIB,
  /** Reject before any large allocation when footer claims a larger total. */
  maxBundleImportBytes: MAX_PCAP_FILE_BYTES + 48 * BYTES_PER_MIB,

  /** Default / max plaintext per DATA or INDEX frame. */
  defaultFramePlaintextBytes: 1 * BYTES_PER_MIB,
  maxFramePlaintextBytes: 2 * BYTES_PER_MIB,

  maxDataFrames: 256_000,
  maxIndexFrames: 4_096,
  maxLookupEntries: 2_000_000,
  maxOccurrences: 8_000_000,
  maxStringBytes: 4_096,
  maxUnlockedIndexBytes: 64 * BYTES_PER_MIB,
  maxQueryBytes: 512 * 1024,
  maxQueryCandidates: 256,
  maxResultPageSize: 64,

  /** Unacked chunks for the active export/restore stream. */
  maxUnackedChunks: 2,

  /** Target / hard additional JS heap over baseline for 100 MiB capture. */
  targetExtraHeapBytes: 64 * BYTES_PER_MIB,
  hardExtraHeapBytes: 96 * BYTES_PER_MIB,

  /** Session inactivity lock (ms). Background timers may throttle — also check on RPC. */
  sessionIdleTimeoutMs: 15 * 60 * 1000,

  /** Progress emission rate (UI must not flood). */
  maxProgressMessagesPerSecond: 10,

  recoveryIdBytes: 16,
  anonymizedHashPrefixBytes: 8,
  sha256Bytes: 32,
  /** v3 publicHeader with salt + wrappedDEK. */
  maxPreambleBytes: 256,
  maxManifestPlaintextBytes: 2048,

  /** Max original filename stored inside encrypted manifest (download label only). */
  maxOriginalFileNameBytes: 512,
  maxEngineVersionBytes: 64,

  /**
   * COPY_ANON is opt-in until a benchmark proves size savings without exceeding
   * the export CPU budget. Production UI must not enable this by default.
   */
  copyAnonDefaultEnabled: false,
  /** Equal runs shorter than this stay LITERAL (matches export provenance). */
  copyAnonMinRunBytes: 16,
} as const

export type PcapRecoveryLimits = typeof PCAP_RECOVERY_LIMITS
