/**
 * Single source of truth for anonymizer capacity and mapping limits.
 * UI, preflight, workers and tests import from here — no scattered numeric literals.
 */

/** Binary megabyte (1024 × 1024 bytes). All user-facing size labels use MiB. */
export const BYTES_PER_MIB = 1024 * 1024

/** Supported maximum for a single text log file (90 MiB inclusive). */
export const MAX_TEXT_FILE_BYTES = 90 * BYTES_PER_MIB

/** Supported maximum for a single PCAP/PCAPNG capture (100 MiB inclusive). */
export const MAX_PCAP_FILE_BYTES = 100 * BYTES_PER_MIB

/** Text input limits derived from file/paste policy. */
export const TEXT_INPUT_LIMITS = {
  commonMaxLines: 100_000,
  commonMaxBytes: 30 * BYTES_PER_MIB,
  fileMaxLines: 400_000,
  fileMaxBytes: MAX_TEXT_FILE_BYTES,
  pasteMaxBytes: 30 * BYTES_PER_MIB,
  oversizedLineBytes: 256 * 1024,
  profileMaxBytes: 1 * BYTES_PER_MIB,
  profileMaxRules: 500,
} as const

/** PCAP container/record limits (separate from file-size cap). */
export const PCAP_RECORD_LIMITS = {
  /** Defensive cap per record/block body — not the same as MAX_PCAP_FILE_BYTES. */
  maxRecordSize: 16 * BYTES_PER_MIB,
} as const

/** PCAP preview random-access cache (Stage 9). */
export const PCAP_PREVIEW_LIMITS = {
  /** Total bytes retained for hydrated packet payloads in the LRU. */
  lruByteBudget: 4 * BYTES_PER_MIB,
  /** Maximum single packet payload cached (matches maxRecordSize). */
  maxPacketBytes: PCAP_RECORD_LIMITS.maxRecordSize,
} as const

/**
 * T-01 kernel budgets — session-wide PCAP raw/metadata ceilings.
 * Values are the approved initial implementation limits (not measured baseline).
 * Change only with a reproducible benchmark justification.
 */
export const PCAP_KERNEL_BUDGETS = {
  /** Pull-reader batch: bytes or record count, whichever hits first. */
  batchMaxBytes: 4 * BYTES_PER_MIB,
  batchMaxRecords: 4_096,
  /** Worker queue: batches in flight and ordinary payload bytes. */
  workerMaxBatchesInFlight: 2,
  workerMaxPayloadBytesInFlight: 8 * BYTES_PER_MIB,
  /** Aggregate reassembly (tails, fragments, pending streams). */
  reassemblyMaxBytes: 32 * BYTES_PER_MIB,
  /**
   * All live PCAP raw buffers: read-ahead, queues, scratch, reassembly, preview.
   * Preview LRU is counted inside this aggregate, not as an extra exception.
   */
  rawBuffersMaxBytes: 64 * BYTES_PER_MIB,
  /** Preview cache — must stay ≤ PCAP_PREVIEW_LIMITS.lruByteBudget and within raw aggregate. */
  previewCacheMaxBytes: PCAP_PREVIEW_LIMITS.lruByteBudget,
  /**
   * Per-packet retained session bytes: journal records, ops, intents and coverage / issue lists
   * (shared ops and lists counted once, see SemanticJournalBuilder.addPacket). Sized for the
   * 100 MiB PCAP limit on RTP-heavy real traffic, measured 2026-10-20 (production build, Chromium):
   * 47 MB / 225k packets → 264–279 MiB estimate, 271 MiB retained processing-worker heap;
   * the same capture doubled (94 MB / 451k packets) → 524–553 MiB estimate, worker 542–582 MiB
   * retained, peak 1.7 GB (diagnostic) / 2.2 GB (high-privacy), no crash. Denser traffic (more
   * packets or ops per MiB) fails closed with journal-exceeded.
   */
  journalMaxBytes: 640 * BYTES_PER_MIB,
  /** T04 — retained AnonymizationIncident records (count). */
  incidentLogMaxRecords: 1_000,
  /** T04 — approximate serialized budget for retained incident records. */
  incidentLogMaxBytes: 256 * 1024,
  /** Mapping + interned identity strings (500k identity cap remains). */
  mappingMaxBytes: 64 * BYTES_PER_MIB,
  /** Progress / cancel responsiveness targets (ms). */
  progressMaxIntervalMs: 250,
  cancelVisibleMaxMs: 250,
  cancelCompleteMaxMs: 1_000,
  /** Registry probe bounds — exceeding yields explicit fallback, not silent mask of wrong protocol. */
  maxProbesPerUnit: 8,
  maxProbeBytes: 2_048,
  maxProbeNesting: 4,
} as const

export type PcapKernelBudgets = typeof PCAP_KERNEL_BUDGETS

/** Entity discovery cardinality (text + PCAP share the same ceiling). */
export const MAX_ENTITY_CARDINALITY = 500_000

/**
 * Mapping / correlation / bundle limits — enforced before registry mutation or decode.
 * Values are conservative placeholders calibrated in Stage 0; Stage 20 may tighten KDF/bundle caps.
 */
export const MAPPING_CAPABILITY_LIMITS = {
  maxIdentities: MAX_ENTITY_CARDINALITY,
  /** Representation aliases per canonical identity (hostname length variants, etc.). */
  maxAliasesPerIdentity: 16,
  /** Packed occurrence index budget per active session (bytes). */
  maxOccurrenceIndexBytes: 64 * BYTES_PER_MIB,
  /** Plaintext JSON mapping bundle on disk (bytes). */
  maxBundleBytes: 32 * BYTES_PER_MIB,
  /** Upper bound on ciphertext read before KDF (anti resource-exhaustion). */
  maxBundleImportBytes: 64 * BYTES_PER_MIB,
  /** Maximum sources in one correlation session (future stage). */
  maxSourcesPerSession: 8,
  /** Legacy unused KDF constants retained until T46 reference cleanup; not an encryption requirement. */
  pbkdf2MinIterations: 100_000,
  pbkdf2MaxIterations: 600_000,
  pbkdf2DefaultIterations: 310_000,
  pbkdf2SaltBytes: 16,
  /** Legacy unused bundle-frame constant; current mapping format is plain JSON (cleanup T46). */
  maxBundleFramePlaintextBytes: 4 * BYTES_PER_MIB,
  /** Legacy unused ciphertext constant; current mapping format has no ciphertext (cleanup T46). */
  maxBundleFrameCiphertextBytes: 4 * BYTES_PER_MIB + 32,
  /** Legacy header cap; no KDF is performed by the current JSON codec (cleanup T46). */
  maxBundleHeaderBytes: 512,
} as const

/**
 * Multi-source correlation session limits (Stage 23).
 * Aggregate cap is explicit — not derived as maxSources × per-file maximum.
 * Single 100 MiB PCAP alone always fits (below aggregate cap).
 */
export const CORRELATION_SESSION_LIMITS = {
  maxSources: MAPPING_CAPABILITY_LIMITS.maxSourcesPerSession,
  /** Initial aggregate budget — Stage 0 baseline; lower if browser benchmark fails. */
  maxAggregateBytes: 200 * BYTES_PER_MIB,
} as const

/** In-memory / paste aggregate cap for multi-source correlation (Stage 24). */
export const CORRELATION_PASTE_LIMITS = {
  maxAggregateBytes: TEXT_INPUT_LIMITS.pasteMaxBytes,
} as const

/** Resolve-only workspace / AI report scan limits (Stage 22). */
export const RESOLVE_WORKSPACE_LIMITS = {
  /** Max pasted AI report size (bytes). */
  maxAiReportBytes: 512 * 1024,
  /** Max pseudonym findings returned from one scan. */
  maxAiReportFindings: 10_000,
  /** Max alias length for exact lookup input. */
  maxExactLookupAliasBytes: 1024,
} as const

/** Prefix bytes used for content sniffing (PCAP magic / binary / text). */
export const SOURCE_PROBE_HEAD_BYTES = 8192 as const

export type TextInputLimits = typeof TEXT_INPUT_LIMITS
export type PcapRecordLimits = typeof PCAP_RECORD_LIMITS
export type MappingCapabilityLimits = typeof MAPPING_CAPABILITY_LIMITS

/** Format byte length as MiB with one decimal for Czech UI messages. */
export function formatMiB(bytes: number): string {
  return `${(bytes / BYTES_PER_MIB).toFixed(1)} MiB`
}

/** Returns true when value is within inclusive byte limit. */
export function withinByteLimit(value: number, limit: number): boolean {
  return value >= 0 && value <= limit
}
