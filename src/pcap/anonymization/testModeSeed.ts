/**
 * TEST MODE vs PRODUCTION mapping session seeds (enterprise step 13).
 *
 * PRODUCTION → CSPRNG session entropy (different runs → different aliases OK).
 * TEST MODE  → injected deterministic seed → bit-identical aliases across runs/runtimes.
 *
 * Production UI/CLI entrypoints must call {@link createProductionSessionMapping}
 * (or omit seed). Never default a fixed seed in production.
 */

import { SessionMapping, DEFAULT_MAPPING_CONFIG, type MappingConfig } from './mapping'

/** Minimum length for an injected TEST MODE seed (rejects empty / trivial defaults). */
export const TEST_MODE_SEED_MIN_LENGTH = 8

/**
 * Seeds that must never be used as an implicit production default.
 * Explicit TEST MODE injection of these strings is still rejected — pick a longer opaque seed.
 */
export const FORBIDDEN_PRODUCTION_DEFAULT_SEEDS: ReadonlySet<string> = new Set([
  '',
  '0',
  'test',
  'deterministic',
  'default',
  'fixed',
])

export type MappingSessionOptions = {
  /**
   * TEST MODE only. When set, SessionMapping entropy is derived from this seed.
   * Production paths must omit this field.
   */
  readonly seed?: string
}

/** True when options request an injected seed (TEST MODE). */
export function isTestModeMappingSeed(options?: MappingSessionOptions): boolean {
  return typeof options?.seed === 'string' && options.seed.length > 0
}

/**
 * Reject fixed/default seeds on the production path.
 * Call from UI/CLI production entrypoints before constructing a session.
 */
export function assertProductionMappingHasNoFixedSeed(options?: MappingSessionOptions): void {
  if (options?.seed !== undefined) {
    throw new Error(
      'Fixed mapping seed is TEST MODE only; production must use CSPRNG (omit seed)',
    )
  }
}

/** Production session mapping — always CSPRNG, never a fixed seed. */
export function createProductionSessionMapping(
  config: MappingConfig = DEFAULT_MAPPING_CONFIG,
): SessionMapping {
  return new SessionMapping(config)
}

/**
 * TEST MODE session mapping — deterministic aliases for the given seed.
 * Same seed + same config + same map() sequence → bit-identical aliases.
 */
export function createTestSessionMapping(
  seed: string,
  config: MappingConfig = DEFAULT_MAPPING_CONFIG,
): SessionMapping {
  if (typeof seed !== 'string' || seed.length < TEST_MODE_SEED_MIN_LENGTH) {
    throw new Error(
      `TEST MODE mapping seed must be a string of length ≥ ${TEST_MODE_SEED_MIN_LENGTH}`,
    )
  }
  if (FORBIDDEN_PRODUCTION_DEFAULT_SEEDS.has(seed)) {
    throw new Error('TEST MODE seed must not be a forbidden production default placeholder')
  }
  return new SessionMapping(config, { seed })
}
