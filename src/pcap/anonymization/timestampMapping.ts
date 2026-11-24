/**
 * Timestamp authority — PCAP record time transforms (CF-12).
 *
 * Modes:
 * - relative-exact: session-random (or seeded) anchor, exact inter-packet deltas
 * - relative-bucketed: round deltas into buckets; never reverse order
 * - enumerated: synthetic constant step from anchor (high-privacy)
 */

import type { PacketTimestamp } from '../domain/types';

export type TimestampMode = 'relative-exact' | 'relative-bucketed' | 'enumerated';

/** Profile / mapping config spelling — `relative` means relative-exact. */
export type TimestampMappingConfig = 'relative' | 'relative-bucketed' | 'enumerated';

export function timestampModeFromConfig(config: TimestampMappingConfig | undefined): TimestampMode {
  switch (config) {
    case 'relative-bucketed':
      return 'relative-bucketed';
    case 'enumerated':
      return 'enumerated';
    case 'relative':
    default:
      return 'relative-exact';
  }
}

export interface TimestampMappingOptions {
  readonly mode?: TimestampMode;
  /**
   * Deterministic anchor seconds since Unix epoch.
   * When omitted, a per-instance random anchor is chosen (CF-12: no fixed global epoch).
   */
  readonly anchorSeconds?: bigint;
  /** Bucket width in timestamp units (ticks) for relative-bucketed. Default = 1ms in current resolution. */
  readonly bucketTicks?: bigint;
  /** Synthetic step for enumerated mode (ticks). Default = 1ms. */
  readonly enumeratedStepTicks?: bigint;
}

const DEFAULT_ANCHOR_MIN_S = 1_600_000_000n; // ~2020
const DEFAULT_ANCHOR_SPAN_S = 200_000_000n; // ~6 years

function randomAnchorSeconds(): bigint {
  let n = 0n;
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const buf = new Uint8Array(8);
    crypto.getRandomValues(buf);
    for (const b of buf) n = (n << 8n) | BigInt(b);
  } else {
    n = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
  }
  return DEFAULT_ANCHOR_MIN_S + (n % DEFAULT_ANCHOR_SPAN_S);
}

/** Stable per-plan anchor so preview/sync/incremental export stay byte-identical (CF-12). */
export function anchorSecondsFromPlanSeed(seed: string): bigint {
  let h = 2166136261n;
  for (let i = 0; i < seed.length; i++) {
    h ^= BigInt(seed.charCodeAt(i));
    h = BigInt.asUintN(64, h * 16777619n);
  }
  return DEFAULT_ANCHOR_MIN_S + (h % DEFAULT_ANCHOR_SPAN_S);
}

export function createTimestampMappingForPlan(
  timestamps: TimestampMappingConfig | undefined,
  planSeed: string,
): TimestampMapping {
  return new TimestampMapping({
    mode: timestampModeFromConfig(timestamps),
    anchorSeconds: anchorSecondsFromPlanSeed(planSeed),
  });
}

export class TimestampMapping {
  private readonly _mode: TimestampMode;
  private readonly _anchorSeconds: bigint;
  private readonly _bucketTicks: bigint | null;
  private readonly _enumeratedStep: bigint;
  private _offsetTicks: bigint | null = null;
  /** unitsPerSecond of the capture clock that established `_offsetTicks` (T14). */
  private _bindUnitsPerSecond: bigint | null = null;
  private _lastMappedTicks: bigint | null = null;
  private _enumeratedIndex = 0n;

  constructor(options: TimestampMappingOptions = {}) {
    this._mode = options.mode ?? 'relative-exact';
    this._anchorSeconds = options.anchorSeconds ?? randomAnchorSeconds();
    this._bucketTicks = options.bucketTicks ?? null;
    this._enumeratedStep = options.enumeratedStepTicks ?? 0n;
  }

  get mode(): TimestampMode {
    return this._mode;
  }

  get anchorSeconds(): bigint {
    return this._anchorSeconds;
  }

  get isInitialized(): boolean {
    return this._offsetTicks !== null || this._mode === 'enumerated';
  }

  /** True when exact inter-packet deltas are preserved (correlation residual). */
  get preservesExactDeltas(): boolean {
    return this._mode === 'relative-exact';
  }

  mapTicks(ts: PacketTimestamp): PacketTimestamp {
    const anchorTicks = this._anchorSeconds * ts.unitsPerSecond;
    const bucket = this._bucketTicks && this._bucketTicks > 0n
      ? this._bucketTicks
      : ts.unitsPerSecond / 1000n > 0n
        ? ts.unitsPerSecond / 1000n
        : 1n;
    const enumStep = this._enumeratedStep > 0n
      ? this._enumeratedStep
      : ts.unitsPerSecond / 1000n > 0n
        ? ts.unitsPerSecond / 1000n
        : 1n;

    if (this._mode === 'enumerated') {
      if (this._offsetTicks === null) {
        this._offsetTicks = 0n;
        this._bindUnitsPerSecond = ts.unitsPerSecond;
        this._lastMappedTicks = anchorTicks;
        this._enumeratedIndex = 0n;
        return { ...ts, ticks: anchorTicks };
      }
      this._enumeratedIndex += 1n;
      const mapped = anchorTicks + this._enumeratedIndex * enumStep;
      this._lastMappedTicks = mapped;
      return { ...ts, ticks: mapped };
    }

    if (this._offsetTicks === null) {
      this._offsetTicks = anchorTicks - ts.ticks;
      this._bindUnitsPerSecond = ts.unitsPerSecond;
      const mapped = ts.ticks + this._offsetTicks;
      this._lastMappedTicks = mapped;
      return { ...ts, ticks: mapped };
    }

    let mapped = ts.ticks + this._offsetTicks;

    if (this._mode === 'relative-bucketed') {
      const deltaFromAnchor = mapped - anchorTicks;
      const rounded = deltaFromAnchor >= 0n
        ? (deltaFromAnchor / bucket) * bucket
        : -(((-deltaFromAnchor + bucket - 1n) / bucket) * bucket);
      mapped = anchorTicks + rounded;
      // Never reverse order within a capture
      if (this._lastMappedTicks !== null && mapped < this._lastMappedTicks) {
        mapped = this._lastMappedTicks;
      }
    }

    this._lastMappedTicks = mapped;
    return { ...ts, ticks: mapped };
  }

  /** @deprecated use mapTicks */
  map(ts: PacketTimestamp): PacketTimestamp {
    return this.mapTicks(ts);
  }

  /**
   * T14 — shift an absolute payload timestamp with the same wall-clock Δ as capture
   * records. Unit-independent: Δ is computed in seconds from the bound capture
   * reference, then applied in `ts.unitsPerSecond`. Does not advance enumerated
   * packet index.
   */
  shiftAbsoluteTicks(ts: PacketTimestamp): PacketTimestamp | null {
    if (this._offsetTicks === null) {
      // Not yet bound via mapTicks — refuse rather than invent Δ.
      return null;
    }

    if (this._mode === 'enumerated') {
      // High-privacy: absolute payload times land on the synthetic anchor.
      return { ...ts, ticks: this._anchorSeconds * ts.unitsPerSecond };
    }

    // offsetTicks was computed in the capture clock's units; convert via seconds.
    // mappedCapture = captureTicks + offsetTicks = anchorSeconds * captureUps
    // ⇒ offsetSeconds = anchorSeconds - captureTicks/captureUps
    // We recover offsetSeconds from the already-applied first mapped tick:
    // firstMapped = lastMapped after bind ≈ anchor (relative-exact first packet).
    // Safer: store offset as rational from bind. Here derive from _offsetTicks by
    // requiring callers to pass the same units as the bind clock OR we keep
    // _bindUnitsPerSecond.
    const bindUps = this._bindUnitsPerSecond;
    if (bindUps === null || bindUps <= 0n) return null;

    // offsetSeconds = offsetTicks / bindUps (exact rational applied in target units)
    // mappedTicks = ts.ticks + offsetTicks * ts.ups / bindUps
    const mapped =
      ts.ticks + (this._offsetTicks * ts.unitsPerSecond) / bindUps;

    if (this._mode === 'relative-bucketed') {
      const anchorTicks = this._anchorSeconds * ts.unitsPerSecond;
      const bucket = this._bucketTicks && this._bucketTicks > 0n
        ? this._bucketTicks
        : ts.unitsPerSecond / 1000n > 0n
          ? ts.unitsPerSecond / 1000n
          : 1n;
      const deltaFromAnchor = mapped - anchorTicks;
      const rounded = deltaFromAnchor >= 0n
        ? (deltaFromAnchor / bucket) * bucket
        : -(((-deltaFromAnchor + bucket - 1n) / bucket) * bucket);
      return { ...ts, ticks: anchorTicks + rounded };
    }

    return { ...ts, ticks: mapped };
  }

  reset(): void {
    this._offsetTicks = null;
    this._bindUnitsPerSecond = null;
    this._lastMappedTicks = null;
    this._enumeratedIndex = 0n;
  }
}
