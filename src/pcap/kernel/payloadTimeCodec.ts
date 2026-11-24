/**
 * T14 — payload absolute-time codec aligned with capture TimestampMapping.
 *
 * Distinguishes absolute epoch times (HTTP/SIP Date) from relative durations
 * and ambiguous local clocks. Unwritable formats fail closed to same-length mask.
 */

import type { PacketTimestamp } from '../domain/types'
import {
  createTimestampMappingForPlan,
  type TimestampMapping,
  type TimestampMappingConfig,
} from '../anonymization/timestampMapping'

export type PayloadTimeKind = 'absolute-epoch' | 'relative-duration' | 'ambiguous-local'

export type PayloadTimeRewrite =
  | { readonly kind: 'shifted'; readonly text: string }
  | { readonly kind: 'mask'; readonly reasonCode: string }

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const
const MONTH_NAMES = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
] as const

const HTTP_DATE_RE =
  /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/

/**
 * Session-scoped payload time transform. Bind the first capture timestamp once
 * (same packet order as export) so Δ matches PCAP record remapping.
 */
export class PayloadTimeSession {
  private readonly _ts: TimestampMapping
  private _bound = false

  constructor(
    timestamps: TimestampMappingConfig | undefined,
    planSeed: string,
  ) {
    this._ts = createTimestampMappingForPlan(timestamps, planSeed)
  }

  /** Expose underlying capture mapper for tests / export parity checks. */
  get timestampMapping(): TimestampMapping {
    return this._ts
  }

  get isBound(): boolean {
    return this._bound
  }

  /**
   * Initialize offset from the first packet that export will map.
   * Safe to call once; subsequent calls are no-ops.
   */
  bindCaptureReference(captureTs: PacketTimestamp): void {
    if (this._bound) return
    this._ts.mapTicks(captureTs)
    this._bound = true
  }

  classify(kind: PayloadTimeKind): PayloadTimeKind {
    return kind
  }

  /**
   * Shift an absolute Unix epoch (ms) with the same Δ as capture timestamps.
   * Requires {@link bindCaptureReference}. Returns null if unbound.
   */
  shiftAbsoluteEpochMs(epochMs: number): number | null {
    if (!this._bound || !Number.isFinite(epochMs)) return null
    const units = 1000n
    const original: PacketTimestamp = {
      ticks: BigInt(Math.trunc(epochMs)),
      unitsPerSecond: units,
      offsetSeconds: 0n,
    }
    const mapped = this._ts.shiftAbsoluteTicks(original)
    if (mapped === null) return null
    const ms = mapped.ticks
    if (ms > BigInt(Number.MAX_SAFE_INTEGER) || ms < BigInt(Number.MIN_SAFE_INTEGER)) {
      return null
    }
    return Number(ms)
  }

  /** Parse RFC 1123 / IMF-preferred HTTP-date; null if unsupported spelling. */
  parseHttpDate(value: string): number | null {
    const trimmed = value.trim()
    if (!HTTP_DATE_RE.test(trimmed)) return null
    const ms = Date.parse(trimmed)
    if (!Number.isFinite(ms)) return null
    return ms
  }

  /** Always 29 ASCII bytes: `Wed, 17 Oct 2026 12:00:00 GMT`. */
  formatHttpDate(epochMs: number): string {
    const d = new Date(epochMs)
    const day = DAY_NAMES[d.getUTCDay()]!
    const dd = String(d.getUTCDate()).padStart(2, '0')
    const mon = MONTH_NAMES[d.getUTCMonth()]!
    const yyyy = String(d.getUTCFullYear()).padStart(4, '0')
    const hh = String(d.getUTCHours()).padStart(2, '0')
    const mm = String(d.getUTCMinutes()).padStart(2, '0')
    const ss = String(d.getUTCSeconds()).padStart(2, '0')
    return `${day}, ${dd} ${mon} ${yyyy} ${hh}:${mm}:${ss} GMT`
  }

  /**
   * Length-preserving HTTP-date rewrite. Unparseable / unbound / length mismatch → mask.
   */
  rewriteHttpDateFixedLength(original: string): PayloadTimeRewrite {
    const parsed = this.parseHttpDate(original)
    if (parsed === null) {
      return { kind: 'mask', reasonCode: 'unwritable-payload-time' }
    }
    const shifted = this.shiftAbsoluteEpochMs(parsed)
    if (shifted === null) {
      return { kind: 'mask', reasonCode: 'payload-time-unbound' }
    }
    const text = this.formatHttpDate(shifted)
    if (text.length !== original.length) {
      return { kind: 'mask', reasonCode: 'unwritable-payload-time-length' }
    }
    return { kind: 'shifted', text }
  }
}

export function createPayloadTimeSession(
  timestamps: TimestampMappingConfig | undefined,
  planSeed: string,
): PayloadTimeSession {
  return new PayloadTimeSession(timestamps, planSeed)
}
