/**
 * Exclusive ID allocation without fixed points (step 3).
 * Picks an unused value from [min, max] that also fails `reject` (typically
 * `n === original`). Exhaustion returns null — callers must fail closed and
 * must not echo the original identity.
 */

export interface DenseProbeCursor {
  /** Next offset in [0, space) to try when random attempts miss. */
  offset: number
}

export interface AllocateExclusiveIdOptions {
  readonly used: ReadonlySet<number>
  readonly min: number
  readonly max: number
  /** Return true to skip this candidate (original, reserved, service port, …). */
  readonly reject: (n: number) => boolean
  /** Non-negative integer stream (CSPRNG). */
  readonly nextRandom: () => number
  readonly randomAttempts?: number
  /**
   * T48 — mutable dense-scan cursor. After a linear-probe hit, advanced so the next
   * near-exhaustion call does not restart from the same origin over a full domain.
   */
  readonly denseProbe?: DenseProbeCursor
}

/**
 * Allocate an injective alias in [min, max]. Never returns a rejected or used id.
 * When the free set is empty, returns null.
 */
export function allocateExclusiveId(options: AllocateExclusiveIdOptions): number | null {
  const { used, min, max, reject, nextRandom, denseProbe } = options
  const space = max - min + 1
  if (space <= 0) return null
  // Once every value in [min, max] is already used, no allocation can ever succeed again for
  // this `used` set (entries are never released) — every future call would otherwise redo the
  // full O(space) scan below only to fail identically. On a real capture this space (e.g. the
  // 16-bit IPv4 identification alias space) fills up well before the packet count does, turning
  // the remaining calls into a multi-billion-iteration tail without this short-circuit.
  if (used.size >= space) return null

  const accept = (n: number): boolean => !used.has(n) && !reject(n)
  const rememberProbe = (n: number): void => {
    if (denseProbe) denseProbe.offset = (n - min + 1) % space
  }

  const randomAttempts = options.randomAttempts ?? 32
  let candidate = min + (nextRandom() % space)
  for (let attempt = 0; attempt < randomAttempts; attempt++) {
    if (accept(candidate)) {
      rememberProbe(candidate)
      return candidate
    }
    candidate = min + (nextRandom() % space)
  }

  const startOffset = denseProbe ? ((denseProbe.offset % space) + space) % space : (candidate - min)
  for (let i = 0; i < space; i++) {
    const next = min + ((startOffset + i) % space)
    if (accept(next)) {
      rememberProbe(next)
      return next
    }
  }
  return null
}

/**
 * Allocate in a huge domain where a full linear probe is infeasible.
 * Bounded random retries only; null on failure (fail closed).
 */
export function allocateExclusiveIdSparse(options: {
  readonly used: ReadonlySet<number>
  readonly space: number
  readonly reject: (n: number) => boolean
  readonly nextRandom: () => number
  readonly randomAttempts?: number
}): number | null {
  const { used, space, reject, nextRandom } = options
  if (space <= 0) return null
  const randomAttempts = options.randomAttempts ?? 32
  for (let attempt = 0; attempt < randomAttempts; attempt++) {
    const candidate = nextRandom() % space
    if (!used.has(candidate) && !reject(candidate)) return candidate
  }
  return null
}
