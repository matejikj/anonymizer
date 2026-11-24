/**
 * T66 / T70 — B2 common-word allowlist stub.
 *
 * Identities whose spelling is in this set are NOT propagated across free text
 * (avoids rewriting “user”, “host”, …). T70 will replace this with the generated
 * KONOS/RGW dictionary; until then only a tiny hard-coded stop list applies.
 */

const STOP = new Set(
  [
    'user',
    'host',
    'name',
    'from',
    'this',
    'that',
    'with',
    'call',
    'null',
    'true',
    'false',
    'test',
    'admin',
    'root',
    'info',
    'data',
    'port',
    'type',
    'none',
    'default',
    // Czech common short tokens that appear in logs
    'uzivatel',
    'stanice',
    'system',
  ].map((s) => s.toLowerCase()),
)

/** True when `spelling` is a common non-identifying word (skip propagation). */
export function isCommonWordAllowlisted(spelling: string): boolean {
  const key = spelling.trim().toLowerCase()
  if (key.length < 4) return true
  return STOP.has(key)
}
