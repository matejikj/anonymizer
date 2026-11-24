/**
 * Best-effort overwrite of a byte buffer. JavaScript strings cannot be wiped.
 */

export function wipeBytes(bytes: Uint8Array | undefined | null): void {
  if (!bytes) return
  bytes.fill(0)
}
