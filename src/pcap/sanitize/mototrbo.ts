/**
 * MOTOTRBO (IP Site Connect / Capacity Plus) — best-effort detection only.
 *
 * Motorola's wire format has no public specification, so field-level parsing is
 * deliberately NOT attempted here — guessing offsets risks silently corrupting the
 * packet or missing the actual identifying field. Instead this recognizes a narrow,
 * explicit port list and redacts the payload wholesale, reporting `redacted`:
 * detected and zeroed, but not structurally parsed — never silently `covered`.
 *
 * The payload is zeroed but its length is kept (not truncated away) — that preserves
 * packet size/timing for traffic-pattern diagnostics without exposing content.
 *
 * Ports are intentionally narrow, not a wide "50000+" range — a blanket range risks
 * swallowing unrelated UDP traffic (e.g. STUN/TURN) sharing the same ephemeral space.
 * If a deployment's IPSC ports differ from this list, or if internal/vendor wire-format
 * documentation becomes available for deeper coverage, extend this from confirmed
 * observed traffic rather than guessing.
 */

import type { PatchCollector } from './PatchCollector';
import type { AppLayerResult } from './types';

const MOTOTRBO_PORTS = new Set([50000, 50001, 50002]);

export function sanitizeMototrboIpsc(
  offset: number,
  length: number,
  dstPort: number,
  collector: PatchCollector,
): AppLayerResult | null {
  if (!MOTOTRBO_PORTS.has(dstPort)) return null;

  // maskRange replaces any overlapping patch, so the 'redacted' claim below always holds.
  collector.maskRange(offset, new Uint8Array(length)); // zero-filled

  return { coverage: [{ protocol: 'mototrbo-ipsc', offset, length, status: 'redacted' }] };
}
