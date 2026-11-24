/**
 * Explicit coverage disposition matrix (diagnostic anonymization step 1).
 * Replaces ad-hoc decisions based solely on `truncateUnsupported`.
 */

import type {
  CoverageStatus,
  MalformedPayloadPolicy,
  SanitizationPolicy,
  UnsupportedPayloadPolicy,
  VoipMediaPolicy,
} from './types';

/**
 * Resulting handling for a coverage status under the active policy.
 * Media layers may override via mediaPolicy when `layerKind` is voip media.
 */
export type CoverageDisposition =
  | 'keep'
  | 'preserve-encrypted'
  | 'mask-in-place'
  | 'mask-application-in-place'
  | 'truncate'
  | 'drop'
  | 'preserve-unsafe'
  | 'strip-media-payload';

export type CoverageLayerKind =
  | 'generic'
  | 'application'
  | 'media'
  | 'transport'
  | 'network'
  | 'link';

const MEDIA_PROTOCOLS = new Set([
  'rtp',
  'rtcp',
  'srtp',
  'media',
  'voip-media',
]);

export function isMediaLayerKind(layerKind: CoverageLayerKind | string): boolean {
  const key = layerKind.toLowerCase();
  return key === 'media' || MEDIA_PROTOCOLS.has(key);
}

function unsupportedDisposition(policy: UnsupportedPayloadPolicy): CoverageDisposition {
  switch (policy) {
    case 'mask-in-place':
      return 'mask-in-place';
    case 'truncate':
      return 'truncate';
    case 'preserve-unsafe':
      return 'preserve-unsafe';
  }
}

function malformedDisposition(policy: MalformedPayloadPolicy): CoverageDisposition {
  switch (policy) {
    case 'mask-application-in-place':
      return 'mask-application-in-place';
    case 'drop':
      return 'drop';
    case 'preserve-unsafe':
      return 'preserve-unsafe';
  }
}

function mediaDisposition(policy: VoipMediaPolicy): CoverageDisposition {
  switch (policy) {
    case 'strip-payload':
      return 'strip-media-payload';
    case 'drop':
      return 'drop';
    case 'preserve-unsafe':
      return 'preserve-unsafe';
  }
}

/**
 * Resolve disposition for a coverage status under the sanitization policy.
 * When `layerKind` identifies VoIP media, `mediaPolicy` wins over payload policies
 * (mediaPolicy itself realizes the step-11 MEDIA classification table: MASK→strip, DROP→drop).
 */
export function resolveCoverageDisposition(
  policy: Pick<
    SanitizationPolicy,
    'unsupportedPayloadPolicy' | 'malformedPayloadPolicy' | 'mediaPolicy' | 'preset'
  >,
  status: CoverageStatus,
  layerKind: CoverageLayerKind | string = 'generic',
): CoverageDisposition {
  if (isMediaLayerKind(layerKind) && (status === 'unsupported' || status === 'preserved-unsafe' || status === 'encrypted' || status === 'heuristic' || status === 'covered' || status === 'redacted')) {
    // Confirmed/suspected media uses mediaPolicy; encrypted SRTP still strips/drops/preserves via media.
    // Diagnostic (MEDIA=MASK) must never DROP the whole media datagram.
    if (
      policy.preset === 'diagnostic'
      && policy.mediaPolicy === 'drop'
    ) {
      return 'strip-media-payload'
    }
    if (status === 'covered' || status === 'redacted') {
      // Already handled structurally — keep unless mediaPolicy says drop whole record.
      if (policy.mediaPolicy === 'drop') return 'drop';
      if (policy.mediaPolicy === 'strip-payload') return 'strip-media-payload';
      return 'keep';
    }
    return mediaDisposition(policy.mediaPolicy);
  }

  switch (status) {
    case 'covered':
    case 'redacted':
    case 'truncated':
    case 'preserved-for-diagnostics':
      return 'keep';
    case 'encrypted':
      return 'preserve-encrypted';
    case 'preserved-unsafe':
      return 'preserve-unsafe';
    case 'unsupported':
    case 'heuristic':
    case 'requires-reassembly':
      // Step 11: diagnostic UNKNOWN_UNVERIFIED → MASK (never truncate/drop).
      if (policy.preset === 'diagnostic') {
        return 'mask-in-place'
      }
      return unsupportedDisposition(policy.unsupportedPayloadPolicy);
    case 'malformed':
      if (policy.preset === 'diagnostic') {
        return 'mask-application-in-place'
      }
      return malformedDisposition(policy.malformedPayloadPolicy);
    case 'processing-failed':
      // T07: already fail-closed at isolation; keep so plan/export don't re-mutate.
      return 'keep'
  }
}

/** Map export-boundary blocking region to disposition using the policy matrix. */
export function resolveBlockingExportDisposition(
  policy: Pick<
    SanitizationPolicy,
    'unsupportedPayloadPolicy' | 'malformedPayloadPolicy'
  >,
  blockingStatus: CoverageStatus | null,
): CoverageDisposition {
  if (blockingStatus === 'malformed') {
    return malformedDisposition(policy.malformedPayloadPolicy);
  }
  if (
    blockingStatus === 'unsupported'
    || blockingStatus === 'heuristic'
    || blockingStatus === 'requires-reassembly'
    || blockingStatus === null
  ) {
    return unsupportedDisposition(policy.unsupportedPayloadPolicy);
  }
  if (blockingStatus === 'preserved-unsafe') return 'preserve-unsafe';
  if (blockingStatus === 'encrypted') return 'preserve-encrypted';
  return 'keep';
}
