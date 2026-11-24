/**
 * Fail-closed handling for reassembly failures (step 9 / step 4 mask-in-place).
 */

import type { LayerCoverage, SanitizationPolicy, SipUncoveredAction } from '../sanitize/types';
import { createProtocolNeutralMaskFill } from '../sanitize/maskFill';
import type { PacketReassemblyOverlay, ReassemblyStatus } from './types';

function actionForStatus(
  policy: SanitizationPolicy,
  status: ReassemblyStatus,
): SipUncoveredAction {
  if (status === 'limit-exceeded') {
    return policy.sipHandling.reassemblyLimitExceeded;
  }
  if (status === 'overlap-conflict') {
    return policy.sipHandling.malformed;
  }
  // incomplete | gap — cannot safely classify across missing stream bytes
  return policy.sipHandling.incompleteMessage;
}

export function overlayForReassemblyFailure(
  policy: SanitizationPolicy,
  packetIndex: number,
  payloadOffset: number,
  payloadLength: number,
  status: ReassemblyStatus,
  transport: 'tcp' | 'udp' | 'sctp',
): PacketReassemblyOverlay {
  const action = actionForStatus(policy, status);
  const protocol =
    transport === 'tcp' ? 'tcp-reassembly'
    : transport === 'sctp' ? 'sctp-reassembly'
    : 'udp-reassembly';
  const coverageStatus: LayerCoverage['status'] =
    status === 'overlap-conflict' ? 'malformed' : 'requires-reassembly';

  const coverage: LayerCoverage[] = [{
    protocol,
    offset: payloadOffset,
    length: payloadLength,
    status: coverageStatus,
  }];

  const resourceLimit = status === 'limit-exceeded';
  const issues = resourceLimit
    ? [`RESOURCE_LIMIT_FALLBACK (${transport})`, `Reassembly ${status} (${transport})`]
    : [`Reassembly ${status} (${transport})`];

  switch (action) {
    case 'drop':
      return {
        patches: [],
        coverage,
        issues: [...issues, 'Dropped by reassembly policy'],
        drop: true,
        intents: [{ kind: 'drop-record', packetIndex }],
        skipAppLayer: true,
      };
    case 'truncate':
      return {
        patches: [],
        coverage,
        issues,
        drop: false,
        truncatedLength: payloadOffset,
        intents: [{ kind: 'truncation', packetIndex, truncatedLength: payloadOffset }],
        skipAppLayer: true,
      };
    case 'mask-in-place': {
      const fill = createProtocolNeutralMaskFill({
        length: payloadLength,
        packetIndex,
        offset: payloadOffset,
        domain: resourceLimit
          ? `reassembly:RESOURCE_LIMIT_FALLBACK:${transport}`
          : `reassembly:${status}:${transport}`,
      });
      return {
        patches: payloadLength > 0 ? [{ offset: payloadOffset, data: fill }] : [],
        coverage: coverage.map((c) => ({ ...c, status: 'redacted' as const })),
        issues: [
          ...issues,
          resourceLimit
            ? 'RESOURCE_LIMIT_FALLBACK: application masked in-place (never leave-original)'
            : 'Application masked in-place (gap/incomplete — never passthrough)',
        ],
        drop: false,
        intents: payloadLength > 0
          ? [{
              kind: 'mask-range' as const,
              packetIndex,
              offset: payloadOffset,
              byteLength: payloadLength,
              reason: resourceLimit ? 'RESOURCE_LIMIT_FALLBACK' : `reassembly-${status}`,
              protocol,
            }]
          : [],
        skipAppLayer: true,
      };
    }
    case 'mark-uncovered':
    default:
      return {
        patches: [],
        coverage: coverage.map((c) => ({ ...c, status: 'unsupported' as const })),
        issues,
        drop: false,
        intents: [],
        skipAppLayer: true,
      };
  }
}
