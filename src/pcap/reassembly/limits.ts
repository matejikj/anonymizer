import type { ReassemblyLimits } from './types';

/** Keep in sync with sanitize/tunnel MAX_TUNNEL_DEPTH (avoid circular import). */
const TUNNEL_DEPTH_LIMIT = 4;

export const DEFAULT_REASSEMBLY_LIMITS: ReassemblyLimits = {
  maxConcurrentFlows: 256,
  maxBytesPerFlow: 256 * 1024,
  maxDatagramBytes: 65535,
  maxFragmentGroups: 256,
  maxSipProbeBytes: 512,
  maxHttpProbeBytes: 1024,
  maxHttpDecodedSize: 256 * 1024,
  maxMultipartParts: 64,
  maxParserNesting: 32,
  maxTunnelDepth: TUNNEL_DEPTH_LIMIT,
  maxSctpAssociations: 256,
  maxSctpMessagesPerAssociation: 512,
  maxSctpMessageBytes: 256 * 1024,
  maxSctpFragmentsPerMessage: 64,
};
