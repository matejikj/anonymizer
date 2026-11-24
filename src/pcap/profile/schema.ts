/**
 * Slim PCAP mapping types.
 * Editable PCAP profile ruleset (Zod URN/version/import/export) was removed —
 * only two built-in anonymization levels remain.
 */

export type {
  PcapAnonymizationLevel,
  PcapMapping,
  PcapProtocols,
  PcapLevelDefinition,
} from './pcapAnonymizationLevel'

export type { DerivedPcapPolicyView as PcapProfile } from './presets'

export type PcapMediaPolicy = 'strip-payload' | 'drop' | 'preserve-unsafe'
export type PcapUnsupportedPayloadPolicy = 'mask-in-place' | 'truncate' | 'preserve-unsafe'
export type PcapMalformedPayloadPolicy =
  | 'mask-application-in-place'
  | 'drop'
  | 'preserve-unsafe'
