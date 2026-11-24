export interface SdpParseLimits {
  readonly maxSessionBytes: number;
  readonly maxLineBytes: number;
  readonly maxMediaSections: number;
  readonly maxAttributesPerSection: number;
  readonly maxCandidatesPerMedia: number;
}

export const DEFAULT_SDP_PARSE_LIMITS: SdpParseLimits = {
  maxSessionBytes: 65_536,
  maxLineBytes: 4_096,
  maxMediaSections: 32,
  maxAttributesPerSection: 128,
  maxCandidatesPerMedia: 64,
};
