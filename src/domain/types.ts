/** Domain model — ARCHITECTURE §6 */

export type Category =
  | 'ip'
  | 'hostname'
  | 'sip-phone'
  | 'email'
  | 'person'
  | 'user-id'
  | 'internal-id'
  | 'port'
  | 'custom'

export type EntitySource = 'builtin' | 'custom-rule'

export interface RawMatch {
  start: number
  end: number
  line: number
  category: Category
  original: string
  normalized: string
  detectorId: string
  ruleId?: string
  priority: number
  confidence: number
}

export interface ResolvedMatch extends RawMatch {
  entityKey: string
}

export interface Entity {
  key: string
  category: Category
  originalSample: string
  normalized: string
  replacement: string
  occurrenceCount: number
  occurrenceIndexes: Uint32Array
  enabled: boolean
  source: EntitySource
  sourceId: string
  createdOrder: number
}

export interface EntitySummary {
  key: string
  category: Category
  originalSample: string
  normalized: string
  replacement: string
  occurrenceCount: number
  enabled: boolean
  source: EntitySource
  sourceId: string
  createdOrder: number
}

export interface TransformSegment {
  originalFrom: number
  originalTo: number
  outputFrom: number
  outputTo: number
  line: number
  entityKey?: string
}

export interface PackedMatchIndex {
  starts: Uint32Array
  lengths: Uint32Array
  lines: Uint32Array
  entityIndexes: Uint32Array
  flags: Uint16Array
}

export interface OffsetMap {
  originalToOutput(originalOffset: number): number
  outputToOriginal(outputOffset: number): number
  updateMatch(matchIndex: number, lengthDelta: number): void
}

export type CustomRuleKind = 'literal' | 'regex'

export interface CustomRule {
  id: string
  name: string
  kind: CustomRuleKind
  pattern: string
  category: Category
  enabled: boolean
  /** Higher wins; custom rules start at 1000+. */
  priority: number
  caseSensitive?: boolean
  wholeWord?: boolean
  replacementMode: 'auto' | 'fixed'
  fixedReplacement?: string
}

export interface DetectorConfig {
  hostnameSuffixes: string[]
  userIdPrefixes: string[]
  internalIdPatterns: RegExp[]
  customRules: CustomRule[]
}

export const DEFAULT_DETECTOR_CONFIG: DetectorConfig = {
  hostnameSuffixes: ['.corp.example', '.vaf.local', '.example.local', '.example.invalid', '.local'],
  userIdPrefixes: ['disp'],
  internalIdPatterns: [/\bMP_[A-Za-z0-9_]+\b/g, /\bGRP_[A-Za-z0-9_]+\b/g],
  customRules: [],
}

/** Builtin detector priorities (custom rules use ≥ 1000). */
export const PRIORITY = {
  customMin: 1000,
  email: 90,
  person: 80,
  sipPhone: 70,
  userId: 65,
  internalId: 60,
  port: 55,
  ip: 50,
  hostname: 40,
} as const
