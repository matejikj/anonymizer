/**
 * Run builtin + custom detectors on a single physical line and remap to absolute offsets.
 */

import type { DetectorConfig, RawMatch } from '../domain/types.ts'
import type { RulesetBuiltinToggles } from '../domain/configSchema.ts'
import { buildLineIndex } from '../engine/lineIndex.ts'
import {
  detectContextualIdentifiers,
  detectContextualPersons,
  detectCustomRules,
  detectEmails,
  detectHostnames,
  detectIps,
  detectPorts,
  detectSipPhones,
  detectUserIds,
} from '../engine/detectors/index.ts'

export function detectOnPhysicalLine(
  lineText: string,
  lineNumber: number,
  absoluteStart: number,
  config: DetectorConfig,
  builtins: RulesetBuiltinToggles,
): RawMatch[] {
  if (lineText.length === 0) return []
  const lineIndex = buildLineIndex(lineText)
  const raw: RawMatch[] = []

  if (builtins.ip) raw.push(...detectIps(lineText, lineIndex, config))
  if (builtins.hostname) raw.push(...detectHostnames(lineText, lineIndex, config))
  if (builtins['sip-phone']) raw.push(...detectSipPhones(lineText, lineIndex, config))
  if (builtins.email) raw.push(...detectEmails(lineText, lineIndex, config))
  if (builtins['user-id']) raw.push(...detectUserIds(lineText, lineIndex, config))
  if (builtins.person) raw.push(...detectContextualPersons(lineText, lineIndex, config))
  if (builtins['internal-id']) {
    raw.push(...detectContextualIdentifiers(lineText, lineIndex, config))
  }
  if (builtins.port) raw.push(...detectPorts(lineText, lineIndex, config))
  raw.push(...detectCustomRules(lineText, lineIndex, config))

  return raw.map((m) => ({
    ...m,
    start: m.start + absoluteStart,
    end: m.end + absoluteStart,
    line: lineNumber,
  }))
}
