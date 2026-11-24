import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { DEFAULT_DETECTOR_CONFIG } from '../../domain/types.ts'
import type { LineIndex } from '../lineIndex.ts'
import { detectIps } from './ip.ts'
import { detectHostnames } from './hostname.ts'
import { detectSipPhones } from './sipPhone.ts'
import { detectEmails } from './email.ts'
import { detectUserIds } from './userId.ts'
import { detectContextualPersons } from './contextualPerson.ts'
import { detectContextualIdentifiers } from './contextualIdentifier.ts'
import { detectCustomRules } from './customRule.ts'
import { detectPorts } from './port.ts'

export type DetectorFn = (
  text: string,
  lineIndex: LineIndex,
  config?: DetectorConfig,
) => RawMatch[]

export const BUILTIN_DETECTORS: DetectorFn[] = [
  detectIps,
  detectHostnames,
  detectSipPhones,
  detectEmails,
  detectUserIds,
  detectContextualPersons,
  detectContextualIdentifiers,
  detectPorts,
  detectCustomRules,
]

export function runAllDetectors(
  text: string,
  lineIndex: LineIndex,
  config: DetectorConfig = DEFAULT_DETECTOR_CONFIG,
): RawMatch[] {
  const all: RawMatch[] = []
  for (const detect of BUILTIN_DETECTORS) {
    const found = detect(text, lineIndex, config)
    // Avoid `push(...huge)` — stack overflow on 90MB / 250k+ match profiles.
    for (let i = 0; i < found.length; i++) all.push(found[i]!)
  }
  return all
}

export {
  detectIps,
  detectHostnames,
  detectSipPhones,
  detectEmails,
  detectUserIds,
  detectContextualPersons,
  detectContextualIdentifiers,
  detectCustomRules,
  detectPorts,
}
