import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { PRIORITY } from '../../domain/types.ts'
import { normalizePerson } from '../normalize.ts'

/**
 * Contextual person names (ARCHITECTURE §7.1):
 * - dispatcher 'First Last'
 * - user=First Last / initiator=First Last
 * - parenthetical after login is optional; fixtures use dispatcher / user= / initiator=
 */
/** Two+ Title-Case words — avoids swallowing trailing keys like `group=`. */
const PERSON_NAME =
  "([A-ZÁ-ŽÄÖÜ][A-Za-zÁ-žäöüÄÖÜß'-]*(?:\\s+[A-ZÁ-ŽÄÖÜ][A-Za-zÁ-žäöüÄÖÜß'-]*)+)"

const PATTERNS: RegExp[] = [
  new RegExp(`dispatcher\\s+'${PERSON_NAME}'`, 'gi'),
  // Parentheses after a quoted login: user 'disp4' (Prochazka Karel)
  new RegExp(`'[^']+'\\s+\\(${PERSON_NAME}\\)`, 'gi'),
  new RegExp(`\\buser=${PERSON_NAME}(?=[\\s,;'"\\]|]|$)`, 'gi'),
  new RegExp(`\\binitiator=${PERSON_NAME}(?=[\\s,;'"\\]|]|$)`, 'gi'),
]

export function detectContextualPersons(
  text: string,
  lineIndex: LineIndex,
  _config?: DetectorConfig,
): RawMatch[] {
  const out: RawMatch[] = []
  const seen = new Set<string>()

  for (const re of PATTERNS) {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const name = m[1]!
      const full = m[0]
      const start = m.index + full.indexOf(name)
      const end = start + name.length
      const key = `${start}:${end}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({
        start,
        end,
        line: lineIndex.lineAt(start),
        category: 'person',
        original: name,
        normalized: normalizePerson(name),
        detectorId: 'builtin.contextualPerson',
        priority: PRIORITY.person,
        confidence: 0.9,
      })
    }
  }
  return out
}
