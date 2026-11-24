/**
 * Live preview for a draft custom rule against the current session log.
 * Scans per physical line to match Worker detection (ARCHITECTURE §3.4 / §7.3).
 */

import { buildLineIndex } from '../../engine/lineIndex.ts'
import { detectCustomRules } from '../../engine/detectors/customRule.ts'
import { PRIORITY } from '../../domain/types.ts'
import type { CustomRule, RawMatch } from '../../domain/types.ts'
import { getSessionModel } from '../workspace/sessionModel.ts'
import type { RuleDraft } from './ruleValidation.ts'
import { ruleDraftIsSavable } from './ruleValidation.ts'

export interface RulePreviewSample {
  line: number
  before: string
  match: string
  after: string
  replacementPreview: string
  start: number
  end: number
}

export interface RuleCollision {
  with: 'builtin-or-other' | 'self-overlap'
  line: number
  detail: string
}

export interface RulePreviewResult {
  matchCount: number
  samples: RulePreviewSample[]
  collisions: RuleCollision[]
  ready: boolean
  truncated: boolean
}

const CONTEXT = 24
const MAX_SAMPLES = 3
const MAX_PREVIEW_LINES = 50_000

export function previewRuleDraft(draft: RuleDraft): RulePreviewResult {
  if (!ruleDraftIsSavable(draft) || !draft.pattern) {
    return { matchCount: 0, samples: [], collisions: [], ready: false, truncated: false }
  }

  const session = getSessionModel()
  const text = session?.original ?? ''
  if (!text) {
    return { matchCount: 0, samples: [], collisions: [], ready: true, truncated: false }
  }

  const rule: CustomRule = {
    id: draft.id ?? '__preview__',
    name: draft.name || 'preview',
    kind: draft.kind,
    pattern: draft.pattern,
    category: draft.category,
    enabled: true,
    priority: PRIORITY.customMin + 9999,
    caseSensitive: draft.caseSensitive,
    wholeWord: draft.wholeWord,
    replacementMode: draft.replacementMode,
    fixedReplacement:
      draft.replacementMode === 'fixed' ? draft.fixedReplacement : undefined,
  }

  const lineIndex = buildLineIndex(text)
  const lineLimit = Math.min(lineIndex.lineCount, MAX_PREVIEW_LINES)
  const truncated = lineIndex.lineCount > MAX_PREVIEW_LINES
  const matches: Array<RawMatch & { absStart: number; absEnd: number }> = []

  for (let line = 1; line <= lineLimit; line++) {
    const { start, end } = lineIndex.lineContentRange(line)
    const lineText = text.slice(start, end)
    const localIndex = buildLineIndex(lineText)
    const local = detectCustomRules(lineText, localIndex, {
      hostnameSuffixes: [],
      userIdPrefixes: [],
      internalIdPatterns: [],
      customRules: [rule],
    }).filter((m) => m.end > m.start)
    for (const m of local) {
      matches.push({
        ...m,
        line,
        absStart: start + m.start,
        absEnd: start + m.end,
        start: start + m.start,
        end: start + m.end,
      })
    }
  }

  const replacementPreview =
    draft.replacementMode === 'fixed' && draft.fixedReplacement
      ? draft.fixedReplacement
      : autoReplacementLabel(draft.category)

  const samples: RulePreviewSample[] = []
  for (const m of matches) {
    if (samples.length >= MAX_SAMPLES) break
    const before = text.slice(Math.max(0, m.absStart - CONTEXT), m.absStart)
    const after = text.slice(m.absEnd, Math.min(text.length, m.absEnd + CONTEXT))
    samples.push({
      line: m.line,
      before,
      match: text.slice(m.absStart, m.absEnd),
      after,
      replacementPreview,
      start: m.absStart,
      end: m.absEnd,
    })
  }

  const collisions: RuleCollision[] = []
  if (session) {
    const packed = session.packed
    for (const m of matches.slice(0, 200)) {
      for (let i = 0; i < packed.starts.length; i++) {
        const s = packed.starts[i]!
        const e = s + packed.lengths[i]!
        if (m.absStart < e && m.absEnd > s) {
          const ent = session.entities[packed.entityIndexes[i]!]
          collisions.push({
            with: 'builtin-or-other',
            line: m.line,
            detail: ent
              ? `Překryv s ${ent.category} „${ent.originalSample}“ (vyhraje vyšší priorita).`
              : 'Překryv s existujícím nálezem.',
          })
          break
        }
      }
      if (collisions.length >= 3) break
    }
  }

  return {
    matchCount: matches.length,
    samples,
    collisions,
    ready: true,
    truncated,
  }
}

function autoReplacementLabel(category: string): string {
  switch (category) {
    case 'ip':
      return '10.255.x.x'
    case 'hostname':
      return 'host-N.example.invalid'
    case 'email':
      return 'userN@example.invalid'
    case 'person':
      return 'Person N'
    case 'user-id':
      return 'account-N'
    case 'sip-phone':
      return '90000000N'
    case 'internal-id':
      return 'internal-N'
    case 'port':
      return ':49152'
    default:
      return 'custom-N'
  }
}
