import { describe, expect, it, beforeEach } from 'vitest'
import {
  emptyRuleDraft,
  validateRuleDraft,
  ruleDraftIsSavable,
  regexCanMatchEmpty,
  suggestRuleName,
  draftToRulesetRule,
  type RuleDraft,
} from '../../src/features/rules/ruleValidation.ts'
import { previewRuleDraft } from '../../src/features/rules/rulePreview.ts'
import { buildSessionModel, clearSessionModel } from '../../src/features/workspace/sessionModel.ts'
import { analyze } from '../../src/engine/analyze.ts'
import {
  packResolvedMatches,
  toTransferableBuffers,
  entityKeyToIndex,
} from '../../src/engine/packedMatchIndex.ts'
import { resetActiveProfile, replaceActiveRules } from '../../src/features/rules/activeProfile.ts'

function draft(partial: Partial<RuleDraft> = {}): RuleDraft {
  return { ...emptyRuleDraft(), name: 'Test', pattern: 'SECRET', ...partial }
}

describe('ruleValidation (Krok 7)', () => {
  it('requires name and pattern', () => {
    const issues = validateRuleDraft(emptyRuleDraft())
    expect(issues.some((i) => i.code === 'name-required')).toBe(true)
    expect(issues.some((i) => i.code === 'pattern-required')).toBe(true)
    expect(ruleDraftIsSavable(emptyRuleDraft())).toBe(false)
  })

  it('rejects regex with surrounding slashes and zero-length', () => {
    expect(
      validateRuleDraft(draft({ kind: 'regex', pattern: '/abc/' })).some(
        (i) => i.code === 'regex-slashes',
      ),
    ).toBe(true)
    expect(regexCanMatchEmpty('a*', true)).toBe(true)
    expect(
      validateRuleDraft(draft({ kind: 'regex', pattern: 'a*' })).some(
        (i) => i.code === 'zero-length',
      ),
    ).toBe(true)
    expect(ruleDraftIsSavable(draft({ kind: 'regex', pattern: 'token=[A-Za-z0-9]+' }))).toBe(true)
  })

  it('rejects newlines and invalid regex syntax', () => {
    expect(
      validateRuleDraft(draft({ pattern: 'a\nb' })).some((i) => i.code === 'pattern-newline'),
    ).toBe(true)
    expect(
      validateRuleDraft(draft({ kind: 'regex', pattern: '(unclosed' })).some(
        (i) => i.code === 'regex-syntax',
      ),
    ).toBe(true)
  })

  it('warns on fixed replacement collapsing values', () => {
    const issues = validateRuleDraft(
      draft({ replacementMode: 'fixed', fixedReplacement: 'X' }),
    )
    expect(issues.some((i) => i.code === 'fixed-collapses' && i.severity === 'warning')).toBe(true)
    expect(ruleDraftIsSavable(draft({ replacementMode: 'fixed', fixedReplacement: 'X' }))).toBe(
      true,
    )
  })

  it('suggests name and maps draft to ruleset rule', () => {
    expect(suggestRuleName({ kind: 'literal', pattern: 'ABC' })).toBe('Literal: ABC')
    const rule = draftToRulesetRule(
      draft({
        kind: 'regex',
        pattern: 'CODE-\\d+',
        replacementMode: 'fixed',
        fixedReplacement: 'REDACTED',
      }),
      'rule-1',
      1001,
    )
    expect(rule.id).toBe('rule-1')
    expect(rule.priority).toBe(1001)
    expect(rule.replacement).toEqual({ kind: 'fixed', value: 'REDACTED' })
  })
})

describe('rulePreview (Krok 7)', () => {
  beforeEach(() => {
    clearSessionModel()
    resetActiveProfile()
  })

  it('counts matches and returns up to 3 samples', () => {
    const text = [
      'alpha SECRET_TOKEN beta',
      'SECRET_TOKEN again',
      'third SECRET_TOKEN here',
      'fourth SECRET_TOKEN',
      'noise',
    ].join('\n')
    const result = analyze(text)
    const entityIndexByKey = entityKeyToIndex(result.entities)
    const packed = packResolvedMatches(result.matches, entityIndexByKey, () => true)
    const { buffers } = toTransferableBuffers(packed)
    buildSessionModel({
      text,
      detection: {
        requestId: 't',
        packedMatches: buffers,
        entities: result.entitySummaries,
        lineCount: result.lineCount,
        failedRuleIds: [],
      },
      fileName: 't.log',
      byteLength: text.length,
      mode: 'common',
      workerPlanTrusted: false,
    })

    const preview = previewRuleDraft(
      draft({
        name: 'secret',
        pattern: 'SECRET_TOKEN',
        kind: 'literal',
        replacementMode: 'fixed',
        fixedReplacement: 'REDACTED',
      }),
    )
    expect(preview.ready).toBe(true)
    expect(preview.matchCount).toBe(4)
    expect(preview.samples).toHaveLength(3)
    expect(preview.samples[0]!.match).toBe('SECRET_TOKEN')
    expect(preview.samples[0]!.replacementPreview).toBe('REDACTED')
  })

  it('reports collisions with existing packed matches', () => {
    const text = 'peer 10.16.1.105 ready'
    const result = analyze(text)
    const entityIndexByKey = entityKeyToIndex(result.entities)
    const packed = packResolvedMatches(result.matches, entityIndexByKey, () => true)
    const { buffers } = toTransferableBuffers(packed)
    buildSessionModel({
      text,
      detection: {
        requestId: 't2',
        packedMatches: buffers,
        entities: result.entitySummaries,
        lineCount: result.lineCount,
        failedRuleIds: [],
      },
      fileName: 't2.log',
      byteLength: text.length,
      mode: 'common',
      workerPlanTrusted: false,
    })

    const preview = previewRuleDraft(
      draft({
        name: 'ip-literal',
        pattern: '10.16.1.105',
        kind: 'literal',
      }),
    )
    expect(preview.matchCount).toBe(1)
    expect(preview.collisions.length).toBeGreaterThan(0)
  })
})

describe('activeProfile rules replace', () => {
  beforeEach(() => {
    resetActiveProfile()
  })

  it('stores rules in memory profile', () => {
    const rule = draftToRulesetRule(draft({ name: 'A', pattern: 'AAA' }), 'r-a', 1001)
    replaceActiveRules([rule])
    expect(replaceActiveRules([rule]).profile.rules).toHaveLength(1)
  })
})
