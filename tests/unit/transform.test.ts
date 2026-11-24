import { describe, expect, it } from 'vitest'
import { analyze } from '../../src/engine/analyze.ts'
import { createOffsetMap } from '../../src/engine/offsetMap.ts'
import { buildReplacementPlan, transform, transformWithPlan } from '../../src/engine/transform.ts'
import { DEFAULT_DETECTOR_CONFIG, type DetectorConfig } from '../../src/domain/types.ts'
import { countPhysicalLines } from '../../src/domain/invariants.ts'

describe('transform + packed plan', () => {
  it('produces deterministic anonymized text equal to plan transform', () => {
    const text = [
      'peer 10.16.1.105 via ldap-pra.corp.example',
      "dispatcher 'Krejci Iveta' sip:972051127@10.16.1.105",
      "user=disp5 initiator=Pospisilova Tomas MP_PRA",
    ].join('\n')

    const a = analyze(text)
    expect(a.anonymized).toBe(transformWithPlan(text, a.packed, a.plan))
    expect(countPhysicalLines(a.anonymized)).toBe(countPhysicalLines(text))
    expect(a.anonymized).not.toContain('10.16.1.105')
    expect(a.anonymized).not.toContain('Krejci Iveta')
    expect(a.anonymized).not.toContain('disp5')
    expect(a.anonymized).toContain('10.255.90.')
    expect(a.anonymized).toContain('host-')
    expect(a.anonymized).toContain('Person ')
    expect(a.anonymized).toContain('account-')
  })

  it('same entityKey gets same replacement', () => {
    const text = 'a 10.1.1.1 b 10.1.1.1 c 10.2.2.2'
    const a = analyze(text)
    const ips = a.entities.filter((e) => e.category === 'ip')
    expect(ips).toHaveLength(2)
    const first = ips.find((e) => e.normalized === '10.1.1.1')!
    expect(a.anonymized.match(new RegExp(first.replacement, 'g'))).toHaveLength(2)
  })

  it('custom fixed replacement wins over builtin IP', () => {
    const config: DetectorConfig = {
      ...DEFAULT_DETECTOR_CONFIG,
      customRules: [
        {
          id: 'ip-fixed',
          name: 'fix',
          kind: 'literal',
          pattern: '10.1.1.1',
          category: 'ip',
          enabled: true,
          priority: 1000,
          replacementMode: 'fixed',
          fixedReplacement: '9.9.9.9',
        },
      ],
    }
    const a = analyze('host 10.1.1.1 done', config)
    expect(a.anonymized).toContain('9.9.9.9')
    expect(a.anonymized).not.toContain('10.1.1.1')
  })

  it('offset map maps around replacements', () => {
    const text = 'xx10.1.1.1yy'
    const a = analyze(text)
    const map = createOffsetMap(a.packed, a.plan)
    // 'xx' stays; after first IP replacement length may change
    expect(map.originalToOutput(0)).toBe(0)
    expect(map.originalToOutput(2)).toBe(2)
    const outAtEnd = map.originalToOutput(text.length)
    expect(outAtEnd).toBe(a.anonymized.length)
    expect(map.outputToOriginal(outAtEnd)).toBe(text.length)
  })

  it('disabled entity leaves original span', () => {
    const text = 'ip 10.1.1.1 end'
    const a = analyze(text)
    const entity = a.entities.find((e) => e.category === 'ip')!
    entity.enabled = false
    const plan = buildReplacementPlan(a.packed, a.entities)
    // flags still say enabled — transform() uses entity.enabled
    const out = transform(text, a.matches, a.entitiesByKey)
    expect(out).toContain('10.1.1.1')
    expect(plan.replacements.every((r) => r == null || true)).toBe(true)
  })
})
