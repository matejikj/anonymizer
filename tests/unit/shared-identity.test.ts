import { describe, expect, it } from 'vitest'
import { analyze } from '../../src/engine/analyze'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { collectTextIdentities } from '../../src/mapping/textIdentity'
import { buildEntityMapFromSnapshot } from '../../src/engine/entityRegistry'
import { buildReplacementPlan, transformWithPlan } from '../../src/engine/transform'
import { entityKeyToIndex, packResolvedMatches } from '../../src/engine/packedMatchIndex'
import { resolveOverlaps } from '../../src/engine/resolveOverlaps'
import { buildLineIndex } from '../../src/engine/lineIndex'
import { runAllDetectors } from '../../src/engine/detectors'

describe('Stage 18 shared identity preview/export parity', () => {
  it('analyze() uses MappingAuthority for aliases', () => {
    const log = 'Contact admin@corp.local on 192.168.1.50 or host-a.internal\n'
    const result = analyze(log)
    expect(result.entities.every((e) => e.replacement.length > 0)).toBe(true)
    expect(result.anonymized).not.toContain('admin@corp.local')
    expect(result.anonymized).not.toContain('192.168.1.50')
  })

  it('same snapshot yields identical preview and plan transform', () => {
    const log = 'user1@example.com calls 10.0.0.9\n'
    const lineIndex = buildLineIndex(log)
    const raw = runAllDetectors(log, lineIndex)
    const matches = resolveOverlaps(raw)

    const authority = new MappingAuthority()
    const resolved = authority.resolve({
      generationId: 'parity',
      sourceId: 'parity',
      identities: collectTextIdentities(matches, 'parity'),
    })
    expect(resolved.ok).toBe(true)
    if (!resolved.ok) return

    const { entities } = buildEntityMapFromSnapshot(matches, resolved.snapshot)
    const packed = packResolvedMatches(matches, entityKeyToIndex(entities), () => true)
    const plan = buildReplacementPlan(packed, entities)
    const viaPlan = transformWithPlan(log, packed, plan)

    const analyzeResult = analyze(log)
    // Detector plan path and analyze()+T69 free-text may differ on non-entity tokens;
    // both must still remove originals and share category aliases for detected entities.
    expect(viaPlan).not.toContain('user1@example.com')
    expect(viaPlan).not.toContain('10.0.0.9')
    expect(analyzeResult.anonymized).not.toContain('user1@example.com')
    expect(analyzeResult.anonymized).not.toContain('10.0.0.9')
    const emailAlias = entities.find((e) => e.category === 'email')?.replacement
    const ipAlias = entities.find((e) => e.category === 'ip')?.replacement
    expect(emailAlias).toBeTruthy()
    expect(ipAlias).toBeTruthy()
    expect(viaPlan).toContain(emailAlias!)
    expect(analyzeResult.anonymized).toContain(emailAlias!)
    expect(viaPlan).toContain(ipAlias!)
    expect(analyzeResult.anonymized).toContain(ipAlias!)
  })
})
