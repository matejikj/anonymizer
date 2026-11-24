import { describe, expect, it } from 'vitest'
import { DetectionSession } from '../../src/workers/detectionSession.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { FIXTURE_LOGS, readFixtureLog } from '../fixtures/loadFixtures.ts'
import { allMustNotLeakTokens } from '../fixtures/mustNotLeak.ts'
import { fromTransferableBuffers } from '../../src/engine/packedMatchIndex.ts'
import { transformWithPlan, buildReplacementPlan } from '../../src/engine/transform.ts'
import { entityKeyToIndex, packResolvedMatches } from '../../src/engine/packedMatchIndex.ts'
import { resolveOverlaps } from '../../src/engine/resolveOverlaps.ts'
import { buildEntityMapFromSnapshot } from '../../src/engine/entityRegistry.ts'
import { MappingAuthority } from '../../src/mapping/mappingAuthority.ts'
import { collectTextIdentities } from '../../src/mapping/textIdentity.ts'
import { rulesetToDetectorConfig } from '../../src/domain/configSchema.ts'
import { detectOnPhysicalLine } from '../../src/engine/detectLine.ts'
import { createLineAssembler, pushText } from '../../src/features/import-log/streamingDecode.ts'

describe('Krok 3 fixture streaming detection', () => {
  for (const name of FIXTURE_LOGS) {
    it(`streams ${name} without leaking curated tokens`, () => {
      const original = readFixtureLog(name)
      const session = new DetectionSession({
        onProgress: () => {},
        onRuleStarted: () => {},
        onHeartbeat: () => {},
      })
      session.start('fix', createDefaultRulesetConfig())

      // Multi-chunk like the Worker path
      const chunk = Math.ceil(original.length / 5)
      for (let i = 0; i < original.length; i += chunk) {
        const end = Math.min(original.length, i + chunk)
        session.pushTextChunk(original.slice(i, end), end >= original.length)
      }
      const out = session.finalizeDetection()
      expect(out.lineCount).toBeGreaterThan(100)

      // Rebuild anonymized via packed plan
      const assembler = createLineAssembler()
      const { lines } = pushText(assembler, original, true)
      const config = rulesetToDetectorConfig(createDefaultRulesetConfig())
      const builtins = createDefaultRulesetConfig().profile.builtins
      const raw = lines.flatMap((l) =>
        detectOnPhysicalLine(l.text, l.line, l.start, config, builtins),
      )
      const matches = resolveOverlaps(raw)
      const authority = new MappingAuthority()
      const identities = collectTextIdentities(matches, 'fixture')
      const resolved = authority.resolve({
        generationId: 'fixture',
        sourceId: 'fixture',
        identities,
      })
      expect(resolved.ok).toBe(true)
      if (!resolved.ok) return
      const { entities, byKey } = buildEntityMapFromSnapshot(matches, resolved.snapshot, config.customRules)
      const packed = packResolvedMatches(matches, entityKeyToIndex(entities), (k) =>
        byKey.get(k)?.enabled ?? true,
      )
      const plan = buildReplacementPlan(packed, entities)
      const anonymized = transformWithPlan(original, packed, plan)

      const present = allMustNotLeakTokens().filter((t) => original.includes(t))
      for (const token of present) {
        expect(anonymized.includes(token), `leaked ${token} in ${name}`).toBe(false)
      }

      const transferred = fromTransferableBuffers(out.packedMatches)
      expect(transferred.starts.length).toBe(matches.length)
    })
  }
})
