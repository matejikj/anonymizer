import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it } from 'vitest'
import { BUILTIN_UNIFIED_PROFILE_ID } from '../../src/domain/configSchema.ts'
import { closeRndLogAnonymizerDb, deleteRndLogAnonymizerDatabase } from '../../src/persistence/idb.ts'
import {
  ensureDefaultProfile,
  getStoredProfile,
  listStoredProfiles,
  putStoredProfile,
  deleteStoredProfile,
  clearAllRndLogAnonymizerData,
} from '../../src/persistence/profileRepository.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'

describe('profileRepository (Krok 8)', () => {
  beforeEach(async () => {
    await closeRndLogAnonymizerDb()
    await deleteRndLogAnonymizerDatabase()
  })

  it('stores profiles without accepting log-like blobs in the API', async () => {
    const def = await ensureDefaultProfile()
    expect(def.id).toBe(BUILTIN_UNIFIED_PROFILE_ID)
    expect(def.config).not.toHaveProperty('pcapProfile')
    expect(JSON.stringify(def.config)).not.toMatch(/pcapProfile|mediaPolicy|preservePacketLengths/)

    const cfg = createDefaultRulesetConfig()
    cfg.profile.id = 'team-a'
    cfg.profile.name = 'Team A'
    cfg.profile.rules.push({
      id: 'r1',
      name: 'Secret',
      enabled: true,
      kind: 'literal',
      pattern: 'SECRET',
      category: 'custom',
      replacement: { kind: 'generated' },
    })
    await putStoredProfile(cfg)
    const list = await listStoredProfiles()
    expect(list.map((p) => p.id).sort()).toEqual([BUILTIN_UNIFIED_PROFILE_ID, 'team-a'])
    const loaded = await getStoredProfile('team-a')
    expect(loaded?.config.profile.rules[0]?.pattern).toBe('SECRET')
    expect(JSON.stringify(loaded)).not.toMatch(/original|anonymized|packedMatches/)
  })

  it('deletes profiles and can wipe the whole DB', async () => {
    await ensureDefaultProfile()
    const cfg = createDefaultRulesetConfig()
    cfg.profile.id = 'tmp'
    cfg.profile.name = 'Tmp'
    await putStoredProfile(cfg)
    await deleteStoredProfile('tmp')
    expect(await getStoredProfile('tmp')).toBeUndefined()
    await clearAllRndLogAnonymizerData()
    const again = await ensureDefaultProfile()
    expect(again.id).toBe(BUILTIN_UNIFIED_PROFILE_ID)
    expect(await listStoredProfiles()).toHaveLength(1)
  })

  it('detaches a renamed built-in into a deletable profile and restores bundled default', async () => {
    const renamed = createDefaultRulesetConfig()
    renamed.profile.id = BUILTIN_UNIFIED_PROFILE_ID
    renamed.profile.name = 'Zkouska'
    renamed.profile.rules.push({
      id: 'r1',
      name: 'Keep me',
      enabled: true,
      kind: 'literal',
      pattern: 'KEEP',
      category: 'custom',
      replacement: { kind: 'generated' },
    })
    await putStoredProfile(renamed)

    const restored = await ensureDefaultProfile()
    expect(restored.id).toBe(BUILTIN_UNIFIED_PROFILE_ID)
    expect(restored.name).toContain('RND Team')

    const list = await listStoredProfiles()
    expect(list.some((p) => p.id === BUILTIN_UNIFIED_PROFILE_ID)).toBe(true)
    const detached = list.find((p) => p.id !== BUILTIN_UNIFIED_PROFILE_ID)
    expect(detached?.name).toBe('Zkouska')
    expect(detached?.config.profile.rules[0]?.pattern).toBe('KEEP')
  })

  it('removes legacy id=default profile so only RND Team remains built-in', async () => {
    await ensureDefaultProfile()
    const legacy = createDefaultRulesetConfig()
    legacy.profile.id = 'default'
    legacy.profile.name = 'Výchozí'
    await putStoredProfile(legacy)

    expect(await getStoredProfile('default')).toBeDefined()
    await ensureDefaultProfile()
    expect(await getStoredProfile('default')).toBeUndefined()
    const list = await listStoredProfiles()
    expect(list.filter((p) => p.id === BUILTIN_UNIFIED_PROFILE_ID)).toHaveLength(1)
    expect(list.some((p) => p.name === 'Výchozí')).toBe(false)
  })
})
