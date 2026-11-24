import 'fake-indexeddb/auto'
import { beforeEach, describe, expect, it } from 'vitest'
import { openDB } from 'idb'
import { DB_NAME, DB_VERSION } from '../../src/persistence/db.ts'
import {
  closeRndLogAnonymizerDb,
  deleteRndLogAnonymizerDatabase,
  openRndLogAnonymizerDb,
  type StoredProfile,
} from '../../src/persistence/idb.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { clearAllRndLogAnonymizerData } from '../../src/persistence/profileRepository.ts'

async function seedV1Database(profile: StoredProfile): Promise<void> {
  await closeRndLogAnonymizerDb()
  await deleteRndLogAnonymizerDatabase()

  const db = await openDB(DB_NAME, 1, {
    upgrade(database) {
      const store = database.createObjectStore('profiles', { keyPath: 'id' })
      store.createIndex('by-updated', 'updatedAt')
      database.createObjectStore('preferences', { keyPath: 'key' })
    },
  })
  await db.put('profiles', profile)
  await db.put('preferences', { key: 'activeProfileId', value: profile.id })
  db.close()
}

async function seedV2DatabaseWithPcap(profile: StoredProfile): Promise<void> {
  await closeRndLogAnonymizerDb()
  await deleteRndLogAnonymizerDatabase()

  const db = await openDB(DB_NAME, 2, {
    upgrade(database, oldVersion) {
      if (oldVersion < 1) {
        const store = database.createObjectStore('profiles', { keyPath: 'id' })
        store.createIndex('by-updated', 'updatedAt')
        database.createObjectStore('preferences', { keyPath: 'key' })
      }
      if (oldVersion < 2) {
        const pcapStore = database.createObjectStore('pcapProfiles', { keyPath: 'id' })
        pcapStore.createIndex('by-updated', 'updatedAt')
      }
    },
  })
  await db.put('profiles', profile)
  await db.put('pcapProfiles', {
    id: 'pcap-lab',
    name: 'Lab',
    config: { id: 'pcap-lab', name: 'Lab', preset: 'diagnostic' },
    createdAt: 1,
    updatedAt: 1,
  })
  db.close()
}

describe('IndexedDB migration to v3 (text-only profiles)', () => {
  beforeEach(async () => {
    await closeRndLogAnonymizerDb()
    await deleteRndLogAnonymizerDatabase()
  })

  it('upgrades v1 text-only DB to v3 and keeps text profiles', async () => {
    const cfg = createDefaultRulesetConfig()
    cfg.profile.id = 'legacy-team'
    cfg.profile.name = 'Legacy Team'
    const seeded: StoredProfile = {
      id: 'legacy-team',
      name: 'Legacy Team',
      config: cfg,
      createdAt: 1_700_000_000_000,
      updatedAt: 1_700_000_000_100,
    }
    await seedV1Database(seeded)

    const db = await openRndLogAnonymizerDb()
    expect(db.version).toBe(DB_VERSION)
    expect([...db.objectStoreNames].sort()).toEqual(['preferences', 'profiles'])

    const text = await db.get('profiles', 'legacy-team')
    expect(text?.name).toBe('Legacy Team')
  })

  it('drops legacy pcapProfiles store when upgrading v2 → v3', async () => {
    const cfg = createDefaultRulesetConfig()
    cfg.profile.id = 'team'
    const seeded: StoredProfile = {
      id: 'team',
      name: 'Team',
      config: cfg,
      createdAt: 1,
      updatedAt: 1,
    }
    await seedV2DatabaseWithPcap(seeded)

    const db = await openRndLogAnonymizerDb()
    expect(db.version).toBe(3)
    expect([...db.objectStoreNames]).not.toContain('pcapProfiles')
    expect(await db.get('profiles', 'team')).toBeDefined()
  })

  it('clear data wipes text profiles only; PCAP runtime level is not stored', async () => {
    const textCfg = createDefaultRulesetConfig()
    textCfg.profile.id = 'wipe-me'
    textCfg.profile.name = 'Wipe'
    const db = await openRndLogAnonymizerDb()
    await db.put('profiles', {
      id: 'wipe-me',
      name: 'Wipe',
      config: textCfg,
      createdAt: 1,
      updatedAt: 1,
    })

    await clearAllRndLogAnonymizerData()

    const again = await openRndLogAnonymizerDb()
    expect(again.version).toBe(DB_VERSION)
    expect(await again.getAll('profiles')).toEqual([])
    expect([...again.objectStoreNames]).not.toContain('pcapProfiles')
    expect(await again.getAll('preferences')).toEqual([])
  })

  it('deleteDatabase is a full rollback; next open recreates v3 without pcapProfiles', async () => {
    await openRndLogAnonymizerDb()
    await deleteRndLogAnonymizerDatabase()

    const reopened = await openRndLogAnonymizerDb()
    expect(reopened.version).toBe(3)
    expect([...reopened.objectStoreNames]).toEqual(['preferences', 'profiles'])
  })
})
