/**
 * Profile repository — IndexedDB only, never log content (ARCHITECTURE §9.2 / Krok 8).
 */

import {
  BUILTIN_UNIFIED_PROFILE_ID,
  createDefaultRulesetConfig,
  type RulesetConfig,
} from '../domain/configSchema.ts'
import { cloneRulesetConfig, parseRulesetJsonText } from '../domain/rulesetValidate.ts'
import {
  openRndLogAnonymizerDb,
  type StoredProfile,
} from './idb.ts'
import bundledTeamProduction from '../../profiles/rnd-team-production.json'

export type { StoredProfile }

function loadBuiltinUnifiedProfile(): RulesetConfig {
  const parsed = parseRulesetJsonText(JSON.stringify(bundledTeamProduction))
  if (parsed.ok) {
    return cloneRulesetConfig(parsed.config)
  }
  const fallback = createDefaultRulesetConfig()
  fallback.profile.id = BUILTIN_UNIFIED_PROFILE_ID
  fallback.profile.name = 'RND Team — Production'
  fallback.schemaVersion = 2
  return fallback
}

export async function listStoredProfiles(): Promise<StoredProfile[]> {
  const db = await openRndLogAnonymizerDb()
  const all = await db.getAll('profiles')
  return all.sort((a, b) => b.updatedAt - a.updatedAt)
}

export async function getStoredProfile(id: string): Promise<StoredProfile | undefined> {
  const db = await openRndLogAnonymizerDb()
  return db.get('profiles', id)
}

export async function putStoredProfile(config: RulesetConfig): Promise<StoredProfile> {
  const db = await openRndLogAnonymizerDb()
  const existing = await db.get('profiles', config.profile.id)
  const now = Date.now()
  const row: StoredProfile = {
    id: config.profile.id,
    name: config.profile.name,
    config: cloneRulesetConfig(config),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  }
  await db.put('profiles', row)
  return row
}

export async function deleteStoredProfile(id: string): Promise<void> {
  const db = await openRndLogAnonymizerDb()
  await db.delete('profiles', id)
}

export async function ensureDefaultProfile(): Promise<StoredProfile> {
  const factory = loadBuiltinUnifiedProfile()
  const existing = await getStoredProfile(BUILTIN_UNIFIED_PROFILE_ID)
  let restored: StoredProfile
  if (!existing) {
    restored = await putStoredProfile(factory)
  } else {
    const factoryName = factory.profile.name
    const storedName = existing.name || existing.config.profile.name
    const configName = existing.config.profile.name
    // Built-in default must stay singular and undeletable. If it was renamed,
    // detach that copy into a normal profile and restore the bundled default.
    if (storedName === factoryName && configName === factoryName) {
      restored = existing
    } else {
      const detached = cloneRulesetConfig(existing.config)
      detached.profile.id = `profile-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
      detached.profile.name = storedName || configName
      const detachedRow = await putStoredProfile(detached)
      restored = await putStoredProfile(factory)

      const lastId = (await getIdbPreference(PREF_LAST_PROFILE_ID)) as string | undefined
      if (!lastId || lastId === BUILTIN_UNIFIED_PROFILE_ID || lastId === 'default') {
        await setIdbPreference(PREF_LAST_PROFILE_ID, detachedRow.id)
      }
    }
  }

  // Drop legacy built-in id from older installs so the selector shows only RND Team.
  const legacyDefault = await getStoredProfile('default')
  if (legacyDefault) {
    await deleteStoredProfile('default')
    const lastId = (await getIdbPreference(PREF_LAST_PROFILE_ID)) as string | undefined
    if (lastId === 'default') {
      await setIdbPreference(PREF_LAST_PROFILE_ID, BUILTIN_UNIFIED_PROFILE_ID)
    }
  }

  return restored
}

export async function getIdbPreference(key: string): Promise<unknown | undefined> {
  const db = await openRndLogAnonymizerDb()
  const row = await db.get('preferences', key)
  return row?.value
}

export async function setIdbPreference(key: string, value: unknown): Promise<void> {
  const db = await openRndLogAnonymizerDb()
  await db.put('preferences', { key, value })
}

export async function clearAllRndLogAnonymizerData(): Promise<void> {
  const db = await openRndLogAnonymizerDb()
  const tx = db.transaction(['profiles', 'preferences'], 'readwrite')
  await tx.objectStore('profiles').clear()
  // Shared preferences store — only drop the text profile pointer; leave PCAP prefs alone.
  await tx.objectStore('preferences').delete(PREF_LAST_PROFILE_ID)
  await tx.done
}

export const PREF_LAST_PROFILE_ID = 'lastProfileId'
