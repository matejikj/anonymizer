/**
 * IndexedDB database `rnd-log-anonymizer` v3 (ARCHITECTURE §9.2).
 * Never stores log content, matches, session replacements, or mapping secrets.
 *
 * v1 → v2: added `pcapProfiles` store (removed in v3).
 * v2 → v3: drops `pcapProfiles` — PCAP uses runtime level only, not persisted profiles.
 */

import { openDB, type DBSchema, type IDBPDatabase } from 'idb'
import type { RulesetConfig } from '../domain/configSchema.ts'
import { DB_NAME, DB_VERSION } from './db.ts'

export interface StoredProfile {
  id: string
  name: string
  config: RulesetConfig
  createdAt: number
  updatedAt: number
}

export interface RndLogAnonymizerDB extends DBSchema {
  profiles: {
    key: string
    value: StoredProfile
    indexes: { 'by-updated': number }
  }
  preferences: {
    key: string
    value: { key: string; value: unknown }
  }
}

let dbPromise: Promise<IDBPDatabase<RndLogAnonymizerDB>> | null = null

export function openRndLogAnonymizerDb(): Promise<IDBPDatabase<RndLogAnonymizerDB>> {
  if (!dbPromise) {
    dbPromise = openDB<RndLogAnonymizerDB>(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion) {
        if (oldVersion < 1) {
          const store = db.createObjectStore('profiles', { keyPath: 'id' })
          store.createIndex('by-updated', 'updatedAt')
          db.createObjectStore('preferences', { keyPath: 'key' })
        }
        // v2 briefly had pcapProfiles — remove on upgrade to v3.
        // Typed schema no longer lists the store; cast for legacy upgrade path.
        if (oldVersion < 3) {
          const stores = db.objectStoreNames as DOMStringList
          if (stores.contains('pcapProfiles')) {
            ;(db as unknown as IDBDatabase).deleteObjectStore('pcapProfiles')
          }
        }
      },
    })
  }
  return dbPromise
}

/** Test helper — closes and forgets the shared connection. */
export async function closeRndLogAnonymizerDb(): Promise<void> {
  if (!dbPromise) return
  const db = await dbPromise
  db.close()
  dbPromise = null
}

/** Wipe only the rnd-log-anonymizer database (ARCHITECTURE §9.2 clear action). */
export async function deleteRndLogAnonymizerDatabase(): Promise<void> {
  await closeRndLogAnonymizerDb()
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error ?? new Error('deleteDatabase failed'))
    req.onblocked = () => resolve()
  })
}
