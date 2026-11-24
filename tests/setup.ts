import 'fake-indexeddb/auto'
import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

/**
 * T46 — some jsdom/happy-dom hosts expose a partial Storage. Ensure removeItem/setItem
 * exist so PCAP UI pref teardown never throws `removeItem is not a function`.
 */
function ensureMemoryLocalStorage(): void {
  const current = globalThis.localStorage
  if (
    current &&
    typeof current.getItem === 'function' &&
    typeof current.setItem === 'function' &&
    typeof current.removeItem === 'function' &&
    typeof current.clear === 'function'
  ) {
    return
  }
  const map = new Map<string, string>()
  const storage: Storage = {
    get length() {
      return map.size
    },
    clear() {
      map.clear()
    },
    getItem(key: string) {
      return map.has(key) ? map.get(key)! : null
    },
    key(index: number) {
      return [...map.keys()][index] ?? null
    },
    removeItem(key: string) {
      map.delete(key)
    },
    setItem(key: string, value: string) {
      map.set(key, String(value))
    },
  }
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    enumerable: true,
    value: storage,
  })
}

ensureMemoryLocalStorage()

afterEach(() => {
  cleanup()
})
