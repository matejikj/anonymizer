import type { Category } from '../domain/types.ts'
import { canonicalizeTextIdentity } from '../mapping/textCanonical.ts'

/** Build stable entityKey = category + "::" + normalized canonical */
export function entityKey(category: Category, normalized: string): string {
  return `${category}::${normalized}`
}

export function entityKeyFromOriginal(category: Category, original: string): string | null {
  const normalized = canonicalizeTextIdentity(category, original)
  if (normalized === null) return null
  return entityKey(category, normalized)
}

export function normalizeIp(value: string): string {
  return canonicalizeTextIdentity('ip', value) ?? value.trim()
}

export function normalizeHostname(value: string): string {
  return canonicalizeTextIdentity('hostname', value) ?? value.trim().toLowerCase()
}

export function normalizeEmail(value: string): string {
  return canonicalizeTextIdentity('email', value) ?? value.trim().toLowerCase()
}

export function normalizePerson(value: string): string {
  return canonicalizeTextIdentity('person', value) ?? value.trim().replace(/\s+/g, ' ').toLowerCase()
}

export function normalizeUserId(value: string): string {
  return canonicalizeTextIdentity('user-id', value) ?? value.trim().toLowerCase()
}

export function normalizeInternalId(value: string): string {
  return canonicalizeTextIdentity('internal-id', value) ?? value.trim()
}

export function normalizeSipPhone(value: string): string {
  const c = canonicalizeTextIdentity('sip-phone', value)
  return c ?? value.trim()
}

export function normalizeByCategory(category: Category, value: string): string {
  return canonicalizeTextIdentity(category, value) ?? value
}
