import { describe, expect, it } from 'vitest'
import {
  entityKey,
  normalizeEmail,
  normalizeHostname,
  normalizePerson,
} from '../../src/engine/normalize.ts'

describe('normalize', () => {
  it('builds entityKey as category::normalized', () => {
    expect(entityKey('ip', '10.0.0.1')).toBe('ip::10.0.0.1')
    expect(entityKey('hostname', normalizeHostname('Host.LOCAL'))).toBe(
      'hostname::host.local',
    )
  })

  it('lowercases hostname and email domain', () => {
    expect(normalizeHostname('LDAP-PRA.CORP.EXAMPLE')).toBe('ldap-pra.corp.example')
    expect(normalizeEmail('Admin@Example.COM')).toBe('Admin@example.com')
  })

  it('collapses person whitespace case-insensitively', () => {
    expect(normalizePerson('  Krejci   Iveta ')).toBe('krejci iveta')
  })
})
