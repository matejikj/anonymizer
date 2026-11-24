import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import {
  cloneRulesetConfig,
  exportFileName,
  migrateV0ToV1,
  parseRulesetConfig,
  parseRulesetJsonText,
  serializeRulesetConfig,
  stableStringify,
} from '../../src/domain/rulesetValidate.ts'

const here = dirname(fileURLToPath(import.meta.url))

describe('rulesetValidate (Krok 8)', () => {
  it('round-trips default config with stable key order', () => {
    const a = createDefaultRulesetConfig()
    a.profile.rules.push({
      id: 'r1',
      name: 'Tenant',
      enabled: true,
      kind: 'literal',
      pattern: 'Acme Corp',
      category: 'custom',
      replacement: { kind: 'fixed', value: 'Customer 1' },
    })
    const json = serializeRulesetConfig(a)
    const again = serializeRulesetConfig(JSON.parse(json))
    expect(again).toBe(json)
    const parsed = parseRulesetJsonText(json)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.config.profile.rules).toHaveLength(1)
      expect(parsed.warnings.some((w) => w.code === 'literal-sensitive')).toBe(true)
    }
  })

  it('rejects unknown fields and invalid regex', () => {
    const base = createDefaultRulesetConfig() as unknown as Record<string, unknown>
    base.extra = true
    const unknown = parseRulesetConfig(base)
    expect(unknown.ok).toBe(false)

    const badRegex = createDefaultRulesetConfig()
    badRegex.profile.rules.push({
      id: 'bad',
      name: 'Bad',
      enabled: true,
      kind: 'regex',
      pattern: 'a*',
      category: 'custom',
      replacement: { kind: 'generated' },
    })
    const zero = parseRulesetConfig(badRegex)
    expect(zero.ok).toBe(false)
    if (!zero.ok) {
      expect(zero.issues.some((i) => i.code === 'zero-length')).toBe(true)
    }
  })

  it('rejects newer schemaVersion without mutating input semantics', () => {
    const raw = {
      format: 'rnd-log-anonymizer-ruleset',
      schemaVersion: 99,
      profile: createDefaultRulesetConfig().profile,
    }
    const result = parseRulesetConfig(raw)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.schemaTooNew).toBe(true)
    }
  })

  it('rejects invalid JSON with parse error', () => {
    const result = parseRulesetJsonText('{ not json')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.issues.some((i) => i.code === 'json-parse')).toBe(true)
    }
  })

  it('migrates synthetic v0 document to v1', () => {
    const v0 = {
      schemaVersion: 0,
      profile: {
        id: 'legacy',
        name: 'Legacy',
        rules: [
          {
            id: 't1',
            name: 'Ticket',
            enabled: true,
            kind: 'regex',
            pattern: 'TICKET-[0-9]{6}',
            category: 'internal-id',
            replacement: { kind: 'generated' },
          },
        ],
      },
    }
    const migrated = migrateV0ToV1(v0)
    const parsed = parseRulesetConfig(migrated)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.config.schemaVersion).toBe(2)
      expect(parsed.config.profile.id).toBe('legacy')
      expect(parsed.config.profile.rules[0]?.pattern).toBe('TICKET-[0-9]{6}')
    }
  })

  it('ships a local JSON Schema fixture without remote $ref', () => {
    const schemaPath = join(here, '../../src/domain/ruleset.schema.json')
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as {
      $id: string
      $schema?: string
    }
    expect(schema.$id).toBe('urn:rnd-log-anonymizer:schema:ruleset:1')
    expect(schema.$schema ?? '').not.toMatch(/^https?:/i)
  })

  it('names export files with slug + .rnd-log-anonymizer.json', () => {
    const cfg = createDefaultRulesetConfig()
    cfg.profile.name = 'Demo Profile — default'
    expect(exportFileName(cfg)).toBe('demo-profile-default.rnd-log-anonymizer.json')
  })

  it('clone via serialize is deep-equal for sorted keys', () => {
    const cfg = createDefaultRulesetConfig()
    const clone = cloneRulesetConfig(cfg)
    expect(stableStringify(clone)).toBe(stableStringify(cfg))
  })

  it('rejects embedded pcapProfile in text ruleset JSON', () => {
    const raw = {
      ...createDefaultRulesetConfig(),
      pcapProfile: {
        id: 'x',
        name: 'X',
        preset: 'diagnostic',
      },
    }
    const result = parseRulesetConfig(raw)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.issues.some((i) => i.code === 'pcap-config-not-allowed')).toBe(true)
      expect(result.issues.some((i) => i.path === 'pcapProfile')).toBe(true)
    }
  })

  it('export never serializes PCAP fields', () => {
    const json = serializeRulesetConfig(createDefaultRulesetConfig())
    expect(json).not.toMatch(/pcapProfile|mediaPolicy|preservePacketLengths|unsupportedPayloadPolicy/)
    const parsed = JSON.parse(json) as Record<string, unknown>
    expect(parsed).not.toHaveProperty('pcapProfile')
  })
})
