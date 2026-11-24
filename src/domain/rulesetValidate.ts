/**
 * Zod schema + parse/serialize for shared ruleset JSON (ARCHITECTURE §10 / Krok 8).
 * Unknown keys are rejected (.strict). Validation never triggers network I/O.
 */

import { z } from 'zod'
import {
  MAX_RULE_PATTERN_LENGTH,
  MAX_RULE_REPLACEMENT_LENGTH,
  LEGACY_SCHEMA_VERSION,
  RND_LOG_ANONYMIZER_SCHEMA_URN,
  SUPPORTED_SCHEMA_VERSION,
  createDefaultRulesetConfig,
  type RulesetConfig,
  type RulesetRule,
} from './configSchema.ts'

import { BYTES_PER_MIB, TEXT_INPUT_LIMITS } from './capabilityContract.ts'

/** Root keys that belong to PCAP configuration and must not appear in text rulesets. */
const FORBIDDEN_PCAP_ROOT_KEYS = [
  'pcapProfile',
  'pcapLevel',
  'pcapAnonymizationLevel',
  'mediaPolicy',
  'unsupportedPayloadPolicy',
  'malformedPayloadPolicy',
] as const

export const MAX_PROFILE_JSON_BYTES = TEXT_INPUT_LIMITS.profileMaxBytes

const categorySchema = z.enum([
  'ip',
  'hostname',
  'sip-phone',
  'email',
  'person',
  'user-id',
  'internal-id',
  'port',
  'custom',
])

const replacementSchema = z
  .discriminatedUnion('kind', [
    z
      .object({
        kind: z.literal('generated'),
      })
      .strict(),
    z
      .object({
        kind: z.literal('fixed'),
        value: z.string().min(1).max(MAX_RULE_REPLACEMENT_LENGTH),
      })
      .strict(),
  ])

const ruleSchema = z
  .object({
    id: z.string().min(1).max(128),
    name: z.string().min(1).max(200),
    enabled: z.boolean(),
    kind: z.enum(['literal', 'regex']),
    pattern: z.string().min(1).max(MAX_RULE_PATTERN_LENGTH),
    caseSensitive: z.boolean().optional(),
    wholeWord: z.boolean().optional(),
    category: categorySchema,
    replacement: replacementSchema,
    description: z.string().max(1000).optional(),
    priority: z.number().int().min(0).max(1_000_000).optional(),
  })
  .strict()

const builtinsSchema = z
  .object({
    ip: z.boolean(),
    hostname: z.boolean(),
    'sip-phone': z.boolean(),
    email: z.boolean(),
    person: z.boolean(),
    'user-id': z.boolean(),
    'internal-id': z.boolean(),
    port: z.boolean().default(true),
  })
  .strict()

const settingsSchema = z
  .object({
    hostnameSuffixes: z.array(z.string().min(1).max(253)).max(100),
    userIdPrefixes: z.array(z.string().min(1).max(64)).max(50),
    internalIdPrefixes: z.array(z.string().min(1).max(64)).max(50),
  })
  .strict()

const profileSchema = z
  .object({
    id: z.string().min(1).max(128),
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    builtins: builtinsSchema,
    settings: settingsSchema,
    rules: z.array(ruleSchema).max(500),
  })
  .strict()

/** Structural Zod schema for schemaVersion === 1 (legacy text-only). */
export const rulesetConfigSchemaV1 = z
  .object({
    $schema: z.literal(RND_LOG_ANONYMIZER_SCHEMA_URN).optional(),
    format: z.literal('rnd-log-anonymizer-ruleset'),
    schemaVersion: z.literal(LEGACY_SCHEMA_VERSION),
    profile: profileSchema,
  })
  .strict()

/** Structural Zod schema for schemaVersion === 2 (text detection rules only). */
export const rulesetConfigSchemaV2 = z
  .object({
    $schema: z.literal(RND_LOG_ANONYMIZER_SCHEMA_URN).optional(),
    format: z.literal('rnd-log-anonymizer-ruleset'),
    schemaVersion: z.literal(SUPPORTED_SCHEMA_VERSION),
    profile: profileSchema,
  })
  .strict()

/** @deprecated Use rulesetConfigSchemaV2 for new exports. */
export const rulesetConfigSchema = rulesetConfigSchemaV2

export type ValidationIssue = {
  path: string
  message: string
  code: string
}

export type ParseRulesetResult =
  | { ok: true; config: RulesetConfig; warnings: ValidationIssue[] }
  | { ok: false; issues: ValidationIssue[]; schemaTooNew?: boolean }

function pathOf(parts: PropertyKey[]): string {
  if (parts.length === 0) return '(root)'
  return parts
    .map((p, i) => {
      if (typeof p === 'number') return `[${p}]`
      const s = String(p)
      return i === 0 ? s : `.${s}`
    })
    .join('')
    .replace(/\.\[/g, '[')
}

function zodIssues(err: z.ZodError): ValidationIssue[] {
  return err.issues.map((i) => ({
    path: pathOf(i.path),
    message: i.message,
    code: i.code,
  }))
}

/** Semantic checks beyond structural Zod (ARCHITECTURE §7.3 / §10.2). */
export function semanticValidateRuleset(config: RulesetConfig): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  const ruleIds = new Set<string>()

  for (let i = 0; i < config.profile.rules.length; i++) {
    const rule = config.profile.rules[i]!
    const base = `profile.rules[${i}]`

    if (ruleIds.has(rule.id)) {
      issues.push({
        path: `${base}.id`,
        message: `Duplicitní rule id „${rule.id}“.`,
        code: 'duplicate-rule-id',
      })
    }
    ruleIds.add(rule.id)

    if (rule.pattern.includes('\n') || rule.pattern.includes('\r')) {
      issues.push({
        path: `${base}.pattern`,
        message: 'Vzor nesmí obsahovat konec řádku.',
        code: 'pattern-newline',
      })
    }

    if (rule.replacement.kind === 'fixed') {
      const v = rule.replacement.value ?? ''
      if (v.includes('\n') || v.includes('\r')) {
        issues.push({
          path: `${base}.replacement.value`,
          message: 'Náhrada nesmí obsahovat konec řádku.',
          code: 'replacement-newline',
        })
      }
    }

    if (rule.kind === 'regex') {
      if (rule.pattern.startsWith('/') && rule.pattern.lastIndexOf('/') > 0) {
        issues.push({
          path: `${base}.pattern`,
          message: 'Regex zadávejte bez okolních lomítek /…/.',
          code: 'regex-slashes',
        })
      }
      try {
        const flags = rule.caseSensitive === false ? 'gi' : 'g'
        void new RegExp(rule.pattern, flags)
        if (regexCanMatchEmpty(rule.pattern, rule.caseSensitive !== false)) {
          issues.push({
            path: `${base}.pattern`,
            message: 'Regex nesmí umět najít shodu nulové délky.',
            code: 'zero-length',
          })
        }
      } catch (err) {
        issues.push({
          path: `${base}.pattern`,
          message: err instanceof Error ? `Neplatný regex: ${err.message}` : 'Neplatný regex.',
          code: 'regex-syntax',
        })
      }
    }

    if (rule.kind === 'literal' && rule.wholeWord == null) {
      // ok — optional
    }
    if (rule.kind === 'regex' && rule.wholeWord) {
      issues.push({
        path: `${base}.wholeWord`,
        message: 'wholeWord platí jen pro literal pravidla.',
        code: 'whole-word-regex',
      })
    }
  }

  return issues
}

export function literalSensitivityWarnings(config: RulesetConfig): ValidationIssue[] {
  const warnings: ValidationIssue[] = []
  for (let i = 0; i < config.profile.rules.length; i++) {
    const rule = config.profile.rules[i]!
    if (rule.kind === 'literal') {
      warnings.push({
        path: `profile.rules[${i}].pattern`,
        message: `Literal „${rule.name}“ může sám obsahovat citlivý údaj.`,
        code: 'literal-sensitive',
      })
    }
  }
  return warnings
}

/**
 * Parse + validate a ruleset from unknown JSON value (no side effects on active profile).
 */
export function parseRulesetConfig(input: unknown): ParseRulesetResult {
  if (input == null || typeof input !== 'object' || Array.isArray(input)) {
    return {
      ok: false,
      issues: [{ path: '(root)', message: 'Očekáván JSON objekt.', code: 'not-object' }],
    }
  }

  const raw = input as Record<string, unknown>
  const pcapIssues = rejectPcapFieldsInTextRuleset(raw)
  if (pcapIssues.length > 0) {
    return { ok: false, issues: pcapIssues }
  }

  const version = raw.schemaVersion
  if (typeof version === 'number' && version > SUPPORTED_SCHEMA_VERSION) {
    return {
      ok: false,
      schemaTooNew: true,
      issues: [
        {
          path: 'schemaVersion',
          message: `Profil vyžaduje novější rnd-log-anonymizer (schemaVersion ${version}; podporováno ${SUPPORTED_SCHEMA_VERSION}).`,
          code: 'schema-too-new',
        },
      ],
    }
  }

  const migrated = migrateRulesetUnknown(raw)
  if (!migrated.ok) return migrated

  const migratedVersion = (migrated.value as Record<string, unknown>).schemaVersion
  const structural =
    migratedVersion === LEGACY_SCHEMA_VERSION
      ? rulesetConfigSchemaV1.safeParse(migrated.value)
      : rulesetConfigSchemaV2.safeParse(migrated.value)
  if (!structural.success) {
    return { ok: false, issues: zodIssues(structural.error) }
  }

  const config = structural.data as RulesetConfig
  const semantic = semanticValidateRuleset(config)
  if (semantic.length > 0) {
    return { ok: false, issues: semantic }
  }

  return {
    ok: true,
    config: {
      ...config,
      $schema: config.$schema ?? RND_LOG_ANONYMIZER_SCHEMA_URN,
    },
    warnings: literalSensitivityWarnings(config),
  }
}

export function parseRulesetJsonText(
  text: string,
): ParseRulesetResult & { parseError?: { line: number; column: number; message: string } } {
  const bytes = new TextEncoder().encode(text).byteLength
  if (bytes > MAX_PROFILE_JSON_BYTES) {
    return {
      ok: false,
      issues: [
        {
          path: '(file)',
          message: `Soubor je větší než ${MAX_PROFILE_JSON_BYTES / BYTES_PER_MIB} MiB.`,
          code: 'too-large',
        },
      ],
    }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Neplatný JSON'
    const pos = extractJsonPosition(message)
    return {
      ok: false,
      issues: [{ path: '(json)', message, code: 'json-parse' }],
      parseError: { line: pos.line, column: pos.column, message },
    }
  }
  return parseRulesetConfig(parsed)
}

function extractJsonPosition(message: string): { line: number; column: number } {
  const m = /position\s+(\d+)/i.exec(message)
  if (!m) return { line: 1, column: 1 }
  // Without original text offset→line is best-effort; callers may refine.
  return { line: 1, column: Number(m[1]) + 1 }
}

/**
 * Stable export: sorted object keys, 2-space indent (ARCHITECTURE §10.3).
 */
export function serializeRulesetConfig(config: RulesetConfig): string {
  const normalized: RulesetConfig = {
    $schema: RND_LOG_ANONYMIZER_SCHEMA_URN,
    format: 'rnd-log-anonymizer-ruleset',
    schemaVersion: SUPPORTED_SCHEMA_VERSION,
    profile: {
      id: config.profile.id,
      name: config.profile.name,
      ...(config.profile.description ? { description: config.profile.description } : {}),
      builtins: { ...config.profile.builtins },
      settings: {
        hostnameSuffixes: [...config.profile.settings.hostnameSuffixes],
        userIdPrefixes: [...config.profile.settings.userIdPrefixes],
        internalIdPrefixes: [...config.profile.settings.internalIdPrefixes],
      },
      rules: config.profile.rules.map(normalizeRuleForExport),
    },
  }
  return `${stableStringify(normalized, 2)}\n`
}

function rejectPcapFieldsInTextRuleset(raw: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  for (const key of FORBIDDEN_PCAP_ROOT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(raw, key)) {
      issues.push({
        path: key,
        message:
          key === 'pcapProfile'
            ? 'Pole „pcapProfile“ není součástí textové konfigurace. Úroveň anonymizace PCAP se nastavuje samostatně.'
            : `Pole „${key}“ patří k PCAP konfiguraci a v textovém rulesetu není povoleno.`,
        code: 'pcap-config-not-allowed',
      })
    }
  }
  return issues
}

function normalizeRuleForExport(rule: RulesetRule): RulesetRule {
  const out: RulesetRule = {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    kind: rule.kind,
    pattern: rule.pattern,
    category: rule.category,
    replacement:
      rule.replacement.kind === 'fixed'
        ? { kind: 'fixed', value: rule.replacement.value }
        : { kind: 'generated' },
  }
  if (rule.caseSensitive !== undefined) out.caseSensitive = rule.caseSensitive
  if (rule.kind === 'literal' && rule.wholeWord) out.wholeWord = true
  if (rule.description) out.description = rule.description
  if (rule.priority !== undefined) out.priority = rule.priority
  return out
}

export function stableStringify(value: unknown, space = 2): string {
  return JSON.stringify(sortKeys(value), null, space)
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = sortKeys(obj[key])
    }
    return sorted
  }
  return value
}

export function slugifyProfileName(name: string): string {
  const slug = name
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80)
  return slug || 'profile'
}

export function exportFileName(config: RulesetConfig): string {
  return `${slugifyProfileName(config.profile.name)}.rnd-log-anonymizer.json`
}

/** Pure migrations: unknown → current schemaVersion (ARCHITECTURE §10.2). */
export function migrateRulesetUnknown(
  raw: Record<string, unknown>,
):
  | { ok: true; value: unknown }
  | { ok: false; issues: ValidationIssue[]; schemaTooNew?: boolean } {
  const version = raw.schemaVersion
  if (version === undefined || version === null) {
    return {
      ok: false,
      issues: [
        {
          path: 'schemaVersion',
          message: 'Chybí schemaVersion.',
          code: 'missing-version',
        },
      ],
    }
  }
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 1) {
    return {
      ok: false,
      issues: [
        {
          path: 'schemaVersion',
          message: 'Neplatná schemaVersion.',
          code: 'bad-version',
        },
      ],
    }
  }
  if (version > SUPPORTED_SCHEMA_VERSION) {
    return {
      ok: false,
      schemaTooNew: true,
      issues: [
        {
          path: 'schemaVersion',
          message: `Profil vyžaduje novější rnd-log-anonymizer (schemaVersion ${version}).`,
          code: 'schema-too-new',
        },
      ],
    }
  }

  let current: Record<string, unknown> = { ...raw }
  let v = version
  while (v < SUPPORTED_SCHEMA_VERSION) {
    const next = MIGRATE[v]
    if (!next) {
      return {
        ok: false,
        issues: [
          {
            path: 'schemaVersion',
            message: `Chybí migrace z verze ${v}.`,
            code: 'missing-migration',
          },
        ],
      }
    }
    current = next(current)
    v += 1
  }
  return { ok: true, value: current }
}

/**
 * Migration table. v1 → v2 bumps schemaVersion only (text rules unchanged).
 */
export const MIGRATE: Record<number, (doc: Record<string, unknown>) => Record<string, unknown>> =
  {
    1: (doc) => ({
      ...doc,
      schemaVersion: SUPPORTED_SCHEMA_VERSION,
    }),
  }

/** Test helper: apply a synthetic v0→v1 migration path. */
export function migrateV0ToV1(doc: Record<string, unknown>): Record<string, unknown> {
  const profile = (doc.profile ?? {}) as Record<string, unknown>
  return {
    $schema: RND_LOG_ANONYMIZER_SCHEMA_URN,
    format: 'rnd-log-anonymizer-ruleset',
    schemaVersion: 1,
    profile: {
      id: typeof profile.id === 'string' ? profile.id : 'migrated',
      name: typeof profile.name === 'string' ? profile.name : 'Migrated',
      description: typeof profile.description === 'string' ? profile.description : undefined,
      builtins: {
        ...createDefaultRulesetConfig().profile.builtins,
        ...(typeof profile.builtins === 'object' && profile.builtins
          ? (profile.builtins as object)
          : {}),
      },
      settings: {
        ...createDefaultRulesetConfig().profile.settings,
        ...(typeof profile.settings === 'object' && profile.settings
          ? (profile.settings as object)
          : {}),
      },
      rules: Array.isArray(profile.rules) ? profile.rules : [],
    },
  }
}

export function cloneRulesetConfig(config: RulesetConfig): RulesetConfig {
  return JSON.parse(serializeRulesetConfig(config)) as RulesetConfig
}

function regexCanMatchEmpty(pattern: string, caseSensitive: boolean): boolean {
  try {
    const flags = caseSensitive ? 'g' : 'gi'
    const reEmpty = new RegExp(pattern, flags)
    const onEmpty = reEmpty.exec('')
    if (onEmpty && onEmpty[0].length === 0) return true
    const reProbe = new RegExp(pattern, flags)
    const onProbe = reProbe.exec('x')
    if (onProbe && onProbe[0].length === 0) return true
    return false
  } catch {
    return false
  }
}
