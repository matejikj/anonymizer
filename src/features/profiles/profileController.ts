/**
 * Active profile lifecycle — load/save/switch/import/export (ARCHITECTURE §10 / Krok 8).
 * Text detection profiles only; PCAP level is owned by the PCAP subsystem.
 */

import {
  BUILTIN_UNIFIED_PROFILE_ID,
  createDefaultRulesetConfig,
  rulesetToDetectorConfig,
  type RulesetBuiltinToggles,
  type RulesetConfig,
  type RulesetSettings,
} from '../../domain/configSchema.ts'
import {
  cloneRulesetConfig,
  exportFileName,
  literalSensitivityWarnings,
  parseRulesetJsonText,
  serializeRulesetConfig,
  type ValidationIssue,
} from '../../domain/rulesetValidate.ts'
import {
  deleteStoredProfile,
  ensureDefaultProfile,
  getIdbPreference,
  getStoredProfile,
  listStoredProfiles,
  PREF_LAST_PROFILE_ID,
  putStoredProfile,
  setIdbPreference,
  clearAllRndLogAnonymizerData,
  type StoredProfile,
} from '../../persistence/profileRepository.ts'
import { getActiveProfile, setActiveProfile } from '../rules/activeProfile.ts'
import {
  getLastImportedText,
  reanalyzeWithActiveProfile,
} from '../../app/sessionController.ts'
import { useAppStore } from '../../app/store.ts'
import { buildLineIndex } from '../../engine/lineIndex.ts'
import { detectOnPhysicalLine } from '../../engine/detectLine.ts'
import { resolveOverlaps } from '../../engine/resolveOverlaps.ts'
import {
  createNewUnifiedDefaultConfig,
  isBuiltInUnifiedProfile,
  loadBundledTeamProductionUnified,
  normalizeUnifiedConfig,
} from './unifiedProfile.ts'
import { cs } from '../../i18n/cs.ts'

let dirty = false
let savedSnapshot: string = serializeRulesetConfig(createDefaultRulesetConfig())
let bootstrapped = false

export function isProfileDirty(): boolean {
  return dirty
}

export function markProfileDirty(): void {
  dirty = true
  useAppStore.getState().setProfileDirty(true)
  useAppStore.getState().bumpProfileEpoch()
}

export function clearProfileDirty(): void {
  dirty = false
  savedSnapshot = serializeRulesetConfig(getActiveProfile())
  useAppStore.getState().setProfileDirty(false)
  useAppStore.getState().bumpProfileEpoch()
}

export function getSavedSnapshot(): string {
  return savedSnapshot
}

export async function bootstrapProfiles(): Promise<void> {
  if (bootstrapped) return
  try {
    bootstrapped = true
    const def = await ensureDefaultProfile()
    const lastId = (await getIdbPreference(PREF_LAST_PROFILE_ID)) as string | undefined
    const migratedLastId =
      lastId === 'default' ? BUILTIN_UNIFIED_PROFILE_ID : lastId
    if (migratedLastId !== lastId) {
      await setIdbPreference(PREF_LAST_PROFILE_ID, migratedLastId)
    }
    const chosen =
      (migratedLastId ? await getStoredProfile(migratedLastId) : undefined) ?? def
    const normalized = normalizeUnifiedConfig(chosen.config)
    setActiveProfile(cloneRulesetConfig(normalized))
    savedSnapshot = serializeRulesetConfig(normalized)
    dirty = false
    useAppStore.getState().setProfileDirty(false)
    useAppStore.getState().setActiveProfileId(chosen.id)
    useAppStore.getState().bumpProfileEpoch()
  } catch {
    // IndexedDB unavailable (private mode / unit env) — keep in-memory bundled default.
    bootstrapped = true
    const fallback = loadBundledTeamProductionUnified()
    setActiveProfile(fallback)
    savedSnapshot = serializeRulesetConfig(fallback)
    dirty = false
    useAppStore.getState().setProfileDirty(false)
    useAppStore.getState().setActiveProfileId(fallback.profile.id)
    useAppStore.getState().bumpProfileEpoch()
  }
}

export async function refreshProfileList(): Promise<StoredProfile[]> {
  try {
    // A pure read must not bump profileEpoch — TextProfileSelector's effect re-fetches the
    // list on every epoch change, and this call used to bump the epoch on every invocation,
    // which made the effect re-trigger itself forever (infinite IndexedDB reads + re-renders,
    // never settling, running for as long as the tab stayed open). Every real mutation
    // (activateProfile, markProfileDirty, clearProfileDirty, bootstrapProfiles, reset) already
    // bumps its own epoch independently, so nothing legitimately depends on this one.
    const list = await listStoredProfiles()
    return list
  } catch {
    const active = getActiveProfile()
    return [
      {
        id: active.profile.id,
        name: active.profile.name,
        config: active,
        createdAt: 0,
        updatedAt: 0,
      },
    ]
  }
}

export async function activateProfile(
  id: string,
  options: { force?: boolean } = {},
): Promise<{ ok: true } | { ok: false; reason: 'dirty' | 'missing' }> {
  if (!options.force && dirty) return { ok: false, reason: 'dirty' }
  const row = await getStoredProfile(id)
  if (!row) return { ok: false, reason: 'missing' }
  const normalized = normalizeUnifiedConfig(row.config)
  setActiveProfile(cloneRulesetConfig(normalized))
  savedSnapshot = serializeRulesetConfig(normalized)
  dirty = false
  await setIdbPreference(PREF_LAST_PROFILE_ID, id)
  useAppStore.getState().setProfileDirty(false)
  useAppStore.getState().setActiveProfileId(id)
  useAppStore.getState().bumpProfileEpoch()
  // Text profile switch must not rebuild or alter the active PCAP plan.
  if (useAppStore.getState().phase === 'correlation-review') {
    useAppStore.getState().setPlanBusy(true)
    try {
      await import('../../correlation/rebuildCorrelationAfterTextProfileChange.ts').then((m) =>
        m.rebuildCorrelationAfterTextProfileChange(),
      )
    } finally {
      useAppStore.getState().setPlanBusy(false)
    }
  } else if (getLastImportedText()) {
    useAppStore.getState().setPlanBusy(true)
    try {
      await reanalyzeWithActiveProfile()
    } finally {
      useAppStore.getState().setPlanBusy(false)
    }
  }
  return { ok: true }
}

export async function saveActiveProfile(): Promise<StoredProfile> {
  const config = normalizeUnifiedConfig(getActiveProfile())
  setActiveProfile(config)
  const row = await putStoredProfile(config)
  await setIdbPreference(PREF_LAST_PROFILE_ID, row.id)
  clearProfileDirty()
  useAppStore.getState().setActiveProfileId(row.id)
  useAppStore.getState().setToast({
    message: `Profil „${row.name}“ uložen.`,
  })
  return row
}

export async function revertActiveProfile(): Promise<void> {
  const id = useAppStore.getState().activeProfileId || BUILTIN_UNIFIED_PROFILE_ID
  const row = await getStoredProfile(id)
  if (!row) return
  setActiveProfile(cloneRulesetConfig(row.config))
  clearProfileDirty()
  if (getLastImportedText()) {
    useAppStore.getState().setPlanBusy(true)
    try {
      await reanalyzeWithActiveProfile()
    } finally {
      useAppStore.getState().setPlanBusy(false)
    }
  }
}

export async function createNewProfile(name = 'Nový profil'): Promise<StoredProfile> {
  if (dirty) {
    // Caller should handle dirty; still allow force via save first.
  }
  const base = createNewUnifiedDefaultConfig(name)
  const row = await putStoredProfile(base)
  await activateProfile(row.id, { force: true })
  return row
}

export async function duplicateActiveProfile(): Promise<StoredProfile> {
  const src = normalizeUnifiedConfig(getActiveProfile())
  const copy = cloneRulesetConfig(src)
  copy.profile.id = `profile-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
  copy.profile.name = `${src.profile.name} (kopie)`
  const row = await putStoredProfile(copy)
  await activateProfile(row.id, { force: true })
  return row
}

export async function deleteActiveProfile(): Promise<{ ok: true } | { ok: false; reason: string }> {
  const id = useAppStore.getState().activeProfileId || getActiveProfile().profile.id
  if (isBuiltInUnifiedProfile(id)) {
    return { ok: false, reason: 'default' }
  }
  await deleteStoredProfile(id)
  await activateProfile(BUILTIN_UNIFIED_PROFILE_ID, { force: true })
  return { ok: true }
}

export function updateActiveMeta(input: {
  name?: string
  description?: string
  builtins?: RulesetBuiltinToggles
  settings?: RulesetSettings
}): void {
  const cur = getActiveProfile()
  const isDefault = isBuiltInUnifiedProfile(cur.profile.id)
  setActiveProfile({
    ...cur,
    profile: {
      ...cur.profile,
      name: isDefault
        ? loadBundledTeamProductionUnified().profile.name
        : (input.name ?? cur.profile.name),
      description:
        input.description !== undefined ? input.description || undefined : cur.profile.description,
      builtins: input.builtins ?? cur.profile.builtins,
      settings: input.settings ?? cur.profile.settings,
    },
  })
  markProfileDirty()
}

export type ImportPreview = {
  config: RulesetConfig
  warnings: ValidationIssue[]
  collision: StoredProfile | null
  summary: {
    name: string
    ruleCount: number
    disabledBuiltins: string[]
    literalCount: number
  }
  impact: { before: number; after: number } | null
}

export async function buildImportPreview(text: string): Promise<
  | { ok: true; preview: ImportPreview }
  | {
      ok: false
      issues: ValidationIssue[]
      schemaTooNew?: boolean
      parseError?: { line: number; column: number; message: string }
    }
> {
  if (text.startsWith('RNDPCAPR')) {
    return {
      ok: false,
      issues: [
        {
          path: '(file)',
          message: cs.profiles.importRecoveryRejected,
          code: 'recovery-bundle',
        },
      ],
    }
  }
  const parsed = parseRulesetJsonText(text)
  if (!parsed.ok) {
    return {
      ok: false,
      issues: parsed.issues,
      schemaTooNew: parsed.schemaTooNew,
      parseError: 'parseError' in parsed ? parsed.parseError : undefined,
    }
  }
  const collision = (await getStoredProfile(parsed.config.profile.id)) ?? null
  const builtins = parsed.config.profile.builtins
  const disabledBuiltins = (Object.keys(builtins) as Array<keyof typeof builtins>).filter(
    (k) => !builtins[k],
  )
  const log = getLastImportedText()
  let impact: ImportPreview['impact'] = null
  if (log) {
    const before = countMatches(log, getActiveProfile())
    const after = countMatches(log, parsed.config)
    impact = { before, after }
  }
  return {
    ok: true,
    preview: {
      config: parsed.config,
      warnings: parsed.warnings,
      collision,
      summary: {
        name: parsed.config.profile.name,
        ruleCount: parsed.config.profile.rules.length,
        disabledBuiltins,
        literalCount: parsed.config.profile.rules.filter((r) => r.kind === 'literal').length,
      },
      impact,
    },
  }
}

function countMatches(text: string, config: RulesetConfig): number {
  const det = rulesetToDetectorConfig(config)
  const lineIndex = buildLineIndex(text)
  const limit = Math.min(lineIndex.lineCount, 50_000)
  const raw = []
  for (let line = 1; line <= limit; line++) {
    const { start, end } = lineIndex.lineContentRange(line)
    const lineText = text.slice(start, end)
    try {
      raw.push(
        ...detectOnPhysicalLine(lineText, line, start, det, config.profile.builtins),
      )
    } catch {
      // T07: preview count must not abort on a single line detector failure.
    }
  }
  return resolveOverlaps(raw).length
}

export async function commitImport(
  config: RulesetConfig,
  mode: 'copy' | 'replace',
): Promise<StoredProfile> {
  let next = normalizeUnifiedConfig(cloneRulesetConfig(config))
  if (mode === 'copy') {
    const existing = await getStoredProfile(next.profile.id)
    if (existing) {
      next.profile.id = `${next.profile.id}-import-${Date.now().toString(36)}`
      next.profile.name = `${next.profile.name} (import)`
    }
  }
  next = normalizeUnifiedConfig(next)
  const row = await putStoredProfile(next)
  await activateProfile(row.id, { force: true })
  return row
}

export function prepareExport(): {
  json: string
  fileName: string
  warnings: ValidationIssue[]
} {
  const config = normalizeUnifiedConfig(getActiveProfile())
  return {
    json: serializeRulesetConfig(config),
    fileName: exportFileName(config),
    warnings: literalSensitivityWarnings(config),
  }
}

export function downloadTextFile(fileName: string, contents: string): void {
  const blob = new Blob([contents], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export async function wipeLocalProfilesAndPreferences(): Promise<void> {
  await clearAllRndLogAnonymizerData()
  bootstrapped = false
  setActiveProfile(loadBundledTeamProductionUnified())
  dirty = false
  savedSnapshot = serializeRulesetConfig(getActiveProfile())
  // Also clear sync localStorage prefs used by the shell
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith('rnd-log-anonymizer:pref:')) localStorage.removeItem(key)
    }
  } catch {
    // ignore
  }
  useAppStore.getState().setProfileDirty(false)
  useAppStore.getState().setActiveProfileId(BUILTIN_UNIFIED_PROFILE_ID)
  useAppStore.getState().bumpProfileEpoch()
  await bootstrapProfiles()
}

export { literalSensitivityWarnings }

/** Test-only: allow re-running bootstrap. */
export function resetProfileBootstrapForTests(): void {
  bootstrapped = false
}
