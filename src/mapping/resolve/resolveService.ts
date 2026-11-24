/**
 * Resolve workspace service — exact lookup and AI report scan (Stage 22).
 */

import { RESOLVE_WORKSPACE_LIMITS } from '../../domain/capabilityContract'
import { getSharedMappingClient } from '../sharedMappingClient'
import type { MappingBundlePayload } from '../bundle/types'
import type { MappingSnapshot } from '../types'
import { AliasLookupIndex } from './aliasIndex'
import { scanReportForPseudonyms } from './pseudonymScanner'
import { buildAnnotatedReport } from './annotateReport'
import type {
  ExactLookupResult,
  ResolveError,
  ResolveMappingSource,
  ScanReportResult,
} from './types'

export function loadAliasIndex(
  source: ResolveMappingSource,
  bundlePayload: MappingBundlePayload | null = null,
): AliasLookupIndex | ResolveError {
  if (source === 'imported-bundle') {
    if (!bundlePayload || bundlePayload.entries.length === 0) {
      return { code: 'resolve-no-mapping', message: 'No imported mapping bundle' }
    }
    return AliasLookupIndex.fromBundlePayload(bundlePayload)
  }

  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  if (!snapshot || snapshot.entries.length === 0) {
    return { code: 'resolve-no-mapping', message: 'No active session mapping' }
  }
  return AliasLookupIndex.fromSnapshot(snapshot)
}

export function loadAliasIndexFromSnapshot(snapshot: MappingSnapshot | null): AliasLookupIndex | ResolveError {
  if (!snapshot || snapshot.entries.length === 0) {
    return { code: 'resolve-no-mapping', message: 'No mapping snapshot' }
  }
  return AliasLookupIndex.fromSnapshot(snapshot)
}

export function loadAliasIndexFromPayload(payload: MappingBundlePayload | null): AliasLookupIndex | ResolveError {
  if (!payload || payload.entries.length === 0) {
    return { code: 'resolve-no-mapping', message: 'No bundle payload' }
  }
  return AliasLookupIndex.fromBundlePayload(payload)
}

function validateAliasInput(alias: string): ResolveError | null {
  const trimmed = alias.trim()
  if (!trimmed) {
    return { code: 'resolve-alias-empty', message: 'Alias is empty' }
  }
  if (new TextEncoder().encode(trimmed).byteLength > RESOLVE_WORKSPACE_LIMITS.maxExactLookupAliasBytes) {
    return { code: 'resolve-alias-too-long', message: 'Alias exceeds length limit' }
  }
  return null
}

export function exactLookupByAlias(
  alias: string,
  source: ResolveMappingSource,
  bundlePayload: MappingBundlePayload | null = null,
): ExactLookupResult | ResolveError {
  const err = validateAliasInput(alias)
  if (err) return err

  const trimmed = alias.trim()
  const indexOrErr = loadAliasIndex(source, bundlePayload)
  if ('code' in indexOrErr) return indexOrErr

  const candidates = indexOrErr.lookupExact(trimmed)
  const ambiguous =
    candidates.length > 1 ||
    candidates.some((c) => c.disposition === 'ambiguous-fixed')

  return { alias: trimmed, candidates, ambiguous }
}

export function scanAiReport(
  report: string,
  source: ResolveMappingSource,
  bundlePayload: MappingBundlePayload | null = null,
): ScanReportResult | ResolveError {
  const indexOrErr = loadAliasIndex(source, bundlePayload)
  if ('code' in indexOrErr) return indexOrErr

  try {
    return scanReportForPseudonyms(report, indexOrErr)
  } catch (e) {
    if (e && typeof e === 'object' && 'code' in e) {
      return e as ResolveError
    }
    throw e
  }
}

export function annotateAiReport(
  report: string,
  scan: ScanReportResult,
  ambiguousLabel: string,
): string {
  return buildAnnotatedReport(report, scan.findings, { ambiguousLabel })
}

export { buildAnnotatedReport } from './annotateReport'
export { AliasLookupIndex } from './aliasIndex'
export { AhoCorasick } from './ahoCorasick'
