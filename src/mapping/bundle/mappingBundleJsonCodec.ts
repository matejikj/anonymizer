/**
 * Human-readable JSON mapping bundle (plaintext export).
 * Current product supports plaintext JSON only; bundle encryption is not planned.
 */

import { z } from 'zod'
import { stableStringify } from '../../domain/rulesetValidate.ts'
import { ALL_IDENTITY_CATEGORIES } from '../identityCategories.ts'
import {
  MAPPING_BUNDLE_FORMAT,
  MAPPING_BUNDLE_SCHEMA_VERSION,
} from './formatConstants.ts'
import { BUNDLE_CODEC_ERROR, bundleFail, type BundleCodecResult } from './errors.ts'
import { validatePayloadLimits } from './payloadCodec.ts'
import type { MappingBundlePayload } from './types.ts'

export const MAPPING_BUNDLE_JSON_SCHEMA_URN =
  'urn:rnd-log-anonymizer:schema:mapping-bundle:1' as const

export const MAPPING_BUNDLE_JSON_EXTENSION = '.rnd-mapping-bundle.json' as const

const categorySchema = z.enum(ALL_IDENTITY_CATEGORIES as [string, ...string[]])

const entrySchema = z
  .object({
    identityId: z.number().int().nonnegative(),
    category: categorySchema,
    canonical: z.string(),
    alias: z.string(),
    disposition: z.enum(['bijective', 'ambiguous-fixed', 'preserved']),
    occurrenceCount: z.number().int().nonnegative(),
  })
  .strict()

const sourceSchema = z
  .object({
    id: z.string().min(1),
    kind: z.enum(['text', 'pcap']),
    name: z.string().min(1),
  })
  .strict()

const payloadSchema = z
  .object({
    sessionId: z.string().min(1),
    canonicalizationVersion: z.number().int().positive(),
    mappingRevision: z.number().int().nonnegative(),
    sources: z.array(sourceSchema),
    entries: z.array(entrySchema),
  })
  .strict()

const envelopeSchema = z
  .object({
    $schema: z.literal(MAPPING_BUNDLE_JSON_SCHEMA_URN).optional(),
    format: z.literal(MAPPING_BUNDLE_FORMAT),
    schemaVersion: z.literal(MAPPING_BUNDLE_SCHEMA_VERSION),
    payload: payloadSchema,
  })
  .strict()

export type MappingBundleJsonEnvelope = z.infer<typeof envelopeSchema>

export function isMappingBundleJsonBytes(bytes: Uint8Array): boolean {
  if (bytes.byteLength === 0) return false
  const probe = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, Math.min(bytes.length, 64)))
  return probe.trimStart().startsWith('{')
}

export function isMappingBundleJsonFileName(fileName: string): boolean {
  return fileName.toLowerCase().endsWith('.json') || fileName.toLowerCase().endsWith(MAPPING_BUNDLE_JSON_EXTENSION)
}

export function serializeMappingBundleJson(payload: MappingBundlePayload): string {
  const limits = validatePayloadLimits(payload)
  if (!limits.ok) {
    throw new Error(limits.message)
  }
  const envelope: MappingBundleJsonEnvelope = {
    $schema: MAPPING_BUNDLE_JSON_SCHEMA_URN,
    format: MAPPING_BUNDLE_FORMAT,
    schemaVersion: MAPPING_BUNDLE_SCHEMA_VERSION,
    payload: {
      sessionId: payload.sessionId,
      canonicalizationVersion: payload.canonicalizationVersion,
      mappingRevision: payload.mappingRevision,
      sources: payload.sources.map((s) => ({ id: s.id, kind: s.kind, name: s.name })),
      entries: payload.entries.map((e) => ({
        identityId: e.identityId,
        category: e.category,
        canonical: e.canonical,
        alias: e.alias,
        disposition: e.disposition,
        occurrenceCount: e.occurrenceCount,
      })),
    },
  }
  return `${stableStringify(envelope, 2)}\n`
}

export function parseMappingBundleJsonText(text: string): BundleCodecResult<MappingBundlePayload> {
  let parsed: unknown
  try {
    parsed = JSON.parse(text) as unknown
  } catch {
    return bundleFail(BUNDLE_CODEC_ERROR.payloadInvalid, 'invalid JSON')
  }

  const structural = envelopeSchema.safeParse(parsed)
  if (!structural.success) {
    return bundleFail(BUNDLE_CODEC_ERROR.payloadInvalid, 'invalid mapping bundle JSON envelope')
  }

  const payload = structural.data.payload as MappingBundlePayload
  const limits = validatePayloadLimits(payload)
  if (!limits.ok) return limits

  return { ok: true, value: payload }
}

export function parseMappingBundleJsonBytes(bytes: Uint8Array): BundleCodecResult<MappingBundlePayload> {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  return parseMappingBundleJsonText(text)
}
