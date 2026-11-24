import { describe, expect, it } from 'vitest'
import {
  MAPPING_BUNDLE_CANONICALIZATION_VERSION,
  MAPPING_BUNDLE_FORMAT,
  MAPPING_BUNDLE_SCHEMA_VERSION,
  serializeMappingBundleJson,
  parseMappingBundleJsonText,
  isMappingBundleJsonBytes,
} from '../../src/mapping/bundle'
import type { MappingBundlePayload } from '../../src/mapping/bundle'

function samplePayload(): MappingBundlePayload {
  return {
    sessionId: 'g1:text',
    canonicalizationVersion: MAPPING_BUNDLE_CANONICALIZATION_VERSION,
    mappingRevision: 3,
    sources: [{ id: 'g1', kind: 'text', name: 'app.log' }],
    entries: [
      {
        identityId: 1,
        category: 'ip',
        canonical: '10.0.0.8',
        alias: '192.0.2.42',
        disposition: 'bijective',
        occurrenceCount: 4,
      },
    ],
  }
}

describe('mapping bundle JSON codec', () => {
  it('serializes human-readable JSON with stable key order', () => {
    const json = serializeMappingBundleJson(samplePayload())
    expect(json).toContain('"format": "rnd-log-anonymizer-mapping-bundle"')
    expect(json).toContain('"canonical": "10.0.0.8"')
    expect(json).toContain('"alias": "192.0.2.42"')
    expect(json.endsWith('\n')).toBe(true)

    const parsed = parseMappingBundleJsonText(json)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.value.entries[0]?.canonical).toBe('10.0.0.8')
    }
  })

  it('detects JSON bytes by leading brace', () => {
    const bytes = new TextEncoder().encode(serializeMappingBundleJson(samplePayload()))
    expect(isMappingBundleJsonBytes(bytes)).toBe(true)
    expect(isMappingBundleJsonBytes(new Uint8Array([0x52, 0x4e, 0x4c, 0x4d]))).toBe(false)
  })

  it('validates envelope format and schemaVersion', () => {
    const bad = {
      format: MAPPING_BUNDLE_FORMAT,
      schemaVersion: MAPPING_BUNDLE_SCHEMA_VERSION,
      payload: samplePayload(),
      extra: true,
    }
    const result = parseMappingBundleJsonText(JSON.stringify(bad))
    expect(result.ok).toBe(false)
  })

  it('rejects a payload with too many sources', () => {
    const payload = samplePayload()
    const tooManySources = {
      ...payload,
      // T72 raised the session cap to 256 — reject just above it.
      sources: Array.from({ length: 257 }, (_, i) => ({ id: `s${i}`, kind: 'text' as const, name: `f${i}.log` })),
    }
    const json = JSON.stringify({
      format: MAPPING_BUNDLE_FORMAT,
      schemaVersion: MAPPING_BUNDLE_SCHEMA_VERSION,
      payload: tooManySources,
    })
    const result = parseMappingBundleJsonText(json)
    expect(result.ok).toBe(false)
  })
})
