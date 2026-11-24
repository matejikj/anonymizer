import { describe, expect, it } from 'vitest'
import { assertNoNewline, assertNonEmptyMatch } from '../../src/domain/invariants.ts'
import { BYTES_PER_MIB, MAX_TEXT_FILE_BYTES, TEXT_INPUT_LIMITS } from '../../src/domain/capabilityContract.ts'
import { INPUT_LIMITS } from '../../src/features/import-log/inputLimits.ts'
import { RND_LOG_ANONYMIZER_SCHEMA_URN, SUPPORTED_SCHEMA_VERSION } from '../../src/domain/configSchema.ts'

describe('domain invariants', () => {
  it('rejects newlines in replacements', () => {
    expect(() => assertNoNewline('ok', 'replacement')).not.toThrow()
    expect(() => assertNoNewline('bad\n', 'replacement')).toThrow(/nového řádku/)
    expect(() => assertNoNewline('bad\r', 'replacement')).toThrow(/nového řádku/)
  })

  it('rejects empty matches', () => {
    expect(() => assertNonEmptyMatch(0, 1)).not.toThrow()
    expect(() => assertNonEmptyMatch(3, 3)).toThrow(/kladnou délku/)
  })
})

describe('input limits', () => {
  it('matches capability contract capacities', () => {
    expect(BYTES_PER_MIB).toBe(1024 * 1024)
    expect(TEXT_INPUT_LIMITS.commonMaxBytes).toBe(30 * BYTES_PER_MIB)
    expect(TEXT_INPUT_LIMITS.fileMaxBytes).toBe(MAX_TEXT_FILE_BYTES)
    expect(INPUT_LIMITS.fileMaxBytes).toBe(MAX_TEXT_FILE_BYTES)
    expect(TEXT_INPUT_LIMITS.pasteMaxBytes).toBe(30 * BYTES_PER_MIB)
    expect(TEXT_INPUT_LIMITS.fileMaxLines).toBe(400_000)
  })
})

describe('config schema placeholders', () => {
  it('uses a local URN, not a network URL', () => {
    expect(RND_LOG_ANONYMIZER_SCHEMA_URN.startsWith('urn:')).toBe(true)
    expect(RND_LOG_ANONYMIZER_SCHEMA_URN.includes('http')).toBe(false)
    expect(SUPPORTED_SCHEMA_VERSION).toBe(2)
    expect(RND_LOG_ANONYMIZER_SCHEMA_URN).toBe('urn:rnd-log-anonymizer:schema:ruleset:1')
  })
})
