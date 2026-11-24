import { describe, expect, it } from 'vitest'
import {
  BYTES_PER_MIB,
  MAX_ENTITY_CARDINALITY,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
  CORRELATION_SESSION_LIMITS,
  MAPPING_CAPABILITY_LIMITS,
  PCAP_RECORD_LIMITS,
  TEXT_INPUT_LIMITS,
  withinByteLimit,
} from '../../src/domain/capabilityContract.ts'
import { INPUT_LIMITS } from '../../src/features/import-log/inputLimits.ts'
import { MAX_RECORD_SIZE } from '../../src/pcap/domain/types.ts'
import { MAX_ENTITY_CARDINALITY as PCAP_MAX_ENTITY } from '../../src/pcap/anonymization/entityRegistry.ts'
import {
  MAX_FIXTURE_TEXT_CANARIES,
  generateMicroClassicPcap,
  generateMicroPcapng,
  generateMicroText,
  MAXIMUM_FIXTURE_TARGETS,
} from '../performance/maximumFixtureGenerators.ts'
import {
  createPerfDiagnosticHook,
} from '../performance/perfDiagnostics.ts'

describe('capabilityContract', () => {
  it('defines canonical byte limits', () => {
    expect(MAX_TEXT_FILE_BYTES).toBe(90 * BYTES_PER_MIB)
    expect(MAX_PCAP_FILE_BYTES).toBe(100 * BYTES_PER_MIB)
    expect(TEXT_INPUT_LIMITS.fileMaxBytes).toBe(MAX_TEXT_FILE_BYTES)
    expect(INPUT_LIMITS.fileMaxBytes).toBe(MAX_TEXT_FILE_BYTES)
  })

  it('accepts limit and rejects limit + 1 for text files', () => {
    expect(withinByteLimit(MAX_TEXT_FILE_BYTES, MAX_TEXT_FILE_BYTES)).toBe(true)
    expect(withinByteLimit(MAX_TEXT_FILE_BYTES + 1, MAX_TEXT_FILE_BYTES)).toBe(false)
  })

  it('accepts limit and rejects limit + 1 for pcap files', () => {
    expect(withinByteLimit(MAX_PCAP_FILE_BYTES, MAX_PCAP_FILE_BYTES)).toBe(true)
    expect(withinByteLimit(MAX_PCAP_FILE_BYTES + 1, MAX_PCAP_FILE_BYTES)).toBe(false)
  })

  it('shares entity cardinality between text and pcap', () => {
    expect(MAX_ENTITY_CARDINALITY).toBe(500_000)
    expect(PCAP_MAX_ENTITY).toBe(MAX_ENTITY_CARDINALITY)
  })

  it('keeps record size separate from file cap', () => {
    expect(PCAP_RECORD_LIMITS.maxRecordSize).toBe(16 * BYTES_PER_MIB)
    expect(MAX_RECORD_SIZE).toBe(PCAP_RECORD_LIMITS.maxRecordSize)
    expect(PCAP_RECORD_LIMITS.maxRecordSize).toBeLessThan(MAX_PCAP_FILE_BYTES)
  })

  it('defines correlation session aggregate limits explicitly', () => {
    // T72 — package/support-bundle source count; aggregate bytes remain the hard budget.
    expect(CORRELATION_SESSION_LIMITS.maxSources).toBe(256)
    expect(CORRELATION_SESSION_LIMITS.maxAggregateBytes).toBe(200 * BYTES_PER_MIB)
    expect(CORRELATION_SESSION_LIMITS.maxSources).toBe(MAPPING_CAPABILITY_LIMITS.maxSourcesPerSession)
    expect(MAX_PCAP_FILE_BYTES).toBeLessThan(CORRELATION_SESSION_LIMITS.maxAggregateBytes)
  })

  it('defines mapping bundle limits before serialization', () => {
    expect(MAPPING_CAPABILITY_LIMITS.maxIdentities).toBe(MAX_ENTITY_CARDINALITY)
    expect(MAPPING_CAPABILITY_LIMITS.maxAliasesPerIdentity).toBeGreaterThan(0)
    expect(MAPPING_CAPABILITY_LIMITS.maxBundleBytes).toBeLessThanOrEqual(
      MAPPING_CAPABILITY_LIMITS.maxBundleImportBytes,
    )
    expect(MAPPING_CAPABILITY_LIMITS.pbkdf2MinIterations).toBeGreaterThanOrEqual(100_000)
    expect(MAPPING_CAPABILITY_LIMITS.pbkdf2MaxIterations).toBeGreaterThan(
      MAPPING_CAPABILITY_LIMITS.pbkdf2MinIterations,
    )
    expect(MAPPING_CAPABILITY_LIMITS.pbkdf2DefaultIterations).toBeGreaterThanOrEqual(
      MAPPING_CAPABILITY_LIMITS.pbkdf2MinIterations,
    )
  })

  it('maximum fixture targets match contract', () => {
    expect(MAXIMUM_FIXTURE_TARGETS.textBytes).toBe(MAX_TEXT_FILE_BYTES)
    expect(MAXIMUM_FIXTURE_TARGETS.pcapBytes).toBe(MAX_PCAP_FILE_BYTES)
  })
})

describe('maximumFixtureGenerators (micro)', () => {
  it('hits exact micro byte targets for LF and CRLF', () => {
    const lf = generateMicroText(4096, 'lf')
    expect(lf.byteLength).toBe(4096)
    expect(lf.lineEnding).toBe('lf')

    const crlf = generateMicroText(8192, 'crlf')
    expect(crlf.byteLength).toBe(8192)
    expect(crlf.text).toContain('\r\n')
  })

  it('embeds builtin and production-profile canaries', () => {
    const sample = generateMicroText(16_384, 'lf')
    for (const token of MAX_FIXTURE_TEXT_CANARIES.builtin) {
      expect(sample.text).toContain(token)
    }
    for (const token of MAX_FIXTURE_TEXT_CANARIES.productionProfile) {
      expect(sample.text).toContain(token)
    }
  })

  it('builds classic PCAP and PCAPNG at exact micro target size', () => {
    const classic = generateMicroClassicPcap(32 * 1024)
    expect(classic.byteLength).toBe(32 * 1024)

    const ng = generateMicroPcapng(48 * 1024)
    expect(ng.byteLength).toBe(48 * 1024)
  })
})

describe('perfDiagnostics', () => {
  it('records first progress, interactive, copies and phases', () => {
    const hook = createPerfDiagnosticHook(1000)
    hook.markPhase('import')
    hook.recordFirstProgress()
    hook.recordCopy(512)
    hook.recordTransfer(256)
    hook.setInFlightBytes(1024)
    hook.recordInteractive()
    hook.endPhase('import')
    const snap = hook.snapshot()
    expect(snap.timeToFirstProgressMs).toBeDefined()
    expect(snap.timeToInteractiveMs).toBeDefined()
    expect(snap.copyOperations).toBe(1)
    expect(snap.copiedBytes).toBe(512)
    expect(snap.transferredBytes).toBe(256)
    expect(snap.maxInFlightBytes).toBe(1024)
    expect(snap.phases.length).toBe(1)
  })
})
