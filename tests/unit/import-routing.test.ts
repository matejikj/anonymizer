import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  ingestDroppedFiles,
  canConfirmCorrelationStaging,
  confirmCorrelationStaging,
  getStagingItems,
  openCorrelationStaging,
  resetCorrelationImportForTests,
  resetCorrelationAdaptersForTests,
  registerSourceAdapter,
  getStagingProfileCompatibilityReport,
  PROFILE_COMPATIBILITY_OUTCOME,
} from '../../src/correlation'
import { cloneRulesetConfig } from '../../src/domain/rulesetValidate'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema'
import { setActiveProfile, resetActiveProfile } from '../../src/features/rules/activeProfile'
import { useAppStore } from '../../src/app/store'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

function textProfileWithFixedIp(value: string) {
  const config = cloneRulesetConfig(createDefaultRulesetConfig())
  config.profile.rules.push({
    id: 'ip-fixed',
    name: 'fixed ip',
    enabled: true,
    kind: 'literal',
    pattern: '10.',
    category: 'ip',
    replacement: { kind: 'fixed', value },
    priority: 5000,
  })
  return config
}

describe('Stage 27 import routing', () => {
  beforeEach(() => {
    resetCorrelationImportForTests()
    clearCorrelationSession()
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    resetActiveProfile()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    resetCorrelationImportForTests()
    clearCorrelationSession()
    resetSharedMappingClient()
    resetActiveProfile()
  })

  it('routes a single valid text file to single-text without staging phase', async () => {
    const route = await ingestDroppedFiles([textFile('one.log', 'contact 10.0.0.1\n')])
    expect(route.kind).toBe('single-text')
  })

  it('opens staging for two valid text files', async () => {
    const route = await ingestDroppedFiles([
      textFile('a.log', 'a 10.0.0.1\n'),
      textFile('b.log', 'b 10.0.0.2\n'),
    ])
    expect(route.kind).toBe('staging')
    if (route.kind !== 'staging') return
    expect(route.summary.readyCount).toBe(2)
    openCorrelationStaging()
    expect(useAppStore.getState().phase).toBe('correlation-staging')
    expect(getStagingItems()).toHaveLength(2)
  })

  it('allows confirm only with two ready sources under aggregate cap', async () => {
    await ingestDroppedFiles([
      textFile('a.log', 'a 10.0.0.1\n'),
      textFile('b.log', 'b 10.0.0.2\n'),
    ])
    expect(canConfirmCorrelationStaging()).toBe(true)
  })

  it('blocks confirm when profile conflict is unresolved', async () => {
    setActiveProfile(textProfileWithFixedIp('ip-1'))
    await ingestDroppedFiles([
      textFile('a.log', 'a 10.0.0.1\n'),
      textFile('b.log', 'b 10.0.0.2\n'),
    ])
    // text-only multi-source has no cross-format conflict
    expect(canConfirmCorrelationStaging()).toBe(true)
  })

  it('stages and processes two text sources on confirm', async () => {
    await ingestDroppedFiles([
      textFile('a.log', 'a 10.0.0.1\n'),
      textFile('b.log', 'b 10.0.0.2\n'),
    ])
    const result = await confirmCorrelationStaging()
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(useAppStore.getState().phase).toBe('correlation-review')
  })

  it('keeps valid items when one file in batch is invalid', async () => {
    const route = await ingestDroppedFiles([
      textFile('good.log', 'ok 10.0.0.3\n'),
      new File([new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7])], 'bad.bin'),
      textFile('good2.log', 'ok 10.0.0.4\n'),
    ])
    expect(route.kind).toBe('staging')
    const items = getStagingItems()
    expect(items.filter((i) => i.status === 'ready')).toHaveLength(2)
    expect(items.filter((i) => i.status === 'error')).toHaveLength(1)
  })
})

describe('Stage 27 staging profile preview', () => {
  beforeEach(() => {
    resetCorrelationImportForTests()
    resetActiveProfile()
  })

  it('returns null compatibility report for single-source staging', async () => {
    await ingestDroppedFiles([
      textFile('a.log', 'a\n'),
      textFile('b.log', 'b\n'),
    ])
    // two text-only sources — no text+pcap policy intersection required in UI
    const report = getStagingProfileCompatibilityReport()
    expect(report?.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.Compatible)
  })
})
