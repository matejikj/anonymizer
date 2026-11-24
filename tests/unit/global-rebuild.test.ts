import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema'
import { cloneRulesetConfig } from '../../src/domain/rulesetValidate'
import { setActiveProfile } from '../../src/features/rules/activeProfile'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets'
import { setActivePcapProfile } from '../../src/pcap/profile/activePcapProfile'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient, getSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  PROFILE_COMPATIBILITY_OUTCOME,
  clearCorrelationSession,
  compileAndEvaluateSessionPolicy,
  createTextSourceAdapter,
  getPublishedCorrelationManifest,
  isSourcePlanStaleWithManifest,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resolveProfileConflict,
  runCorrelationSession,
  runGlobalCorrelationRebuild,
  requiresGlobalRebuild,
  sessionPolicyAllowsProcessing,
  stageCorrelationDescriptors,
  ProfileImpactKind,
  classifyProfileImpact,
  compileCorrelationPolicy,
} from '../../src/correlation'
import { getActiveProfile } from '../../src/features/rules/activeProfile'

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

describe('Stage 26 global rebuild and session policy integration', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    setActiveProfile(createDefaultRulesetConfig())
    setActivePcapProfile(createDefaultPcapProfile().profile)
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('blocks session processing until profile conflict is resolved', () => {
    setActiveProfile(textProfileWithFixedIp('ip-1'))

    compileAndEvaluateSessionPolicy({
      sourceKinds: [SK.Text, SK.Pcap],
      textProfile: getActiveProfile(),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    expect(sessionPolicyAllowsProcessing()).toBe(false)

    resolveProfileConflict('ipv4', { kind: PROFILE_COMPATIBILITY_OUTCOME.SessionOverride })
    expect(sessionPolicyAllowsProcessing()).toBe(true)
  })

  it('rejects stale source plan after generation and mapping revision change', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'log-a', kind: SK.Text, file: textFile('a.log', 'peer 10.0.0.44 connected\n') },
    ])
    await runCorrelationSession()

    const manifestBefore = getPublishedCorrelationManifest()
    expect(manifestBefore).toBeTruthy()

    expect(isSourcePlanStaleWithManifest({
      planGenerationId: manifestBefore!.generationId,
      planMappingRevision: manifestBefore!.mappingRevision,
      sessionGenerationId: manifestBefore!.generationId,
      manifestMappingRevision: manifestBefore!.mappingRevision,
    })).toBe(false)

    expect(isSourcePlanStaleWithManifest({
      planGenerationId: manifestBefore!.generationId,
      planMappingRevision: manifestBefore!.mappingRevision,
      sessionGenerationId: 'gen-new',
      manifestMappingRevision: manifestBefore!.mappingRevision + 1,
    })).toBe(true)
  })

  it('runs global rebuild for representation-policy impact on ready text session', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'log-a', kind: SK.Text, file: textFile('a.log', 'peer 10.0.0.44 connected\n') },
    ])
    await runCorrelationSession()

    const before = getPublishedCorrelationManifest()!
    const impact = classifyProfileImpact(
      compileCorrelationPolicy({ sourceKinds: [SK.Text], textProfile: createDefaultRulesetConfig() }),
      compileCorrelationPolicy({ sourceKinds: [SK.Text], textProfile: textProfileWithFixedIp('9.9.9.9') }),
    )
    expect(requiresGlobalRebuild(impact)).toBe(true)
    expect(impact.kind).toBe(ProfileImpactKind.RepresentationPolicy)

    setActiveProfile(textProfileWithFixedIp('9.9.9.9'))
    const rebuilt = await runGlobalCorrelationRebuild(impact)
    expect('ok' in rebuilt && rebuilt.ok).toBe(true)

    const after = getPublishedCorrelationManifest()!
    expect(after.mappingRevision).toBeGreaterThanOrEqual(before.mappingRevision)
    expect(after.generationId).not.toBe(before.generationId)
  })
})
