import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import {
  installInProcessMappingWorkerForTests,
  resetInProcessMappingWorkerForTests,
} from '../helpers/inProcessMappingWorker'
import { releaseMappingSession } from '../../src/mapping/sessionLifecycle'
import { getSharedMappingClient } from '../../src/mapping/sharedMappingClient'

describe('Stage 19 session lifecycle', () => {
  beforeEach(() => {
    installInProcessMappingWorkerForTests()
  })

  afterEach(() => {
    resetInProcessMappingWorkerForTests()
  })

  it('releaseMappingSession terminates worker and clears published snapshot', async () => {
    const client = getSharedMappingClient()
    await client.resolve('gen', 'source', [{
      category: 'ip',
      canonical: '10.0.0.1',
      constraint: { kind: 'ipv4-wire' },
    }])
    expect(client.getPublishedSnapshot()).not.toBeNull()
    expect(client.getPublishedRevision()).toBeGreaterThan(0)

    releaseMappingSession()

    const client2 = getSharedMappingClient()
    expect(client2.getPublishedSnapshot()).toBeNull()
    expect(client2.getPublishedRevision()).toBe(0)
  })

  it('resetSession clears mapping revision on worker', async () => {
    const client = getSharedMappingClient()
    await client.resolve('gen', 'source', [{
      category: 'ip',
      canonical: '10.0.0.5',
      constraint: { kind: 'ipv4-wire' },
    }])
    expect(client.getPublishedRevision()).toBe(1)
    await client.resetSession()
    expect(client.getPublishedRevision()).toBe(0)
    expect(client.getPublishedSnapshot()).toBeNull()
  })
})
