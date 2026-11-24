import { describe, expect, it } from 'vitest'
import { SequentialGate, correlationResolveGate } from '../../src/correlation/sequentialGate'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient, getSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'

describe('Stage 23 sequential gate', () => {
  it('runs tasks with bounded concurrency 1', async () => {
    const gate = new SequentialGate()
    let concurrent = 0
    let maxConcurrent = 0

    const task = async (ms: number) => {
      concurrent++
      maxConcurrent = Math.max(maxConcurrent, concurrent)
      await new Promise((r) => setTimeout(r, ms))
      concurrent--
    }

    await Promise.all([
      gate.run('a', () => task(20)),
      gate.run('b', () => task(20)),
      gate.run('c', () => task(20)),
    ])

    expect(maxConcurrent).toBe(1)
  })

  it('mapping resolve races serialize through correlationResolveGate', async () => {
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    const client = getSharedMappingClient()

    const identity = {
      category: 'ip' as const,
      canonical: '10.0.0.44',
      constraint: { kind: 'ipv4-wire' as const },
    }

    const [snapA, snapB] = await Promise.all([
      correlationResolveGate.run('resolve-a', () =>
        client.resolve('g-race', 'source-a', [identity]),
      ),
      correlationResolveGate.run('resolve-b', () =>
        client.resolve('g-race', 'source-b', [identity]),
      ),
    ])

    const aliasA = snapA.entries.find((e) => e.canonical === '10.0.0.44')?.alias
    const aliasB = snapB.entries.find((e) => e.canonical === '10.0.0.44')?.alias
    expect(aliasA).toBeTruthy()
    expect(aliasB).toBe(aliasA)
    resetSharedMappingClient()
  })
})
