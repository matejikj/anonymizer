/**
 * Shared SourceAdapter conformance suite (Stage 23).
 * Built from Stage 16 primitives — probe, preflight, discover, buildPlan, no-network.
 */

import { expect } from 'vitest'
import type { SourceAdapter } from '../../src/correlation/types'
import { correlationSourceLimits } from '../../src/correlation/sourceLimits'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { assertNoNetworkInConformance, expectVersionedRequest } from './primitives'

export interface AdapterConformanceContext {
  readonly adapter: SourceAdapter
  readonly sampleFile: File
  readonly generationId: string
  readonly sourceId: string
}

export async function runSourceAdapterConformance(ctx: AdapterConformanceContext): Promise<void> {
  const restoreNetwork = assertNoNetworkInConformance()
  try {
    const limits = correlationSourceLimits()
    const head = new Uint8Array(await ctx.sampleFile.slice(0, 16).arrayBuffer())

    const probe = ctx.adapter.probe(head, ctx.sampleFile)
    expect(probe.ok).toBe(true)

    const preflight = await ctx.adapter.preflight(ctx.sampleFile, limits)
    expect(preflight.ok).toBe(true)

    const discovery = await ctx.adapter.discover({
      generationId: ctx.generationId,
      sourceId: ctx.sourceId,
      file: ctx.sampleFile,
    })
    expect(discovery.sourceId).toBe(ctx.sourceId)
    expect(discovery.generationId).toBe(ctx.generationId)
    expect(discovery.identities.length).toBeGreaterThanOrEqual(0)

    for (const id of discovery.identities) {
      expect(id.canonical.length).toBeGreaterThan(0)
    }

    const authority = new MappingAuthority()
    const resolved = authority.resolve({
      generationId: ctx.generationId,
      sourceId: ctx.sourceId,
      identities: [...discovery.identities],
    })
    expect(resolved.ok).toBe(true)
    if (!resolved.ok) return

    const planA = await ctx.adapter.buildPlan({
      generationId: ctx.generationId,
      sourceId: ctx.sourceId,
      snapshot: resolved.snapshot,
      discovery,
    })
    const planB = await ctx.adapter.buildPlan({
      generationId: ctx.generationId,
      sourceId: ctx.sourceId,
      snapshot: resolved.snapshot,
      discovery,
    })

    expect(JSON.stringify(planA)).toBe(JSON.stringify(planB))
    expectVersionedRequest({ protocolVersion: 1 })
  } finally {
    restoreNetwork()
  }
}
