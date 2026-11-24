/**
 * Test-only source adapter for conformance / registry tests (Stage 23).
 */

import type { CanonicalIdentity } from '../../src/mapping/types.ts'
import type {
  BuildPlanRequest,
  DiscoveryRequest,
  ProbeResult,
  SourceAdapter,
  SourceLimits,
  SourcePreflightResult,
  TestSourceDiscovery,
  TestSourcePlan,
} from '../../src/correlation/types.ts'

export function createTestSourceAdapter(): SourceAdapter<TestSourceDiscovery, TestSourcePlan> {
  return {
    kind: 'test',

    probe(_head: Uint8Array, file: File): ProbeResult {
      if (!file.name.endsWith('.testsrc')) {
        return { ok: false, code: 'not-test', message: 'Expected .testsrc fixture' }
      }
      return { ok: true, kind: 'test' }
    },

    async preflight(file: File, limits: SourceLimits): Promise<SourcePreflightResult> {
      if (file.size > limits.maxFileBytes) {
        return { ok: false, code: 'too-large', message: 'Test source too large' }
      }
      return { ok: true, byteLength: file.size, kind: 'test' }
    },

    async discover(request: DiscoveryRequest): Promise<TestSourceDiscovery> {
      const text = await request.file.text()
      const identities: CanonicalIdentity[] = []
      const token = text.trim()
      if (token.includes('10.0.0.1')) {
        identities.push({
          category: 'ip',
          canonical: '10.0.0.1',
          constraint: { kind: 'ipv4-wire' },
        })
      }
      return {
        kind: 'test',
        generationId: request.generationId,
        sourceId: request.sourceId,
        fileName: request.file.name,
        byteLength: request.file.size,
        identities,
      }
    },

    async buildPlan(
      request: BuildPlanRequest & { discovery: TestSourceDiscovery },
    ): Promise<TestSourcePlan> {
      const aliasCount = request.snapshot.entries.length
      return {
        kind: 'test',
        generationId: request.generationId,
        sourceId: request.sourceId,
        mappingRevision: request.snapshot.mappingRevision,
        signature: `${request.sourceId}:${aliasCount}:${request.discovery.identities.length}`,
        outputFileName: request.discovery.fileName.replace('.testsrc', '.anonym.test'),
      }
    },
  }
}

export const testSourceAdapter = createTestSourceAdapter()
