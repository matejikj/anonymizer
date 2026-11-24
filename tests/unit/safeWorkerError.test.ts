/**
 * T03 — safe worker error boundary must never forward original values.
 */

import { describe, expect, it } from 'vitest'
import { toSafeWorkerError } from '../../src/domain/safeWorkerError'
import { MappingLookupError, MappingPatchError } from '../../src/pcap/anonymization/mappingErrors'
import { PlanInvariantError } from '../../src/pcap/plan/planErrors'
import { SnapshotMappingAdapter } from '../../src/pcap/plan/snapshotMappingAdapter'
import { formatUnknownPlanErrorForUser } from '../../src/pcap/ui/formatPlanError'
import type { MappingSnapshot } from '../../src/mapping/types'

const CANARY = 'CANARY-SDP-SESSION-ID-2890844526123456789'

describe('T03 MappingLookupError messages', () => {
  it('never embeds canonical/raw values', () => {
    const err = new MappingLookupError('missing-snapshot-alias', { category: 'sdp-session-id' })
    expect(err.message).not.toContain(CANARY)
    expect(err.message).toContain('sdp-session-id')
    expect(err.message).toContain('missing-snapshot-alias')
    expect(err.category).toBe('sdp-session-id')
  })

  it('snapshot adapter throws without canonical in message', () => {
    const snapshot: MappingSnapshot = {
      scope: 'session',
      revision: 1,
      mappingRevision: 1,
      canonicalizationVersion: 1,
      generationId: 'g',
      sourceId: 'src',
      overflow: false,
      entries: [],
    }
    const adapter = new SnapshotMappingAdapter(snapshot)
    expect(() => adapter.map('sdp-session-id', CANARY)).toThrow(MappingLookupError)
    try {
      adapter.map('sdp-session-id', CANARY)
    } catch (e) {
      expect(e).toBeInstanceOf(MappingLookupError)
      expect((e as Error).message).not.toContain(CANARY)
      expect((e as MappingLookupError).category).toBe('sdp-session-id')
    }
  })
})

describe('T03 toSafeWorkerError', () => {
  it('maps MappingLookupError to Czech safeMessage without canary', () => {
    const err = new MappingLookupError('missing-snapshot-alias', { category: 'ssrc' })
    const safe = toSafeWorkerError(err, 'pcap-processing')
    expect(safe.safeMessage).not.toContain(CANARY)
    expect(safe.safeMessage).toMatch(/ssrc|mapování/i)
    expect(safe.code).toBe('missing-snapshot-alias')
  })

  it('never forwards unknown Error.message', () => {
    const err = new Error(`Internal boom with ${CANARY}`)
    const safe = toSafeWorkerError(err, 'pcap-export', 'internal')
    expect(safe.safeMessage).not.toContain(CANARY)
    expect(safe.safeMessage).not.toContain('Internal boom')
    expect(safe.safeMessage).toMatch(/Interní chyba|kód/i)
    expect(safe.code).toBe('internal')
  })

  it('maps PlanInvariantError and MappingPatchError safely', () => {
    const planErr = new PlanInvariantError({
      code: 'mapping-closure',
      message: `Missing alias ${CANARY}`,
      category: 'ipv4',
      canonical: CANARY,
      packetNumber: 7,
    })
    const safe = toSafeWorkerError(planErr, 'pcap-processing')
    expect(safe.safeMessage).not.toContain(CANARY)
    expect(safe.safeMessage).toContain('7')

    const patch = new MappingPatchError('length-mismatch', `len for ${CANARY}`)
    const safePatch = toSafeWorkerError(patch, 'pcap-processing')
    expect(safePatch.safeMessage).not.toContain(CANARY)
  })
})

describe('T03 formatUnknownPlanErrorForUser', () => {
  it('does not scrub-and-show raw Error.message', () => {
    const text = formatUnknownPlanErrorForUser(new Error(`leak ${CANARY}`))
    expect(text).not.toContain(CANARY)
    expect(text).toMatch(/Interní chyba|kód/i)
  })
})

describe('T03 mergePatchesStrict', () => {
  it('collision message never embeds nested err.message / canary', async () => {
    const { mergePatchesStrict } = await import('../../src/pcap/plan/mergePatchesStrict')
    const { PlanInvariantError } = await import('../../src/pcap/plan/planErrors')
    expect(() =>
      mergePatchesStrict(32, 3, [
        { offset: 0, data: new Uint8Array([1, 2, 3, 4]) },
        { offset: 2, data: new Uint8Array([9, 9]) },
      ]),
    ).toThrow(PlanInvariantError)
    try {
      mergePatchesStrict(32, 3, [
        { offset: 0, data: new Uint8Array([1, 2, 3, 4]) },
        { offset: 2, data: new Uint8Array([9, 9]) },
      ])
    } catch (e) {
      expect(e).toBeInstanceOf(PlanInvariantError)
      const msg = (e as Error).message
      expect(msg).toContain('packetIndex=3')
      expect(msg).toContain('patch-overlap')
      expect(msg).not.toContain(CANARY)
      // Must not embed MappingPatchError's verbose overlap detail template.
      expect(msg).not.toMatch(/vs \[/)
    }
  })
})
