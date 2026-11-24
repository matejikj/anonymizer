import { describe, expect, it } from 'vitest'
import { DetectionSession } from '../../src/workers/detectionSession.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { fromTransferableBuffers } from '../../src/engine/packedMatchIndex.ts'
import { analyze } from '../../src/engine/analyze.ts'

describe('DetectionSession', () => {
  it('matches reference analyze() for multi-chunk paste text', () => {
    const text = [
      'peer 10.16.1.105 via ldap-pra.corp.example',
      "dispatcher 'Krejci Iveta' sip:972051127@10.16.1.105",
      'user=disp5 MP_PRA',
    ].join('\n')

    const progress: Array<[number, number]> = []
    const session = new DetectionSession({
      onProgress: (b, l) => progress.push([b, l]),
      onRuleStarted: () => {},
      onHeartbeat: () => {},
    })
    const profile = createDefaultRulesetConfig()
    session.start('r1', profile)
    const mid = Math.floor(text.length / 2)
    session.pushTextChunk(text.slice(0, mid), false)
    session.pushTextChunk(text.slice(mid), true)
    const out = session.finalizeDetection()

    const ref = analyze(text)
    expect(out.lineCount).toBe(ref.lineCount)
    expect(out.entities.length).toBe(ref.entities.length)

    const packed = fromTransferableBuffers(out.packedMatches)
    expect(packed.starts.length).toBe(ref.matches.length)
    expect(progress.length).toBeGreaterThan(0)
  })

  it('respects byteOffset/byteLength on a larger backing buffer', () => {
    const enc = new TextEncoder()
    const payload = enc.encode('10.1.1.1\n')
    const backing = new Uint8Array(32)
    backing.set(payload, 4)

    const session = new DetectionSession({
      onProgress: () => {},
      onRuleStarted: () => {},
      onHeartbeat: () => {},
    })
    session.start('r2', createDefaultRulesetConfig())
    session.pushByteChunk(backing.buffer, 4, payload.byteLength, true)
    const out = session.finalizeDetection()
    expect(out.entities.some((e) => e.category === 'ip')).toBe(true)
  })
})
