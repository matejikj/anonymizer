import { describe, expect, it, vi } from 'vitest'
import { analyze } from '../../src/engine/analyze.ts'
import {
  toTransferableBuffers,
  packResolvedMatches,
  entityKeyToIndex,
  FLAG_ENABLED,
} from '../../src/engine/packedMatchIndex.ts'
import { buildReplacementPlan } from '../../src/engine/transform.ts'
import {
  buildSessionModel,
  clearSessionModel,
  rebuildSessionPlan,
} from '../../src/features/workspace/sessionModel.ts'
import {
  applyPackedLineEndings,
  packLineEndingsFromText,
} from '../../src/features/export-log/lineEndings.ts'
import { anonymizedDownloadName } from '../../src/features/export-log/exportFileName.ts'
import {
  copyAnonymizedBlob,
  ExportCancelledError,
  exportAnonymizedChunkedMain,
  exportAnonymizedReference,
  planExportChunks,
  runChunkedExport,
} from '../../src/features/export-log/exportCoordinator.ts'
import { getExportPlanSnapshot } from '../../src/features/export-log/replacementSnapshot.ts'
import { applyEffectiveMatchFlags } from '../../src/features/review/entityState.ts'

function sessionFromText(
  text: string,
  fileName: string | null = null,
  mode: 'common' | 'large' = 'common',
) {
  const lineEndings = packLineEndingsFromText(text)
  const lf = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  const result = analyze(lf)
  const entityIndexByKey = entityKeyToIndex(result.entities)
  const packed = packResolvedMatches(result.matches, entityIndexByKey, () => true)
  const { buffers } = toTransferableBuffers(packed)
  return buildSessionModel({
    text: lf,
    detection: {
      requestId: 't',
      packedMatches: buffers,
      entities: result.entitySummaries,
      lineCount: result.lineCount,
      failedRuleIds: [],
    },
    fileName,
    byteLength: text.length,
    mode,
    workerPlanTrusted: false,
    lineEndings,
  })
}

describe('export Krok 9', () => {
  it('names downloads per ARCHITECTURE §3.5', () => {
    expect(anonymizedDownloadName('app.log')).toBe('app.anonymized.log')
    expect(anonymizedDownloadName('notes.txt')).toBe('notes.anonymized.log')
    expect(anonymizedDownloadName('raw')).toBe('raw.anonymized.log')
    expect(anonymizedDownloadName(null, new Date('2026-08-16T10:11:12'))).toBe(
      'rnd-log-anonymizer-anonymized-20260816-101112.log',
    )
  })

  it('preserves CRLF on export while editor uses LF', () => {
    clearSessionModel()
    const raw = 'peer 10.1.1.1 ready\r\nnext line\r\n'
    const session = sessionFromText(raw, 'crlf.log')
    expect(session.original.includes('\r')).toBe(false)
    const snap = getExportPlanSnapshot(session)!
    const out = exportAnonymizedReference(snap)
    expect(out).toContain('\r\n')
    expect(out).not.toContain('10.1.1.1')
    expect(out.split('\r\n').length).toBe(raw.split('\r\n').length)
  })

  it('chunked main-thread export matches reference transform', async () => {
    clearSessionModel()
    const text = [
      'peer 10.16.1.105 via ldap-pra.corp.example',
      "dispatcher 'Krejci Iveta' sip:972051127@10.16.1.105",
      'user=disp5 MP_PRA',
    ].join('\n')
    sessionFromText(text, 'sample.log')
    const snap = getExportPlanSnapshot()!
    const reference = exportAnonymizedReference(snap)
    const result = await runChunkedExport({ forceMainThread: true })
    const exported = await result.blob.text()
    expect(exported).toBe(reference)
    expect(result.fileName).toBe('sample.anonymized.log')
  })

  it('multi-chunk main path matches full reference (30/90MB strategy)', () => {
    clearSessionModel()
    const lines = Array.from({ length: 200 }, (_, i) => `line-${i} peer 10.0.0.${i % 250}`)
    const raw = lines.join('\r\n') + '\r\n'
    sessionFromText(raw, 'big.log')
    const snap = getExportPlanSnapshot()!
    const reference = exportAnonymizedReference(snap)
    const chunked = exportAnonymizedChunkedMain(snap, 80)
    expect(planExportChunks(snap.original, 80).length).toBeGreaterThan(1)
    expect(chunked).toBe(reference)
    expect(chunked).toContain('\r\n')
    expect(chunked).not.toContain('10.0.0.1')
  })

  it('cancel via AbortSignal throws ExportCancelledError', async () => {
    clearSessionModel()
    sessionFromText('ip 10.1.1.1 end', 'x.log')
    const ac = new AbortController()
    ac.abort()
    await expect(runChunkedExport({ forceMainThread: true, signal: ac.signal })).rejects.toBeInstanceOf(
      ExportCancelledError,
    )
  })

  it('planExportChunks snaps to line boundaries', () => {
    const text = Array.from({ length: 20 }, (_, i) => `line-${i} 10.0.0.${i}`).join('\n')
    const chunks = planExportChunks(text, 40)
    expect(chunks.length).toBeGreaterThan(1)
    for (const c of chunks) {
      expect(c.to).toBeGreaterThan(c.from)
      if (c.to < text.length) {
        expect(text[c.to - 1] === '\n' || text.slice(c.to - 2, c.to) === '\r\n').toBe(true)
      }
    }
    expect(chunks[0]!.from).toBe(0)
    expect(chunks[chunks.length - 1]!.to).toBe(text.length)
  })

  it('applyPackedLineEndings round-trips mixed endings', () => {
    const raw = 'a\r\nb\nc\r'
    const endings = packLineEndingsFromText(raw)
    const lf = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    expect(applyPackedLineEndings(lf, endings)).toBe(raw)
  })

  it('disabled match stays original in export snapshot', () => {
    clearSessionModel()
    const text = 'ip 10.1.1.1 end'
    const session = sessionFromText(text)
    const ent = session.entities.find((e) => e.category === 'ip')!
    ent.enabled = false
    applyEffectiveMatchFlags(session.packed, session.entities, session.categoryMasters)
    session.plan = buildReplacementPlan(session.packed, session.entities)
    rebuildSessionPlan(session.entities)
    const out = exportAnonymizedReference(getExportPlanSnapshot(session)!)
    expect(out).toContain('10.1.1.1')
    expect(session.packed.flags.some((f) => (f & FLAG_ENABLED) === 0)).toBe(true)
  })

  it('clipboard string fallback keeps blob when writeText fails', async () => {
    const blob = new Blob(['anon'], { type: 'text/plain' })
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    vi.stubGlobal('navigator', {
      clipboard: { writeText, write: undefined },
    })
    vi.stubGlobal('ClipboardItem', undefined)
    const result = await copyAnonymizedBlob(blob, { allowStringFallback: true })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.blob).toBe(blob)
      expect(result.reason).toContain('denied')
    }
    vi.unstubAllGlobals()
  })

  it('large mode disallows string fallback unless opted in', async () => {
    const blob = new Blob(['anon'], { type: 'text/plain' })
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn(), write: undefined },
    })
    vi.stubGlobal('ClipboardItem', undefined)
    const denied = await copyAnonymizedBlob(blob, { allowStringFallback: false })
    expect(denied.ok).toBe(false)
    const allowed = await copyAnonymizedBlob(blob, { allowStringFallback: true })
    expect(allowed.ok).toBe(true)
    if (allowed.ok) expect(allowed.method).toBe('write-text')
    vi.unstubAllGlobals()
  })
})
