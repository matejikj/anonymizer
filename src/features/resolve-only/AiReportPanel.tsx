/**
 * "Translate an AI answer back to originals" tool for the resolve-only workspace (Stage 30
 * redesign). Paste a chunk of AI-generated text containing pseudonyms; get every one of them
 * resolved (or flagged ambiguous) and, on request, a fully annotated copy.
 */

import { useId, useMemo, useState } from 'react'
import { RESOLVE_WORKSPACE_LIMITS } from '../../domain/capabilityContract.ts'
import type { MappingBundlePayload } from '../../mapping/bundle/types.ts'
import {
  annotateAiReport,
  scanAiReport,
  type ReportFinding,
  type ResolveLookupCandidate,
  type ScanReportResult,
} from '../../mapping/resolve/index.ts'
import { cs } from '../../i18n/cs.ts'
import { Button } from '../../design-system/index.ts'
import { identityCategoryLabel } from './identityCategoryLabel.ts'
import { MaskedOriginal } from './MaskedOriginal.tsx'

export function AiReportPanel(props: { bundlePayload: MappingBundlePayload }) {
  const reportInputId = useId()
  const [reportText, setReportText] = useState('')
  const [scanResult, setScanResult] = useState<ScanReportResult | null>(null)
  const [annotated, setAnnotated] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reportBytes = useMemo(
    () => new TextEncoder().encode(reportText).byteLength,
    [reportText],
  )

  const runScan = () => {
    setError(null)
    setAnnotated(null)
    const result = scanAiReport(reportText, 'imported-bundle', props.bundlePayload)
    if ('code' in result) {
      setError(result.message)
      setScanResult(null)
      return
    }
    setScanResult(result)
  }

  const runAnnotate = () => {
    if (!scanResult) return
    setAnnotated(annotateAiReport(reportText, scanResult, cs.resolve.ambiguousLabel))
  }

  const copyAnnotated = async () => {
    if (!annotated) return
    try {
      await navigator.clipboard.writeText(annotated)
      setError(null)
    } catch {
      setError(cs.resolve.clipboardFailed)
    }
  }

  return (
    <section className="resolve-panel__section mapping-ai-report" data-testid="mapping-ai-report">
      <h2 className="type-section-title">{cs.resolveReturn.aiReportTitle}</h2>

      <label htmlFor={reportInputId}>{cs.resolve.reportLabel}</label>
      <textarea
        id={reportInputId}
        data-testid="resolve-report-input"
        rows={8}
        value={reportText}
        onChange={(e) => setReportText(e.target.value)}
      />
      <p className="resolve-panel__meta">
        {(reportBytes / 1024).toFixed(1)} KiB / {(RESOLVE_WORKSPACE_LIMITS.maxAiReportBytes / 1024).toFixed(0)} KiB
      </p>
      <div className="resolve-panel__row">
        <Button variant="secondary" data-testid="resolve-scan-submit" onClick={runScan}>
          {cs.resolve.scanReport}
        </Button>
        <Button
          variant="ghost"
          data-testid="resolve-annotate-submit"
          disabled={!scanResult || scanResult.findings.length === 0}
          onClick={runAnnotate}
        >
          {cs.resolve.annotateReport}
        </Button>
      </div>
      {scanResult ? (
        <p data-testid="resolve-scan-summary">
          {cs.resolve.scanSummary
            .replace('{n}', String(scanResult.findings.length))
            .replace('{trunc}', scanResult.truncated ? cs.resolve.scanTruncated : '')}
        </p>
      ) : null}
      {scanResult && scanResult.findings.length > 0 ? <FindingsList findings={scanResult.findings} /> : null}
      {annotated ? (
        <div className="resolve-panel__annotated" data-testid="resolve-annotated-output">
          <h3>{cs.resolve.annotatedTitle}</h3>
          <p className="resolve-panel__hint">{cs.resolveReturn.annotateContainsOriginals}</p>
          <textarea readOnly rows={8} value={annotated} />
          <Button variant="ghost" data-testid="resolve-copy-annotated" onClick={() => void copyAnnotated()}>
            {cs.resolve.copyAnnotated}
          </Button>
        </div>
      ) : null}
      {error ? (
        <p className="form-error" role="alert" data-testid="resolve-error">
          {error}
        </p>
      ) : null}
    </section>
  )
}

function FindingsList(props: { findings: readonly ReportFinding[] }) {
  return (
    <ul className="resolve-panel__findings" data-testid="resolve-findings-list">
      {props.findings.slice(0, 50).map((f, i) => (
        <li key={`${f.start}-${f.end}-${i}`} data-testid="resolve-finding">
          <code>{f.alias}</code>
          {f.ambiguous ? (
            <>
              <span> — {cs.resolve.ambiguousShort}</span>
              <CandidateList candidates={f.candidates} />
            </>
          ) : (
            <>
              <span> → </span>
              <MaskedOriginal value={f.candidates[0]?.canonical ?? '?'} />
            </>
          )}
        </li>
      ))}
      {props.findings.length > 50 ? (
        <li>{cs.resolve.findingsTruncated.replace('{n}', String(props.findings.length))}</li>
      ) : null}
    </ul>
  )
}

function CandidateList(props: { candidates: readonly ResolveLookupCandidate[] }) {
  return (
    <ul className="resolve-panel__candidates">
      {props.candidates.map((c) => (
        <li key={`${c.identityId}-${c.alias}`} data-testid="resolve-candidate">
          <MaskedOriginal value={c.canonical} />
          <span> — {identityCategoryLabel(c.category)}</span>
          <span> · {cs.resolve.occurrences.replace('{n}', String(c.occurrenceCount))}</span>
          {c.disposition === 'ambiguous-fixed' ? (
            <span className="resolve-panel__tag">{cs.resolve.fixedReplacement}</span>
          ) : null}
        </li>
      ))}
    </ul>
  )
}
