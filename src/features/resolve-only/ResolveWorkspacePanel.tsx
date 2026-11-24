import { useId, useMemo, useState } from 'react'
import { RESOLVE_WORKSPACE_LIMITS } from '../../domain/capabilityContract.ts'
import type { MappingBundlePayload } from '../../mapping/bundle/types.ts'
import {
  annotateAiReport,
  exactLookupByAlias,
  scanAiReport,
  type ExactLookupResult,
  type ReportFinding,
  type ResolveError,
  type ResolveLookupCandidate,
  type ResolveMappingSource,
  type ScanReportResult,
} from '../../mapping/resolve/index.ts'
import { cs } from '../../i18n/cs.ts'
import { Button } from '../../design-system/index.ts'
import { identityCategoryLabel } from './identityCategoryLabel.ts'
import { MaskedOriginal } from './MaskedOriginal.tsx'

export function ResolveWorkspacePanel(props: {
  source: ResolveMappingSource
  bundlePayload?: MappingBundlePayload | null
  onClose?: () => void
}) {
  const aliasInputId = useId()
  const reportInputId = useId()
  const [aliasQuery, setAliasQuery] = useState('')
  const [exactResult, setExactResult] = useState<ExactLookupResult | ResolveError | null>(null)
  const [reportText, setReportText] = useState('')
  const [scanResult, setScanResult] = useState<ScanReportResult | null>(null)
  const [annotated, setAnnotated] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reportBytes = useMemo(
    () => new TextEncoder().encode(reportText).byteLength,
    [reportText],
  )

  const runExactLookup = () => {
    setError(null)
    setAnnotated(null)
    const result = exactLookupByAlias(aliasQuery, props.source, props.bundlePayload ?? null)
    setExactResult(result)
    if ('code' in result) setError(result.message)
  }

  const runScan = () => {
    setError(null)
    setAnnotated(null)
    const result = scanAiReport(reportText, props.source, props.bundlePayload ?? null)
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
    <section className="resolve-panel" data-testid="resolve-workspace-panel">
      <header className="resolve-panel__header">
        <h2>{cs.resolve.title}</h2>
        {props.onClose ? (
          <Button variant="ghost" data-testid="resolve-panel-close" onClick={props.onClose}>
            {cs.resolveReturn.closeClear}
          </Button>
        ) : null}
      </header>

      <div className="resolve-panel__section">
        <h3>{cs.resolve.exactTitle}</h3>
        <label htmlFor={aliasInputId}>{cs.resolve.aliasLabel}</label>
        <div className="resolve-panel__row">
          <input
            id={aliasInputId}
            type="text"
            data-testid="resolve-alias-input"
            value={aliasQuery}
            onChange={(e) => setAliasQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') runExactLookup()
            }}
          />
          <Button variant="secondary" data-testid="resolve-exact-submit" onClick={runExactLookup}>
            {cs.resolve.lookup}
          </Button>
        </div>
        {exactResult && !('code' in exactResult) ? (
          <ExactResultView result={exactResult} />
        ) : null}
      </div>

      <div className="resolve-panel__section">
        <h3>{cs.resolve.reportTitle}</h3>
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
        {scanResult && scanResult.findings.length > 0 ? (
          <FindingsList findings={scanResult.findings} />
        ) : null}
        {annotated ? (
          <div className="resolve-panel__annotated" data-testid="resolve-annotated-output">
            <h4>{cs.resolve.annotatedTitle}</h4>
            <p className="resolve-panel__hint">{cs.resolveReturn.annotateContainsOriginals}</p>
            <textarea readOnly rows={8} value={annotated} />
            <Button variant="ghost" data-testid="resolve-copy-annotated" onClick={() => void copyAnnotated()}>
              {cs.resolve.copyAnnotated}
            </Button>
          </div>
        ) : null}
      </div>

      {error ? (
        <p className="form-error" role="alert" data-testid="resolve-error">
          {error}
        </p>
      ) : null}
    </section>
  )
}

function ExactResultView(props: { result: ExactLookupResult }) {
  if (props.result.candidates.length === 0) {
    return <p data-testid="resolve-exact-empty">{cs.resolve.notFound}</p>
  }
  if (props.result.ambiguous) {
    return (
      <div data-testid="resolve-exact-ambiguous">
        <p className="resolve-panel__warn">{cs.resolve.ambiguousWarning}</p>
        <CandidateList candidates={props.result.candidates} />
      </div>
    )
  }
  return (
    <div data-testid="resolve-exact-result">
      <CandidateList candidates={props.result.candidates} />
    </div>
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
