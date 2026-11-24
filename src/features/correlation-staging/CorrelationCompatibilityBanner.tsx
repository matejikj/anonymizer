import { useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import {
  PROFILE_COMPATIBILITY_OUTCOME,
  type ProfileCompatibilityReport,
} from '../../correlation/profileCompatibility'
import type { CrossFormatCategory } from '../../mapping/crossFormat/types'
import type { ProfileConflictResolution } from '../../correlation/profileCompatibility/types'
import { Button } from '../../design-system/index.ts'

function conflictMessage(report: ProfileCompatibilityReport): string {
  const first = report.unresolved[0]
  if (!first) return ''
  const key = first.reasonKey
  if (key.startsWith('text-fixed-non-wire-ipv4') || key.startsWith('text-fixed-non-wire-ipv6')) {
    return cs.correlationStaging.conflictIpFormat
  }
  if (key.startsWith('text-fixed-non-wire-')) {
    return cs.correlationStaging.conflictCategory(first.category)
  }
  return cs.correlationStaging.conflictGeneric(first.category)
}

function resolutionLabel(resolution: ProfileConflictResolution): string {
  if (resolution.kind === PROFILE_COMPATIBILITY_OUTCOME.SessionOverride) {
    return cs.correlationStaging.resolutionSessionOverride
  }
  if (resolution.kind === PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory) {
    return cs.correlationStaging.resolutionUncorrelated
  }
  return cs.correlationStaging.resolutionBlocking
}

export interface CorrelationCompatibilityBannerProps {
  readonly report: ProfileCompatibilityReport | null
  readonly onApplyRecommended: () => void
  readonly onResolve: (category: CrossFormatCategory, resolution: ProfileConflictResolution) => void
}

export function CorrelationCompatibilityBanner({
  report,
  onApplyRecommended,
  onResolve,
}: CorrelationCompatibilityBannerProps) {
  const [advancedOpen, setAdvancedOpen] = useState(false)

  if (!report || report.unresolved.length === 0) return null

  const first = report.unresolved[0]!

  return (
    <div className="staging-banner staging-banner--warn" role="region" aria-labelledby="compat-banner-title">
      <p id="compat-banner-title" className="staging-banner__title type-section-title">
        {cs.correlationStaging.conflictTitle}
      </p>
      <p className="staging-banner__body">{conflictMessage(report)}</p>
      <div className="staging-banner__actions">
        <Button variant="primary" data-testid="compat-apply-recommended" onClick={onApplyRecommended}>
          {cs.correlationStaging.applyRecommended}
        </Button>
        <Button
          variant="ghost"
          aria-expanded={advancedOpen}
          data-testid="compat-advanced-toggle"
          onClick={() => setAdvancedOpen((v) => !v)}
        >
          {cs.correlationStaging.otherOptions}
        </Button>
      </div>
      {advancedOpen ? (
        <ul className="staging-banner__options">
          <li className="staging-banner__impact" data-testid="compat-recommended-impact">
            {cs.correlationStaging.conflictRecommendedImpact}
          </li>
          <li
            className="staging-banner__impact staging-banner__impact--muted"
            data-testid="compat-uncorrelated-impact"
          >
            {cs.correlationStaging.conflictUncorrelatedImpact}
          </li>
          {first.resolutions.map((resolution) => (
            <li key={resolution.kind}>
              <Button
                variant="secondary"
                data-testid={`compat-resolution-${first.category}-${resolution.kind}`}
                onClick={() => onResolve(first.category, resolution)}
              >
                {resolutionLabel(resolution)}
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
