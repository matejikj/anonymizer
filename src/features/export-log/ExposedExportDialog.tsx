import type { ExposedSummary } from '../review/entityState.ts'
import { CATEGORY_LABELS } from '../review/categoryLabels.ts'
import { AccessibleModal, Button, ExportSummary } from '../../design-system/index.ts'
import { cs } from '../../i18n/cs.ts'

export function ExposedExportDialog(props: {
  exposed: ExposedSummary
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <AccessibleModal
      open
      onClose={props.onCancel}
      titleId="exposed-export-title"
      title={cs.export.exposedTitle}
      testId="exposed-export-dialog"
      actions={
        <>
          <Button variant="ghost" onClick={props.onCancel}>
            {cs.export.cancel}
          </Button>
          <Button variant="primary" data-testid="exposed-export-confirm" data-autofocus onClick={props.onConfirm}>
            {cs.export.exportWithExposed}
          </Button>
        </>
      }
    >
      <ExportSummary>
        <section className="ds-export-summary__section">
          <p className="modal__impact">{cs.export.exposedImpact}</p>
          <p>
            {cs.security.exposedSummary
              .replace('{cats}', String(props.exposed.categoryCount))
              .replace('{ents}', String(props.exposed.entityCount))
              .replace('{occs}', String(props.exposed.occurrenceCount))}
          </p>
          <details open>
            <summary>{cs.export.exposedDetails}</summary>
            <ul>
              {props.exposed.categories.map((c) => (
                <li key={c.category}>
                  {CATEGORY_LABELS[c.category]}: {c.entityCount} {cs.review.values},{' '}
                  {c.occurrenceCount} {cs.review.occurrences}
                </li>
              ))}
            </ul>
          </details>
        </section>
      </ExportSummary>
    </AccessibleModal>
  )
}
