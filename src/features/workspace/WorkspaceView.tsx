import { TextProgressView } from '../import-log/TextProgressView.tsx'
import { WorkspaceCommandStrip, OversizedLineBanner } from './WorkspaceCommandStrip.tsx'
import { DualLogView } from './DualLogView.tsx'
import { ReviewPanel } from '../review/ReviewPanel.tsx'
import { TextAnonymizationOutcomePanel } from '../review/TextAnonymizationOutcomePanel.tsx'
import { useAppStore } from '../../app/store.ts'

export function WorkspaceView() {
  const phase = useAppStore((s) => s.phase)

  if (phase === 'importing') {
    return (
      <section className="workspace workspace--importing" data-testid="workspace" data-reference="text-workspace">
        <TextProgressView />
      </section>
    )
  }

  return (
    <section className="workspace" data-testid="workspace" data-reference="text-workspace">
      <WorkspaceCommandStrip />
      <OversizedLineBanner />
      <TextAnonymizationOutcomePanel />
      <div className="workspace__stage" data-testid="workspace-stage">
        <DualLogView />
        <ReviewPanel />
      </div>
    </section>
  )
}
