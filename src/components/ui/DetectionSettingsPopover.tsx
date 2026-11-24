import { useEffect } from 'react'
import { TextProfileSelector } from '../../features/profiles/TextProfileSelector.tsx'
import { PcapAnonymizationLevelSelect } from '../../pcap/ui/PcapAnonymizationLevelSelect.tsx'
import { bootstrapPcapLevel } from '../../pcap/profile/pcapLevelController.ts'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'

/** Text + PCAP detection controls — PCAP level hidden in standalone text import/workspace. */
export function DetectionSettingsPopover() {
  const phase = useAppStore((s) => s.phase)
  const activeMode = useAppStore((s) => s.activeMode)
  const textOnlyChrome = activeMode === 'text' && (phase === 'importing' || phase === 'workspace')
  const mixedSet = phase === 'correlation-review' || phase === 'correlation-processing'

  useEffect(() => {
    void bootstrapPcapLevel()
  }, [])

  return (
    <div
      className="app-header__detection"
      role="group"
      aria-label={cs.header.detectionSettings}
      data-testid="detection-settings-panel"
      data-mixed-set={mixedSet || undefined}
    >
      <div className="app-header__detection-scopes">
        <div className="app-header__detection-scope" data-testid="detection-scope-text">
          <TextProfileSelector />
        </div>
        {textOnlyChrome ? null : (
          <div className="app-header__detection-scope" data-testid="detection-scope-pcap">
            <PcapAnonymizationLevelSelect />
          </div>
        )}
      </div>
    </div>
  )
}
