/**
 * Top-bar select for switching between the two PCAP anonymization levels.
 * Keyboard-accessible, aria-busy during rebuild, aria-live status announcements.
 */

import { useId, useRef, useEffect } from 'react'
import { usePcapStore } from './pcapStore.ts'
import { PCAP_ANONYMIZATION_LEVELS, levelDisplayName } from '../profile/pcapAnonymizationLevel.ts'
import { DEFAULT_PCAP_LEVEL } from '../profile/presets.ts'
import { setPcapAnonymizationLevel } from '../profile/pcapLevelController.ts'
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel.ts'
import { cs } from '../../i18n/cs.ts'

function optionLabel(level: PcapAnonymizationLevel): string {
  const name = levelDisplayName(level)
  return level === DEFAULT_PCAP_LEVEL
    ? `${name} (${cs.pcap.presets.defaultPresetBadge})`
    : name
}

export function PcapAnonymizationLevelSelect() {
  const activeLevel = usePcapStore((s) => s.activePcapLevel)
  const requestedLevel = usePcapStore((s) => s.requestedPcapLevel)
  const phase = usePcapStore((s) => s.phase)
  const selectId = useId()
  const liveRef = useRef<HTMLSpanElement>(null)

  const rebuilding = requestedLevel !== null
  const hasCapture = phase === 'workspace' || phase === 'analyzing'

  const onChange = (level: PcapAnonymizationLevel) => {
    void setPcapAnonymizationLevel(level, { rebuild: hasCapture })
  }

  useEffect(() => {
    if (!rebuilding && liveRef.current) {
      liveRef.current.textContent = cs.pcap.presets.levelChanged
      const t = setTimeout(() => {
        if (liveRef.current) liveRef.current.textContent = ''
      }, 2000)
      return () => clearTimeout(t)
    }
  }, [rebuilding])

  return (
    <div className="pcap-level-select" data-testid="pcap-level-select">
      <label htmlFor={selectId} className="pcap-level-select__label">
        <span className="pcap-level-select__label-text">{cs.header.pcapProfileSection}</span>
      </label>
      <select
        id={selectId}
        data-testid="pcap-level-select-input"
        value={rebuilding ? requestedLevel : activeLevel}
        disabled={rebuilding}
        aria-busy={rebuilding}
        aria-label={cs.pcap.presets.levelSelectLabel}
        onChange={(e) => onChange(e.target.value as PcapAnonymizationLevel)}
      >
        {PCAP_ANONYMIZATION_LEVELS.map((level) => (
          <option key={level} value={level}>
            {optionLabel(level)}
          </option>
        ))}
      </select>
      {rebuilding ? (
        <span className="pcap-level-select__busy" aria-hidden="true">
          {cs.pcap.presets.levelSelectAnalyzing}
        </span>
      ) : null}
      <span
        ref={liveRef}
        className="visually-hidden"
        role="status"
        aria-live="polite"
        data-testid="pcap-level-live"
      />
    </div>
  )
}
