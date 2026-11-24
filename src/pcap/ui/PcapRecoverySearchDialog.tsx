import { useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { findPacketIndexByNumber } from './pcapSession.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import { searchRecoveryViaWorker } from '../recovery/worker/client'
import { getActiveRecoverySessionRef } from '../recovery/restore/activeRecoverySession'
import type { RecoveryHit } from '../recovery/domain/types'

/**
 * Single-value lookup for a recovery session — reuses the still-unlocked worker session from
 * bootstrap. Only shown in the toolbar while `session.sessionKind === 'recover'`.
 */
export function PcapRecoverySearchDialog() {
  const open = usePcapStore((s) => s.recoverySearchDialogOpen)
  const setOpen = usePcapStore((s) => s.setRecoverySearchDialogOpen)
  const setSelectedPacketIndex = usePcapStore((s) => s.setSelectedPacketIndex)
  const setFocusedPane = usePcapStore((s) => s.setFocusedPane)

  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [hit, setHit] = useState<RecoveryHit | null>(null)

  if (!open) return null

  const onClose = () => {
    setOpen(false)
    setQuery('')
    setError(null)
    setHit(null)
  }

  const onSearch = async () => {
    if (!query.trim()) {
      setError(cs.pcap.recovery.searchQueryInvalid)
      return
    }
    const ref = getActiveRecoverySessionRef()
    if (!ref) {
      setError(cs.pcap.recovery.searchLocked)
      return
    }
    setBusy(true)
    setError(null)
    setHit(null)
    try {
      const page = await searchRecoveryViaWorker({
        generationId: ref.generationId,
        sessionId: ref.sessionId,
        query: query.trim(),
        limit: 1,
      })
      const first = page.hits[0]
      if (!first) {
        setError(cs.pcap.recovery.searchNotFound)
        return
      }
      setHit(first)
    } catch {
      setError(cs.pcap.recovery.searchFailed)
    } finally {
      setBusy(false)
    }
  }

  const onGoToPacket = () => {
    if (hit?.anonymizedPacketNumber == null) return
    // The recovery engine's packet numbers are 1-based; PacketRecordDescriptor.packetNumber is 0-based.
    const index = findPacketIndexByNumber(hit.anonymizedPacketNumber - 1)
    if (index < 0) return
    setFocusedPane('anonymized')
    setSelectedPacketIndex(index)
    onClose()
  }

  return (
    <AccessibleModal
      open
      onClose={onClose}
      titleId="pcap-recovery-search-title"
      title={cs.pcap.recovery.searchTitle}
      testId="pcap-recovery-search-dialog"
      actions={
        <Button variant="ghost" onClick={onClose} data-testid="pcap-recovery-search-close">
          {cs.pcap.recovery.searchClose}
        </Button>
      }
    >
      <form
        className="pcap-recovery-search"
        onSubmit={(e) => {
          e.preventDefault()
          void onSearch()
        }}
      >
        <label htmlFor="pcap-recovery-search-input">{cs.pcap.recovery.searchLabel}</label>
        <input
          id="pcap-recovery-search-input"
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={cs.pcap.recovery.searchPlaceholder}
          data-testid="pcap-recovery-search-input"
          autoFocus
        />
        <Button type="submit" variant="primary" busy={busy} data-testid="pcap-recovery-search-submit">
          {cs.pcap.recovery.searchSubmit}
        </Button>
      </form>

      {error ? (
        <p className="pcap-recovery-search__error" role="alert" data-testid="pcap-recovery-search-error">
          {error}
        </p>
      ) : null}

      {hit ? (
        <div className="pcap-recovery-search__result" data-testid="pcap-recovery-search-result">
          {hit.status === 'exact' && hit.originalValue ? (
            <>
              <p className="pcap-recovery-search__original">
                <span>{cs.pcap.recovery.searchOriginalLabel}</span>
                <strong data-testid="pcap-recovery-search-original-value">{hit.originalValue}</strong>
              </p>
              {hit.anonymizedPacketNumber != null ? (
                <p className="pcap-recovery-search__meta">
                  {cs.pcap.recovery.searchPacketLabel.replace('{n}', String(hit.anonymizedPacketNumber - 1))}
                </p>
              ) : null}
              {hit.anonymizedPacketNumber != null ? (
                <Button variant="secondary" onClick={onGoToPacket} data-testid="pcap-recovery-search-goto">
                  {cs.pcap.recovery.searchGoToPacket}
                </Button>
              ) : null}
            </>
          ) : hit.status === 'ambiguous' ? (
            <p role="status">{cs.pcap.recovery.searchAmbiguous}</p>
          ) : hit.status === 'redacted' ? (
            <p role="status">{cs.pcap.recovery.searchRedacted}</p>
          ) : (
            <p role="status">{cs.pcap.recovery.searchNotFound}</p>
          )}
        </div>
      ) : null}
    </AccessibleModal>
  )
}
