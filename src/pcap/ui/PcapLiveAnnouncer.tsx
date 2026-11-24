/**
 * Screen reader announcements for PCAP workspace (step 3).
 */

import { useEffect, useRef, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPacketRowMeta } from './pcapSession.ts'

export function PcapLiveAnnouncer() {
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const displayFilterApplied = usePcapStore((s) => s.displayFilterApplied)
  const displayFilterStatus = usePcapStore((s) => s.displayFilterStatus)
  const displayFilterError = usePcapStore((s) => s.displayFilterError)
  const filteredIndices = usePcapStore((s) => s.filteredIndices)
  const dataView = usePcapStore((s) => s.dataView)
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const liveAnnounce = usePcapStore((s) => s.liveAnnounce)
  const exportMessage = usePcapStore((s) => s.exportMessage)
  const exportBusy = usePcapStore((s) => s.exportBusy)
  const selectedFieldPath = usePcapStore((s) => s.selectedFieldPath)
  const [message, setMessage] = useState('')
  const prevPacket = useRef<number | null>(null)

  useEffect(() => {
    if (selectedPacketIndex === prevPacket.current) return
    prevPacket.current = selectedPacketIndex
    const meta = getPacketRowMeta(selectedPacketIndex)
    if (!meta.descriptor) {
      setMessage(cs.pcap.a11y.noPacketSelected)
      return
    }
    setMessage(
      cs.pcap.a11y.packetSelected
        .replace('{n}', String(meta.descriptor.packetNumber))
        .replace('{proto}', meta.summary?.protocols.at(-1) ?? '—'),
    )
  }, [selectedPacketIndex])

  useEffect(() => {
    if (!displayFilterApplied) return
    if (displayFilterStatus === 'invalid' && displayFilterError) {
      setMessage(cs.pcap.a11y.filterInvalid.replace('{msg}', displayFilterError.message))
      return
    }
    setMessage(
      cs.pcap.a11y.filterApplied
        .replace('{expr}', displayFilterApplied)
        .replace('{count}', String(filteredIndices.length)),
    )
  }, [displayFilterApplied, displayFilterStatus, displayFilterError, filteredIndices.length])

  useEffect(() => {
    if (selectedFieldPath) {
      setMessage(cs.pcap.a11y.fieldSelected.replace('{path}', selectedFieldPath))
    }
  }, [selectedFieldPath])

  useEffect(() => {
    if (exportBusy) {
      setMessage(cs.pcap.a11y.exportStarted)
    } else if (exportMessage) {
      setMessage(exportMessage)
    }
  }, [exportBusy, exportMessage])

  useEffect(() => {
    if (dataView === 'original' && compareLayout !== 'dual') {
      setMessage(cs.pcap.a11y.originalViewWarning)
    }
  }, [dataView, compareLayout])

  useEffect(() => {
    if (liveAnnounce) setMessage(liveAnnounce)
  }, [liveAnnounce])

  return (
    <div
      className="visually-hidden"
      aria-live="polite"
      aria-atomic="true"
      data-testid="pcap-live-announcer"
    >
      {message}
    </div>
  )
}
