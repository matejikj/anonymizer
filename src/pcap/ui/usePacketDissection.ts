import { useMemo } from 'react'
import { buildPacketDissection } from '../dissection/buildPacketDissection'
import type { PacketDissection } from '../dissection/types'
import { unifiedSpansForPacket } from '../coverage/buildUnifiedCoverage'
import { initProtocols } from '../protocols/init'
import { getPcapSession } from './pcapSession'
import { usePacketPreview } from '../preview/usePacketPreview'

export function usePacketDissection(
  packetIndex: number,
  sessionEpoch: number,
  dataView: 'original' | 'anonymized',
): { dissection: PacketDissection | null; loading: boolean } {
  const { preview, loading } = usePacketPreview(packetIndex, sessionEpoch)
  const dissection = useMemo(() => {
    if (!preview || packetIndex < 0) return null
    initProtocols()
    const session = getPcapSession()
    if (!session) return null
    const descriptor = session.descriptors[packetIndex]
    if (!descriptor) return null
    const bytes = dataView === 'original' ? preview.original.data : preview.anonymizedBytes
    const unifiedSpans = unifiedSpansForPacket(session.unifiedCoverage, packetIndex)
    const planPkt = session.plan.packets[packetIndex]
    const summary = session.analysis.summaries[packetIndex]
    return buildPacketDissection({
      data: bytes,
      linkType: descriptor.linkType,
      packetIndex,
      capturedLength: descriptor.capturedLength,
      unifiedSpans,
      planPkt,
      appProtocols: summary?.protocols,
    })
  }, [preview, packetIndex, dataView, sessionEpoch])
  return { dissection, loading }
}
