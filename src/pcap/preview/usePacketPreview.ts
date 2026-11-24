/**
 * React hook for async packet preview (Stage 9 random access).
 */

import { useEffect, useState } from 'react'
import { getPcapSession } from '../ui/pcapSession'
import { fetchPacketPreview, type PacketPreview } from './pcapPreviewController'

export function usePacketPreview(packetIndex: number, sessionEpoch: number): {
  preview: PacketPreview | null
  loading: boolean
} {
  const [preview, setPreview] = useState<PacketPreview | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (packetIndex < 0) {
      setPreview(null)
      setLoading(false)
      return
    }
    const session = getPcapSession()
    if (!session) {
      setPreview(null)
      return
    }

    let cancelled = false
    setLoading(true)
    void fetchPacketPreview(session, packetIndex).then((result) => {
      if (cancelled) return
      setPreview(result)
      setLoading(false)
    })

    return () => {
      cancelled = true
    }
  }, [packetIndex, sessionEpoch])

  return { preview, loading }
}
