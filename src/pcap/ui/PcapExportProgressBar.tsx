import { useEffect, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { Progress } from '../../design-system/Controls.tsx'
import { formatPacketCount, formatDurationMmSs } from './formatters.ts'

export function PcapExportProgressBar() {
  const packetsDone = usePcapStore((s) => s.exportPacketsDone)
  const packetsTotal = usePcapStore((s) => s.exportPacketsTotal)
  const startedAt = usePcapStore((s) => s.exportStartedAt)
  const [elapsedSec, setElapsedSec] = useState(0)

  useEffect(() => {
    if (startedAt <= 0) {
      setElapsedSec(0)
      return
    }
    const tick = () => setElapsedSec(Math.max(0, Math.round((Date.now() - startedAt) / 1000)))
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [startedAt])

  if (packetsTotal <= 0) return null

  const detail = cs.pcap.progress.packets
    .replace('{done}', formatPacketCount(packetsDone))
    .replace('{total}', formatPacketCount(packetsTotal))

  return (
    <div className="pcap-workspace__export-progress" data-testid="pcap-export-progress">
      <Progress value={packetsDone} max={packetsTotal} label={detail} />
      <p className="pcap-workspace__export-progress-time type-meta">
        {cs.pcap.export.progressElapsed.replace('{time}', formatDurationMmSs(elapsedSec))}
      </p>
    </div>
  )
}
