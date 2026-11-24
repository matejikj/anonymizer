/**
 * Publish the mounted PCAP session plan back into the correlation source record.
 */

import { useAppStore } from '../app/store'
import { getPcapSession } from '../pcap/ui/pcapSession'
import { SourceKind as SK } from '../domain/sourceArtifact'
import {
  getCorrelationSource,
  updateSourceRecord,
} from './correlationSessionModel'
import { assessCorrelationSourceExport } from './export/correlationExportSecurity'
import type { PcapSourcePlan } from './types'

export function publishCorrelationPcapPlanFromSession(sourceId: string): boolean {
  const record = getCorrelationSource(sourceId)
  const session = getPcapSession()
  if (!record || !session || record.kind !== SK.Pcap || record.plan?.kind !== 'pcap') return false

  const nextPlan: PcapSourcePlan = {
    ...record.plan,
    plan: session.plan,
    mappingRevision: session.mappingRevision,
  }

  updateSourceRecord(sourceId, { plan: nextPlan })
  const updated = getCorrelationSource(sourceId)
  if (!updated) return false
  const security = assessCorrelationSourceExport({ ...updated, exportState: 'ready' })
  updateSourceRecord(sourceId, {
    exportState: security === 'blocked' ? 'blocked' : 'ready',
    coverageState: security === 'exposed' ? 'partial' : 'ok',
  })
  useAppStore.getState().bumpCorrelationEpoch()
  return true
}

export function getActiveCorrelationPcapSourceId(): string | null {
  const selected = useAppStore.getState().selectedCorrelationSourceId
  if (!selected || selected === 'all') return null
  const record = getCorrelationSource(selected)
  if (!record || record.kind !== SK.Pcap) return null
  return selected
}
