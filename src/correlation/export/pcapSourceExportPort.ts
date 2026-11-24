/**
 * PCAP source export from correlation plan (Stage 29).
 */

import { countUnsupportedFromUnified } from '../../pcap/coverage/buildUnifiedCoverage'
import type { PcapSourceDiscovery, PcapSourcePlan } from '../types'
import {
  PcapExportCancelledError,
  runPcapExport,
  type PcapExportProgress,
} from '../../pcap/export/coordinator'
import type { ExportSink } from '../../pcap/export/sinks'

export async function exportPcapSourcePlan(input: {
  plan: PcapSourcePlan
  discovery: PcapSourceDiscovery
  sourceBlob: Blob
  outputFileName: string
  sink?: ExportSink
  skipAutoDownload?: boolean
  onProgress?: (p: PcapExportProgress) => void
}): Promise<{ fileName: string; byteLength: number; blob?: Blob }> {
  const container = input.discovery.container
  try {
    const policy = input.discovery.policy
    const result = await runPcapExport({
      plan: input.plan.plan,
      descriptors: container.descriptors,
      sourceBlob: input.sourceBlob,
      baselineIssues: container.issues,
      unsupportedLayers: countUnsupportedFromUnified(input.discovery.discovery.unifiedCoverage),
      protocolCoverage: input.discovery.discovery.unifiedCoverage.byProtocol,
      preferFileSystemAccess: false,
      sink: input.sink,
      skipAutoDownload: input.skipAutoDownload ?? true,
      onProgress: input.onProgress,
      profile: {
        preset: policy.preset,
        mediaPolicy:
          policy.mediaPolicy === 'preserve-unsafe'
            ? 'preserve-unsafe'
            : policy.mediaPolicy === 'strip-payload'
              ? 'strip-payload'
              : 'drop',
        mapping: {
          ip: input.plan.plan.pcapLevel === 'high-privacy'
            ? 'privacy-preserving'
            : 'topology-preserving',
          mac: 'locally-administered',
          timestamps: input.plan.plan.timestamps,
          ephemeralPorts: 'permute',
          contentSignalingPorts: 'preserve',
          vlan: 'map',
          imsiPlmn: input.plan.plan.pcapLevel === 'high-privacy' ? 'map-all' : 'preserve-plmn',
        },
      },
      policy,
      coverage: input.discovery.discovery.packetDiscovery.flatMap((pd) => [...pd.coverage]),
      // Correlation export dialog is the explicit operator acknowledgement.
      unsafeExportAcknowledged: true,
    })
    return {
      fileName: input.outputFileName || result.fileName,
      byteLength: result.byteLength,
      blob: result.blob,
    }
  } catch (err) {
    if (err instanceof PcapExportCancelledError) throw err
    throw err
  }
}
