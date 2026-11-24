/**
 * Bootstraps a PCAP recovery ("reversed editor") session: unlock the anonymized+recovery pair,
 * restore the full verified original, lightweight-parse it for packet offsets, then load the
 * anonymized file through the normal single-file PCAP pipeline and attach the restored bytes as
 * its counterpart source. On success the app lands directly on the regular PCAP workspace —
 * left pane = the anonymized file, right pane = the deanonymized original — with no intermediate
 * wizard or password prompt.
 */
import { CaptureFormat, type PacketRecordDescriptor } from '../../pcap/domain/types'
import { BlobSliceCursor, parseClassicPcapFraming, parsePcapngFraming, probeFormat } from '../../pcap/capture'
import {
  getPacketNumberMapViaWorker,
  preflightRecoveryPairViaWorker,
  restoreAllViaWorker,
  unlockRecoveryPairViaWorker,
} from '../../pcap/recovery/worker/client'
import { setActiveRecoverySessionRef } from '../../pcap/recovery/restore/activeRecoverySession'
import { attachRecoveryCounterpart } from '../../pcap/ui/pcapSession'
import { extractEndpointFields, type CounterpartEndpointFields } from '../../pcap/ui/counterpartFieldExtraction'
import { loadPcapFile } from '../../pcap/ui/pcapLoadController'
import { usePcapStore } from '../../pcap/ui/pcapStore'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'

export class RecoveryBootstrapError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecoveryBootstrapError'
  }
}

async function lightweightParseDescriptors(blob: Blob): Promise<Map<number, PacketRecordDescriptor>> {
  const head = await blob.slice(0, 8).arrayBuffer()
  const probed = probeFormat(head)
  const cursor = new BlobSliceCursor(blob)
  const framed =
    probed.format === CaptureFormat.Pcapng
      ? await parsePcapngFraming(cursor, { retainPayload: false })
      : await parseClassicPcapFraming(cursor, { retainPayload: false })
  const map = new Map<number, PacketRecordDescriptor>()
  for (const d of framed.descriptors) map.set(d.packetNumber, d)
  return map
}

function nextGenerationId(): string {
  return `rec-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

/**
 * Precomputes real addressing fields for every anonymized packet number, reading the restored
 * blob's bytes once. This is what lets the "anonymized" (deanonymized) pane's Source/Destination
 * columns and display filters show true original endpoints instead of the alias-mapped values
 * the rest of the app would otherwise compute for whatever file happens to be loaded.
 *
 * `anonymizedToOriginal` (from the recovery engine) uses 1-based packet numbers; everything else
 * in this app — `PacketRecordDescriptor.packetNumber`, and therefore the keys of
 * `byOriginalPacketNumber` and this function's own output map — is 0-based. Convert at the
 * boundary so nothing downstream has to know about the recovery engine's own convention.
 */
async function buildEndpointsByAnonymizedPacketNumber(
  restoredBlob: Blob,
  byOriginalPacketNumber: ReadonlyMap<number, PacketRecordDescriptor>,
  anonymizedToOriginal: readonly number[],
): Promise<Map<number, CounterpartEndpointFields>> {
  const restoredBytes = new Uint8Array(await restoredBlob.arrayBuffer())
  const out = new Map<number, CounterpartEndpointFields>()
  for (let engineAnonymizedPn = 1; engineAnonymizedPn < anonymizedToOriginal.length; engineAnonymizedPn++) {
    const engineOriginalPn = anonymizedToOriginal[engineAnonymizedPn]
    if (engineOriginalPn == null || engineOriginalPn < 1) continue
    const descriptor = byOriginalPacketNumber.get(engineOriginalPn - 1)
    if (!descriptor) continue
    const bytes = restoredBytes.subarray(descriptor.dataOffset, descriptor.dataOffset + descriptor.capturedLength)
    out.set(engineAnonymizedPn - 1, extractEndpointFields(bytes, descriptor.linkType))
  }
  return out
}

export async function startPcapRecoverySession(input: {
  anonymizedFile: File
  recoveryFile: File
}): Promise<void> {
  const generationId = nextGenerationId()

  let preflight
  try {
    preflight = await preflightRecoveryPairViaWorker({
      generationId,
      anonymizedBlob: input.anonymizedFile,
      recoveryBlob: input.recoveryFile,
    })
  } catch (err) {
    throw new RecoveryBootstrapError(err instanceof Error ? err.message : cs.pcap.recovery.preflightFailed)
  }
  if (!preflight.pairLooksCompatible) {
    throw new RecoveryBootstrapError(cs.pcap.recovery.pairMismatch)
  }

  let unlocked
  try {
    unlocked = await unlockRecoveryPairViaWorker({ generationId })
  } catch (err) {
    throw new RecoveryBootstrapError(err instanceof Error ? err.message : cs.pcap.recovery.unlockFailed)
  }
  setActiveRecoverySessionRef({ generationId, sessionId: unlocked.sessionId })

  let restored
  try {
    restored = await restoreAllViaWorker({ generationId, sessionId: unlocked.sessionId })
  } catch (err) {
    throw new RecoveryBootstrapError(err instanceof Error ? err.message : cs.pcap.recovery.restoreFailed)
  }
  if (!restored.summary.verified) {
    throw new RecoveryBootstrapError(cs.pcap.recovery.restoreUnverified)
  }

  const anonymizedToOriginal = await getPacketNumberMapViaWorker({
    generationId,
    sessionId: unlocked.sessionId,
  })
  const byOriginalPacketNumber = await lightweightParseDescriptors(restored.blob)
  const endpointsByAnonymizedPacketNumber = await buildEndpointsByAnonymizedPacketNumber(
    restored.blob,
    byOriginalPacketNumber,
    anonymizedToOriginal,
  )

  useAppStore.getState().setActiveMode('pcap')
  await loadPcapFile(input.anonymizedFile)

  attachRecoveryCounterpart({
    blob: restored.blob,
    byOriginalPacketNumber,
    anonymizedToOriginal,
    endpointsByAnonymizedPacketNumber,
  })
  usePcapStore.getState().bumpSessionEpoch()
}
