/**
 * Ensure a jumped PCAP packet is visible — clear display filter if it hides the target.
 */

import { useAppStore } from '../app/store'
import { usePcapStore } from '../pcap/ui/pcapStore'
import { refreshPcapFilter } from '../pcap/ui/pcapLoadController'
import { cs } from '../i18n/cs'

/** Returns true when the display filter was cleared to reveal the packet. */
export function revealPcapPacketForJump(packetIndex: number): boolean {
  const store = usePcapStore.getState()
  if (store.filteredIndices.includes(packetIndex)) {
    store.setSelectedPacketIndex(packetIndex)
    return false
  }
  store.clearDisplayFilter()
  void refreshPcapFilter()
  store.setSelectedPacketIndex(packetIndex)
  useAppStore.getState().setToast({ message: cs.correlationWorkspace.filterClearedForJump })
  return true
}
