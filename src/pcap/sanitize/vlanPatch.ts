/**
 * 802.1Q / 802.1ad TCI patch — map VLAN ID, preserve PCP and DEI (step 3).
 */

import type { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { LayerCoverage } from './types'

const VLAN_VID_MASK = 0x0fff
const VLAN_PCP_DEI_MASK = 0xf000

export function patchVlanTci(
  data: Uint8Array,
  tciOffset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (tciOffset + 2 > data.length) return

  const tci = (data[tciOffset]! << 8) | data[tciOffset + 1]!
  const pcpDei = tci & VLAN_PCP_DEI_MASK
  const vlanId = tci & VLAN_VID_MASK
  const canonical = `${vlanId}`

  if (vlanId === 0 || vlanId === 4095) {
    coverage.push({
      protocol: 'vlan',
      offset: tciOffset,
      length: 2,
      status: 'covered',
    })
    issues.push(`vlan-reserved-preserved:${vlanId}`)
    return
  }

  if (intents) {
    intents.recordEntityReplacement(packetIndex, tciOffset, 'vlan', canonical, 2)
  }

  // PF-06: defer mapping.map() so plan-build can resolve against the real snapshot without
  // re-parsing. The original TCI (pcpDei) is captured by the closure — packet bytes are the
  // same in both passes, so preserving PCP/DEI needs no re-read at resolve time either.
  // No try/catch here, matching the original unconditional collector.add() — an overlap at
  // this offset is a genuine bug, not an expected condition to swallow.
  collector.addDeferred(tciOffset, 2, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('vlan', canonical)
    const mappedId = Number.parseInt(mapped, 10)
    if (!Number.isInteger(mappedId) || mappedId < 0 || mappedId > 4095) return null
    const newTci = pcpDei | (mappedId & VLAN_VID_MASK)
    if (newTci === tci) return null
    return new Uint8Array([(newTci >> 8) & 0xff, newTci & 0xff])
  })
  coverage.push({
    protocol: 'vlan',
    offset: tciOffset,
    length: 2,
    status: 'covered',
  })
}
