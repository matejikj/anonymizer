/**
 * T38 — mask TCP MD5 signature (kind 19) and TCP-AO (kind 29) option payloads.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { maskBytes } from './common.ts'

const TCPOPT_EOL = 0
const TCPOPT_NOP = 1
const TCPOPT_MD5 = 19
const TCPOPT_AO = 29

/**
 * Walk TCP options and mask MD5/AO cryptographic material (kind/length preserved).
 */
export function sanitizeTcpAuthOptions(
  data: Uint8Array,
  optionsOffset: number,
  optionsLength: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): LayerCoverage[] {
  const coverage: LayerCoverage[] = []
  let pos = optionsOffset
  const end = optionsOffset + optionsLength
  while (pos < end) {
    const kind = data[pos]!
    if (kind === TCPOPT_EOL) break
    if (kind === TCPOPT_NOP) {
      pos++
      continue
    }
    if (pos + 1 >= end) break
    const len = data[pos + 1]!
    if (len < 2 || pos + len > end) break
    if ((kind === TCPOPT_MD5 || kind === TCPOPT_AO) && len > 2) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        pos + 2,
        len - 2,
        kind === TCPOPT_MD5 ? 'tcp-md5' : 'tcp-ao',
        'tcp-auth',
      )
      coverage.push({
        protocol: kind === TCPOPT_MD5 ? 'tcp-md5' : 'tcp-ao',
        offset: pos,
        length: len,
        status: 'redacted',
      })
    }
    pos += len
  }
  return coverage
}
