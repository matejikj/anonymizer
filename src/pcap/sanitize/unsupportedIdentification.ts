/**
 * T09 — lightweight identify-only signatures for unsupported application payloads.
 * Port + ASCII/binary sniff only — no parsing, no sanitization change.
 * Coverage protocol id becomes `unsupported:<name>`; status/disposition stay fail-closed.
 *
 * Designed so T14 can promote these to `identifyOnly: true` handlers without renaming ids.
 */

export const UNSUPPORTED_PROTOCOL_NAMES = [
  'mgcp',
  // T24: h248 / skinny / iax2 / rtsp / h323 promoted to structured handlers
  // T18: ssdp / llmnr / netbios; T20: snmp / syslog / ntp; T22: radius / diameter
  // T23: ldap / kerberos promoted to structured handlers
  // T30: mqtt promoted to structured handler
] as const

export type UnsupportedProtocolName = (typeof UNSUPPORTED_PROTOCOL_NAMES)[number]

export interface IdentifyUnsupportedInput {
  readonly data: Uint8Array
  readonly offset: number
  readonly length: number
  readonly srcPort: number
  readonly dstPort: number
  readonly transport: 'udp' | 'tcp' | 'unknown'
}

const MGCP_CMD =
  /^(?:EPCF|CRCX|MDCX|DLCX|RQNT|NTFY|AUEP|AUCX|RSIP) \d+ \S+ MGCP 1\.[01]/i
const MGCP_RSP = /^\d{3} \d+/
const MGCP_PORTS = new Set([2427, 2727])

const ASCII_SNIFF = 256

function portHit(src: number, dst: number, ports: ReadonlySet<number>): boolean {
  return ports.has(src) || ports.has(dst)
}

function asciiHead(data: Uint8Array, offset: number, length: number): string {
  const n = Math.min(length, ASCII_SNIFF)
  return new TextDecoder('ascii', { fatal: false }).decode(data.subarray(offset, offset + n))
}

/**
 * Identify an unsupported application protocol. Returns canonical short name or null.
 * Never claims more than port+signature evidence (UI marks as probable).
 */
export function identifyUnsupportedApplicationPayload(
  input: IdentifyUnsupportedInput,
): UnsupportedProtocolName | null {
  const { data, offset, length, srcPort, dstPort, transport } = input
  if (length <= 0) return null
  const text = asciiHead(data, offset, length)
  const tcp = transport === 'tcp'

  // T11: UDP MGCP is structured (`protocol: mgcp`). TCP remains identify-only
  // until a framing profile exists (no message-boundary guessing).
  if (
    tcp
    && portHit(srcPort, dstPort, MGCP_PORTS)
    && (MGCP_CMD.test(text) || MGCP_RSP.test(text))
  ) {
    return 'mgcp'
  }

  return null
}

export function unsupportedCoverageProtocolId(name: UnsupportedProtocolName): string {
  return `unsupported:${name}`
}
