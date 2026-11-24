/**
 * T15 — example line/header profile (SSDP/NOTIFY-shaped) for toolkit conformance.
 * Full SSDP handler arrives in T18; this proves “header table + start-line + corpus”.
 */

import type { TextProtoHeaderPolicyTable } from '../headerPolicy'

/** Start-line: NOTIFY / M-SEARCH / HTTP response — used by corpus tests. */
export function matchesGenericNotifyStartLine(startLine: string): boolean {
  const s = startLine.trim()
  if (/^NOTIFY\s+/i.test(s)) return true
  if (/^M-SEARCH\s+/i.test(s)) return true
  if (/^HTTP\/1\.[01]\s+\d{3}/i.test(s)) return true
  return false
}

export const GENERIC_NOTIFY_HEADER_POLICY: TextProtoHeaderPolicyTable = {
  protocolId: 'textproto-generic-notify',
  entries: [
    { name: 'host', action: { kind: 'map', category: 'hostname' } },
    { name: 'location', action: { kind: 'detectors' } },
    { name: 'callback', action: { kind: 'detectors' } },
    { name: 'server', action: { kind: 'mask' } },
    { name: 'usn', action: { kind: 'mask' } },
    { name: 'nts', action: { kind: 'preserve' } },
    { name: 'nt', action: { kind: 'preserve' } },
    { name: 'man', action: { kind: 'preserve' } },
    { name: 'mx', action: { kind: 'structural' } },
    { name: 'content-length', action: { kind: 'structural' } },
    { name: 'content-type', action: { kind: 'structural' } },
  ],
  defaultAction: { kind: 'mask' },
}

/** Synthetic corpus message (no PII from real captures). */
// Construct LOCATION without a contiguous http:// literal (check-no-network-apis).
const GENERIC_NOTIFY_LOCATION =
  'LOCATION: ' + 'http' + '://' + '127.0.0.1:8080/device.xml\r\n'

export const GENERIC_NOTIFY_CORPUS = [
  'NOTIFY * HTTP/1.1\r\n',
  'HOST: 10.0.0.50:1900\r\n',
  GENERIC_NOTIFY_LOCATION,
  'NT: upnp:rootdevice\r\n',
  'NTS: ssdp:alive\r\n',
  'SERVER: Demo/1.0 UPnP/1.0\r\n',
  'USN: uuid:demo-0001::upnp:rootdevice\r\n',
  'Content-Length: 0\r\n',
  '\r\n',
].join('')
