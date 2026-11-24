/**
 * Versioned default coloring preset — first-match order from most specific to general.
 */

import type { PcapColoringRule } from './types'
import { DEFAULT_COLORING_PRESET_VERSION } from './types'

function pair(fg: string, bg: string) {
  return { foreground: fg, background: bg }
}

const DEFAULT_RULES: readonly PcapColoringRule[] = [
  {
    id: 'default-malformed',
    name: 'Malformed / issue',
    enabled: true,
    priority: 10,
    filter: 'frame.issue == true',
    light: pair('#5c1a1a', '#fde8e8'),
    dark: pair('#fecaca', '#3f1515'),
    source: 'default',
  },
  {
    id: 'default-sip',
    name: 'SIP',
    enabled: true,
    priority: 20,
    filter: 'sip',
    light: pair('#1e3a5f', '#e8f0fe'),
    dark: pair('#bfdbfe', '#152a45'),
    source: 'default',
  },
  {
    id: 'default-sdp',
    name: 'SDP',
    enabled: true,
    priority: 21,
    filter: 'sdp',
    light: pair('#1a4d3a', '#e6f6ef'),
    dark: pair('#a7f3d0', '#123528'),
    source: 'default',
  },
  {
    id: 'default-voip-media',
    name: 'RTP / RTCP',
    enabled: true,
    priority: 30,
    filter: 'rtp or rtcp or srtp',
    light: pair('#4a3b12', '#fef9e7'),
    dark: pair('#fde68a', '#3d3010'),
    source: 'default',
  },
  {
    id: 'default-dns',
    name: 'DNS / mDNS',
    enabled: true,
    priority: 40,
    filter: 'dns or mdns',
    light: pair('#1a4d3a', '#e8f8f0'),
    dark: pair('#86efac', '#123528'),
    source: 'default',
  },
  {
    id: 'default-icmp',
    name: 'ICMP',
    enabled: true,
    priority: 41,
    filter: 'icmp or icmpv4 or icmpv6',
    light: pair('#4a1942', '#fce8f5'),
    dark: pair('#f9a8d4', '#3d1535'),
    source: 'default',
  },
  {
    id: 'default-arp',
    name: 'ARP',
    enabled: true,
    priority: 42,
    filter: 'arp',
    light: pair('#3d2e0f', '#fef3c7'),
    dark: pair('#fcd34d', '#2e2209'),
    source: 'default',
  },
  {
    id: 'default-tcp',
    name: 'TCP',
    enabled: true,
    priority: 50,
    filter: 'tcp',
    light: pair('#1e3a5f', '#eef2ff'),
    dark: pair('#c7d2fe', '#152a45'),
    source: 'default',
  },
  {
    id: 'default-udp',
    name: 'UDP',
    enabled: true,
    priority: 51,
    filter: 'udp',
    light: pair('#3b2f0f', '#fffbeb'),
    dark: pair('#fde68a', '#2e2409'),
    source: 'default',
  },
  {
    id: 'default-ipv4',
    name: 'IPv4',
    enabled: true,
    priority: 60,
    filter: 'ipv4',
    light: pair('#374151', '#f3f4f6'),
    dark: pair('#d1d5db', '#1f2937'),
    source: 'default',
  },
  {
    id: 'default-ipv6',
    name: 'IPv6',
    enabled: true,
    priority: 61,
    filter: 'ipv6',
    light: pair('#374151', '#f9fafb'),
    dark: pair('#e5e7eb', '#1f2937'),
    source: 'default',
  },
  {
    id: 'default-ethernet',
    name: 'Ethernet',
    enabled: true,
    priority: 70,
    filter: 'ethernet',
    light: pair('#4b5563', '#f9fafb'),
    dark: pair('#e5e7eb', '#111827'),
    source: 'default',
  },
]

export function createDefaultColoringRules(): readonly PcapColoringRule[] {
  return DEFAULT_RULES.map((r) => ({ ...r, light: { ...r.light }, dark: { ...r.dark } }))
}

export function defaultColoringPresetVersion(): number {
  return DEFAULT_COLORING_PRESET_VERSION
}

export function defaultColoringPresetFingerprint(): string {
  return `v${DEFAULT_COLORING_PRESET_VERSION}:${DEFAULT_RULES.map((r) => r.id).join(',')}`
}
