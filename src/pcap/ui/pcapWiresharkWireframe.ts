/** Wireframe / visual regression state catalog (step 3). */

export const PCAP_WIRESHARK_WIREFRAME_STATES = [
  'loaded-capture',
  'valid-filter-draft',
  'invalid-filter',
  'applied-filter',
  'empty-filter-result',
  'selected-field',
  'highlight-changes',
  'original-view-warning',
  'blocked-export',
  'narrow-layout-tabs',
  'long-ipv6-sip-values',
  'malformed-packet',
  'dual-pane-side-by-side',
  'single-pane-toggle',
  'dropped-counterpart',
  'filtered-counterpart',
] as const

export const PCAP_WIRESHARK_VISUAL_SCENARIOS = [
  'desktop-loaded-light',
  'desktop-loaded-dark',
  'narrow-layout-light',
  'invalid-filter',
  'empty-filter-result',
  'selected-field-sync',
  'highlight-changes-on',
  'original-data-warning',
  'blocked-export-hint',
  'long-endpoint-values',
  'dual-1920',
  'dual-1440',
  'dual-just-above-1100',
  'single-just-below-1100',
  'single-768',
] as const

export type PcapWiresharkWireframeState = (typeof PCAP_WIRESHARK_WIREFRAME_STATES)[number]
