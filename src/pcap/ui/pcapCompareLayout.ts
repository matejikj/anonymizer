/**
 * PCAP Original/Anonymized comparison layout constants (side-by-side task).
 */

/** Workspace inline width (px) at/above which dual panes are shown. */
export const PCAP_DUAL_PANE_MIN_WIDTH = 1100

/**
 * Hysteresis band around the dual/single threshold so ResizeObserver layout
 * thrash (dual chrome slightly narrower than single) cannot oscillate forever.
 */
export const PCAP_DUAL_PANE_ENTER_WIDTH = 1120
export const PCAP_DUAL_PANE_EXIT_WIDTH = 1080

/** Full column set without compacting Delta (px). */
export const PCAP_FULL_COLUMNS_MIN_WIDTH = 1440

export const PCAP_COMPARE_RATIO_DEFAULT = 0.5
export const PCAP_COMPARE_RATIO_MIN = 0.35
export const PCAP_COMPARE_RATIO_MAX = 0.65
export const PCAP_COMPARE_RATIO_STEP = 0.02

export type PcapCompareLayout = 'dual' | 'single'
export type PcapFocusedPane = 'original' | 'anonymized'

export function clampCompareRatio(ratio: number): number {
  if (!Number.isFinite(ratio)) return PCAP_COMPARE_RATIO_DEFAULT
  return Math.min(PCAP_COMPARE_RATIO_MAX, Math.max(PCAP_COMPARE_RATIO_MIN, ratio))
}

/** Initial layout pick (no prior layout) — hard threshold. */
export function layoutFromWorkspaceWidth(width: number): PcapCompareLayout {
  return width >= PCAP_DUAL_PANE_MIN_WIDTH ? 'dual' : 'single'
}

/** Sticky layout transitions — prefer staying put inside the hysteresis band. */
export function nextCompareLayout(
  width: number,
  previous: PcapCompareLayout,
): PcapCompareLayout {
  if (previous === 'dual') {
    return width <= PCAP_DUAL_PANE_EXIT_WIDTH ? 'single' : 'dual'
  }
  return width >= PCAP_DUAL_PANE_ENTER_WIDTH ? 'dual' : 'single'
}
