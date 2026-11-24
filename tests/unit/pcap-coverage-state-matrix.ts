/**
 * Stage 6.4 — component-state matrix for PCAP coverage UX (wireframe substitute).
 *
 * States × surfaces: Overview | Coverage | Filter | Detail | Export dialog | Status strip
 *
 * | Preset / state     | Summary verdict              | Primary CTA              | Coverage dual cols | Export confirm sections |
 * |--------------------|------------------------------|--------------------------|--------------------|-------------------------|
 * | high-privacy + covered | Safe to export            | Export                   | recognized/protected (cs UI) | n/a (direct export)     |
 * | diagnostic + risk      | Export possible / caution | Review / Export          | risk verdict       | optional confirm        |
 * | malformed/blocked  | Export blocked               | Export unavailable       | blocking           | blocked hint            |
 * | sanitizer-only DNS | Protected without full analysis | Export                | N/M dual counts    | n/a                     |
 *
 * Usability walkthrough checklist (moderated; Czech product copy in app):
 * 1. Decide whether export is safe — expected ≤2 steps (summary → CTA).
 * 2. Find an unsupported protocol — Coverage tab + click → filter.
 * 3. recognized vs protected — dual columns + legend.
 * 4. Remove active filter — chip ×.
 * 5. Help keyboard-only — Help open, Tab trap, Escape, focus restore.
 */

export const STAGE6_COVERAGE_STATE_MATRIX = [
  'high-privacy-covered',
  'diagnostic-risk',
  'malformed-blocked',
  'sanitizer-only-dns',
] as const

export type Stage6CoverageState = (typeof STAGE6_COVERAGE_STATE_MATRIX)[number]