/**
 * Stage 6.4 — component-state matrix for PCAP coverage UX (wireframe substitute).
 *
 * States × surfaces: Overview | Coverage | Filter | Detail | Export dialog | Status strip
 *
 * | Preset / state     | Summary verdict              | Primary CTA              | Coverage dual cols | Export confirm sections |
 * |--------------------|------------------------------|--------------------------|--------------------|-------------------------|
 * | high-privacy + covered | Lze bezpečně exportovat   | Exportovat               | rozpoznáno/chráněno| n/a (direct export)     |
 * | diagnostic + risk      | Export možný / pozornost  | Zkontrolovat / Export    | risk verdict       | optional confirm        |
 * | malformed/blocked  | Export blokován              | Export není dostupný     | blocking           | blocked hint            |
 * | sanitizer-only DNS | Chráněno bez plné analýzy    | Exportovat               | N/M dual counts    | n/a                     |
 *
 * Usability walkthrough checklist (moderated):
 * 1. Zjistit, zda lze bezpečně exportovat — očekáváno ≤2 kroky (summary → CTA).
 * 2. Najít nepodporovaný protokol — Coverage tab + klik → filtr.
 * 3. Rozdíl rozpoznáno vs chráněno — dual columns + legend.
 * 4. Odstranit aktivní filtr — chip ×.
 * 5. Nápověda jen klávesnicí — Help open, Tab trap, Escape, focus restore.
 */

export const STAGE6_COVERAGE_STATE_MATRIX = [
  'high-privacy-covered',
  'diagnostic-risk',
  'malformed-blocked',
  'sanitizer-only-dns',
] as const

export const STAGE6_USABILITY_TASKS = [
  'can-export-safely',
  'find-unsupported-protocol',
  'explain-recognized-vs-protected',
  'remove-active-filter',
  'help-keyboard-only',
] as const
