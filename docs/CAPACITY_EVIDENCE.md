# Capacity evidence

Sanitized results for supported maxima. **No original identities, aliases, or paths
to private files.** Node bench ≠ browser SLA.

## Measurement conditions

| Item | Value |
|---|---|
| Application | project root @ commit recorded in evidence JSON |
| OS | macOS / Linux (recorded in evidence JSON) |
| Node | LTS (`node -v` in evidence) |
| Browsers | Chromium / Firefox / WebKit via Playwright (`PLAYWRIGHT_BROWSERS_PATH=./.playwright-browsers`) |
| Text limit | 90 MiB (LF and CRLF) |
| PCAP limit | 100 MiB |
| Correlation | 200 MiB aggregate |
| Fixtures | synthetic (`npm run fixtures:maximum` / max-size harness) |

## How to refresh

```sh
npm run fixtures:maximum
npm run bench:pcap-capacity          # Node engine → tests/pcap/bench/results/
npm run release:max-size:ui          # tri-browser micro/full → tests/performance/results/max-size-*.json
npm run release:correlation:ui       # tri-browser correlation micro
npm run release:max-size:baseline    # compare against max-size-baseline.json
```

Full 90/100/200 MiB run: `MAX_SIZE_FULL=1 npm run release:max-size:ui:full` (separate CI job).

## Stored artifacts

| File | Meaning |
|---|---|
| `tests/performance/results/max-size-baseline.json` | Approved wall/export ceilings (tri-browser keys) |
| `tests/performance/results/capacity-evidence.json` | Latest documented conditions + Node/browser records |
| `tests/performance/results/correlation-ui-report.json` | Correlation UI gate report (no PII) |

Browser numbers under baseline ceilings are GO for the micro gate; exceeding >25% without
`MAX_SIZE_BASELINE_ALLOW_REGRESSION=1` is a regression (`check-max-size-baseline`).
