# Release checklist — rnd-log-anonymizer

Plaintext product: mapping bundle = JSON, PCAP recovery = v4 plaintext.
SHA-256/CRC check pairing/structure, **not** authentication or secrecy.
Private map/recovery/originals must never land in shareable/AI/release ZIP.

## Environment

- [ ] Node.js LTS (local `node -v`)
- [ ] `npm ci` in the project root
- [ ] Playwright browsers: `PLAYWRIGHT_BROWSERS_PATH=./.playwright-browsers npx playwright install chromium firefox webkit`

## Required commands (clean checkout, no private `logs/`)

```sh
npm run check:network
npm run check:architecture
npm run check:offline-release
npm run lint
npx tsc -b
npm test
npm run pcap:voip-gate
npm run pcap:diagnostic-gate
npm run pcap:recovery-gate
npm run enterprise-invariants
npm run build
npm run check:anonym-subpath
npm run check:dist-artifacts
npm run sbom
npm run release:manifest
```

T70 vocabulary (offline allowlist): regenerate after KONOS/RGW log-template changes
via `VOCAB_SOURCE_ROOTS=… npm run vocab:build`. `check:offline-release` verifies
`vocabulary.<hash>.bin` hash, age, and `vocabulary.license.json`.

Optional (tri-browser, needs Playwright binaries):

```sh
npm run test:e2e
npm run test:a11y
npm run test:visual
npm run release:max-size:ui
npm run release:correlation:ui
```

Full `npm run verify` includes audit — address known transitive CVEs via inventory, do not disable privacy tests.

## Privacy / offline

- [ ] Production `dist/index.html` CSP includes `connect-src 'none'`
- [ ] No `fetch`/XHR/WebSocket in `src/` (`check:network`)
- [ ] TLS Hello privacy gate (T47) remains in `pcap:diagnostic-gate` / `pcap:voip-gate` — **do not skip**
- [ ] Shareable/AI report contains no mapping, recovery, passphrase, or original identities

## Artifacts

- [ ] `npm run sbom` → `release/sbom.cdx.json` (CycloneDX)
- [ ] `npm run release:manifest` → checksums; optional `GPG_SIGN_RELEASE=1` for signing
- [ ] Release ZIP / pack: no `.rnd-mapping-bundle.json`, no `.rnd-pcap-recovery.bin`, no restored AI reports with originals
- [ ] Capacity evidence: `docs/CAPACITY_EVIDENCE.md` + `tests/performance/results/` (sanitized timings, no raw identities)

## Legacy naming (plaintext recovery)

Internal `decrypt*` / `Decrypted*` in recovery are **legacy aliases for reading plaintext frames**,
not a cryptographic service. Prefer “plaintext / read frame” naming in new code;
KDF/passphrase UI does not return.

## Signing

```sh
GPG_SIGN_RELEASE=1 npm run release:manifest
```
