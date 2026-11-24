# rnd-log-anonymizer

Local Czech-UI SPA that anonymizes **logs** and **PCAP/PCAPNG** captures in the browser.
No backend, telemetry, login, accounts, or roles. Input is never stored in browser storage and never sent over the network.

## Capabilities

- **Text mode** — dual-pane preview (original / anonymized), search in both panes,
  rule profiles, export to clipboard or file.
- **PCAP mode** — streamed analysis and capture export, packet filter including full-text search,
  Inspector, three security statuses.
- **Multi-source correlation** — shared mapping across text and PCAP; per-source export plus
  optional shareable manifest (no originals).
- **Resolve-only lookup** — import an unencrypted JSON mapping bundle and look up the original
  value from an anonymized alias or AI report.
- **Unified text profile** — built-in `rnd-team-production` profile (text rules only) in
  [profiles/rnd-team-production.json](profiles/rnd-team-production.json).
- **PCAP level** — two fixed runtime modes (`diagnostic`, `high-privacy`) in the top bar,
  independent of the text profile.

**Limits:** text **90 MiB** / 400,000 lines, PCAP **100 MiB**, correlation aggregate **200 MiB**.
`.gz` (gzip) input is decompressed in the browser; limits apply to the **decompressed** size.

**Mapping:** private unencrypted `.rnd-mapping-bundle.json`.
**PCAP recovery:** optional private unencrypted `.rnd-pcap-recovery.bin` (v4) to restore the original.
Both formats stay password-free with no planned encryption. Keep them out of AI-shared output;
hashes check integrity and file pairing, not secrecy or authentication.
Shareable `correlation-manifest.json` contains only aliases and non-identifying metadata.

**Release gate (configured):** max-size + correlation for Chromium, Firefox, and WebKit
(`npm run release:correlation`). Local release gate and checklist:
`npm run verify`, `docs/RELEASE_CHECKLIST.md`, `docs/CAPACITY_EVIDENCE.md`.

## Run

```sh
npm install
npm run dev
```

Production build:

```sh
npm run build
npm run preview
```

Serve `dist/` over HTTP(S), not `file://`. The same build works at `/` and under `/anonym/`.

## Verify

```sh
npm run verify                 # network + audit + lint + unit + build
npm run check:anonym-subpath   # after build: CSP + relative assets under /anonym/
npm run check:dist-artifacts   # after build: dist/ without profiles, fixtures, or captures
npm run pcap:hardening         # fuzz corpus + hardening unit smoke
npm run test:e2e:chromium
npm run test:visual              # Chromium screenshot baselines + tri-browser hierarchy
npm run test:a11y                # axe + keyboard + forced-colors (tri-browser)
npm run test:e2e:gallery         # design-system gallery (Vite, not dist)
npm run release:max-size:ui     # tri-browser max text/PCAP micro gate
npm run release:correlation:ui     # tri-browser correlation gate (micro)
npm run release:pack-artifact  # dist + sanitized reports (no mapping bundle)
```

## Performance (optional)

```sh
npm run bench:baseline           # micro baseline + temp maximum fixtures
npm run fixtures:maximum         # 90 MiB text + 100 MiB PCAP/PCAPNG into a temp directory
npm run bench:text-pipeline      # text product pipeline (Node)
npm run bench:pcap-capacity      # PCAP common / max / ~250 MiB baseline
npm run pcap:census -- <files>   # local protocol census (aggregates only → bench/results/)
```

Browser reports (max-size / correlation) are generated locally under
`tests/performance/results/` (gitignored).
Large release fixtures (90/100 MiB) are not checked in —
`npm run fixtures:max-size` creates them locally under `tests/performance/fixtures/max-size/`.

## Profiles and formats

| Mode | Extension | Format |
|------|-----------|--------|
| text (ruleset) | `.rnd-log-anonymizer.json` | `rnd-log-anonymizer-ruleset` (text rules only) |
| mapping bundle | `.rnd-mapping-bundle.json` | unencrypted JSON |
| PCAP recovery | `.rnd-pcap-recovery.bin` | unencrypted framed binary v4 |

Built-in text profile: [profiles/rnd-team-production.json](profiles/rnd-team-production.json).
PCAP anonymization uses two fixed UI runtime levels — there is no separate PCAP profile JSON.

## Deploy

```sh
./deploy.sh <host> [remote_user] [remote_dir]
sudo ./install-systemd-service.sh <app_dir> [port] [run_user]
```

The systemd helper exposes `/anonym/` via a symlink webroot. Production: reverse proxy + HTTPS + CSP HTTP headers.

## Documentation

- In-app PCAP principles (Czech UI copy): [docs/PCAP_ANONYMIZATION_OVERVIEW.md](docs/PCAP_ANONYMIZATION_OVERVIEW.md)
- Release checklist: [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)
- Capacity evidence: [docs/CAPACITY_EVIDENCE.md](docs/CAPACITY_EVIDENCE.md)
- Proprietary protocol onboarding: [docs/PROPRIETARY_PROTOCOL_ONBOARDING.md](docs/PROPRIETARY_PROTOCOL_ONBOARDING.md)
- Protocol support matrix source: `src/pcap/docs/protocolSupportMatrix.ts` (`npm run docs:protocol-matrix`)

Local implementation scratch lives under `tasks/` (gitignored) and is not part of the public tree.
