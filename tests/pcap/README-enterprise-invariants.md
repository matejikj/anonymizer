# Enterprise invariants corpus (step 13)

Adversarial validation suite for the dual-goal contract:

- **`diagnostic`** — preserve packet count / order / length / Δt; MASK secrets; never DROP; AI root-cause class survives sanitization.
- **`high-privacy`** — same engine, aggressive policy (confirmed media DROP allowed).

## How to run

```bash
npm run enterprise-invariants
```

This script is also part of `npm run verify`.

## What it covers

| Area | Primary tests |
| --- | --- |
| Diagnostic count/order/length/Δt + AI root-cause goldens (SIP 403, one-way RTP, DNS NXDOMAIN, TCP RST/retransmit) | `enterpriseStep13InvariantsCorpus.test.ts` |
| TCP split-at-every-byte / retransmitted-secret / OOO / overlapping / missing-middle | `enterpriseStep3TcpReassembly.test.ts` |
| Full diagnostic fact equivalence + tshark oracle | `diagnosticEquivalenceGate.test.ts` |
| Packet-count / length property gate | `diagnosticPropertyGate.test.ts` |
| Privacy / token absence | `diagnosticPrivacyGate.test.ts` |
| Property / malformed / truncated fuzz | `fuzz.test.ts`, `malformed.test.ts` |
| Plaintext recovery v4 reversible + SHA round-trip | `pcap-recovery-golden.test.ts`, `pcap-recovery-contract.test.ts` |

## TEST MODE deterministic seed

```text
PRODUCTION  → CSPRNG session seed (omit seed; different runs → different aliases OK)
TEST MODE   → createTestSessionMapping(seed) / MappingAuthority(config, { seed })
```

- Production entrypoints must call `assertProductionMappingHasNoFixedSeed()` / `createProductionSessionMapping()`.
- API must **not** default a fixed seed.
- Same TEST MODE seed + same map sequence → bit-identical aliases across CI runs.

Fixture seeds: `tests/pcap/fixtures/diagnosticIncidents.ts` (`DIAGNOSTIC_SEED*`).
