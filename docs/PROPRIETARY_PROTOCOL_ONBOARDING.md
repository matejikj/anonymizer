# Proprietary / radio protocol onboarding

Goal: add structured protection **only** via a declarative descriptor in the repository.
No runtime schema upload, no `eval`, no user-uploaded policy.

## When a protocol may be “structured”

1. Legally usable specification (RFC / vendor PDF with license / internal schema owned by the team).
2. Synthetic corpus (canary identities, GPS/text/secrets) — **never** a real customer PCAP in git.
3. Descriptor passes `validateWireProtocolDescriptor` (byte coverage, categories, `preserve` + reason).
4. Negative test: intentional offset/length mutation must fail the validator or wire test.
5. Entry in the support matrix with status and limitations; no full-support claim without a proven variant.

Without a schema the protocol stays **mask-only / identify-only** (MOTOTRBO IPSC pattern).

## Minimum information from the specification owner

| Item | Required |
|---|---|
| Transport + verified ports (narrow list) | yes |
| Magic / framing / endianness / version | yes |
| Message discriminator (msg type → body) | yes |
| Identity fields (subscriber, site, group, …) + namespace | yes |
| Secrets (auth, PSK, provisioning) | yes — always mask/secret |
| Voice / media | policy like RTP (both levels) |
| GPS / free text | mask (default) |
| Normative revision + license | yes |

## PR checklist

1. Copy `src/pcap/protocols/descriptors/template.ts` → `<id>.ts`.
2. Fill fields so there is **no gap** in `headerLength` (validator).
3. Register in `registry.ts` + handler id in `APPLICATION_HANDLER_ORDER`.
4. Sanitize via `sanitizeFromDescriptor` (no second ad-hoc parser).
5. Kernel module (probe/analyze) for the T-01 catalog when making a production claim.
6. Unit tests: validator OK, reject gap/preserve-without-reason, wire must-not-leak canary.
7. `npm run docs:protocol-matrix`, bump `PCAP_ENGINE_VERSION`.
8. Update the in-app overview (`docs/PCAP_ANONYMIZATION_OVERVIEW.md`) only for proven variants.

## Pilot

`rnd-dispatch-lite` (UDP 49992) is a **synthetic** proprietary dialect owned by this project —
framework proof, not a vendor format. MOTOTRBO / Hytera / P25 ISI wait on a licensed schema.
