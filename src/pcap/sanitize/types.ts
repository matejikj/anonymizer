/**
 * Core types for the PCAP sanitization engine.
 * Patches are length-preserving and never overlap.
 */

export interface BytePatch {
  /** Absolute byte offset in the original packet buffer. */
  readonly offset: number;
  /** Replacement bytes (same length as original span). */
  readonly data: Uint8Array;
}

/**
 * PF-06: context passed to a deferred patch's compute function when it is finally resolved.
 * Separated from `MappingLike` because fingerprint fields need the *live*, packet-order-shared
 * `FingerprintSession` rather than one captured at record time (discovery uses a throwaway,
 * unseeded session per packet since its patch bytes are never used — only plan-build's single
 * shared, seeded session across all packets in order produces correct fingerprint values).
 */
export interface DeferredPatchContext {
  readonly mapping: import('../anonymization/mapping').MappingLike;
  readonly fingerprints: import('../anonymization/fingerprintSession').FingerprintSession;
  /** T04 — optional bounded incident log; filled when deferred compute fails closed. */
  readonly incidentLog?: import('../../domain/anonymizationIncident').IncidentLog;
  readonly sourceId?: string;
  readonly packetIndex?: number;
  readonly packetNumber?: number;
  /** T14 — capture-aligned absolute payload time rewrite (HTTP/SIP Date). */
  readonly payloadTime?: import('../kernel/payloadTimeCodec').PayloadTimeSession;
}

/**
 * T04 — how to fill a deferred span when compute() fails (same length, never NUL/original).
 * Set by the sanitizer that knows the field; defaults to binary-mask.
 */
export interface DeferredPatchMeta {
  readonly fallbackKind: import('./fieldFallback').FieldFallbackKind;
  readonly protocol?: string;
  readonly category?: string;
  readonly packetIndex?: number;
  readonly sourceId?: string;
  /**
   * R09 — when category+protocol and the map wire fields below are set, PatchCollector
   * mirrors a structured `map` op for SemanticJournal / frozen plans (legacy defer unchanged).
   */
  readonly canonical?: string;
  readonly constraint?: import('../../mapping/types').WireRepresentationConstraint;
  readonly encoder?: import('../kernel/operations').WireEncoderKind;
  readonly originalSpelling?: string;
  /** T-01.B — when set with packetIndex, PatchCollector mirrors a journal `mask` / `secret` op. */
  readonly maskDomain?: string;
  readonly maskFillKind?: import('../kernel/operations').FillKind;
  readonly reasonCode?: string;
  /** T-01.B — journal `fingerprint` op (IPv4 ID / flow label / TCP seq space). */
  readonly fingerprintField?: import('../kernel/operations').FingerprintField;
  readonly srcIp?: string;
  readonly dstIp?: string;
  readonly ipProto?: number;
  readonly originalU16?: number;
  readonly originalU32?: number;
  readonly srcPort?: number;
  readonly dstPort?: number;
  readonly flowHeaderByte0?: number;
  readonly flowHeaderByte1?: number;
  readonly tcpSeqKind?: import('../kernel/operations').TcpSeqFingerprintKind;
  /** T-01.B / T01 — journal `session-version-shift` (not a MappingAuthority identity). */
  readonly sessionVersionDigits?: string;
  readonly sessionIdCanonicalForVersion?: string;
}

/** Returns null to mean "no patch after all" (e.g. port-wire's no-op-if-unchanged case). */
export type DeferredPatchCompute = (ctx: DeferredPatchContext) => Uint8Array | null;

export type SanitizationPreset = 'diagnostic' | 'high-privacy';

/**
 * RTP/RTCP media disposition. Implicit preservation is not allowed.
 * `strip-payload` keeps the packet record and header diagnostics; media bytes are masked later.
 */
export type VoipMediaPolicy = 'strip-payload' | 'drop' | 'preserve-unsafe';

/** How unsupported / unknown application payload is handled. */
export type UnsupportedPayloadPolicy = 'mask-in-place' | 'truncate' | 'preserve-unsafe';

/** How malformed application payload is handled. */
export type MalformedPayloadPolicy = 'mask-application-in-place' | 'drop' | 'preserve-unsafe';

/**
 * Fail-closed action for SIP that cannot be safely anonymized.
 * Encrypted SIP is never decrypted — it is only marked.
 */
export type SipUncoveredAction = 'drop' | 'truncate' | 'mark-uncovered' | 'mask-in-place';
export type SipEncryptedAction = 'mark-encrypted';

export interface SipHandlingPolicy {
  /** Incomplete SIP (truncated TCP/UDP payload, missing body vs Content-Length). */
  readonly incompleteMessage: SipUncoveredAction;
  /** Parser classified the payload as malformed SIP. */
  readonly malformed: SipUncoveredAction;
  /** TLS or otherwise encrypted SIP. Never decrypt in v1. */
  readonly encrypted: SipEncryptedAction;
  /** Reassembly budget exceeded (bytes, flows, or time window). */
  readonly reassemblyLimitExceeded: SipUncoveredAction;
}

/** CF-11 / step 7 — IP/TCP fingerprint field disposition. */
export type FingerprintFieldPolicy =
  | 'normalize'
  | 'map'
  | 'preserve-for-diagnostics'
  | 'preserve-unsafe';

export interface NetworkFingerprintPolicy {
  readonly ttl: FingerprintFieldPolicy;
  readonly tcpWindow: FingerprintFieldPolicy;
  readonly flowLabel: FingerprintFieldPolicy;
  /** IPv4 identification — `map` keeps fragment groups joinable without device counters. */
  readonly ipv4Id: FingerprintFieldPolicy;
  /** TCP SEQ/ACK/SACK space — `map` applies per-direction 32-bit offsets. */
  readonly tcpSeq: FingerprintFieldPolicy;
  readonly tcpOptions: FingerprintFieldPolicy;
}

export interface SanitizationPolicy {
  readonly preset: SanitizationPreset;
  /**
   * Explicit unsupported-payload policy (replaces ambiguous truncateUnsupported alone).
   * `truncateUnsupported` below is derived for legacy call sites.
   */
  readonly unsupportedPayloadPolicy: UnsupportedPayloadPolicy;
  /** Explicit malformed-payload policy. */
  readonly malformedPayloadPolicy: MalformedPayloadPolicy;
  /**
   * Derived: true when unsupportedPayloadPolicy === 'truncate'.
   * Prefer resolveCoverageDisposition / unsupportedPayloadPolicy for new code.
   */
  readonly truncateUnsupported: boolean;
  /** Process DNS/mDNS application payload. */
  readonly dns: boolean;
  /** Process DHCPv4/v6 application payload. */
  readonly dhcp: boolean;
  /** Process SIP/SDP application payload (signaling anonymization switch). */
  readonly sipSdp: boolean;
  /** Process TLS ClientHello/SNI. */
  readonly tls: boolean;
  /** Process HTTP/1.x headers. */
  readonly http: boolean;
  /** Best-effort regex scan of any otherwise-unrecognized payload (DB wire protocols, proprietary traffic). */
  readonly heuristicScan: boolean;
  /** Process DMR (Homebrew/MMDVM "DMRD") radio packets. */
  readonly dmr: boolean;
  /** Detect MOTOTRBO IPSC traffic (best-effort — no public spec, whole payload redacted). */
  readonly mototrbo: boolean;
  /** Process VRRP (IP proto 112) — remap the embedded virtual IP(s), preserve VRID/priority/timers. */
  readonly vrrp: boolean;
  /** Process Spanning Tree (802.3 LLC DSAP/SSAP 0x42) BPDUs — remap bridge/root system IDs, preserve topology fields. */
  readonly stp: boolean;
  /** Process Cisco Discovery Protocol (SNAP OUI 00-00-0c) — remap device/hostname TLVs, preserve capability/platform TLVs. */
  readonly cdp: boolean;
  /** T19 — LLDP / LLDP-MED (EtherType 0x88CC). */
  readonly lldp: boolean;
  /** T19 — LACP / Slow Protocols (EtherType 0x8809). */
  readonly lacp: boolean;
  /** T19 — EAPOL / 802.1X (EtherType 0x888E). */
  readonly eapol: boolean;
  /**
   * Derived: true when malformedPayloadPolicy === 'drop'.
   * Prefer malformedPayloadPolicy / resolveCoverageDisposition for new code.
   */
  readonly dropMalformed: boolean;
  /** RTP/RTCP media disposition. `preserve-unsafe` is never a safe export. */
  readonly mediaPolicy: VoipMediaPolicy;
  /** Fail-closed SIP handling for incomplete, malformed, encrypted, and over-limit messages. */
  readonly sipHandling: SipHandlingPolicy;
  /** IP/TCP fingerprint fields (TTL, window, flow label) — CF-11. */
  readonly networkFingerprint: NetworkFingerprintPolicy;
  /** Diagnostic invariant: keep captured/wire lengths (in-place rewrite only). */
  readonly preservePacketLengths: boolean;
  /** Diagnostic invariant: one input record → one output record in order. */
  readonly preservePacketOrder: boolean;
}

export type CoverageStatus =
  | 'covered'
  | 'redacted'
  | 'unsupported'
  | 'truncated'
  | 'requires-reassembly'
  | 'malformed'
  | 'encrypted'
  | 'heuristic'
  | 'preserved-unsafe'
  | 'preserved-for-diagnostics'
  /** T07 — sanitizer/processor threw; packet/payload fail-closed. Never treat as covered. */
  | 'processing-failed'

export interface LayerCoverage {
  readonly protocol: string;
  readonly offset: number;
  readonly length: number;
  readonly status: CoverageStatus;
  /**
   * UI thread only (R10 packed discover): this entry stands for N sanitizer spans with the
   * same protocol × status, `length` = their total bytes. Counting consumers weight by it.
   */
  readonly aggregateCount?: number;
}

export interface PacketSanitizationResult {
  readonly packetIndex: number;
  readonly patches: BytePatch[];
  /** New captured length if truncation applies, otherwise undefined. */
  readonly truncatedLength?: number;
  readonly coverage: LayerCoverage[];
  /** True if packet should be dropped (malformed in safe mode). */
  readonly drop: boolean;
  readonly issues: string[];
  /**
   * PF-06: present only when sanitizePacket() was called with `deferPatchResolution: true`
   * (in which case `patches` above is a placeholder, not real bytes). Call with the live
   * mapping/fingerprints to materialize real patch bytes without re-running the structural
   * decode that found them — the whole point being that decode runs once (discovery) and
   * this cheap step runs again later (plan build) against the resolved mapping.
   */
  readonly resolvePatches?: (ctx: DeferredPatchContext) => BytePatch[];
  /** R09 — journal-native symbolic ops (map/mask/secret) collected alongside deferred placeholders. */
  readonly symbolicMapOps?: readonly import('../kernel/operations').SymbolicOperation[];
  /** True when every winning deferred patch has a matching journal symbolic op (can omit legacyResolve). */
  readonly deferredFullySymbolized?: boolean;
}

/**
 * Return shape for app-layer sanitizers that can report more than covered/not-covered
 * (e.g. requires-reassembly, unsupported-subtype, heuristic). `null` means "not this
 * protocol, let the caller try the next handler" — mirrors `TunnelResult | null` from
 * sanitize/tunnel.ts.
 */
export interface AppLayerResult {
  readonly coverage: LayerCoverage[];
  /** Enterprise step 2 — optional SensitiveField classifications from the parser. */
  readonly fields?: readonly import('../trust').SensitiveField[];
  /** Safe issue tokens (no original identities) — e.g. tls-branch:ech. */
  readonly issues?: readonly string[];
}

export function isPreserveUnsafeMediaPolicy(policy: VoipMediaPolicy): boolean {
  return policy === 'preserve-unsafe';
}

export function isStripPayloadMediaPolicy(policy: VoipMediaPolicy): boolean {
  return policy === 'strip-payload';
}

/** Derive legacy truncate flag from explicit unsupported policy. */
export function derivesTruncateUnsupported(policy: UnsupportedPayloadPolicy): boolean {
  return policy === 'truncate';
}

/** Derive legacy drop-malformed flag from explicit malformed policy. */
export function derivesDropMalformed(policy: MalformedPayloadPolicy): boolean {
  return policy === 'drop';
}
