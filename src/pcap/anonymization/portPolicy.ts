/**
 * Port policy (enterprise step 6 / CF-14 / T06) — semantic service role + IANA class + flow.
 *
 * Do NOT preserve merely because port < 1024. SIP 5060 is User/Registered (IANA),
 * yet must stay fixed for Decode As. Conversely, an obscure system port is not
 * automatically a preserved service.
 */

/** IANA system ports (0–1023). Classification only — not an auto-preserve rule. */
export const SYSTEM_PORT_MAX = 1023

/** IANA user/registered ports (1024–49151). */
export const USER_REGISTERED_PORT_MIN = 1024
export const USER_REGISTERED_PORT_MAX = 49_151

/** Dynamic/private ports (RFC 6335) — permute target when ephemeralPorts=permute. */
export const DYNAMIC_PORT_MIN = 49_152
export const DYNAMIC_PORT_MAX = 65_535
export const DYNAMIC_PORT_SPACE = DYNAMIC_PORT_MAX - DYNAMIC_PORT_MIN + 1

/** Pair-index space inside the dynamic range (RTP/RTCP +1 preservation). */
export const DYNAMIC_PORT_PAIR_COUNT = Math.floor(DYNAMIC_PORT_SPACE / 2)

export type IanaPortClass = 'system' | 'user-registered' | 'dynamic'

/**
 * Semantic role for anonymization decisions.
 * `media` is assigned from SDP/flow context, not from the port number alone.
 */
export type PortSemanticRole =
  | 'well-known-service'
  | 'signaling'
  | 'media'
  | 'client-ephemeral'
  | 'unclassified'

/** Flow / content hint attached to a port identity (discovery → resolve → plan). */
export type PortFlowHint =
  | 'rtp'
  | 'rtcp'
  | 'sip'
  | 'stun'
  | 'dns'
  | 'http'
  | 'signaling'
  | 'other'

/**
 * Ports whose numeric identity must stay fixed so Wireshark auto-dissectors /
 * diagnostic graphs keep working (semantic services — any IANA class).
 */
export const SEMANTIC_SERVICE_PORTS: ReadonlySet<number> = new Set([
  // System-class services we intentionally preserve
  21, // FTP control
  22, // SSH
  23, // Telnet
  25, // SMTP
  49, // TACACS+
  53, // DNS
  67, 68, // DHCPv4
  80, // HTTP
  110, // POP3
  69, // TFTP
  137, 138, 139, // NBNS / NetBIOS datagram / session (SMB)
  123, // NTP
  143, // IMAP
  161, 162, // SNMP
  389, // LDAP
  443, // HTTPS
  445, // SMB
  465, // SMTPS
  513, // rlogin
  514, // syslog
  601, // syslog (reliable)
  587, // submission
  636, // LDAPS
  993, // IMAPS
  995, // POP3S
  // User/registered signaling & overlay
  546, 547, // DHCPv6
  554, 8554, // RTSP
  853, // DoT
  1719, 1720, // H.323 RAS / H.225
  1812, 1813, 3799, // RADIUS (auth / accounting / CoA)
  1900, // SSDP
  3702, // WS-Discovery
  5355, // LLMNR
  2000, // SCCP / Skinny
  2427, 2727, // MGCP (call-agent / gateway)
  2905, // SIGTRAN M3UA
  2944, 2945, // H.248 / MEGACO
  3478, 3479, // STUN/TURN
  3868, // Diameter
  4569, // IAX2
  5038, // Asterisk AMI
  5060, 5061, // SIP
  5349, // TURN TLS
  5353, // mDNS
  2123, // GTP-C
  2152, // GTP-U
  2775, // SMPP
  3242, // MRCPv2 (common control)
  7547, // CWMP / TR-069 ACS
  30005, // CWMP alternate
  3389, // RDP
  4789, // VXLAN
  5900, 5901, 5902, 5903, // VNC / RFB
  6000, // X11
  623, // IPMI / RMCP+
  1494, 2598, // Citrix ICA / CGP
  16_992, 16_993, 16_994, 16_995, // Intel AMT
  4729, // GSMTAP
  5672, // AMQP
  8088, // Asterisk ARI
  9900, // IUA (RFC 4233)
  9092, // Kafka
  4222, // NATS
  61613, // STOMP
  5222, 5269, // XMPP client / server
  12201, // GELF
  24224, // Fluent Forward
  4317, 4318, // OTLP gRPC / HTTP
  5432, // PostgreSQL
  3306, // MySQL / MariaDB
  1433, // TDS / MS SQL
  6379, // Redis
  27_017, // MongoDB
  1883, // MQTT
  5683, // CoAP
  502, // Modbus/TCP
  2404, // IEC 60870-5-104
  20_000, // DNP3
  4840, // OPC UA
  135, // DCE/RPC endpoint mapper
  3260, // iSCSI
  111, // portmapper / rpcbind
  2049, // NFS
  9060, // HEP / Homer
  37008, // TZSP
])

/** Catalog ports that are telecom / VoIP signaling (role = signaling). */
const SIGNALING_CATALOG_PORTS: ReadonlySet<number> = new Set([
  1720, // H.323
  1812, 1813, // RADIUS
  2000, // SCCP
  2427, 2727, // MGCP
  2905, // M3UA
  2944, 2945, // H.248
  3478, 3479, 5349, // STUN/TURN
  3868, // Diameter
  4569, // IAX2
  5038, // Asterisk AMI
  5060, 5061, // SIP
  8088, // Asterisk ARI
  9900, // IUA
  2775, // SMPP
  3242, // MRCPv2
  7547, // CWMP
  30005, // CWMP alternate
  2123, // GTP-C
  9060, // HEP (SIP capture mirror)
])

/** @deprecated Prefer SEMANTIC_SERVICE_PORTS — same preserve set. */
export const PRESERVED_SERVICE_PORTS = SEMANTIC_SERVICE_PORTS

export function ianaPortClass(port: number): IanaPortClass {
  if (port < 0 || port > DYNAMIC_PORT_MAX) return 'dynamic'
  if (port <= SYSTEM_PORT_MAX) return 'system'
  if (port < DYNAMIC_PORT_MIN) return 'user-registered'
  return 'dynamic'
}

export function isSystemPort(port: number): boolean {
  return ianaPortClass(port) === 'system'
}

export function isDynamicPort(port: number): boolean {
  return ianaPortClass(port) === 'dynamic'
}

export function isUserRegisteredPort(port: number): boolean {
  return ianaPortClass(port) === 'user-registered'
}

export function isSemanticServicePort(port: number): boolean {
  return SEMANTIC_SERVICE_PORTS.has(port)
}

/**
 * Ports that must never be remapped (and must not be used as permute aliases).
 * Based on semantic catalog — NOT on IANA system range alone.
 */
export function isPreservedServicePort(port: number): boolean {
  return isSemanticServicePort(port)
}

/** Merge flow hints — signaling/sip/stun win over media/other (deterministic). */
export function mergePortFlowHints(
  a: PortFlowHint | undefined,
  b: PortFlowHint | undefined,
): PortFlowHint | undefined {
  if (a === undefined) return b
  if (b === undefined) return a
  const rank = (h: PortFlowHint): number => {
    if (h === 'sip' || h === 'stun' || h === 'signaling') return 3
    if (h === 'rtp' || h === 'rtcp') return 2
    if (h === 'dns' || h === 'http') return 1
    return 0
  }
  return rank(b) > rank(a) ? b : a
}

export function semanticPortRole(
  port: number,
  hint?: { readonly flow?: PortFlowHint },
): PortSemanticRole {
  if (hint?.flow === 'rtp' || hint?.flow === 'rtcp') return 'media'
  if (
    hint?.flow === 'sip'
    || hint?.flow === 'stun'
    || hint?.flow === 'signaling'
  ) {
    return 'signaling'
  }
  if (isSemanticServicePort(port)) {
    if (SIGNALING_CATALOG_PORTS.has(port)) return 'signaling'
    return 'well-known-service'
  }
  if (isDynamicPort(port)) return 'client-ephemeral'
  return 'unclassified'
}

/**
 * Whether the port number should stay fixed under ephemeral permute.
 * Content-discovered signaling (hint) is preserved only when `preserveContentSignaling` is true
 * (diagnostic); high-privacy may permute non-catalog signaling ports.
 */
export function shouldPreservePort(
  port: number,
  hint?: { readonly flow?: PortFlowHint; readonly preserveContentSignaling?: boolean },
): boolean {
  const role = semanticPortRole(port, hint)
  if (role === 'well-known-service') return true
  if (role === 'signaling') {
    if (isSemanticServicePort(port)) return true
    // Non-catalog signaling (e.g. SIP on 5070) — policy-gated.
    return hint?.preserveContentSignaling !== false
  }
  return false
}

/** @deprecated Prefer ianaPortClass + semanticPortRole. */
export type PortClass = 'system' | 'registered-service' | 'registered' | 'dynamic'

/** @deprecated Prefer ianaPortClass + isSemanticServicePort. */
export function classifyPort(port: number): PortClass {
  if (isSemanticServicePort(port)) return 'registered-service'
  const iana = ianaPortClass(port)
  if (iana === 'system') return 'system'
  if (iana === 'dynamic') return 'dynamic'
  return 'registered'
}
