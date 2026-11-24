/**
 * T32 — single source of truth for protocol support matrix rows.
 * Single source of truth for in-app matrix and `npm run docs:protocol-matrix` validation.
 * Capability claims stay honest: no structured status without a real handler.
 * T-01.F: 107/108 `APPLICATION_HANDLER_ORDER` ids live in `APPLICATION_DISPATCH_REGISTRY`;
 * `heuristic` stays an intentional inline tail in `engine.ts`. Rows describe sanitize handlers,
 * not a finished unified kernel (R10 browser open; T-01.B journal ops DONE for common traffic).
 */

import { APPLICATION_HANDLER_ORDER } from '../kernel/applicationHandlers.ts'
import { listCatalogProtocols } from '../kernel/catalog.ts'
import type { DispatchSelector } from '../kernel/types.ts'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../sanitize/unsupportedIdentification.ts'
import { resolveEffectiveAppHandlerFlags } from './protocolMatrixVariantConformance.ts'

/** How far the product can protect a recognized capability variant. */
export const SUPPORT_PROTECTION = [
  'structured',
  'mask-only',
  'identify-mask',
  'encrypted-phase',
  'container',
  'decode-map',
] as const
export type SupportProtection = (typeof SUPPORT_PROTECTION)[number]

export interface ProtocolSupportRow {
  readonly id: string
  readonly title: string
  readonly layer: string
  readonly variant: string
  readonly protection: SupportProtection
  readonly identification: boolean
  readonly structured: boolean
  readonly provenCiphertext: boolean
  readonly diagnostic: string
  readonly highPrivacy: string
  readonly limitation?: string
}

/** Per-handler policy notes — must match real sanitize behavior, not aspirational. */
const HANDLER_NOTES: Readonly<
  Record<
    string,
    {
      title: string
      variant: string
      protection: SupportProtection
      diagnostic: string
      highPrivacy: string
      limitation?: string
      provenCiphertext?: boolean
    }
  >
> = {
  dns: {
    title: 'DNS / mDNS',
    variant: 'UDP/TCP 53, mDNS 5353',
    protection: 'structured',
    diagnostic: 'length-preserving map jmen a A/AAAA',
    highPrivacy: 'truncate / fail-closed',
    limitation:
      'T-01.B: journal map/mask/fingerprint/session-version ops; custom TXT entity deferrals bez meta stále legacyResolve',
  },
  dhcpv4: {
    title: 'DHCPv4',
    variant: 'UDP 67/68',
    protection: 'structured',
    diagnostic: 'map adres/hostname/client-id; classless routes: router map, cíl mask; parametry lease ponechány',
    highPrivacy: 'stejné',
    limitation: 'fail-closed: vendor (43/60/125), relay (82), URL (252) a neznámé options → mask hodnoty',
  },
  dhcpv6: {
    title: 'DHCPv6',
    variant: 'UDP 546/547; relay-forw/repl',
    protection: 'structured',
    diagnostic: 'map DUID-LL(T)/IAADDR/serverů a domén; relay link/peer map; status kód ponechán',
    highPrivacy: 'stejné',
    limitation: 'fail-closed: vendor/user class, interface/remote-id, IAID, IA_PD prefix, status text a neznámé options → mask',
  },
  tls: {
    title: 'TLS',
    variant: 'TCP record; Hello / cert / AppData',
    protection: 'encrypted-phase',
    diagnostic:
      'SNI map; Hello random/session_id/unknown ext mask (T47); cert CN/SAN; AppData po SH → encrypted',
    highPrivacy: 'truncate handshake; encrypted AppData ponecháno jen s doloženou fází',
    provenCiphertext: true,
    limitation: 'DTLS není TLS record parser — viz T28 zbytek / T36',
  },
  ssh: {
    title: 'SSH',
    variant: 'TCP; banner + binary packets',
    protection: 'mask-only',
    diagnostic: 'banner fingerprint; KEXINIT preserve; host-key/signature mask; post-NEWKEYS bez důkazu → opaque mask',
    highPrivacy: 'software string mask; stejná host-key politika',
    limitation: 'encrypted-preserved jen s per-direction NEWKEYS + doloženou confidentiality (zatím ne)',
  },
  quic: {
    title: 'QUIC',
    variant: 'UDP long header v1/v2',
    protection: 'mask-only',
    diagnostic: 'CID → opaque-id; Initial protected payload vždy mask (public derivation); short header bez kontextu mask',
    highPrivacy: 'stejné',
    limitation: 'Initial není encrypted-preserved; re-encrypt spike mimo baseline',
  },
  dtls: {
    title: 'DTLS',
    variant: 'UDP record framing (1.0/1.2); content probe',
    protection: 'mask-only',
    diagnostic:
      'record header (13 B) covered; handshake přes normativní 12 B DTLS fragment hlavičku; single-fragment ClientHello → SNI map; multi-fragment / cross-UDP flight → requires-reassembly + mask',
    highPrivacy: 'stejné',
    limitation:
      'cross-UDP datagram flight reassembly nepodporováno; legacy TLS 4 B handshake v DTLS záznamu jen heuristic; app data bez doložené confidentiality → mask',
  },
  openvpn: {
    title: 'OpenVPN',
    variant: 'UDP/TCP 1194; content probe jen hard-reset (kolize NTP/GTP)',
    protection: 'mask-only',
    diagnostic:
      'session-id → opaque-id; control TLS child když čitelný; data/control payload bez doložené AEAD → mask (R02)',
    highPrivacy: 'stejné',
    limitation: 'TCP length framing + partial frame → requires-reassembly; data není encrypted-preserved; mimo 1194 jen hard-reset probe',
  },
  ike: {
    title: 'IKE / ISAKMP',
    variant: 'UDP 500/4500',
    protection: 'encrypted-phase',
    diagnostic: 'SPI preserve; ID/CERT/AUTH/HASH/KE/Nonce/NAT_DETECTION mask; SK → encrypted (IKEv2)',
    highPrivacy: 'stejné',
    provenCiphertext: true,
    limitation: 'ESP bez SA profilu zůstává mask-only (NULL encryption)',
  },
  wireguard: {
    title: 'WireGuard',
    variant: 'UDP type/size/reserved classify',
    protection: 'encrypted-phase',
    diagnostic: 'handshake pubkey/MAC mask; transport AEAD → encrypted po pozitivní klasifikaci',
    highPrivacy: 'stejné',
    provenCiphertext: true,
    limitation: 'náhodný UDP stejné délky ≠ WireGuard',
  },
  sip: {
    title: 'SIP / SDP',
    variant: 'UDP/TCP 5060/5061 + content probe; MCPTT/DTMF/dialog-info bodies (T37)',
    protection: 'structured',
    diagnostic:
      'URI/host/Call-ID/UA; SDP c=/o=/m=/ICE; multipart/SIPREC; MCPTT URI map + location mask; DTMF Signal mask; uaCSTA csta+xml (T49); Geolocation cid map + PIDF-LO/LoST (T53)',
    highPrivacy: 'truncate dle úrovně',
    limitation: 'SIP-I MIME ISUP body → fail-closed mask (SS7 ISUP přes M3UA → app:m3ua); sipfrag partial → mask',
  },
  pidf: {
    title: 'PIDF-LO / geopriv',
    variant: 'application/pidf+xml (+ held); SIP multipart cid',
    protection: 'structured',
    diagnostic:
      'entity/tuple/device id scoped map; coordinates/civic/usage-rules location always mask; XXE reject',
    highPrivacy: 'stejné (location vždy mask)',
    limitation: 'náhradní geometrie není skutečná poloha; signed CMS plaintext stále mask',
  },
  lost: {
    title: 'LoST',
    variant: 'application/lost+xml (RFC 5222)',
    protection: 'structured',
    diagnostic:
      'requestId map; urn:service:sos* preserve; serviceBoundary/displayName/URI/geometry mask',
    highPrivacy: 'stejné',
    limitation: 'anonymizér neprovádí LoST routing ani síťový dotaz; custom service URN → map',
  },
  mrcp: {
    title: 'MRCPv2',
    variant: 'TCP content probe MRCP/2.0; port 3242 hint',
    protection: 'structured',
    diagnostic:
      'method/status/request-state/Completion-Cause preserve; Channel-Identifier session map + known @resource; Interpret-Text/NLSML/SSML/grammar/voiceprint/waveform-URI always mask',
    highPrivacy: 'stejné (speech content vždy mask)',
    limitation: 'MRCPv1/RTSP mimo baseline; RTP audio dle media policy; žádné STT/TTS ani grammar fetch',
  },
  cwmp: {
    title: 'CWMP / TR-069',
    variant: 'SOAP/HTTP CWMP1.4; TCP 7547 hint; HTTP body child',
    protection: 'structured',
    diagnostic:
      'RPC/ID/CommandKey/SerialNumber map; Password/Username/URL secrets; ParameterValueStruct role by Name; XXE reject',
    highPrivacy: 'stejné (credentials vždy mask)',
    limitation: 'HTTPS ciphertext neparsuje; firmware/config transfer payload mask; no ACS download',
  },
  usp: {
    title: 'USP / TR-369',
    variant: 'Record protobuf plaintext; MQTT/STOMP MTP hooks',
    protection: 'structured',
    diagnostic:
      'version/security enum preserve; from_id/to_id/session map; MAC/cert mask; non-plaintext payload mask; Msg strings role-aware',
    highPrivacy: 'stejné',
    limitation: 'E2E TLS/MQTT TLS ciphertext mimo baseline; full TR-181 dictionary mimo pinned walker; no controller contact',
  },
  nas: {
    title: 'NAS EPS / 5GS',
    variant: 'TS 24.301 / 24.501 plaintext + security-header classification; GSMTAP LTE-NAS child',
    protection: 'structured',
    diagnostic:
      'PD/msg-type/cause preserve; IMSI/IMEI TBCD map; GUTI/TMSI opaque map; RAND/AUTN/PCO/TAI mask; ciphered opaque; MAC invalidated',
    highPrivacy: 'stejné (auth/location vždy mask)',
    limitation: 'S1AP/NGAP carriers → T57/T58; no key derivation; unknown cipher → opaque; SUCI concealed mask',
  },
  csta: {
    title: 'CSTA / uaCSTA',
    variant: 'ECMA-323 XML Annex J; SIP application/csta+xml',
    protection: 'structured',
    diagnostic:
      'Annex J length preserve; device/call/monitor IDs map (scoped); MonitorStart/Stop lifecycle graph (XML); invokeID scoped per capture generation; UserData/DTMF/Location mask; uaCSTA via SIP body T02',
    highPrivacy: 'truncate',
    limitation:
      'ASN.1 ROSE/ACSE Phase III → mask-only (no structured decode); schema compiler / full ECMA-269 catalog mimo baseline; XXE reject',
  },
  ami: {
    title: 'Asterisk AMI',
    variant: 'TCP 5038 AMI v2 key:value; banner Asterisk Call Manager/',
    protection: 'structured',
    diagnostic:
      'Action/Event/Response preserve; CallerID/Channel/Uniqueid/Linkedid/Bridge/ActionID scoped map; Variable after= mask',
    highPrivacy: 'stejné (Login Secret/Challenge vždy mask)',
    limitation: 'multiline CLI Command output → line mask; AMI v1/AJAM mimo baseline; unknown keys fail-closed mask',
  },
  ari: {
    title: 'Asterisk ARI',
    variant: 'HTTP /ari/* TCP 8088; JSON body overlay',
    protection: 'structured',
    diagnostic:
      'path resource IDs map; api_key/Authorization mask; JSON number/name/id/channel/bridge map; media_uri mask',
    highPrivacy: 'truncate body dle HTTP policy',
    limitation: 'ARI WebSocket events přes T36 framing; HTTPS/WSS ciphertext neparsuje; Swagger-complete catalog mimo baseline',
  },
  mgcp: {
    title: 'MGCP',
    variant: 'UDP 2427/2727 (RFC 3435)',
    protection: 'structured',
    diagnostic: 'verb/txid/QoS preserve; endpoint/C:/I:/X:/caller map; DTMF/DigitMap mask; nested SDP',
    highPrivacy: 'truncate',
    limitation: 'TCP MGCP zůstává identify-only (unsupported:mgcp)',
  },
  h248: {
    title: 'H.248 / MEGACO',
    variant: 'UDP/TCP 2944/2945 text MEGACO/1',
    protection: 'structured',
    diagnostic: 'MID IP/host map; ds= digit mask; Local/Remote SDP → media flows',
    highPrivacy: 'stejné (digit/auth vždy mask)',
    limitation: 'binary ASN.1 BER → identify+mask; SCTP varianta po T17 claim',
  },
  rtsp: {
    title: 'RTSP',
    variant: 'TCP 554/8554; interleaved $',
    protection: 'structured',
    diagnostic: 'URI/host map; Session opaque; Transport ports; Auth mask; SDP body + media',
    highPrivacy: 'stejné',
    limitation: 'interleaved channel ≠ RTP proof → payload mask; HTTP tunnel mimo baseline',
  },
  iax2: {
    title: 'IAX2',
    variant: 'UDP 4569 full/mini frames',
    protection: 'structured',
    diagnostic: 'IE phones/names/user map; PASSWORD/MD5/RSA/CHALLENGE mask; mini voice mask',
    highPrivacy: 'stejné',
    limitation: 'mini bez full context → media mask-only',
  },
  skinny: {
    title: 'SCCP / Skinny',
    variant: 'TCP 2000',
    protection: 'structured',
    diagnostic: 'Register SEP MAC + IP; CallInfo phone/name; keypad mask; media IP/port',
    highPrivacy: 'stejné',
    limitation: 'unknown message ID → body mask; TLS 2443 → TLS path',
  },
  h323: {
    title: 'H.323 (Q.931 / H.225)',
    variant: 'TCP 1720 TPKT+Q.931; RAS UDP 1719',
    protection: 'structured',
    diagnostic: 'Q.931 Calling/Called/Display map; cause preserve; H.225 UUIE (2B délka) PER mask',
    highPrivacy: 'stejné',
    limitation: 'H.225/H.245 PER bez schema → mask-only; maskovaný UUIE Wireshark nedekóduje; media pairing neslíbeno',
  },
  lapd: {
    title: 'Q.921 LAPD',
    variant: 'LINKTYPE_LINUX_LAPD (177); raw LAPD I/S/U',
    protection: 'structured',
    diagnostic: 'SAPI/control preserve; TEI scoped map; I-frame → Q.931 child',
    highPrivacy: 'stejné',
    limitation: 'FCS rewrite jen při doloženém FCS; non-Q.931 info → mask',
  },
  q931: {
    title: 'Q.931 DSS1',
    variant: 'PD 0x08; IE stream (DSS1/QSIG numbers)',
    protection: 'structured',
    diagnostic:
      'Call-ref scoped map (direction bit preserve); Calling/Called/Connected/Redirect map; Display map; QSIG Facility ROSE pinned decode (name/transfer/diversion ops); plain Facility/UU/keypad mask',
    highPrivacy: 'stejné (non-BER Facility + UU/keypad vždy mask)',
    limitation:
      'Pinned ECMA-164/174/178 ROSE op subset (T51); full ECMA catalog + ACSE/DSE dialog → unknown op argument mask; H.323 TPKT binding zůstává T24',
  },
  iua: {
    title: 'IUA (RFC 4233)',
    variant: 'SCTP PPID 1; QPTM Protocol Data → Q.931/LAPD',
    protection: 'structured',
    diagnostic: 'TLV tag/len preserve; interface id/text map; Protocol Data nested Q.931',
    highPrivacy: 'stejné',
    limitation: 'ASP/RKM management mimo plný dictionary → unknown TLV mask; vyžaduje T17 complete DATA',
  },
  smpp: {
    title: 'SMPP',
    variant: 'TCP 2775; SMPP 3.4/5.0 PDU header + bind/submit/deliver/data',
    protection: 'structured',
    diagnostic:
      'command/status/seq preserve; system_id map; password mask; source/dest addr map; short_message/message_payload always mask; message_id/SAR ref scoped map',
    highPrivacy: 'stejné (SMS body vždy mask)',
    limitation: 'Legacy 3.3 mimo baseline; vendor DLR grammar → body mask; submit_multi dest list fail-closed mask',
  },
  stun: {
    title: 'STUN',
    variant: 'UDP content probe',
    protection: 'structured',
    diagnostic: 'map XOR-MAPPED a související identity',
    highPrivacy: 'truncate / mask',
  },
  rtp: {
    title: 'RTP',
    variant: 'UDP + SDP flow index',
    protection: 'structured',
    diagnostic: 'klasifikace dle SDP; strip-payload v diagnostic',
    highPrivacy: 'drop / strip dle úrovně',
  },
  rtcp: {
    title: 'RTCP',
    variant: 'UDP paired s RTP',
    protection: 'structured',
    diagnostic: 'SDES/identity mask; shape preserve',
    highPrivacy: 'drop / strip',
  },
  http: {
    title: 'HTTP/1.x',
    variant: 'TCP 80/8080/… hlavičky',
    protection: 'structured',
    diagnostic: 'Host map; target/Referer/User-Agent/Cookie/Authorization mask; Date/Last-Modified Δ (T14); HTML/XHTML mask, ostatní text/* → T15 detectors (heuristic)',
    highPrivacy: 'text/* tělo mask; stejné hlavičky',
    limitation: 'jiné tělo fail-closed mask; HTTP/2/gRPC → T36',
  },
  syslog: {
    title: 'Syslog',
    variant: 'UDP/TCP 514/601; RFC 3164/5424',
    protection: 'structured',
    diagnostic: 'HOSTNAME/APP/SD ip·host map; TIMESTAMP Δ; MSG a ostatní SD hodnoty mask',
    highPrivacy: 'stejné',
    limitation: '3164 bez roku/TZ → mask při nejednoznačnosti; čitelný text logu jen v textovém režimu',
  },
  snmp: {
    title: 'SNMP',
    variant: 'UDP 161/162; v1/v2c/v3 BER',
    protection: 'structured',
    diagnostic: 'community/auth/priv mask; sysName→hostname; engine-id map; neznámý OCTET mask',
    highPrivacy: 'stejné tajemství; textové OID hodnoty přísněji mask',
    limitation: 'authPriv scopedPDU bez klíče → mask; MIB dictionary baseline',
  },
  ntp: {
    title: 'NTP',
    variant: 'UDP 123; RFC 5905',
    protection: 'structured',
    diagnostic: 'refid IPv4 map / opaque; timestamp Δ; MAC digest mask',
    highPrivacy: 'stejné',
    limitation: 'mode 6/7 control body mask; IPv6-hash refid není IPv4',
  },
  tftp: {
    title: 'TFTP',
    variant: 'UDP 69 + TID transfer',
    protection: 'structured',
    diagnostic: 'RRQ/WRQ filename map (SEP+MAC); DATA/ERROR text mask',
    highPrivacy: 'filename mask',
    limitation: 'transfer state přes TID hint; OACK options preserve',
  },
  llmnr: {
    title: 'LLMNR',
    variant: 'UDP/TCP 5355 (DNS tvar)',
    protection: 'structured',
    diagnostic: 'reuse sanitizeDns — QNAME/A/AAAA map',
    highPrivacy: 'stejné',
  },
  nbns: {
    title: 'NBNS / NetBIOS',
    variant: 'UDP 137/138',
    protection: 'structured',
    diagnostic: 'first-level A–P → hostname; NB IP/MAC map; datagram payload mask',
    highPrivacy: 'stejné',
    limitation: 'browser/SMB vendor payload bez schématu → mask',
  },
  ssdp: {
    title: 'SSDP',
    variant: 'UDP 1900',
    protection: 'structured',
    diagnostic: 'HOST/LOCATION map; USN uuid→opaque-id; SERVER mask',
    highPrivacy: 'stejné',
  },
  'ws-discovery': {
    title: 'WS-Discovery',
    variant: 'UDP 3702 SOAP',
    protection: 'structured',
    diagnostic: 'urn:uuid opaque-id; URL detektory; DTD/ENTITY reject',
    highPrivacy: 'stejné',
    limitation: 'scopes bez schématu → jen detector hits',
  },
  msrp: {
    title: 'MSRP',
    variant: 'RFC 4975 TCP',
    protection: 'structured',
    diagnostic: 'path host/session map; Message-ID opaque; CPIM From/To map; body mask',
    highPrivacy: 'stejné',
    limitation: 'split chunks přes TCP reassembly best-effort',
  },
  bfcp: {
    title: 'BFCP',
    variant: 'RFC 8855',
    protection: 'structured',
    diagnostic: 'conference/user/floor ID → opaque-id; unknown ATTR mask',
    highPrivacy: 'stejné',
    limitation: 'SDP confid/userid relation baseline',
  },
  t38: {
    title: 'T.38 / UDPTL',
    variant: 'UDPTL IFP',
    protection: 'structured',
    diagnostic: 'seq preserve; IFP/page + FEC mask (no parity recompute)',
    highPrivacy: 'stejné',
    limitation: 'TSI/CSI map až s T.30 codec; claim přes SDP/test, ne slabý sniff',
  },
  zrtp: {
    title: 'ZRTP',
    variant: 'RFC 6189',
    protection: 'structured',
    diagnostic: 'ZID/client map; Hello hashes + Commit/DH/Confirm mask; integrity-invalidated',
    highPrivacy: 'stejné',
    limitation: 'handshake po anonymizaci není funkční',
  },
  http2: {
    title: 'HTTP/2 (h2c)',
    variant: 'cleartext preface / frames',
    protection: 'structured',
    diagnostic: 'frame header preserve; HPACK block fail-closed mask; DATA → gRPC/SBI JSON/mask',
    highPrivacy: 'stejné',
    limitation: 'žádný length-preserving HPACK rewrite; h2 over TLS zůstává encrypted',
  },
  sbi5g: {
    title: '5G SBI (HTTP/JSON)',
    variant:
      'TS29.500/29.571 REL-18 pinned; Nnrf/Namf/Nsmf/Nudm/Nausf/Npcf/Nnssf/Nnef; N1→T59 N2→T58',
    protection: 'structured',
    diagnostic:
      'path/method/status/5QI preserve; SUPI/NF/session IDs map; tokens/auth vectors/location mask; multipart N1/N2 typed children',
    highPrivacy: 'stejné (token/auth/location vždy mask)',
    limitation:
      'Pinned operation subset (ne full Forge REL-18); HPACK fail-closed → API select from path/JSON probe; TLS without decrypt ≠ JSON input',
  },
  websocket: {
    title: 'WebSocket',
    variant: 'RFC 6455; SIP/JSON subprotocol',
    protection: 'structured',
    diagnostic: 'XOR unmask→sanitize→remask; SIP child; Key/Accept linkage v HTTP handshake',
    highPrivacy: 'stejné',
    limitation: 'permessage-deflate → mask; Accept bez Key ve stejném message → mask',
  },
  grpc: {
    title: 'gRPC',
    variant: 'HTTP/2 DATA length-prefix',
    protection: 'structured',
    diagnostic: 'framing preserve; message bytes mask (schema-less protobuf)',
    highPrivacy: 'stejné',
    limitation: 'bez reviewed .proto jen opaque mask; compressed → mask',
  },
  radius: {
    title: 'RADIUS',
    variant: 'UDP 1812/1813/1645/1646/3799',
    protection: 'structured',
    diagnostic: 'User-Name/NAS/Station map; Authenticator·Password·CHAP·Msg-Auth mask; EAP přes T19',
    highPrivacy: 'stejné (tajemství vždy mask)',
    limitation: 'multi-attr EAP fragment → mask; VSA mimo slovník mask',
  },
  tacacs: {
    title: 'TACACS+',
    variant: 'TCP 49',
    protection: 'structured',
    diagnostic: 'session_id opaque; cleartext user/rem_addr map; obfuscated body vždy mask',
    highPrivacy: 'stejné',
    limitation: 'MD5 pad ≠ encrypted-preserved (opaque-obfuscated-redacted)',
  },
  diameter: {
    title: 'Diameter',
    variant: 'TCP 3868; SCTP PPID 46/47 (T17)',
    protection: 'structured',
    diagnostic: 'Session-Id/Host/Realm/Subscription map; auth vectors mask; unknown AVP mask',
    highPrivacy: 'stejné',
    limitation: 'fragmentované SCTP DATA → requires-reassembly; PER/auth AVP slovník baseline',
  },
  hep: {
    title: 'HEP / EEP (Homer)',
    variant: 'UDP/TCP 9060; HEPv3 + HEPv1/v2',
    protection: 'structured',
    diagnostic: 'chunk IP/port map (= L3/L4); captid/corr opaque; auth mask; SIP payload → SIP sanitizer',
    highPrivacy: 'stejné',
    limitation: 'RTCP JSON producer → mask; compressed payload mask; LI mimo rozsah',
  },
  tzsp: {
    title: 'TZSP',
    variant: 'UDP 37008',
    protection: 'structured',
    diagnostic: 'tag walker; sensor MAC map; Ethernet → vnitřní IP/L4; 802.11 jen adresy',
    highPrivacy: 'stejné',
    limitation: 'plné 802.11 → T40; unknown tag body mask',
  },
  'netflow-v5': {
    title: 'NetFlow v5',
    variant: 'UDP 2055/9995/9996',
    protection: 'structured',
    diagnostic: 'src/dst/nexthop IPv4 map; porty; ASN opaque; unix_secs Δ; uptime/seq preserve',
    highPrivacy: 'stejné',
    limitation: 'ASN jen scoped opaque (T48 prefix relations mimo rozsah)',
  },
  ipfix: {
    title: 'NetFlow v9 / IPFIX',
    variant: 'UDP 4739 (+ NetFlow porty)',
    protection: 'structured',
    diagnostic: 'template cache per domain; známé IE map; chybějící šablona → requires-reassembly mask; enterprise IE mask',
    highPrivacy: 'stejné',
    limitation: 'TCP/SCTP IPFIX framing mimo baseline; variable IE 255+ podporováno',
  },
  sflow: {
    title: 'sFlow v5',
    variant: 'UDP 6343',
    protection: 'structured',
    diagnostic: 'agent IP map; sampled Ethernet header → stejný engine; counter preserve; unknown sample mask',
    highPrivacy: 'stejné',
    limitation: 'zkrácená hlavička ≠ malformed; enterprise sample mask',
  },
  ldap: {
    title: 'LDAP / CLDAP',
    variant: 'TCP/UDP 389; GC 3268',
    protection: 'structured',
    diagnostic: 'DN RDN map; attr dictionary; bind/password mask; SASL NTLMSSP → T16; resultCode preserve',
    highPrivacy: 'stejné (hesla vždy mask)',
    limitation: 'LDAPS/StartTLS → TLS path; neznámé atributy mask; CLDAP Netlogon baseline',
  },
  kerberos: {
    title: 'Kerberos',
    variant: 'UDP/TCP 88; kpasswd 464',
    protection: 'structured',
    diagnostic: 'principal/realm map; EncryptedData cipher vždy mask; etype/kvno/error-code preserve; GeneralizedTime Δ',
    highPrivacy: 'stejné (enc-part vždy mask)',
    limitation: 'anonymizované tickety nejsou použitelné k přihlášení; PA-DATA unknown mask',
  },
  gtp: {
    title: 'GTP (v1/v2-C, GTP-U)',
    variant: 'UDP 2123 / 2152; TS 29.060 / 29.274 / 29.281',
    protection: 'structured',
    diagnostic: 'TEID/F-TEID map; IMSI/IMEI/MSISDN/APN/PAA; PCO PAP/CHAP mask; GTP-U T-PDU → IP/Ethernet child',
    highPrivacy: 'stejné',
    limitation:
      'ULI default mask (T25); PAA Ethernet profil mask-only; unknown IE/ext mask',
  },
  pfcp: {
    title: 'PFCP (Sx/N4)',
    variant: 'UDP 8805; TS 29.244 v18 PFCP v1; node + session messages',
    protection: 'structured',
    diagnostic:
      'SEID/F-SEID opaque map (≠ TEID); endpoint-scoped CP/UP F-SEID + session generation; Node ID/UE IP/F-TEID map; User ID IMSI/IMEI/MSISDN; SDF/PFD/unknown mask; Cause/PDR ID preserve; Recovery Δ',
    highPrivacy: 'stejné (SDF/auth vždy mask)',
    limitation:
      'SDF flow-description grammar → mask (ne regex); enterprise IE value mask; SMF restoration/failover bez explicit relation proof; no UPF control',
  },
  smtp: {
    title: 'SMTP',
    variant: 'TCP 25/587 plaintext',
    protection: 'structured',
    diagnostic: 'MAIL/RCPT email map; EHLO/banner hostname; AUTH/base64 mask; DATA body mask, headers map',
    highPrivacy: 'stejné (hesla/tělo vždy mask)',
    limitation: 'SMTPS/465 → TLS path; BDAT chunk baseline',
  },
  imap: {
    title: 'IMAP',
    variant: 'TCP 143 plaintext',
    protection: 'structured',
    diagnostic: 'LOGIN user map + pass mask; AUTHENTICATE mask; FETCH literals mask',
    highPrivacy: 'stejné',
    limitation: 'IMAPS/993 → TLS; IDLE/COMPRESS mimo baseline',
  },
  pop3: {
    title: 'POP3',
    variant: 'TCP 110 plaintext',
    protection: 'structured',
    diagnostic: 'USER map; PASS/APOP digest mask',
    highPrivacy: 'stejné',
    limitation: 'POP3S/995 → TLS',
  },
  ftp: {
    title: 'FTP',
    variant: 'TCP 21 control',
    protection: 'structured',
    diagnostic: 'USER map; PASS mask; PORT/227/EPRT/EPSV → ftp-data IP/port length-stable; paths mask',
    highPrivacy: 'stejné',
    limitation: 'FTPS AUTH TLS → TLS; data channel obsah vždy mask',
  },
  telnet: {
    title: 'Telnet / rlogin',
    variant: 'TCP 23/513; IAC signature',
    protection: 'structured',
    diagnostic: 'IAC option codes preserve; user data + SB body mask',
    highPrivacy: 'stejné',
    limitation: 'port 514/TCP jen s IAC (ne syslog)',
  },
  smb: {
    title: 'SMB2/3',
    variant: 'TCP 445 / NetBIOS 139',
    protection: 'structured',
    diagnostic: 'SessionId/TreeId/GUID opaque; SESSION_SETUP → NTLMSSP/SPNEGO; TREE_CONNECT UNC map; READ/WRITE mask',
    highPrivacy: 'stejné',
    limitation: 'SMB1 identify+mask; SMB3 encryption transform → encrypted path; DCE/RPC TCP 135 → T42 (named-pipe DCE stále přes SMB data mask)',
  },
  dmr: {
    title: 'DMR (DMRD)',
    variant: 'Homebrew/MMDVM shape',
    protection: 'structured',
    diagnostic: 'map radio/talkgroup 24bit; AMBE netknutý',
    highPrivacy: 'truncate',
  },
  mototrbo: {
    title: 'MOTOTRBO IPSC',
    variant: 'úzký port list',
    protection: 'mask-only',
    diagnostic: 'best-effort bez veřejné specifikace — payload redakce',
    highPrivacy: 'truncate',
    limitation: 'unsupported-mototrbo-nospec',
  },
  'rnd-dispatch-lite': {
    title: 'RND Dispatch Lite',
    variant: 'UDP 49992 (T31 descriptor pilot)',
    protection: 'structured',
    diagnostic: 'map radioId + site opaque-id; GPS/text tělo maska',
    highPrivacy: 'truncate',
    limitation: 'syntetický proprietární dialect — ne vendor wire format',
  },
  rip: {
    title: 'RIP / RIPng',
    variant: 'UDP 520/521',
    protection: 'structured',
    diagnostic: 'RIPv2 auth maska; IPv4 route/next-hop map; RIPng tělo maska',
    highPrivacy: 'truncate',
  },
  bfd: {
    title: 'BFD',
    variant: 'UDP 3784/4784',
    protection: 'structured',
    diagnostic: 'diskriminátory preserve; auth sekce maska',
    highPrivacy: 'truncate',
  },
  hsrp: {
    title: 'HSRP / GLBP',
    variant: 'UDP 1985/3222',
    protection: 'structured',
    diagnostic: 'virtual IP map; auth string/digest maska',
    highPrivacy: 'truncate',
  },
  bgp: {
    title: 'BGP',
    variant: 'TCP 179',
    protection: 'structured',
    diagnostic: 'OPEN ID/ASN map; NEXT_HOP map; unknown attr/NLRI maska; TCP MD5/AO maska',
    highPrivacy: 'truncate',
    limitation: 'plný NLRI/MP_REACH dictionary není v této dodávce',
  },
  ldp: {
    title: 'LDP',
    variant: 'TCP/UDP 646',
    protection: 'structured',
    diagnostic: 'LSR ID map; auth/TLV hodnoty maska',
    highPrivacy: 'truncate',
    limitation: 'FEC/label topology dictionary baseline',
  },
  rdp: {
    title: 'RDP',
    variant: 'TCP/UDP 3389',
    protection: 'structured',
    diagnostic: 'TPKT/X.224 Cookie mstshash → user-id; negotiation preserve; opaque security maska',
    highPrivacy: 'truncate',
    limitation: 'Client Info RC4 bez klíče jen opaque mask; CredSSP/TLS přes T28/TLS path',
  },
  vnc: {
    title: 'VNC / RFB',
    variant: 'TCP 5900–5909',
    protection: 'structured',
    diagnostic: 'version/security preserve; DES challenge/response maska; desktop name map; content maska',
    highPrivacy: 'truncate',
    limitation: 'rectangle encodings dictionary baseline — post-init content fail-closed mask',
  },
  x11: {
    title: 'X11',
    variant: 'TCP 6000–6063',
    protection: 'structured',
    diagnostic: 'MIT-MAGIC-COOKIE auth data maska; post-setup body maska',
    highPrivacy: 'truncate',
    limitation: 'BIG-REQUESTS / extension dictionaries mimo baseline',
  },
  ipmi: {
    title: 'IPMI / RMCP+',
    variant: 'UDP 623',
    protection: 'structured',
    diagnostic: 'ASF preserve; RAKP username map; random/HMAC maska; suite None ≠ encrypted',
    highPrivacy: 'truncate',
    limitation: 'plný command inventory dictionary baseline',
  },
  citrix: {
    title: 'Citrix ICA / CGP',
    variant: 'TCP 1494/2598',
    protection: 'identify-mask',
    diagnostic: 'identify + fail-closed maska celého payloadu',
    highPrivacy: 'truncate',
    limitation: 'bez strukturovaného ICA dictionary',
  },
  amt: {
    title: 'Intel AMT',
    variant: 'TCP 16992–16995',
    protection: 'structured',
    diagnostic: 'HTTP digest Authorization přes HTTP sanitizer',
    highPrivacy: 'truncate',
    limitation: 'SOAP body mimo HTTP header policy → mask dle HTTP handleru',
  },
  gsmtap: {
    title: 'GSMTAP',
    variant: 'UDP 4729',
    protection: 'structured',
    diagnostic: 'header type/ARFCN/signal preserve; payload identify+mask unsupported:gsmtap-<typ>',
    highPrivacy: 'truncate',
    limitation: 'LTE NAS → T59 child; TETRA/unsupported payload → unsupported:gsmtap-<typ>',
  },
  amqp: {
    title: 'AMQP 0-9-1',
    variant: 'TCP 5672',
    protection: 'structured',
    diagnostic: 'frame/channel preserve; SASL Start-Ok mask; content body JSON/mask',
    highPrivacy: 'truncate',
    limitation: 'AMQP 1.0 performatives a plné field tables mimo baseline',
  },
  kafka: {
    title: 'Kafka',
    variant: 'TCP 9092',
    protection: 'structured',
    diagnostic: 'API key/correlation preserve; SASL mask; produce/fetch body mask/JSON',
    highPrivacy: 'truncate',
    limitation: 'flexible tags + batch CRC recompute mimo baseline; komprese → mask',
  },
  nats: {
    title: 'NATS',
    variant: 'TCP 4222',
    protection: 'structured',
    diagnostic: 'CONNECT pass/jwt/token mask; user map; PUB/MSG subject map + payload JSON/mask',
    highPrivacy: 'truncate',
    limitation: 'HMSG header block dictionary baseline',
  },
  stomp: {
    title: 'STOMP',
    variant: 'TCP 61613',
    protection: 'structured',
    diagnostic: 'CONNECT login map / passcode mask; destination map; body JSON/mask',
    highPrivacy: 'truncate',
    limitation: 'escaped header grammar mimo baseline',
  },
  xmpp: {
    title: 'XMPP',
    variant: 'TCP 5222/5269',
    protection: 'structured',
    diagnostic: 'JID user/domain/resource map; SASL/auth mask; message body mask',
    highPrivacy: 'truncate',
    limitation: 'plný namespace-aware XML stream / STARTTLS generation mimo baseline',
  },
  gelf: {
    title: 'GELF',
    variant: 'UDP/TCP 12201',
    protection: 'structured',
    diagnostic: 'nekomprimovaný JSON přes sdílený body path; chunk/zlib/gzip → mask',
    highPrivacy: 'truncate',
    limitation: 'chunk reassembly budget mimo tuto dodávku — fragmenty fail-closed',
  },
  fluent: {
    title: 'Fluent Forward',
    variant: 'TCP 24224',
    protection: 'structured',
    diagnostic: 'MessagePack tag map; time/record fail-closed mask',
    highPrivacy: 'truncate',
    limitation: 'PackedForward/CompressedPackedForward bez inverse → mask',
  },
  otlp: {
    title: 'OTLP',
    variant: 'TCP 4317/4318',
    protection: 'structured',
    diagnostic: 'JSON body path; gRPC protobuf schemaless mask (T36 walker)',
    highPrivacy: 'truncate',
    limitation: 'resource/span attribute schema dictionary baseline — unknown mask',
  },
  postgres: {
    title: 'PostgreSQL',
    variant: 'TCP 5432',
    protection: 'structured',
    diagnostic: 'Startup user/db map; Password/SASL mask; Query SQL literals (T15); DataRow mask',
    highPrivacy: 'truncate / celé SQL mask',
    limitation: 'RowDescription column names fail-closed mask (schema policy later)',
  },
  mysql: {
    title: 'MySQL / MariaDB',
    variant: 'TCP 3306',
    protection: 'structured',
    diagnostic: 'handshake salt/auth mask; user/db map; COM_QUERY SQL literals; rows mask',
    highPrivacy: 'truncate / celé SQL mask',
    limitation: 'continuation packets / compression mimo baseline',
  },
  tds: {
    title: 'TDS / MS SQL',
    variant: 'TCP 1433',
    protection: 'structured',
    diagnostic: 'LOGIN7 UTF-16 Host/User/App/Server/DB map; password mask; SQLBatch literals',
    highPrivacy: 'truncate / celé SQL mask',
    limitation: 'token stream ROW/NBCROW dictionary baseline; SSPI → mask',
  },
  redis: {
    title: 'Redis RESP',
    variant: 'TCP 6379',
    protection: 'structured',
    diagnostic: 'command preserve; AUTH mask; key map (diagnostic) / mask (HP); values mask',
    highPrivacy: 'truncate',
    limitation: 'RESP3 push/pubsub dictionary baseline',
  },
  mongodb: {
    title: 'MongoDB',
    variant: 'TCP 27017',
    protection: 'structured',
    diagnostic: 'OP_MSG header preserve; BSON fail-closed mask; SASL/auth tagged',
    highPrivacy: 'truncate',
    limitation: 'schema-known BSON key preserve mimo baseline; OP_COMPRESSED → mask',
  },
  mqtt: {
    title: 'MQTT',
    variant: 'TCP 1883',
    protection: 'structured',
    diagnostic: 'CONNECT password mask; clientId/user map; topic segment map; payload JSON/mask',
    highPrivacy: 'truncate',
    limitation: 'MQTT 5 property dictionary baseline; 8883 → TLS path',
  },
  coap: {
    title: 'CoAP',
    variant: 'UDP 5683',
    protection: 'structured',
    diagnostic: 'header/code/MID preserve; token map; Uri-* map; payload JSON/mask',
    highPrivacy: 'truncate',
    limitation: 'OSCORE/Observe cross-datagram mimo baseline; Block2 reassembly v capture',
  },
  modbus: {
    title: 'Modbus/TCP',
    variant: 'TCP 502',
    protection: 'structured',
    diagnostic: 'MBAP+FC/address/count/exception preserve; register/coil values mask',
    highPrivacy: 'truncate',
    limitation: 'process values default mask (explicit profile needed to preserve)',
  },
  iec104: {
    title: 'IEC 60870-5-104',
    variant: 'TCP 2404',
    protection: 'structured',
    diagnostic: 'APCI/type/COT preserve; CA/IOA opaque map; process values mask',
    highPrivacy: 'truncate',
    limitation: 'ASDU stride/SQ dictionary baseline; CP56Time timezone ambiguous',
  },
  dnp3: {
    title: 'DNP3',
    variant: 'TCP/UDP 20000',
    protection: 'structured',
    diagnostic: 'link addr map; G/V dictionary walk + values mask; CRC-16 recompute',
    highPrivacy: 'truncate',
    limitation: 'normativní object variations mimo baseline dictionary',
  },
  opcua: {
    title: 'OPC UA',
    variant: 'TCP 4840',
    protection: 'structured',
    diagnostic: 'HEL host map; OPN SecurityMode + cert/nonce mask; MSG Sign/None RequestHeader walk',
    highPrivacy: 'truncate',
    limitation: 'plná UA službová schema / SignAndEncrypt bez OPN stavu',
  },
  dcerpc: {
    title: 'DCE/RPC',
    variant: 'TCP 135 + dynamic',
    protection: 'structured',
    diagnostic:
      'PDU header/UUID preserve; NTLM/SPNEGO auth (T16); NETLOGON/DRSUAPI stub mask; EPM port hints',
    highPrivacy: 'truncate',
    limitation: 'NDR bez IDL → stub mask-only; SAMR/LSA jména až s opnum dictionary',
  },
  iscsi: {
    title: 'iSCSI',
    variant: 'TCP 3260',
    protection: 'structured',
    diagnostic: 'BHS preserve; IQN domain/name map; CHAP_R/C/I mask; Data-In/Out mask',
    highPrivacy: 'truncate',
    limitation: 'CRC32c digest renegotiation / multi-PDU Login mimo baseline',
  },
  portmapper: {
    title: 'Portmapper / rpcbind',
    variant: 'TCP/UDP 111',
    protection: 'structured',
    diagnostic: 'ONC RPC header preserve; GETPORT → flow hint; AUTH_SYS hostname map',
    highPrivacy: 'truncate',
    limitation: 'DUMP list partial mask; RPCSEC_GSS body mask',
  },
  nfs: {
    title: 'NFS',
    variant: 'TCP/UDP 2049',
    protection: 'structured',
    diagnostic: 'ONC RPC + AUTH_SYS; file handle/data mask; LOOKUP names map',
    highPrivacy: 'truncate',
    limitation: 'NFSv4 compound dictionary baseline; attribute time-shift mimo baseline',
  },
  heuristic: {
    title: 'Heuristický scanner',
    variant: 'nerozeznaný payload',
    protection: 'mask-only',
    diagnostic: 'stav vždy heuristic, nikdy covered',
    highPrivacy: 'vypnuto',
  },
  'echo-udp-example': {
    title: 'Echo UDP (onboarding příklad)',
    variant: 'UDP 49991',
    protection: 'structured',
    diagnostic: 'kernel onboarding modul — ne produkční protokol',
    highPrivacy: 'truncate',
    limitation: 'pouze demonstrační handler',
  },
}

/** T40 — wireless linktypes (not in APPLICATION_HANDLER_ORDER). */
const WIRELESS_LINK_ROWS: readonly ProtocolSupportRow[] = [
  {
    id: 'link:radiotap-80211',
    title: 'Radiotap + 802.11',
    layer: 'link',
    variant: 'DLT 127 / 105',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'channel/RSSI preserve; vendor/GPS mask; MAC map; SSID map (ssid kategorie, sdílená s RADIUS Called-Station); WPS/SAE mask; protected body mask',
    highPrivacy: 'Probe Request SSID mask (poloha); truncate',
    limitation: 'PPI jen identify+mask; A-MSDU/A-MPDU dictionary baseline',
  },
  {
    id: 'link:bluetooth',
    title: 'Bluetooth / BLE',
    layer: 'link',
    variant: 'DLT 201 / 251 / 254 / 256',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'BD_ADDR→mac (LE); jméno→hostname; SMP klíče vždy mask; ADV data mask',
    highPrivacy: 'stejné (klíče vždy mask)',
    limitation: 'Linux monitor/LL header variants baseline; RPA resolution bez IRK se neslibuje',
  },
]

/** T38 — IP/LLC routing handlers (not in APPLICATION_HANDLER_ORDER). */
const ROUTING_IP_ROWS: readonly ProtocolSupportRow[] = [
  {
    id: 'ip:ospf',
    title: 'OSPFv2/v3',
    layer: 'network',
    variant: 'IP proto 89',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'Router/Area ID map; auth type 1/2 maska; IPv4 prefix↔host /24 (T38.prefix); LSA tělo baseline maska',
    highPrivacy: 'truncate',
    limitation: 'plný LSA dictionary a Fletcher checksum oracle až v dalších dodávkách',
  },
  {
    id: 'ip:eigrp',
    title: 'EIGRP',
    layer: 'network',
    variant: 'IP proto 88',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'AS/router ID map; auth TLV maska; route TLV hodnoty maska',
    highPrivacy: 'truncate',
  },
  {
    id: 'ip:pim',
    title: 'PIM',
    layer: 'network',
    variant: 'IP proto 103',
    protection: 'mask-only',
    identification: true,
    structured: false,
    provenCiphertext: false,
    diagnostic: 'header covered; tělo maska (Register/Join dictionary baseline)',
    highPrivacy: 'truncate',
  },
  {
    id: 'ip:igmp',
    title: 'IGMP',
    layer: 'network',
    variant: 'IP proto 2',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'group/source map; well-known 224.0.0.x preserve',
    highPrivacy: 'truncate',
  },
  {
    id: 'llc:isis',
    title: 'IS-IS',
    layer: 'link',
    variant: 'LLC DSAP/SSAP 0xFE',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'System ID opaque map; hostname TLV map; auth TLV maska',
    highPrivacy: 'truncate',
    limitation: 'LSP Fletcher checksum oracle není v této dodávce',
  },
]

/** L2 ethertype handlers (not in APPLICATION_HANDLER_ORDER — wired in engine decodeLink). */
const LINK_LAYER_ROWS: readonly ProtocolSupportRow[] = [
  {
    id: 'link:lldp',
    title: 'LLDP / LLDP-MED',
    layer: 'link',
    variant: 'EtherType 0x88CC',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'chassis/port/system name map; MED inventory opaque-id; location vždy mask',
    highPrivacy: 'description mask; location vždy mask',
    limitation: 'EAP-TLS fragment reassembly baseline — TLS body mask',
  },
  {
    id: 'link:lacp',
    title: 'LACP',
    layer: 'link',
    variant: 'EtherType 0x8809 subtype 0x01',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'Actor/Partner System MAC map; key/port/priority/state preserve',
    highPrivacy: 'stejné',
    limitation: 'Marker/unknown slow subtype → mask',
  },
  {
    id: 'link:eapol',
    title: 'EAPOL / 802.1X',
    layer: 'link',
    variant: 'EtherType 0x888E',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'EAP Identity map; MD5/MSCHAP/Key nonce·MIC·GTK mask',
    highPrivacy: 'stejné (auth material vždy mask)',
    limitation: 'EAP-TLS/PEAP/TTLS tělo mask bez plné TLS reassembly',
  },
  {
    id: 'link:null-loop',
    title: 'NULL / LOOP (loopback)',
    layer: 'link',
    variant: 'DLT_NULL=0 / DLT_LOOP=108',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'AF preserve; IPv4/IPv6 continue; unknown AF payload mask',
    highPrivacy: 'stejné',
    limitation: 'jen doložené AF (INET/INET6) + IP version nibble',
  },
  {
    id: 'link:ppp-pppoe',
    title: 'PPP / PPPoE',
    layer: 'link',
    variant: 'DLT 9/50/104; EtherType 0x8863/0x8864',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'session/peer map; PAP/CHAP password·challenge mask; IPCP IP map; LCP magic preserve',
    highPrivacy: 'stejné (hesla vždy mask)',
    limitation: 'CCP/compressed PPP není plaintext; EAP přes T19',
  },
  {
    id: 'link:mpls',
    title: 'MPLS',
    layer: 'link',
    variant: 'EtherType 0x8847/0x8848',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'label stack → map; TC/TTL/S preserve; inner IP dle nibblu',
    highPrivacy: 'stejné',
    limitation: 'pseudowire/control-word jen při doloženém profilu; jinak mask',
  },
  {
    id: 'link:geneve-l2tp',
    title: 'Geneve / L2TP',
    layer: 'link',
    variant: 'UDP 6081 / 1701',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'Geneve VNI map + options mask + eth recurse; L2TP tunnel/session map; Challenge/Hidden AVP mask; data→PPP',
    highPrivacy: 'stejné',
    limitation: 'L2TPv3/cookie profil baseline; Geneve critical options mask',
  },
  {
    id: 'link:erspan-macsec-pbb-nflog',
    title: 'ERSPAN / MACsec / PBB / NFLOG',
    layer: 'link',
    variant: 'GRE 0x88BE/0x22EB; 0x88E5; 0x88E7; DLT 239',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'ERSPAN session map + mirrored eth; MACsec SCI MAC map; PBB I-SID preserve + C-MAC map; NFLOG TLV prefix/uid/hwaddr',
    highPrivacy: 'stejné',
    limitation: 'MACsec ciphertext jen integrity-only; NFLOG family→IP; VXLAN-GPE/NSH mimo tuto baseline',
  },
]

/** T25 — SCTP PPID dispatch (not a separate APPLICATION_HANDLER_ORDER TCP/UDP probe). */
const SIGTRAN_ROWS: readonly ProtocolSupportRow[] = [
  {
    id: 'app:m3ua',
    title: 'M3UA / SIGTRAN SS7',
    layer: 'application',
    variant: 'SCTP PPID 3 / port 2905; RFC 4666 + SCCP/ISUP/TCAP-MAP',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic:
      'OPC/DPC → point-code; SCCP GT E.164→sip-phone / E.214→opaque-id; ISUP numbers→sip-phone; MAP IMSI/IMEI/MSISDN map; auth/SMS UD/USSD/location mask',
    highPrivacy: 'stejné (auth/SMS/USSD vždy mask)',
    limitation:
      'M2UA/SUA identify+mask; multi-segment XUDT/LUDT → requires-reassembly (single XUDT OK); plný MAP 29.002 opcode slovník baseline',
  },
  {
    id: 'app:s1ap',
    title: 'S1AP (LTE)',
    layer: 'application',
    variant: 'SCTP PPID 18; TS 36.413 v18 APER via T56; NAS → T59',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic:
      'procedure/criticality/Cause preserve; MME/eNB-UE-S1AP-ID scoped opaque map; NAS-PDU → T59; E-RAB TEID/TLA → T26; SecurityKey/TAI/unknown IE mask',
    highPrivacy: 'stejné (SecurityKey/location vždy mask)',
    limitation:
      'Pinned IE inventory (~19 IEs / 12 procedures, s1apSchemaInventory.ts); ne generované TS36.413 object sets (R09); transparent RRC/handover mask; E-RAB/QoS zjednodušené tvary',
  },
  {
    id: 'app:ngap',
    title: 'NGAP (5G)',
    layer: 'application',
    variant: 'SCTP PPID 60; TS 38.413 v18 APER via T56; NAS → T59; typed N2 for T61',
    protection: 'structured',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic:
      'procedure/Cause preserve; AMF/RAN-UE-NGAP-ID scoped opaque; NAS-PDU → T59; NG-U TEID/TLA → T26; SecurityKey/location/unknown mask; N2 transfer by schemaTypeId',
    highPrivacy: 'stejné (SecurityKey/location vždy mask)',
    limitation:
      'Pinned IE inventory (~17 IEs / 11 procedures + 3 N2 transfers, ngapSchemaInventory.ts); ne full TS38.413; GUAMI/UserLocation pinned tvary; RRC/transparent mask',
  },
]

const CONTAINER_ROWS: readonly ProtocolSupportRow[] = [
  {
    id: 'container:pcap',
    title: 'Classic PCAP 2.4',
    layer: 'container',
    variant: 'LE/BE, µs/ns',
    protection: 'container',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'plná podpora',
    highPrivacy: 'plná podpora',
  },
  {
    id: 'container:pcapng',
    title: 'PCAPNG 1.0',
    layer: 'container',
    variant: 'SHB/IDB/EPB/SPB/obsolete PB, multi-section',
    protection: 'container',
    identification: true,
    structured: true,
    provenCiphertext: false,
    diagnostic: 'NRB/DSB/ISB/comments: detekce + safe drop',
    highPrivacy: 'stejné',
  },
]

function protectionFlags(p: SupportProtection): {
  identification: boolean
  structured: boolean
  provenCiphertext: boolean
} {
  switch (p) {
    case 'structured':
      return { identification: true, structured: true, provenCiphertext: false }
    case 'encrypted-phase':
      return { identification: true, structured: true, provenCiphertext: true }
    case 'container':
      return { identification: true, structured: true, provenCiphertext: false }
    case 'decode-map':
      return { identification: true, structured: true, provenCiphertext: false }
    case 'mask-only':
      return { identification: true, structured: false, provenCiphertext: false }
    case 'identify-mask':
      return { identification: true, structured: false, provenCiphertext: false }
  }
}

function protectionLabel(p: SupportProtection): string {
  switch (p) {
    case 'structured':
      return 'strukturovaná ochrana'
    case 'encrypted-phase':
      return 'strukturovaná + doložený ciphertext'
    case 'container':
      return 'kontejner'
    case 'decode-map':
      return 'decode + mapování'
    case 'mask-only':
      return 'mask-only'
    case 'identify-mask':
      return 'identify → mask (fail-closed)'
  }
}

/** All matrix rows for docs, drift tests, and in-app panel. */
export function buildProtocolSupportMatrix(): readonly ProtocolSupportRow[] {
  const rows: ProtocolSupportRow[] = [
    ...CONTAINER_ROWS,
    ...LINK_LAYER_ROWS,
    ...WIRELESS_LINK_ROWS,
    ...ROUTING_IP_ROWS,
    ...SIGTRAN_ROWS,
  ]

  for (const p of listCatalogProtocols()) {
    rows.push({
      id: `catalog:${p.id}`,
      title: p.title,
      layer: p.layer,
      variant: formatSelectors(p.selectors),
      protection: 'decode-map',
      ...protectionFlags('decode-map'),
      diagnostic: 'decode + mapování / checksum dle vrstvy',
      highPrivacy: 'stejné mapování; neznámé → unsupported-*',
    })
  }

  for (const h of APPLICATION_HANDLER_ORDER) {
    const note = HANDLER_NOTES[h.id]
    if (!note) continue
    const effective = resolveEffectiveAppHandlerFlags(h.id, note)
    rows.push({
      id: `app:${h.id}`,
      title: note.title,
      layer: 'application',
      variant: note.variant,
      protection: effective.protection,
      identification: effective.identification,
      structured: effective.structured,
      provenCiphertext: effective.provenCiphertext,
      diagnostic: note.diagnostic,
      highPrivacy: note.highPrivacy,
      limitation: effective.limitation ?? note.limitation,
    })
  }

  for (const name of UNSUPPORTED_PROTOCOL_NAMES) {
    // UDP MGCP is structured (app:mgcp); TCP remains identify-only — keep catalog row for name.
    const variant =
      name === 'mgcp' ? 'TCP (UDP má strukturovaný handler T11)' : 'port + signatura (T09)'
    rows.push({
      id: `unsupported:${name}`,
      title: name.toUpperCase(),
      layer: 'application',
      variant,
      protection: 'identify-mask',
      ...protectionFlags('identify-mask'),
      diagnostic: `coverage id unsupported:${name}; fail-closed mask/truncate`,
      highPrivacy: 'truncate / drop dle úrovně',
      limitation: 'bez strukturované analýzy — žádejte podporu kódem z panelu Výsledek',
    })
  }

  return rows
}

function formatSelectors(selectors: readonly DispatchSelector[]): string {
  if (selectors.length === 0) return '—'
  return selectors.map((s) => `${s.kind}=${String(s.value)}`).join(', ')
}

const MARKER_START = '<!-- protocol-matrix:start -->'
const MARKER_END = '<!-- protocol-matrix:end -->'

export function protocolMatrixMarkers(): { start: string; end: string } {
  return { start: MARKER_START, end: MARKER_END }
}

/** Markdown table body (without surrounding markers) for docs injection. */
export function renderProtocolSupportMatrixMarkdown(
  rows: readonly ProtocolSupportRow[] = buildProtocolSupportMatrix(),
): string {
  const lines: string[] = [
    '',
    '> Generováno z `src/pcap/docs/protocolSupportMatrix.ts` (`npm run docs:protocol-matrix`).',
    '> Řádek = capability varianta; bez conformance důkazu není „plná podpora“.',
    '',
    '| Id | Protokol | Vrstva | Varianta | Ochrana | Diagnostic | Vysoké soukromí | Omezení |',
    '|---|---|---|---|---|---|---|---|',
  ]
  for (const r of rows) {
    lines.push(
      `| \`${r.id}\` | ${escapeCell(r.title)} | ${escapeCell(r.layer)} | ${escapeCell(r.variant)} | ${escapeCell(protectionLabel(r.protection))} | ${escapeCell(r.diagnostic)} | ${escapeCell(r.highPrivacy)} | ${escapeCell(r.limitation ?? '—')} |`,
    )
  }
  lines.push('')
  return lines.join('\n')
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\n/g, ' ')
}

/**
 * Replace content between markers. Returns null when markers missing.
 */
export function injectProtocolMatrixMarkdown(doc: string, matrixMarkdown: string): string | null {
  const start = doc.indexOf(MARKER_START)
  const end = doc.indexOf(MARKER_END)
  if (start < 0 || end < 0 || end < start) return null
  const before = doc.slice(0, start + MARKER_START.length)
  const after = doc.slice(end)
  return `${before}\n${matrixMarkdown}${after}`
}

/** T32 — clipboard payload for support request (no file bytes / originals). */
export interface SupportRequestItem {
  readonly code: string
  readonly family: string
  readonly packetCount: number
  readonly flowCount: number
}

export function buildSupportRequestClipboard(items: readonly SupportRequestItem[]): string {
  const lines = [
    'Žádost o podporu protokolu (rnd-log-anonymizer)',
    'Bez souboru a bez obsahu paketů — jen kódy a počty.',
    '',
  ]
  for (const it of items) {
    const flows =
      it.flowCount > 0 ? `${it.packetCount} paketů, ${it.flowCount} toků` : `${it.packetCount} paketů`
    lines.push(`- kód: ${it.code}`)
    lines.push(`  rodina: ${it.family}`)
    lines.push(`  rozsah: ${flows}`)
  }
  return lines.join('\n')
}

export function supportRequestUserMessage(item: SupportRequestItem): string {
  const flows =
    item.flowCount > 0
      ? `${item.packetCount} paketů, ${item.flowCount} toků`
      : `${item.packetCount} paketů`
  return `Protokol ${item.code} (${flows}) byl kvůli ochraně dat zamaskován. Pokud ho potřebujete analyzovat, pošlete týmu kód \`${item.code}\` a počty — bez souboru.`
}
