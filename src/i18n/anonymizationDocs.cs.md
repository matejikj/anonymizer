<div class="cover">

# rnd-log-anonymizer
## Anonymizace síťových zachytů (PCAP) a logů — shrnutí řešení

</div>

**Co to je.** Webová aplikace (běží čistě v prohlížeči, žádný server, žádné citlivé
hodnoty se nikam neodesílají ani neukládají), která z PCAP zachytů a textových logů
před jejich dalším použitím odstraní reálné identifikátory — IP a MAC adresy, telefonní
čísla, SIP identity, hostname, VLAN, porty a další — a nahradí je jinými, ale
strukturálně platnými hodnotami. Výsledný soubor zůstává plně čitelný ve Wiresharku
i analyzovatelný běžnými nástroji nebo AI asistentem, ale neobsahuje skutečná data
zákazníků ani naší infrastruktury.

**Proč to řešíme.** Potřebujeme sdílet reálné diagnostické zachyty — s AI nástroji,
externími dodavateli, support týmy — abychom problémy řešili rychleji. Bez anonymizace
to znamená vystavit síťovou topologii, telefonní čísla, SIP účty a další citlivé údaje
třetím stranám. Nástroj tenhle kompromis řeší: zachyt zůstává diagnosticky použitelný,
ale bez reálných identit.

**Jak to funguje ve zkratce.**

- **Konzistentní náhrada.** Stejná původní hodnota dostane vždy stejnou náhradu v rámci
  jedné relace — takže zůstává vidět, že dva pakety patří stejnému zařízení/hovoru,
  i celý komunikační graf, jen bez reálných identit. Funguje to i napříč více soubory
  nahranými do jedné relace najednou (log + log + pcap dohromady).
- **Dvě úrovně.** *Diagnostická* (výchozí) zachovává maximum diagnostické hodnoty —
  časování, velikosti paketů, TTL, hlavičky, a snaží se držet rozpoznatelné vztahy mezi
  adresami v pevném `/16`. *Vysoké soukromí* jde dál — **zahazuje** hlasová média
  (RTP/RTCP), normalizuje otisk OS, ničí přesné časování i topologii adres; nepodporovaný
  payload **ořízne**, nepřepisuje.
- **Výsledek anonymizace.** Po analýze panel se třemi AI stavy (`AI_READY` /
  `AI_READY_WITH_GAPS` / `NOT_AI_READY`), rodinami protokolů a doporučením — stejná
  struktura jde do reportu a `ai-diagnostics.json`.
- **Odolnost.** Chyba v jednom poli/paketu/řádku neshodí celý soubor (fail-closed maska
  + incident bez originálních hodnot). Vstup `.gz` se rozbalí v prohlížeči (limit na
  rozbalenou velikost); zip/xz/… se odmítnou srozumitelnou hláškou. Textové logy: detekce
  kódování (UTF-8 / Windows-1250 / UTF-16) a před detektory maska tajných klíčů ve
  strukturovaných formátech (JSON/NDJSON, CSV/TSV, CEF/LEEF, logfmt, HAR, access log, tshark JSON).
- **Volitelná zpětná obnova.** Při exportu lze vygenerovat samostatný *obnovovací soubor*
  (plaintext recovery v4, nikdy se nesdílí s AI). Mapping bundle je nešifrovaný JSON —
  SHA-256/CRC není autentizace ani utajení.
- **AI-diagnostický sidecar.** `ai-diagnostics.json` nese anonymizované statistiky a
  `anonymizationOutcome` (vč. rozsahů zamaskovaných paketů), nikdy originály.

**Co je strukturovaně podporované (fáze 1 + T38 baseline).** Ethernet/IP/TCP/UDP/ICMP(+vložené),
ARP, DNS/mDNS, DHCPv4/v6, TLS (SNI/cert), SIP/SDP (vč. multipart/SIPREC), MGCP (UDP),
STUN/TURN, RTP/RTCP, HTTP/1.x hlavičky, VRRP, STP/RSTP/MSTP, CDP, DMR,
MOTOTRBO (mask-only bez veřejné specifikace), RND Dispatch Lite (T31 descriptor
pilot), směrování/first-hop T38 (OSPF/EIGRP/PIM/IGMP, RIP/BFD/HSRP/GLBP, BGP, IS-IS,
LDP; TCP MD5/AO maska; auth vždy mask; LSA/NLRI dictionary baseline), vzdálený přístup
T39 (RDP cookie→user; VNC auth/obrazovka/schránka mask; X11 MIT cookie; IPMI RAKP;
Citrix identify+mask; AMT HTTP digest), bezdrát T40 (radiotap/802.11 SSID+WPS; Bluetooth
SMP; GSMTAP identify+mask), messaging/telemetry T41 (AMQP/Kafka/NATS/STOMP/XMPP SASL
mask; GELF/Fluent/OTLP JSON nebo fail-closed mask), databáze T29 (PostgreSQL/MySQL/TDS
SQL literály + auth mask; Redis AUTH; MongoDB BSON fail-closed), průmysl/IoT T30
(MQTT password; Modbus/IEC104/DNP3 process values mask; DNP3 CRC recompute; OPC UA HEL),
Windows RPC/úložiště T42 (DCE/RPC NETLOGON/DRSUAPI stub mask + EPM port hints; iSCSI
CHAP/IQN; NFS AUTH_SYS + file data mask; portmapper GETPORT), CSTA/uaCSTA T49
(Annex J XML device/call map; UserData/DTMF mask; SIP `csta+xml`; ASN.1 ROSE mask-only),
Asterisk AMI/ARI T50 (AMI TCP 5038 Login/channel map; ARI HTTP `/ari/*` api_key + JSON overlay),
ISDN LAPD/Q.931/IUA T51 (LINKTYPE 177 + SCTP PPID 1; numbers map; Facility mask),
SMPP T52 (TCP 2775 bind/submit; SMS body always mask; message_id scoped map),
emergency SIP Geolocation/PIDF-LO/LoST T53 (cid map; coordinates always mask; sos URN preserve),
MRCPv2 T54 (TCP `MRCP/2.0`/3242; Channel-Identifier map; transcript/grammar/voiceprint/URI always mask),
CWMP/USP T55 (SOAP/HTTP TR-069 + USP Record plaintext; credentials/endpoints protected; no ACS fetch),
APER toolkit T56 (schema-driven BitCursor + bit PatchCompiler; toy modules + S1AP/NGAP schemas),
S1AP LTE T57 (SCTP PPID 18; UE S1AP IDs map; NAS→T59; E-RAB TEID/TLA; SecurityKey mask),
NGAP 5G T58 (SCTP PPID 60; AMF/RAN UE NGAP IDs map; NAS→T59; NG-U TEID/TLA; typed N2 for T61),
NAS EPS/5GS T59 (IMSI/IMEI map; auth/location mask; ciphered opaque; GSMTAP LTE-NAS child),
PFCP Sx/N4 T60 (SEID opaque ≠ TEID; Node/UE IP/F-TEID map; SDF/PFD mask; GTP-U TEID shoda),
5G SBI T61 (HTTP/JSON REL-18 pin; SUPI/NF map; token/auth/location mask; multipart N1→T59 N2→T58).
Ostatní aplikační payload: v diagnostické úrovni od bločícího
spanu **zamaskován** deterministickým `maskFill` (FNV+xorshift, ne CSPRNG, nikdy originál);
ve vysokém soukromí **oříznut**. Identifikované nepodporované protokoly mají jméno
`unsupported:<název>` a fail-closed dispozici — ne tiché zelené „covered“.
(SSDP a H.248 mají strukturovanou podporu — viz matice níže; nepatří mezi „unsupported“.)

### Matice podpory protokolů (generovaná)

<!-- protocol-matrix:start -->

> Generováno z `src/pcap/docs/protocolSupportMatrix.ts` (`npm run docs:protocol-matrix`).
> Řádek = capability varianta; bez conformance důkazu není „plná podpora“.

| Id | Protokol | Vrstva | Varianta | Ochrana | Diagnostic | Vysoké soukromí | Omezení |
|---|---|---|---|---|---|---|---|
| `container:pcap` | Classic PCAP 2.4 | container | LE/BE, µs/ns | kontejner | plná podpora | plná podpora | — |
| `container:pcapng` | PCAPNG 1.0 | container | SHB/IDB/EPB/SPB/obsolete PB, multi-section | kontejner | NRB/DSB/ISB/comments: detekce + safe drop | stejné | — |
| `link:lldp` | LLDP / LLDP-MED | link | EtherType 0x88CC | strukturovaná ochrana | chassis/port/system name map; MED inventory opaque-id; location vždy mask | description mask; location vždy mask | EAP-TLS fragment reassembly baseline — TLS body mask |
| `link:lacp` | LACP | link | EtherType 0x8809 subtype 0x01 | strukturovaná ochrana | Actor/Partner System MAC map; key/port/priority/state preserve | stejné | Marker/unknown slow subtype → mask |
| `link:eapol` | EAPOL / 802.1X | link | EtherType 0x888E | strukturovaná ochrana | EAP Identity map; MD5/MSCHAP/Key nonce·MIC·GTK mask | stejné (auth material vždy mask) | EAP-TLS/PEAP/TTLS tělo mask bez plné TLS reassembly |
| `link:null-loop` | NULL / LOOP (loopback) | link | DLT_NULL=0 / DLT_LOOP=108 | strukturovaná ochrana | AF preserve; IPv4/IPv6 continue; unknown AF payload mask | stejné | jen doložené AF (INET/INET6) + IP version nibble |
| `link:ppp-pppoe` | PPP / PPPoE | link | DLT 9/50/104; EtherType 0x8863/0x8864 | strukturovaná ochrana | session/peer map; PAP/CHAP password·challenge mask; IPCP IP map; LCP magic preserve | stejné (hesla vždy mask) | CCP/compressed PPP není plaintext; EAP přes T19 |
| `link:mpls` | MPLS | link | EtherType 0x8847/0x8848 | strukturovaná ochrana | label stack → map; TC/TTL/S preserve; inner IP dle nibblu | stejné | pseudowire/control-word jen při doloženém profilu; jinak mask |
| `link:geneve-l2tp` | Geneve / L2TP | link | UDP 6081 / 1701 | strukturovaná ochrana | Geneve VNI map + options mask + eth recurse; L2TP tunnel/session map; Challenge/Hidden AVP mask; data→PPP | stejné | L2TPv3/cookie profil baseline; Geneve critical options mask |
| `link:erspan-macsec-pbb-nflog` | ERSPAN / MACsec / PBB / NFLOG | link | GRE 0x88BE/0x22EB; 0x88E5; 0x88E7; DLT 239 | strukturovaná ochrana | ERSPAN session map + mirrored eth; MACsec SCI MAC map; PBB I-SID preserve + C-MAC map; NFLOG TLV prefix/uid/hwaddr | stejné | MACsec ciphertext jen integrity-only; NFLOG family→IP; VXLAN-GPE/NSH mimo tuto baseline |
| `link:radiotap-80211` | Radiotap + 802.11 | link | DLT 127 / 105 | strukturovaná ochrana | channel/RSSI preserve; vendor/GPS mask; MAC map; SSID map (ssid kategorie, sdílená s RADIUS Called-Station); WPS/SAE mask; protected body mask | Probe Request SSID mask (poloha); truncate | PPI jen identify+mask; A-MSDU/A-MPDU dictionary baseline |
| `link:bluetooth` | Bluetooth / BLE | link | DLT 201 / 251 / 254 / 256 | strukturovaná ochrana | BD_ADDR→mac (LE); jméno→hostname; SMP klíče vždy mask; ADV data mask | stejné (klíče vždy mask) | Linux monitor/LL header variants baseline; RPA resolution bez IRK se neslibuje |
| `ip:ospf` | OSPFv2/v3 | network | IP proto 89 | strukturovaná ochrana | Router/Area ID map; auth type 1/2 maska; IPv4 prefix↔host /24 (T38.prefix); LSA tělo baseline maska | truncate | plný LSA dictionary a Fletcher checksum oracle až v dalších dodávkách |
| `ip:eigrp` | EIGRP | network | IP proto 88 | strukturovaná ochrana | AS/router ID map; auth TLV maska; route TLV hodnoty maska | truncate | — |
| `ip:pim` | PIM | network | IP proto 103 | mask-only | header covered; tělo maska (Register/Join dictionary baseline) | truncate | — |
| `ip:igmp` | IGMP | network | IP proto 2 | strukturovaná ochrana | group/source map; well-known 224.0.0.x preserve | truncate | — |
| `llc:isis` | IS-IS | link | LLC DSAP/SSAP 0xFE | strukturovaná ochrana | System ID opaque map; hostname TLV map; auth TLV maska | truncate | LSP Fletcher checksum oracle není v této dodávce |
| `app:m3ua` | M3UA / SIGTRAN SS7 | application | SCTP PPID 3 / port 2905; RFC 4666 + SCCP/ISUP/TCAP-MAP | strukturovaná ochrana | OPC/DPC → point-code; SCCP GT E.164→sip-phone / E.214→opaque-id; ISUP numbers→sip-phone; MAP IMSI/IMEI/MSISDN map; auth/SMS UD/USSD/location mask | stejné (auth/SMS/USSD vždy mask) | M2UA/SUA identify+mask; multi-segment XUDT/LUDT → requires-reassembly (single XUDT OK); plný MAP 29.002 opcode slovník baseline |
| `app:s1ap` | S1AP (LTE) | application | SCTP PPID 18; TS 36.413 v18 APER via T56; NAS → T59 | strukturovaná ochrana | procedure/criticality/Cause preserve; MME/eNB-UE-S1AP-ID scoped opaque map; NAS-PDU → T59; E-RAB TEID/TLA → T26; SecurityKey/TAI/unknown IE mask | stejné (SecurityKey/location vždy mask) | Pinned IE inventory (~19 IEs / 12 procedures, s1apSchemaInventory.ts); ne generované TS36.413 object sets (R09); transparent RRC/handover mask; E-RAB/QoS zjednodušené tvary |
| `app:ngap` | NGAP (5G) | application | SCTP PPID 60; TS 38.413 v18 APER via T56; NAS → T59; typed N2 for T61 | strukturovaná ochrana | procedure/Cause preserve; AMF/RAN-UE-NGAP-ID scoped opaque; NAS-PDU → T59; NG-U TEID/TLA → T26; SecurityKey/location/unknown mask; N2 transfer by schemaTypeId | stejné (SecurityKey/location vždy mask) | Pinned IE inventory (~17 IEs / 11 procedures + 3 N2 transfers, ngapSchemaInventory.ts); ne full TS38.413; GUAMI/UserLocation pinned tvary; RRC/transparent mask |
| `catalog:null` | NULL (BSD/macOS loopback) | link | linktype=0 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:loop` | LOOP (OpenBSD) | link | linktype=108 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:ethernet` | Ethernet | link | linktype=1 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:sll` | Linux SLL | link | linktype=113 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:sll2` | Linux SLL2 | link | linktype=276 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:raw-ipv4` | Raw IPv4 | link | linktype=228 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:raw-ipv6` | Raw IPv6 | link | linktype=229 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:arp` | ARP | network | ethertype=2054 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:ipv4` | IPv4 | network | ethertype=2048 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:ipv6` | IPv6 | network | ethertype=34525 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:ipip-ipv4` | IP-in-IP | tunnel | ip-protocol=4 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:ipip-ipv6` | IPv6-in-IP | tunnel | ip-protocol=41 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:gre` | GRE | tunnel | ip-protocol=47 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:vxlan` | VXLAN | tunnel | udp-port=4789 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:tcp` | TCP | transport | ip-protocol=6 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:udp` | UDP | transport | ip-protocol=17 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:sctp` | SCTP | transport | ip-protocol=132 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:icmpv4` | ICMPv4 | transport | ip-protocol=1 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `catalog:icmpv6` | ICMPv6 | transport | ip-protocol=58 | decode + mapování | decode + mapování / checksum dle vrstvy | stejné mapování; neznámé → unsupported-* | — |
| `app:dns` | DNS / mDNS | application | UDP/TCP 53, mDNS 5353 | strukturovaná ochrana | length-preserving map jmen a A/AAAA | truncate / fail-closed | T-01.B: journal map/mask/fingerprint ops; common traffic bez legacyResolve; custom TXT entity / SDP session-version deferrals bez meta stále legacyResolve |
| `app:dhcpv4` | DHCPv4 | application | UDP 67/68 | strukturovaná ochrana | map identifikátorů | truncate | — |
| `app:dhcpv6` | DHCPv6 | application | UDP 546/547 | strukturovaná ochrana | map identifikátorů | truncate | — |
| `app:tls` | TLS | application | TCP record; Hello / cert / AppData | strukturovaná + doložený ciphertext | SNI map; Hello random/session_id/unknown ext mask (T47); cert CN/SAN; AppData po SH → encrypted | truncate handshake; encrypted AppData ponecháno jen s doloženou fází | DTLS není TLS record parser — viz T28 zbytek / T36 |
| `app:ssh` | SSH | application | TCP; banner + binary packets | mask-only | banner fingerprint; KEXINIT preserve; host-key/signature mask; post-NEWKEYS bez důkazu → opaque mask | software string mask; stejná host-key politika | encrypted-preserved jen s per-direction NEWKEYS + doloženou confidentiality (zatím ne) |
| `app:quic` | QUIC | application | UDP long header v1/v2 | mask-only | CID → opaque-id; Initial protected payload vždy mask (public derivation); short header bez kontextu mask | stejné | Initial není encrypted-preserved; re-encrypt spike mimo baseline |
| `app:dtls` | DTLS | application | UDP record framing (1.0/1.2); content probe | mask-only | record header (13 B) covered; handshake přes normativní 12 B DTLS fragment hlavičku; single-fragment ClientHello → SNI map; multi-fragment / cross-UDP flight → requires-reassembly + mask | stejné | cross-UDP datagram flight reassembly nepodporováno; legacy TLS 4 B handshake v DTLS záznamu jen heuristic; app data bez doložené confidentiality → mask |
| `app:ike` | IKE / ISAKMP | application | UDP 500/4500 | strukturovaná + doložený ciphertext | SPI preserve; ID/CERT/AUTH/HASH/KE/Nonce/NAT_DETECTION mask; SK → encrypted (IKEv2) | stejné | ESP bez SA profilu zůstává mask-only (NULL encryption) |
| `app:openvpn` | OpenVPN | application | UDP/TCP 1194; content probe jen hard-reset (kolize NTP/GTP) | mask-only | session-id → opaque-id; control TLS child když čitelný; data/control payload bez doložené AEAD → mask (R02) | stejné | TCP length framing + partial frame → requires-reassembly; data není encrypted-preserved; mimo 1194 jen hard-reset probe |
| `app:wireguard` | WireGuard | application | UDP type/size/reserved classify | strukturovaná + doložený ciphertext | handshake pubkey/MAC mask; transport AEAD → encrypted po pozitivní klasifikaci | stejné | náhodný UDP stejné délky ≠ WireGuard |
| `app:sip` | SIP / SDP | application | UDP/TCP 5060/5061 + content probe; MCPTT/DTMF/dialog-info bodies (T37) | strukturovaná ochrana | URI/host/Call-ID/UA; SDP c=/o=/m=/ICE; multipart/SIPREC; MCPTT URI map + location mask; DTMF Signal mask; uaCSTA csta+xml (T49); Geolocation cid map + PIDF-LO/LoST (T53) | truncate dle úrovně | SIP-I MIME ISUP body → fail-closed mask (SS7 ISUP přes M3UA → app:m3ua); sipfrag partial → mask |
| `app:csta` | CSTA / uaCSTA | application | ECMA-323 XML Annex J; SIP application/csta+xml | strukturovaná ochrana | Annex J length preserve; device/call/monitor IDs map (scoped); MonitorStart/Stop lifecycle graph (XML); invokeID scoped per capture generation; UserData/DTMF/Location mask; uaCSTA via SIP body T02 | truncate | ASN.1 ROSE/ACSE Phase III → mask-only (no structured decode); schema compiler / full ECMA-269 catalog mimo baseline; XXE reject |
| `app:ami` | Asterisk AMI | application | TCP 5038 AMI v2 key:value; banner Asterisk Call Manager/ | strukturovaná ochrana | Action/Event/Response preserve; CallerID/Channel/Uniqueid/Linkedid/Bridge/ActionID scoped map; Variable after= mask | stejné (Login Secret/Challenge vždy mask) | multiline CLI Command output → line mask; AMI v1/AJAM mimo baseline; unknown keys fail-closed mask |
| `app:mgcp` | MGCP | application | UDP 2427/2727 (RFC 3435) | strukturovaná ochrana | verb/txid/QoS preserve; endpoint/C:/I:/X:/caller map; DTMF/DigitMap mask; nested SDP | truncate | TCP MGCP zůstává identify-only (unsupported:mgcp) |
| `app:h248` | H.248 / MEGACO | application | UDP/TCP 2944/2945 text MEGACO/1 | strukturovaná ochrana | MID IP/host map; ds= digit mask; Local/Remote SDP → media flows | stejné (digit/auth vždy mask) | binary ASN.1 BER → identify+mask; SCTP varianta po T17 claim |
| `app:rtsp` | RTSP | application | TCP 554/8554; interleaved $ | strukturovaná ochrana | URI/host map; Session opaque; Transport ports; Auth mask; SDP body + media | stejné | interleaved channel ≠ RTP proof → payload mask; HTTP tunnel mimo baseline |
| `app:iax2` | IAX2 | application | UDP 4569 full/mini frames | strukturovaná ochrana | IE phones/names/user map; PASSWORD/MD5/RSA/CHALLENGE mask; mini voice mask | stejné | mini bez full context → media mask-only |
| `app:skinny` | SCCP / Skinny | application | TCP 2000 | strukturovaná ochrana | Register SEP MAC + IP; CallInfo phone/name; keypad mask; media IP/port | stejné | unknown message ID → body mask; TLS 2443 → TLS path |
| `app:h323` | H.323 (Q.931 / H.225) | application | TCP 1720 TPKT+Q.931; RAS UDP 1719 | strukturovaná ochrana | Q.931 Calling/Called/Display map; cause preserve; H.225 UUIE PER mask | stejné | H.225/H.245 PER bez schema → mask-only; media pairing neslíbeno |
| `app:stun` | STUN | application | UDP content probe | strukturovaná ochrana | map XOR-MAPPED a související identity | truncate / mask | — |
| `app:lapd` | Q.921 LAPD | application | LINKTYPE_LINUX_LAPD (177); raw LAPD I/S/U | strukturovaná ochrana | SAPI/control preserve; TEI scoped map; I-frame → Q.931 child | stejné | FCS rewrite jen při doloženém FCS; non-Q.931 info → mask |
| `app:q931` | Q.931 DSS1 | application | PD 0x08; IE stream (DSS1/QSIG numbers) | strukturovaná ochrana | Call-ref scoped map (direction bit preserve); Calling/Called/Connected/Redirect map; Display map; QSIG Facility ROSE pinned decode (name/transfer/diversion); plain Facility/UU/keypad mask | stejné (non-BER Facility + UU/keypad vždy mask) | Pinned ECMA-164/174/178 ROSE op subset (T51); full ECMA catalog mimo baseline; H.323 TPKT binding zůstává T24 |
| `app:iua` | IUA (RFC 4233) | application | SCTP PPID 1; QPTM Protocol Data → Q.931/LAPD | strukturovaná ochrana | TLV tag/len preserve; interface id/text map; Protocol Data nested Q.931 | stejné | ASP/RKM management mimo plný dictionary → unknown TLV mask; vyžaduje T17 complete DATA |
| `app:msrp` | MSRP | application | RFC 4975 TCP | strukturovaná ochrana | path host/session map; Message-ID opaque; CPIM From/To map; body mask | stejné | split chunks přes TCP reassembly best-effort |
| `app:bfcp` | BFCP | application | RFC 8855 | strukturovaná ochrana | conference/user/floor ID → opaque-id; unknown ATTR mask | stejné | SDP confid/userid relation baseline |
| `app:zrtp` | ZRTP | application | RFC 6189 | strukturovaná ochrana | ZID/client map; Hello hashes + Commit/DH/Confirm mask; integrity-invalidated | stejné | handshake po anonymizaci není funkční |
| `app:t38` | T.38 / UDPTL | application | UDPTL IFP | strukturovaná ochrana | seq preserve; IFP/page + FEC mask (no parity recompute) | stejné | TSI/CSI map až s T.30 codec; claim přes SDP/test, ne slabý sniff |
| `app:smpp` | SMPP | application | TCP 2775; SMPP 3.4/5.0 PDU header + bind/submit/deliver/data | strukturovaná ochrana | command/status/seq preserve; system_id map; password mask; source/dest addr map; short_message/message_payload always mask; message_id/SAR ref scoped map | stejné (SMS body vždy mask) | Legacy 3.3 mimo baseline; vendor DLR grammar → body mask; submit_multi dest list fail-closed mask |
| `app:rtp` | RTP | application | UDP + SDP flow index | strukturovaná ochrana | klasifikace dle SDP; strip-payload v diagnostic | drop / strip dle úrovně | — |
| `app:rtcp` | RTCP | application | UDP paired s RTP | strukturovaná ochrana | SDES/identity mask; shape preserve | drop / strip | — |
| `app:pidf` | PIDF-LO / geopriv | application | application/pidf+xml (+ held); SIP multipart cid | strukturovaná ochrana | entity/tuple/device id scoped map; coordinates/civic/usage-rules location always mask; XXE reject | stejné (location vždy mask) | náhradní geometrie není skutečná poloha; signed CMS plaintext stále mask |
| `app:lost` | LoST | application | application/lost+xml (RFC 5222) | strukturovaná ochrana | requestId map; urn:service:sos* preserve; serviceBoundary/displayName/URI/geometry mask | stejné | anonymizér neprovádí LoST routing ani síťový dotaz; custom service URN → map |
| `app:mrcp` | MRCPv2 | application | TCP content probe MRCP/2.0; port 3242 hint | strukturovaná ochrana | method/status/request-state/Completion-Cause preserve; Channel-Identifier session map + known @resource; Interpret-Text/NLSML/SSML/grammar/voiceprint/waveform-URI always mask | stejné (speech content vždy mask) | MRCPv1/RTSP mimo baseline; RTP audio dle media policy; žádné STT/TTS ani grammar fetch |
| `app:cwmp` | CWMP / TR-069 | application | SOAP/HTTP CWMP1.4; TCP 7547 hint; HTTP body child | strukturovaná ochrana | RPC/ID/CommandKey/SerialNumber map; Password/Username/URL secrets; ParameterValueStruct role by Name; XXE reject | stejné (credentials vždy mask) | HTTPS ciphertext neparsuje; firmware/config transfer payload mask; no ACS download |
| `app:usp` | USP / TR-369 | application | Record protobuf plaintext; MQTT/STOMP MTP hooks | strukturovaná ochrana | version/security enum preserve; from_id/to_id/session map; MAC/cert mask; non-plaintext payload mask; Msg strings role-aware | stejné | E2E TLS/MQTT TLS ciphertext mimo baseline; full TR-181 dictionary mimo pinned walker; no controller contact |
| `app:nas` | NAS EPS / 5GS | application | TS 24.301 / 24.501 plaintext + security-header classification; GSMTAP LTE-NAS child | strukturovaná ochrana | PD/msg-type/cause preserve; IMSI/IMEI TBCD map; GUTI/TMSI opaque map; RAND/AUTN/PCO/TAI mask; ciphered opaque; MAC invalidated | stejné (auth/location vždy mask) | S1AP/NGAP carriers → T57/T58; no key derivation; unknown cipher → opaque; SUCI concealed mask |
| `app:sbi5g` | 5G SBI (HTTP/JSON) | application | TS29.500/29.571 REL-18 pinned; Nnrf/Namf/Nsmf/Nudm/Nausf/Npcf/Nnssf/Nnef; N1→T59 N2→T58 | strukturovaná ochrana | path/method/status/5QI preserve; SUPI/NF/session IDs map; tokens/auth vectors/location mask; multipart N1/N2 typed children | stejné (token/auth/location vždy mask) | Pinned operation subset (ne full Forge REL-18); HPACK fail-closed → API select from path/JSON probe; TLS without decrypt ≠ JSON input |
| `app:ari` | Asterisk ARI | application | HTTP /ari/* TCP 8088; JSON body overlay | strukturovaná ochrana | path resource IDs map; api_key/Authorization mask; JSON number/name/id/channel/bridge map; media_uri mask | truncate body dle HTTP policy | ARI WebSocket events přes T36 framing; HTTPS/WSS ciphertext neparsuje; Swagger-complete catalog mimo baseline |
| `app:http2` | HTTP/2 (h2c) | application | cleartext preface / frames | strukturovaná ochrana | frame header preserve; HPACK block fail-closed mask; DATA → gRPC/SBI JSON/mask | stejné | žádný length-preserving HPACK rewrite; h2 over TLS zůstává encrypted |
| `app:http` | HTTP/1.x | application | TCP 80/8080/… hlavičky | strukturovaná ochrana | Host map; Cookie/Authorization mask; Date/Last-Modified Δ (T14); text/* tělo → T15 detectors (heuristic) | truncate | jiné tělo fail-closed mask; HTTP/2/gRPC → T36 |
| `app:websocket` | WebSocket | application | RFC 6455; SIP/JSON subprotocol | strukturovaná ochrana | XOR unmask→sanitize→remask; SIP child; Key/Accept linkage v HTTP handshake | stejné | permessage-deflate → mask; Accept bez Key ve stejném message → mask |
| `app:grpc` | gRPC | application | HTTP/2 DATA length-prefix | strukturovaná ochrana | framing preserve; message bytes mask (schema-less protobuf) | stejné | bez reviewed .proto jen opaque mask; compressed → mask |
| `app:syslog` | Syslog | application | UDP/TCP 514/601; RFC 3164/5424 | strukturovaná ochrana | HOSTNAME map; TIMESTAMP Δ; MSG → T15 detectors | MSG mask; stejné identity mapování | 3164 bez roku/TZ → mask při nejednoznačnosti |
| `app:snmp` | SNMP | application | UDP 161/162; v1/v2c/v3 BER | strukturovaná ochrana | community/auth/priv mask; sysName→hostname; engine-id map; neznámý OCTET mask | stejné tajemství; textové OID hodnoty přísněji mask | authPriv scopedPDU bez klíče → mask; MIB dictionary baseline |
| `app:ntp` | NTP | application | UDP 123; RFC 5905 | strukturovaná ochrana | refid IPv4 map / opaque; timestamp Δ; MAC digest mask | stejné | mode 6/7 control body mask; IPv6-hash refid není IPv4 |
| `app:tftp` | TFTP | application | UDP 69 + TID transfer | strukturovaná ochrana | RRQ/WRQ filename map (SEP+MAC); DATA/ERROR text mask | filename mask | transfer state přes TID hint; OACK options preserve |
| `app:llmnr` | LLMNR | application | UDP/TCP 5355 (DNS tvar) | strukturovaná ochrana | reuse sanitizeDns — QNAME/A/AAAA map | stejné | — |
| `app:nbns` | NBNS / NetBIOS | application | UDP 137/138 | strukturovaná ochrana | first-level A–P → hostname; NB IP/MAC map; datagram payload mask | stejné | browser/SMB vendor payload bez schématu → mask |
| `app:ssdp` | SSDP | application | UDP 1900 | strukturovaná ochrana | HOST/LOCATION map; USN uuid→opaque-id; SERVER mask | stejné | — |
| `app:ws-discovery` | WS-Discovery | application | UDP 3702 SOAP | strukturovaná ochrana | urn:uuid opaque-id; URL detektory; DTD/ENTITY reject | stejné | scopes bez schématu → jen detector hits |
| `app:radius` | RADIUS | application | UDP 1812/1813/1645/1646/3799 | strukturovaná ochrana | User-Name/NAS/Station map; Authenticator·Password·CHAP·Msg-Auth mask; EAP přes T19 | stejné (tajemství vždy mask) | multi-attr EAP fragment → mask; VSA mimo slovník mask |
| `app:tacacs` | TACACS+ | application | TCP 49 | strukturovaná ochrana | session_id opaque; cleartext user/rem_addr map; obfuscated body vždy mask | stejné | MD5 pad ≠ encrypted-preserved (opaque-obfuscated-redacted) |
| `app:diameter` | Diameter | application | TCP 3868; SCTP PPID 46/47 (T17) | strukturovaná ochrana | Session-Id/Host/Realm/Subscription map; auth vectors mask; unknown AVP mask | stejné | fragmentované SCTP DATA → requires-reassembly; PER/auth AVP slovník baseline |
| `app:hep` | HEP / EEP (Homer) | application | UDP/TCP 9060; HEPv3 + HEPv1/v2 | strukturovaná ochrana | chunk IP/port map (= L3/L4); captid/corr opaque; auth mask; SIP payload → SIP sanitizer | stejné | RTCP JSON producer → mask; compressed payload mask; LI mimo rozsah |
| `app:tzsp` | TZSP | application | UDP 37008 | strukturovaná ochrana | tag walker; sensor MAC map; Ethernet → vnitřní IP/L4; 802.11 jen adresy | stejné | plné 802.11 → T40; unknown tag body mask |
| `app:netflow-v5` | NetFlow v5 | application | UDP 2055/9995/9996 | strukturovaná ochrana | src/dst/nexthop IPv4 map; porty; ASN opaque; unix_secs Δ; uptime/seq preserve | stejné | ASN jen scoped opaque (T48 prefix relations mimo rozsah) |
| `app:ipfix` | NetFlow v9 / IPFIX | application | UDP 4739 (+ NetFlow porty) | strukturovaná ochrana | template cache per domain; známé IE map; chybějící šablona → requires-reassembly mask; enterprise IE mask | stejné | TCP/SCTP IPFIX framing mimo baseline; variable IE 255+ podporováno |
| `app:sflow` | sFlow v5 | application | UDP 6343 | strukturovaná ochrana | agent IP map; sampled Ethernet header → stejný engine; counter preserve; unknown sample mask | stejné | zkrácená hlavička ≠ malformed; enterprise sample mask |
| `app:pfcp` | PFCP (Sx/N4) | application | UDP 8805; TS 29.244 v18 PFCP v1; node + session messages | strukturovaná ochrana | SEID/F-SEID opaque map (≠ TEID); endpoint-scoped CP/UP F-SEID + session generation; Node ID/UE IP/F-TEID map; User ID IMSI/IMEI/MSISDN; SDF/PFD/unknown mask; Cause/PDR ID preserve; Recovery Δ | stejné (SDF/auth vždy mask) | SDF flow-description grammar → mask (ne regex); enterprise IE value mask; SMF restoration/failover bez explicit relation proof; no UPF control |
| `app:gtp` | GTP (v1/v2-C, GTP-U) | application | UDP 2123 / 2152; TS 29.060 / 29.274 / 29.281 | strukturovaná ochrana | TEID/F-TEID map; IMSI/IMEI/MSISDN/APN/PAA; PCO PAP/CHAP mask; GTP-U T-PDU → IP/Ethernet child | stejné | ULI default mask (T25); PAA Ethernet profil mask-only; unknown IE/ext mask |
| `app:ldap` | LDAP / CLDAP | application | TCP/UDP 389; GC 3268 | strukturovaná ochrana | DN RDN map; attr dictionary; bind/password mask; SASL NTLMSSP → T16; resultCode preserve | stejné (hesla vždy mask) | LDAPS/StartTLS → TLS path; neznámé atributy mask; CLDAP Netlogon baseline |
| `app:kerberos` | Kerberos | application | UDP/TCP 88; kpasswd 464 | strukturovaná ochrana | principal/realm map; EncryptedData cipher vždy mask; etype/kvno/error-code preserve; GeneralizedTime Δ | stejné (enc-part vždy mask) | anonymizované tickety nejsou použitelné k přihlášení; PA-DATA unknown mask |
| `app:dmr` | DMR (DMRD) | application | Homebrew/MMDVM shape | strukturovaná ochrana | map radio/talkgroup 24bit; AMBE netknutý | truncate | — |
| `app:mototrbo` | MOTOTRBO IPSC | application | úzký port list | mask-only | best-effort bez veřejné specifikace — payload redakce | truncate | unsupported-mototrbo-nospec |
| `app:rnd-dispatch-lite` | RND Dispatch Lite | application | UDP 49992 (T31 descriptor pilot) | strukturovaná ochrana | map radioId + site opaque-id; GPS/text tělo maska | truncate | syntetický proprietární dialect — ne vendor wire format |
| `app:bgp` | BGP | application | TCP 179 | strukturovaná ochrana | OPEN ID/ASN map; NEXT_HOP map; unknown attr/NLRI maska; TCP MD5/AO maska | truncate | plný NLRI/MP_REACH dictionary není v této dodávce |
| `app:ldp` | LDP | application | TCP/UDP 646 | strukturovaná ochrana | LSR ID map; auth/TLV hodnoty maska | truncate | FEC/label topology dictionary baseline |
| `app:rip` | RIP / RIPng | application | UDP 520/521 | strukturovaná ochrana | RIPv2 auth maska; IPv4 route/next-hop map; RIPng tělo maska | truncate | — |
| `app:bfd` | BFD | application | UDP 3784/4784 | strukturovaná ochrana | diskriminátory preserve; auth sekce maska | truncate | — |
| `app:hsrp` | HSRP / GLBP | application | UDP 1985/3222 | strukturovaná ochrana | virtual IP map; auth string/digest maska | truncate | — |
| `app:smtp` | SMTP | application | TCP 25/587 plaintext | strukturovaná ochrana | MAIL/RCPT email map; EHLO/banner hostname; AUTH/base64 mask; DATA body mask, headers map | stejné (hesla/tělo vždy mask) | SMTPS/465 → TLS path; BDAT chunk baseline |
| `app:imap` | IMAP | application | TCP 143 plaintext | strukturovaná ochrana | LOGIN user map + pass mask; AUTHENTICATE mask; FETCH literals mask | stejné | IMAPS/993 → TLS; IDLE/COMPRESS mimo baseline |
| `app:pop3` | POP3 | application | TCP 110 plaintext | strukturovaná ochrana | USER map; PASS/APOP digest mask | stejné | POP3S/995 → TLS |
| `app:ftp` | FTP | application | TCP 21 control | strukturovaná ochrana | USER map; PASS mask; PORT/227/EPRT/EPSV → ftp-data IP/port length-stable; paths mask | stejné | FTPS AUTH TLS → TLS; data channel obsah vždy mask |
| `app:telnet` | Telnet / rlogin | application | TCP 23/513; IAC signature | strukturovaná ochrana | IAC option codes preserve; user data + SB body mask | stejné | port 514/TCP jen s IAC (ne syslog) |
| `app:smb` | SMB2/3 | application | TCP 445 / NetBIOS 139 | strukturovaná ochrana | SessionId/TreeId/GUID opaque; SESSION_SETUP → NTLMSSP/SPNEGO; TREE_CONNECT UNC map; READ/WRITE mask | stejné | SMB1 identify+mask; SMB3 encryption transform → encrypted path; DCE/RPC TCP 135 → T42 (named-pipe DCE stále přes SMB data mask) |
| `app:rdp` | RDP | application | TCP/UDP 3389 | strukturovaná ochrana | TPKT/X.224 Cookie mstshash → user-id; negotiation preserve; opaque security maska | truncate | Client Info RC4 bez klíče jen opaque mask; CredSSP/TLS přes T28/TLS path |
| `app:vnc` | VNC / RFB | application | TCP 5900–5909 | strukturovaná ochrana | version/security preserve; DES challenge/response maska; desktop name map; content maska | truncate | rectangle encodings dictionary baseline — post-init content fail-closed mask |
| `app:x11` | X11 | application | TCP 6000–6063 | strukturovaná ochrana | MIT-MAGIC-COOKIE auth data maska; post-setup body maska | truncate | BIG-REQUESTS / extension dictionaries mimo baseline |
| `app:ipmi` | IPMI / RMCP+ | application | UDP 623 | strukturovaná ochrana | ASF preserve; RAKP username map; random/HMAC maska; suite None ≠ encrypted | truncate | plný command inventory dictionary baseline |
| `app:citrix` | Citrix ICA / CGP | application | TCP 1494/2598 | identify → mask (fail-closed) | identify + fail-closed maska celého payloadu | truncate | bez strukturovaného ICA dictionary |
| `app:amt` | Intel AMT | application | TCP 16992–16995 | strukturovaná ochrana | HTTP digest Authorization přes HTTP sanitizer | truncate | SOAP body mimo HTTP header policy → mask dle HTTP handleru |
| `app:gsmtap` | GSMTAP | application | UDP 4729 | strukturovaná ochrana | header type/ARFCN/signal preserve; payload identify+mask unsupported:gsmtap-<typ> | truncate | LTE NAS → T59 child; TETRA/unsupported payload → unsupported:gsmtap-<typ> |
| `app:amqp` | AMQP 0-9-1 | application | TCP 5672 | strukturovaná ochrana | frame/channel preserve; SASL Start-Ok mask; content body JSON/mask | truncate | AMQP 1.0 performatives a plné field tables mimo baseline |
| `app:kafka` | Kafka | application | TCP 9092 | strukturovaná ochrana | API key/correlation preserve; SASL mask; produce/fetch body mask/JSON | truncate | flexible tags + batch CRC recompute mimo baseline; komprese → mask |
| `app:nats` | NATS | application | TCP 4222 | strukturovaná ochrana | CONNECT pass/jwt/token mask; user map; PUB/MSG subject map + payload JSON/mask | truncate | HMSG header block dictionary baseline |
| `app:stomp` | STOMP | application | TCP 61613 | strukturovaná ochrana | CONNECT login map / passcode mask; destination map; body JSON/mask | truncate | escaped header grammar mimo baseline |
| `app:xmpp` | XMPP | application | TCP 5222/5269 | strukturovaná ochrana | JID user/domain/resource map; SASL/auth mask; message body mask | truncate | plný namespace-aware XML stream / STARTTLS generation mimo baseline |
| `app:gelf` | GELF | application | UDP/TCP 12201 | strukturovaná ochrana | nekomprimovaný JSON přes sdílený body path; chunk/zlib/gzip → mask | truncate | chunk reassembly budget mimo tuto dodávku — fragmenty fail-closed |
| `app:fluent` | Fluent Forward | application | TCP 24224 | strukturovaná ochrana | MessagePack tag map; time/record fail-closed mask | truncate | PackedForward/CompressedPackedForward bez inverse → mask |
| `app:otlp` | OTLP | application | TCP 4317/4318 | strukturovaná ochrana | JSON body path; gRPC protobuf schemaless mask (T36 walker) | truncate | resource/span attribute schema dictionary baseline — unknown mask |
| `app:postgres` | PostgreSQL | application | TCP 5432 | strukturovaná ochrana | Startup user/db map; Password/SASL mask; Query SQL literals (T15); DataRow mask | truncate / celé SQL mask | RowDescription column names fail-closed mask (schema policy later) |
| `app:mysql` | MySQL / MariaDB | application | TCP 3306 | strukturovaná ochrana | handshake salt/auth mask; user/db map; COM_QUERY SQL literals; rows mask | truncate / celé SQL mask | continuation packets / compression mimo baseline |
| `app:tds` | TDS / MS SQL | application | TCP 1433 | strukturovaná ochrana | LOGIN7 UTF-16 Host/User/App/Server/DB map; password mask; SQLBatch literals | truncate / celé SQL mask | token stream ROW/NBCROW dictionary baseline; SSPI → mask |
| `app:redis` | Redis RESP | application | TCP 6379 | strukturovaná ochrana | command preserve; AUTH mask; key map (diagnostic) / mask (HP); values mask | truncate | RESP3 push/pubsub dictionary baseline |
| `app:mongodb` | MongoDB | application | TCP 27017 | strukturovaná ochrana | OP_MSG header preserve; BSON fail-closed mask; SASL/auth tagged | truncate | schema-known BSON key preserve mimo baseline; OP_COMPRESSED → mask |
| `app:mqtt` | MQTT | application | TCP 1883 | strukturovaná ochrana | CONNECT password mask; clientId/user map; topic segment map; payload JSON/mask | truncate | MQTT 5 property dictionary baseline; 8883 → TLS path |
| `app:coap` | CoAP | application | UDP 5683 | strukturovaná ochrana | header/code/MID preserve; token map; Uri-* map; payload JSON/mask | truncate | OSCORE/Observe cross-datagram mimo baseline; Block2 reassembly v capture |
| `app:modbus` | Modbus/TCP | application | TCP 502 | strukturovaná ochrana | MBAP+FC/address/count/exception preserve; register/coil values mask | truncate | process values default mask (explicit profile needed to preserve) |
| `app:iec104` | IEC 60870-5-104 | application | TCP 2404 | strukturovaná ochrana | APCI/type/COT preserve; CA/IOA opaque map; process values mask | truncate | ASDU stride/SQ dictionary baseline; CP56Time timezone ambiguous |
| `app:dnp3` | DNP3 | application | TCP/UDP 20000 | strukturovaná ochrana | link addr map; G/V dictionary walk + values mask; CRC-16 recompute | truncate | normativní object variations mimo baseline dictionary |
| `app:opcua` | OPC UA | application | TCP 4840 | strukturovaná ochrana | HEL host map; OPN SecurityMode + cert/nonce mask; MSG Sign/None RequestHeader walk | truncate | plná UA službová schema / SignAndEncrypt bez OPN stavu |
| `app:dcerpc` | DCE/RPC | application | TCP 135 + dynamic | strukturovaná ochrana | PDU header/UUID preserve; NTLM/SPNEGO auth (T16); NETLOGON/DRSUAPI stub mask; EPM port hints | truncate | NDR bez IDL → stub mask-only; SAMR/LSA jména až s opnum dictionary |
| `app:iscsi` | iSCSI | application | TCP 3260 | strukturovaná ochrana | BHS preserve; IQN domain/name map; CHAP_R/C/I mask; Data-In/Out mask | truncate | CRC32c digest renegotiation / multi-PDU Login mimo baseline |
| `app:portmapper` | Portmapper / rpcbind | application | TCP/UDP 111 | strukturovaná ochrana | ONC RPC header preserve; GETPORT → flow hint; AUTH_SYS hostname map | truncate | DUMP list partial mask; RPCSEC_GSS body mask |
| `app:nfs` | NFS | application | TCP/UDP 2049 | strukturovaná ochrana | ONC RPC + AUTH_SYS; file handle/data mask; LOOKUP names map | truncate | NFSv4 compound dictionary baseline; attribute time-shift mimo baseline |
| `app:echo-udp-example` | Echo UDP (onboarding příklad) | application | UDP 49991 | strukturovaná ochrana | kernel onboarding modul — ne produkční protokol | truncate | pouze demonstrační handler |
| `app:heuristic` | Heuristický scanner | application | nerozeznaný payload | mask-only | stav vždy heuristic, nikdy covered | vypnuto | — |
| `unsupported:mgcp` | MGCP | application | TCP (UDP má strukturovaný handler T11) | identify → mask (fail-closed) | coverage id unsupported:mgcp; fail-closed mask/truncate | truncate / drop dle úrovně | bez strukturované analýzy — žádejte podporu kódem z panelu Výsledek |
<!-- protocol-matrix:end -->

**Ověřené shrnutí pro zákazníky (fáze 1, po T00–T11).** Ethernet/IP/ARP, SIP/SDP
(vč. 64bit `o=` session-id a multipart/SIPREC), MGCP UDP, RTP/RTCP (diagnostic:
payload maska; high-privacy: **drop** celých paketů), HTTP hlavičky, DNS/DHCP/STUN/TLS
SNI+cert, L2/L3 pomocné protokoly výše — platí. Call-ID se mapuje znak po znaku
(alfanumerika), takže zakódovaná IP v Call-ID nepřežije. Discovery (LLMNR/NBNS/SSDP/WS-Discovery, T18), L2 (LLDP/LACP/EAPOL, T19), AAA
(RADIUS/TACACS+/Diameter TCP, T22), capture obálky (HEP/TZSP, T35), WebSocket/h2c/gRPC (T36),
mission-critical VoIP (MCPTT/MSRP/BFCP/ZRTP/T.38, T37; SIP-I po T25)
management (syslog/SNMP/NTP/TFTP, T20), directory (LDAP/Kerberos/NTLM, T23),
enterprise plaintext (SMTP/IMAP/POP3/FTP/Telnet/SMB2, T27)
a telco signalizace mimo SIP (H.248/RTSP/IAX2/Skinny/H.323, T24) mají strukturované handlery;
ostatní nepodporované (MQTT, …) → diagnostic `maskFill`, high-privacy ořez.
Párování RTCP=RTP+1 a katalog telekom portů (MGCP 2427/2727, …) platí. Reálné lokální
regresní vzorky (`hi2`, `obc2`, `.gz`) jsou v `anonymizer/logs/` (gitignored); Grandstream
Call-ID a produkční MGCP zachyt ještě chybí — doplnit do stejné brány až budou k dispozici.

**Komprimovaný vstup.** `.gz` (magic `1f 8b`) se rozbalí v prohlížeči streamem;
limity platí na **rozbalenou** velikost (ochrana proti gzip bombě). Support bundle
`.zip` / `.tar` / `.tar.gz` (T44) se rozbalí do korelačního stagingu (store/deflate,
path-safe aliasy, bez hesel); xz/zstd/bzip2 a šifrovaný ZIP se odmítnou srozumitelnou
hláškou. Gzip metadata se neuchovávají. Výstupní support ZIP nese jen anonymizované
aliasy a `REPORT.json` — nikdy mapovací bundle ani recovery.

**Pro koho je zbytek dokumentu.** Následující stránky jsou technický detail určený
kolegovi, který je expert na síťovou komunikaci a SIP. Nejde o popis implementace —
jde o vysvětlení **síťových principů**, na kterých anonymizace každé vrstvy PCAP
komunikace stojí, a o to, jak přesně funguje zpětná obnova, abychom od AI nálezu
v anonymizovaném souboru uměli dohledat originální paket a jeho okolí.

<div style="page-break-before: always"></div>

## 1. Základní princip: identita, konzistence, integrita

Anonymizace není „nahradit citlivé řetězce náhodným smetím". Aby zachyt zůstal po
zásahu diagnosticky použitelný a strukturálně validní, musí každá náhrada splňovat
tři vlastnosti současně:

1. **Konzistence (bijekce) v rámci relace.** Jedna reálná hodnota → vždy stejná
   náhradní hodnota, všude, kde se v zachytu objeví — napříč L2/L3/L4 i aplikační
   vrstvou, napříč celým souborem, a napříč více soubory nahranými do jedné relace
   najednou (log + log + pcap). Díky tomu zůstává zachovaný celý komunikační graf:
   které pakety patří stejnému TCP spojení, stejnému SIP dialogu, stejnému RTP
   streamu, stejnému fyzickému zařízení napříč L2/aplikační vrstvou.
2. **Strukturální platnost.** Náhrada musí být syntakticky platná hodnota svého typu
   (funkční IPv4/IPv6 adresa, MAC se správně nastaveným unicast/multicast bitem,
   hostname se zachovaným počtem a délkou labelů). Wireshark i jiné dissectory tedy
   zachyt dál parsují úplně stejně jako originál, jen s jinými hodnotami.
3. **Invariance délky a pořadí paketů.** Anonymizace nikdy nemění délku paketu ani
   pořadí paketů v souboru — jen přepisuje bajty na místě. To je to, co drží při
   životě veškerou časovou diagnostiku (RTT, jitter, retransmise, reassembly), viz
   kapitola 3 a 6.

Ke druhé vlastnosti se váže jeden detail důležitý pro čtení výsledku: **stejná
logická hodnota se v zachytu často objevuje ve dvou různých „bajtových tvarech"** —
jednou jako pevná binární reprezentace v hlavičce (4 bajty IPv4 v IP hlavičce, 6 bajtů
MAC), podruhé jako ASCII text v aplikační vrstvě (tatáž IP adresa vypsaná dekadicky
v SIP `Via`/`Contact`, v SDP `c=` řádku, v HTTP hlavičce). Protože délka paketu se
nesmí změnit, textová náhrada musí mít přesně stejný počet bajtů jako originální
text — binární a textová náhrada proto vycházejí z **jedné a téže identity**, i když
mají jinou (na první pohled nesouvisející) hodnotu. Výsledek: IP adresa v Ethernetové/IP
hlavičce a tatáž IP adresa vypsaná v SIP `Via` hlavičce dostanou po anonymizaci
odlišné náhradní hodnoty (jinak to při zachování délky nejde — jiný „tvar" bajtů),
ale obě jsou svázané se stejnou původní identitou. To je přesně mechanismus, který
umožňuje zpětně poznat „tohle je stejná adresa, jen zapsaná jinak", a je základem
obnovovacího indexu z kapitoly 7.

**Integrita.** Ani jedna z výše uvedených vlastností sama o sobě nezaručuje, že
výsledný paket je na drátě platný — k tomu je potřeba čtvrtá věc, přepočet
kontrolních součtů, protože řada z nich (TCP/UDP, ICMPv6) je počítaná i přes
substituované adresy. Tomu je věnovaná kapitola 3.

<div style="page-break-before: always"></div>

## 2. L2/L3: Ethernet, VLAN, ARP, IP, tunelování, ICMP, fragmentace

**Ethernet a MAC.** Náhradní MAC adresa je vždy tvaru **locally-administered unicast**
(první bajt `02`, zbylých 5 bajtů z CSPRNG) — to je standardní IEEE 802 mechanismus
„tahle adresa nebyla přidělená výrobcem síťové karty", takže dissector dál správně
pozná unicast adresu koncového zařízení, jen bez úniku reálného OUI. Skutečné
protokolové konstanty se **nemapují** — broadcast `ff:ff:ff:ff:ff:ff`, jakákoliv
multicast adresa (I/G bit) — protože to nejsou identity, ale pevné hodnoty, na které
spoléhá každý switch na cestě. Výjimka stojí za vysvětlení: virtuální router MAC
VRRP (`00:00:5e:00:01:xx`, RFC 5798) se také **nemapuje** — VRID bajt je stejně
viditelný přímo v obsahu VRRP paketu, takže by přemapování jen rozbilo křížovou
kontrolu mezi MAC adresou a VRRP payloadem, aniž by cokoliv skrylo.
HSRP/GLBP (T38) mapují virtuální IP; auth string (včetně výchozího `cisco`) a MD5
digest vždy maskují — virtual MAC odvozený z group se nemění.

**VLAN (802.1Q/802.1ad).** Tag nese TPID (že jde o tagovaný frame) a TCI, které se
dál dělí na PCP (priorita), DEI (drop eligible) a VID (12bitové VLAN ID). Identitu
topologie nese jen VID, takže se mapuje jako **bijekce v rámci 1–4094** — rezervované
hodnoty `0` a `4095` zůstávají beze změny, stejně jako priorita a DEI (QoS metadata,
ne identita). U dvojitě tagovaných rámců (QinQ/802.1ad — typicky na hranici
poskytovatele) se S-VLAN a C-VLAN mapují nezávisle, ale konzistentně, takže vztah
vnějšího a vnitřního tagu zůstává čitelný.

**ARP.** Spárování request/reply (`who-has X tell Y` / `X is-at MAC`) stojí na tom,
že IP a MAC ve dvou různých paketech odkazují na tutéž dvojici hodnot. Protože se IP
i MAC mapují identitně konzistentně, ARP výměna zůstává vnitřně koherentní i po
anonymizaci — stejný (náhradní) IP se pořád překládá na stejný (náhradní) MAC, takže
analýza ARP cache, gratuitous ARP nebo detekce duplicitní IP adresy funguje dál
stejně jako na originále.

**IPv4/IPv6 — adresní prostory a zachování topologie.** Náhradní adresa se vždy
vybírá z **pevného, rozpoznatelného rozsahu** podle třídy originálu: privátní IPv4 →
`10.254.0.0/16`, veřejná IPv4 → `198.51.0.0/16` (dokumentační rozsah); IPv6
link-local → `fd00::/8` (unique-local), ostatní → `2001:db8::/32` (IANA dokumentační
prefix). Broadcast, `0.0.0.0`, `::` a IPv4 multicast (`224.0.0.0/4`) se **nemapují**.
U IPv6 se zachovávají jen **well-known** multicast konstanty (`ff02::1`, `ff02::2`, …);
**solicited-node** `ff02::1:ffXX:XXXX` a odpovídající Ethernet `33:33:ff:…` berou spodních
24 bitů z aliasu unicastové adresy (nebo ze scoped group), nikdy z originálu — jinak by
NDP/DAD unikly částí cílové identity. Vložené IPv4 formy (`::ffff:`, NAT64 `64:ff9b::/96`,
6to4, ISATAP, Teredo) sdílejí alias s bare IPv4. Cílové `/16` a `2001:db8::/32` jsou
záměrně nápadné — ve Wiresharku je hned poznat anonymizovaný zachyt.

Diagnostická úroveň navíc zkouší **vlastní topology-preserving kandidát** v pevném
cílovém `/16` (derivace host bitů z originálu, ne standardní AES Crypto-PAn). Při
kolizi v alokační tabulce padá na jiný volný slot **uvnitř stejné mapované /24**
v cílovém `/16`, takže hostitelé i síťové adresy (`mapIpv4Prefix`) ze stejné
původní `/24` sdílejí stejný třetí oktet (T38.prefix). Není to kryptografický
Crypto-PAn slib; mezi různými původními `/24` není slib stejné podsítě mimo
sdílený cílový blok `10.254.0.0/16` / `198.51.0.0/16`. **Vysoké soukromí** kandidáta nepřipravuje a adresu vybírá
náhodně v rámci stejné třídy — topologický signál je pryč, zbývá jen
„veřejná/privátní/multicast“ třída. V obou režimech platí bijekce a fail-closed
chování (při vyčerpání prostoru bezpečný sentinel, nikdy návrat originálu).

**Konečné aliasové domény (T48).** Globální strop 500 000 identit **není** kapacitou
každé kategorie: IPv4 má dvě cílové `/16` po 65 536 slotech, VLAN 4094 hodnot,
dynamické portové páry ~8 192 na transport, radio ID 24 bitů. Registry
`src/pcap/anonymization/mappingDomainRegistry.ts` deklaruje formát, velikost,
rezervy a exhaustion dispozici. Obsazené sloty se drží v persistentních `Set`
(clone/staging/commit atomicky); alokátor neprochází celou historii aliasů při
každém novém `map`.

TTL/Hop Limit, ToS/DSCP a fragmentační příznaky/offset zůstávají beze změny — TTL je
záměrně ponechán kvůli otisku zásobníku, viz kapitola 3. **IPv4 Identification pole**
a **IPv6 flow label** se ale mapují (viz kapitola 3) — surová hodnota by jinak mohla
posloužit jako fingerprint konkrétního OS/stacku nezávisle na IP adrese samotné.
U IPv6 se prochází celý řetězec rozšiřujících hlaviček (hop-by-hop, routing, fragment,
destination options); adresy se substituují jen tam, kde je routing hlavička (typ 0/2)
nebo mobilita samy nesou, zbytek prochází beze změny.

**Fragmentace.** Cokoliv nad L3 (SIP hlavička, DNS jméno) může být rozdělené přes
hranici IP fragmentu, takže sanitizace obsahu aplikační/L4 vrstvy vždy proběhne až
po virtuálním složení fragmentovaného vlaku zpět dohromady. Samotné fragmenty na
drátě — jejich hranice, IP ID, MF příznak, fragment offset — se v exportu nemění,
mění se jen obsahové bajty uvnitř každého fragmentu na správném, fragment-relativním
offsetu. Zachyt, který byl fragmentovaný, zůstane fragmentovaný stejně i po
anonymizaci.

**Tunelování.** IP-in-IP, 6in4/4in6, GRE, VXLAN, GTP-U — vnější i vnitřní IP hlavička se
anonymizují každá jako svá vlastní L3 vrstva (klidně jiný adresní prostor), rozbaleno
do hloubky 4 vnoření jako ochrana proti neomezeně vnořeným tunelům. GTP-U T-PDU
(potvrzený IP nebo Ethernet) prochází stejným nested engine jako GRE/VXLAN; TEID z
řídicí roviny (F-TEID) a z GTP-U hlavičky sdílí kategorii `teid`, PAA UE IP stejný
alias jako vnitřní IP. Cokoliv se uvnitř tunelu dekóduje, podléhá **stejným pravidlům**
jako netunelovaný provoz — SIP hovor vedený uvnitř GTP-U (VoLTE) dostane své SIP
hlavičky anonymizované stejně, jako kdyby žádný tunel nebyl. Unstructured / neznámé
PDU má masku a explicitní gap. Hlubší, nepodporované vnoření se hlásí jako
„nedekódováno", nikdy tiše neprojde beze změny — anonymizátor, který tiše přeskočí
nerozpoznanou strukturu, je únik dat opomenutím, ne bezpečné chování.

**ICMP a vložené hlavičky.** ICMP chybová zpráva (Destination Unreachable, Time
Exceeded/traceroute, Fragmentation Needed/PMTUD) z principu nese kopii původní IP
hlavičky + prvních 8 bajtů transportní hlavičky paketu, který chybu vyvolal — přesně
proto, aby si původní odesílatel uměl chybu spárovat se svým spojením. Pokud by
tahle vložená hlavička nebyla anonymizovaná na **stejné** náhradní hodnoty jako
„živá" kopie téhož paketu jinde v zachytu, byl by to přímý únik reálných adres
zabalený do chybové zprávy. Sanitizuje se proto do hloubky jednoho vnoření, stejnou
identitou jako zbytek zachytu.

<div style="page-break-before: always"></div>

## 3. L4: porty, kontrolní součty a otisk síťového zásobníku

**Porty.** Rozhoduje **sémantická role**, ne jen „je pod 1024". Fixní katalog portů
zůstává beze změny bez ohledu na to, jestli spadají do IANA system rozsahu, protože
je na nich závislé automatické rozpoznání protokolu (Wireshark „Decode As", vlastní
diagnostické grafy): SIP `5060`/`5061`, STUN/TURN `3478`/`3479`/`5349`, RTSP `554`,
H.323 `1720`, MGCP `2427`/`2727`, H.248 `2944`/`2945`, SCCP `2000`, IAX2 `4569`,
SSDP `1900`, Diameter `3868`, RADIUS `1812`/`1813`, M3UA `2905`, GTP-C `2123`,
GTP-U `2152`, VXLAN `4789`, mDNS `5353`, DNS-over-TLS `853`, DHCPv6 `546`/`547`,
a klasické systémové služby
(SSH, DNS, HTTP/S, SMTP/IMAP/POP3, FTP, Telnet, SMB, NTP, LDAP(S), syslog…). Naopak obskurní port pod 1024,
který v katalogu není, se **nepovažuje** za automaticky bezpečný jen proto, že je
„systémový". Port, na kterém discovery **obsahem** rozpozná signalizaci (např. SIP
na `5070`), dostane roli signaling: v diagnostické úrovni se zachová, v high-privacy
se permutuje. Zbylé efemérní/dynamické porty se **permutují po dvojicích**
(`alias(p) = 2·π(⌊p/2⌋) + (p mod 2)`) v dynamickém rozsahu 49152–65535 (user-registered
ve stejném IANA rozsahu), bez kolizí, bez pevného bodu a bez aliasu na katalogový port.
Vztah **RTCP = RTP+1** a **sudá parita RTP** z RFC 3550 tak po anonymizaci
**zůstává zachovaný**; SDP `m=` / `a=rtcp:` a transportní hlavičky sdílejí tutéž
identitu portu.

**Kontrolní součty — nejpodceňovanější invariant.** TCP i UDP checksum se počítá
přes tzv. pseudo-hlavičku, která zahrnuje zdrojovou a cílovou IP adresu (RFC 793 /
RFC 768). V okamžiku, kdy se adresa jednoho z konců spojení nahradí, je **každý**
TCP/UDP checksum v každém paketu daného toku neplatný, dokud se nepřepočítá. Stejně
tak ICMPv6 (na rozdíl od ICMPv4) používá checksum přes pseudo-hlavičku zahrnující
IPv6 adresy. Přepočet checksumů proto není kosmetický úklid na závěr — je to
povinná korektnost, prováděná jako poslední krok, po všech substitucích, průchodem
zevnitř ven přes případné tunelové vrstvy (nejdřív vnitřní checksum, pak vnější,
protože vnější zapouzdření může samo nést checksum přes celý zapouzdřený payload).
Výsledný export tak nikdy neobsahuje neplatný checksum jako vedlejší efekt
anonymizace — jakákoliv chyba checksumu ve výstupu je reálná chyba z originálního
zachytu, ne artefakt nástroje.

**IPv4 Identification, IPv6 flow label a TCP sekvenční prostor.** Tahle tři pole
jsou čistá čísla bez „identity" v běžném slova smyslu, ale dají se zneužít jako
otisk: monotónní IP ID counter dlouhodobě prozrazuje, že dva toky pocházejí ze
stejného stacku, a syrové TCP sekvenční/potvrzovací číslo může korelovat zachyt
s jiným, kde je znát stejný generátor ISN. Proto se **i v diagnostickém režimu**
mapují: IPv4 ID a IPv6 flow label dostanou novou hodnotu vázanou na tok, a TCP
sekvenční i potvrzovací číslo (spolu se souvisejícími SACK bloky ve volbách) se
posune o jednu konzistentní náhodnou konstantu **za směr spojení**, modulo 2³².
Protože je posun v obou směrech spojení konstantní, veškerá **relativní** aritmetika
zůstává platná — délka segmentu odpovídá rozdílu čísel, ACK potvrzuje správný
posun, retransmise a duplicitní ACK se pozná stejně jako na originále, SACK bloky
zůstávají konzistentní — jen surové absolutní číslo už nekóreluje s originálem ani
s žádným jiným zachytem.

**TTL / TCP okno / MSS / pořadí TCP voleb — otisk operačního systému.** Přesně tahle
kombinace polí (TTL nebo Hop Limit, počáteční velikost TCP okna, MSS, window scaling
faktor, a pořadí, ve kterém se objevují volby v SYN paketu) je signál, který
používají nástroje pro pasivní OS fingerprinting (styl p0f) k odhadu vysílajícího
zásobníku. **Diagnostická úroveň** je záměrně ponechává beze změny — díky tomu
zůstává diagnostikovatelná i chyba interoperability vázaná na konkrétní OS/firmware
konkrétního SIP telefonu nebo PBX. **Vysoké soukromí** naopak tato pole vědomě
normalizuje na běžné/generické hodnoty (pevné TTL, pevné okno, přeuspořádané/
odstraněné volby) — cenou je ztráta této diagnostické stopy, výměnou za nižší
identifikovatelnost, jaký přesně výrobce/build zařízení zachyt vyprodukoval.

<div style="page-break-before: always"></div>

## 4. SIP: model dialogu a jeho zachování

SIP dialog je jednoznačně identifikován trojicí **(Call-ID, From-tag, To-tag)**
podle RFC 3261. `Call-ID` je vlastní bijektivní kategorie identity — nikdy se
nezamění s IP adresou nebo telefonním číslem — takže dvě zprávy se stejným Call-ID
mají stejné Call-ID i po anonymizaci. Parametry `tag` v `From`/`To` (nastavené
UAC/UAS pro odlišení forkovaných nebo retargetovaných dialogů) se mapují stejně
konzistentně, takže dialog, který byl korelovatelný před anonymizací, zůstává
korelovatelný i po ní — včetně scénářů forkingu, kde na jeden INVITE přijde víc
`200 OK` odpovědí s různým To-tagem od různých větví.

**Řetězec `Via`.** Každý proxy hop si přidává vlastní `Via` s `sent-by` adresou a
parametrem `branch` (magic cookie `z9hG4bK` + ID transakce) sloužícím k detekci
smyček a směrování odpovědi zpět. Adresa i branch se mapují konzistentně, takže
počet hopů, pořadí proxy řetězce a to, která odpověď patří ke které
request-transakci (podle RFC 3261 pravidel párování transakcí), zůstává plně
analyzovatelné — včetně počítání retransmisí na úrovni transakce.

**Adresní/směrovací hlavičky.** `From`/`To`/`Contact`/`Route`/`Record-Route`/
`Reply-To`/`Refer-To`/`Referred-By`/`P-Asserted-Identity`/`P-Preferred-Identity`/
`P-Associated-URI`/`P-Called-Party-ID`/`Remote-Party-ID`/`Diversion`/`History-Info`/
`Path`/`Service-Route` — hostová část URI se mapuje jako jakákoliv jiná adresní
identita; telefonní číslo (typicky E.164 / `tel:` / SIP `user=phone` / `sip:+…`) se mapuje
jako cross-format kategorie `phone` konzistentně napříč `REGISTER`/`INVITE`, textovými logy
i korelujícími hlavičkami — takže řetězec přesměrování, proxy route set a prezentace CLI
zůstávají analyzovatelné end-to-end, aniž by se kdekoliv objevilo reálné DID/E.164 číslo
nebo adresa proxy. Čistě číselný SIP user bez telefonního kontextu se neslučuje s `tel:`.

**`Authorization`/`Proxy-Authorization`/`WWW-Authenticate` (Digest auth).** Tyhle
hlavičky nesou kryptografický hash spočítaný nad reálným uživatelským jménem,
heslem, realm a nonce — nejde je vybíravě přemapovat, aniž by se rozbil vztah
hash↔vstup (a čisté uživatelské jméno uvnitř by stejně unikalo samo o sobě), takže
se **maskují jako celek**, ne přemapovávají po polích. Existence a struktura
výzvy/odpovědi (tok `401`/`407`) zůstává zachovaná, jen její obsah je opaque.

**`Identity` (STIR/SHAKEN, RFC 8224).** Tahle hlavička nese PASSporT — JWT podepsaný
volajícím operátorem, potvrzující, že volající má právo použít dané volající číslo
(ochrana proti caller-ID spoofingu). Podpis je počítaný přesně nad původními
hlavičkami zprávy — jakákoliv jejich změna (a anonymizace mění `From`/`To` skoro
vždy) podpis neplatně invaliduje. Proto se `Identity` **maskuje jako celek**, nikdy
nepřemapovává, a jeho přítomnost se v exportním reportu hlásí jako signál, že
kryptografická integrita STIR ověření je po anonymizaci `MODIFIED` — ne proto, že
by nástroj něco rozbil chybou, ale proto, že podpis nad pozměněnými hlavičkami už
nemůže platit, a report to říká otevřeně místo aby to skrýval.

**`User-Agent`/`Server`/`Organization`.** Volný text identifikující výrobce/model/
firmware koncového zařízení nebo PBX. Ověřeno na reálných zachytech: `User-Agent`
běžně obsahuje přesně identifikující řetězec (model rádiového terminálu + firmware
build, interní build/revision timestamp brány), zatímco `Server` bývá naopak
generický banner („Asterisk PBX 22.0.0"). Protože se ale u konkrétního zařízení
nedá spolehnout, že `User-Agent`/`Server` bude vždy neškodný, **oba se redigují**
jako celek, ne přemapovávají — je to otisk zařízení/verze, ne opakující se identita,
u které dává smysl zachovávat korelaci.

**`Geolocation`/`Geolocation-Routing`** (RFC 6442, přesná GPS/civic poloha) a
`Identity-Info` (odkaz na certifikát pro ověření STIR podpisu) se ze stejného
důvodu maskují jako celek. Naopak `Privacy`, `Supported`, `Require` a podobné
vyjednávací hlavičky zůstávají beze změny — jsou to protokolové příznaky, ne
identita.

**Tělo zprávy.** Zpráva rozdělená přes víc TCP segmentů se před sanitizací nejdřív
sestaví (reassembly). `multipart/mixed` tělo (typicky SDP + další část, např.
STIR PASSporT nebo SIPREC `application/rs-metadata+xml`) se rozdělí podle hranice
a **každá část se sanitizuje podle svého vlastního Content-Type** — SDP část
dostane plnou strukturovanou sanitizaci (kapitola 5), SIPREC metadata a jiné
nerozpoznané nebo poškozené části se celé zamaskují na stejné délce (fail-closed,
coverage `sip-siprec-metadata` / `sip-body`, nikdy tiché „covered"). Discovery i
export plán sdílejí stejný průchod tělem, takže multipart neshodí celý soubor.

<div style="page-break-before: always"></div>

## 4.1 MGCP (RFC 3435)

MGCP je textová call-agent ↔ gateway signalizace (UDP 2427/2727). Diagnostická úroveň
již **nesmí** celý paket jen zamaskovat: verb, transaction id, response code, známé
QoS/codec parametry a struktura zprávy zůstávají; endpoint domain (hostname / IPv4 /
IPv6 vč. `N:` NotifiedEntity s `[addr]:port`), CallId (`C:`), ConnectionId (`I:`),
RequestIdentifier (`X:`) a caller-id číslo se mapují konzistentně; wildcard endpoint
(`*@host`) se nemění. DTMF číslice, DigitMap **literály mimo** znakové třídy `[…]`,
šifrovací klíč `L:k:`, quoted argumenty neznámých package a volný response text se
maskují (rozsahy DigitMap jako `[2-9]` zůstávají). Vnořené SDP prochází stejným SDP
planem jako u SIPu a registruje RTP toky. Více zpráv v jednom datagramu (piggyback,
řádek `.`) se zpracuje zvlášť. TCP MGCP zatím nemá framing profil — zůstává
identify-only (`unsupported:mgcp`).

## 5. SDP, ICE, STUN, RTP/RTCP, SRTP — mediální rovina hovoru

**SDP offer/answer (RFC 3264).** `o=` řádek nese v username + session-id +
version-number vlastní identitu session a její čítač změn (re-INVITE version
zvyšuje). Username se mapuje jako token; session-id se nahradí číslem stejné
délky (kategorie `sdp-session-id`, konzistentně napříč nabídkou i každou další
odpovědí/přenabídnutím téhož hovoru). Session-version se posouvá o stejnou
konstantu odvozenou z aliasu session-id, takže přírůstky v re-INVITE zůstávají
čitelné, ale hodnota neprozradí originál. `c=`/`m=` řádky nesou skutečnou
transportní adresu/port, kam má protistrana posílat RTP — mapují se jako
jakákoliv jiná IP/port a jsou svázané se stejnou identitou jako RTP SSRC
pozorovaný z téže adresy, takže otázka „čí je tohle médium" zůstává
zodpověditelná.

**ICE (RFC 8445) a STUN (RFC 5389).** Řádky `a=candidate` vyjmenovávají
host/server-reflexive/relay kandidáty získané přes STUN/TURN, každý s vlastní
transportní adresou, prioritou, foundation a typem; atributy `raddr`/`rport` u
server-reflexive a relay kandidátů prozrazují, co NAT/TURN server viděl jako
reálné veřejné mapování. IP adresy procházejí stejným registrem jako zbytek
zachytu (vztah host↔srflx na úrovni IP zůstává korelovatelný). Efemérní porty se
permutují **po dvojicích** (RTCP = RTP+1 a sudá parita), takže párování mediálních
portů zůstává; ICE foundation/priority/typ se nemění. `a=ice-ufrag`/`a=ice-pwd` jsou krátkodobé STUN
přihlašovací údaje pro autentizaci connectivity-check binding requestů — ty se
**maskují**, ne mapují, protože vystavit skutečné, byť krátce platné přihlašovací
údaje pro NAT traversal není „opakující se identita", je to živé tajemství.

Samotné STUN pakety (Binding Request/Response, ať už z ICE, nebo standalone) se
sanitizují stejnou logikou: `(XOR-)MAPPED-ADDRESS` nese IPv4/IPv6+port a mapuje se
přes **stejný registr identit** jako zbytek zachytu — tatáž adresa má tedy stejný
alias, ať se objeví v STUN, v SDP `a=candidate`, nebo přímo v IP hlavičce. `USERNAME`
(ICE ufrag pár) a `REALM` se mapují jako uživatelský/hostname token; `NONCE`,
`SOFTWARE`, `DATA` a `USERHASH` se maskují jako opaque materiál. Pokud zpráva nese
`MESSAGE-INTEGRITY` atribut (HMAC nad celou zprávou), report ho hlásí jako
kryptograficky `MODIFIED` — přemapování adresy/portu podpis pod ním nutně invaliduje,
stejně jako u STIR výše; to je čestně přiznaný vedlejší účinek, ne skrytá chyba.

**RTP (RFC 3550).** SSRC/CSRC identifikují synchronizační/přispívající zdroj a
vybírají se tak, aby se v rámci session nekolidovaly — mapují se přes stejnou
kategorii identity jako IP/MAC, sdílenou s RTCP vrstvou, takže „tohle SSRC v RTP
streamu je stejný mediální zdroj jako tohle SSRC v RTCP SR/RR/SDES/BYE" platí i po
anonymizaci. Sequence number a RTP timestamp zůstávají **nedotčené** — jitter
buffer, detekce ztráty/přeuspořádání paketů a rekonstrukce přehrávacího času na
přijímací straně stojí na jejich nezměněné progresi; nic z toho neidentifikuje
osobu ani zařízení, je to čistě hodinová knihovna média. Hlavičková rozšíření RTP
(RFC 5285 — např. `mid`, client-to-mixer audio level, abs-send-time) se maskují
bez ohledu na to, jestli byla vyjednaná v SDP, nebo jde o neznámý typ — hodnota
uvnitř rozšíření může nést identifikátor zdroje nebo přesné časování, i když samotná
RTP hlavička ne. Protože se veškerý mediální payload maskuje (diagnostická úroveň)
nebo zahazuje (vysoké soukromí), platí totéž i pro DTMF signalizaci přenášenou jako
RTP `telephone-event` (RFC 4733) — vyťukané číslice (PIN, číslo karty zadané po
připojení hovoru) jsou chráněné stejným mechanismem jako hlas, ne zvláštní výjimkou.

**RTCP.** Dvojice NTP timestamp + odpovídající RTP timestamp v Sender Reportu je
to, co umožňuje lip-sync/zarovnání mezi audio a video SSRC ze stejného zdroje —
zůstává nedotčená ze stejného důvodu jako RTP timestamp. Pole Receiver Reportu
(podíl ztrát, kumulativní ztráty, jitter, round-trip) jsou čistá QoS telemetrie,
také nedotčená — analýza kvality hovoru (MOS-like metriky) tedy funguje i po
anonymizaci. SDES CNAME/EMAIL/PHONE/LOC/NOTE je jediná část RTCP, která je reálný
osobní/koncový identifikátor (CNAME má být globálně unikátní napříč všemi SSRC
daného zdroje, často odvozené z `user@host`) — ty se **maskují**. 4bajtové pole
„name" v APP paketu (vendor-specifická ASCII značka, ne osobní údaj) zůstává
čitelné, aby šlo poznat, o jaké vendor-rozšíření RTCP jde; BYE „reason" text se
maskuje.

**SRTP (RFC 3711) a SDES keying (RFC 4568).** Řádek `a=crypto` nese v čitelném SDP
skutečný master klíč + salt (chráněný jen tím, čím je případně chráněný samotný
signalizační kanál) — protože jde o čistý klíčový materiál, ne opakující se
identitu, **maskuje se jako celek**. Pokud nabídka vyjednává SRTP, je RTP/RTCP
payload v zachytu už šifrovaný text a nikdy se nedešifruje (ani by to bez reálného
klíče nešlo) — anonymizaci podléhají jen hlavičková pole RTP/RTCP diskutovaná výše
(ta SRTP z principu nechává v čitelné podobě, protože jinak by na SSRC/sequence/
timestamp nemohl směrovat žádný middlebox).

<div style="page-break-before: always"></div>

## 6. TLS, HTTP, ostatní L2 protokoly, kontrolní součty, časování

**TLS.** `ClientHello` rozšíření **SNI** se mapuje na stejně dlouhý, syntakticky
platný hostname, konzistentní s případným mapováním stejného jména na DNS vrstvě.
**Encrypted Client Hello (ECH)** se rozpozná i v draftové variantě rozšíření —
vnější (`outer`) ClientHello se parsuje normálně a jeho viditelné `public_name`
SNI se mapuje stejně jako běžné SNI; samotný šifrovaný ECH payload (skrytý vnitřní
ClientHello) se nikdy nepovažuje za opaque blob k zahození — nechává se jako
šifrovaný text a je jako takový v reportu explicitně označený, ne tiše přeskočený.
`ClientHello`/`ServerHello` **random(32)** a `session_id` se maskují (random není
veřejná struktura — v TLS 1.2 může nést čas a slouží jako korelátor session).
Výběr cipher suite, legacy verze a vybrané negotiation extensions
(`supported_versions`, ALPN, …) zůstávají; neznámé extension values a key material
(`key_share`, PSK, …) se maskují. **TLS 1.2 Certificate**
(posílaný ještě v čitelném handshaku): rozpoznatelné CN a SAN dNSName/iPAddress
uvnitř DER se **mapují** stejně jako SNI hostname/IP, zbytek certifikátu (klíč,
podpis, sériové číslo) se maskuje jako opaque bajty se zachovanou strukturou
handshaku. **TLS 1.3** posílá všechno od `EncryptedExtensions` dál (certifikát
včetně) už zašifrované uvnitř Application Data záznamů z principu protokolu —
engine to tedy vůbec nemusí speciálně rozpoznávat, prostě to zůstává čitelně
označené jako šifrovaný text, přesně jak má být.

**Kryptografické vedlejší účinky.** Mapování SNI a Certificate CN/SAN nutně mění
bajty, nad kterými byl počítaný TLS handshake transcript — `Finished` zpráva na
konci handshaku (HMAC/podpis nad celým průběhem) po anonymizaci už neodpovídá
přepočtu. Spolu se STIR `Identity` (kapitola 4) a STUN `MESSAGE-INTEGRITY`
(kapitola 5) jde o tři nezávislé kryptografické kontroly, které anonymizace jako
vedlejší efekt nutně invaliduje — nástroj to nezakrývá, ale hlásí to jako
samostatný stavový signál v exportním reportu (`cryptographic_integrity:
MODIFIED`), oddělený od otázky „jsou síťové checksumy platné" (ty **jsou** vždy
platné, viz níže) — je to explicitní přiznání, co přesně anonymizace stojí navíc
k obyčejnému přepočtu paketů.

**HTTP.** Hlavička `Host` se mapuje stejně jako DNS/SNI; `Cookie`/`Authorization`/
`Set-Cookie` se **maskují** (session tokeny, přihlašovací údaje — nejsou to
opakující se identity, u kterých má smysl zachovávat korelaci). Absolutní časy
`Date` / `Last-Modified` (RFC 1123) se **posunou stejným Δ** jako časové značky
capture (PayloadTimeSession / T14); neparsovatelný tvar se zamaskuje na stejné
délce. Tělo požadavku/odpovědi se řeší fail-closed, nikdy neprochází beze změny
naslepo:

- rozpoznaný strukturovaný obsah (JSON) se projde po jednotlivých textových
  hodnotách — telefonní číslo/IPv4/IPv6/hostname/e-mail se **mapuje** (včetně T15 detektorů
  nad `text/*` HTTP těly a sdíleným textproto toolkitem; binární TBCD/NTLMSSP sdílí T16
  `binproto/` toolkit) na stejně
  dlouhou náhradu, hodnota, která vypadá jako token/heslo/klíč (`Bearer …`, dlouhý
  alfanumerický řetězec), se **maskuje** — v obou případech se zachová přesná
  bajtová délka;
- cokoliv jiného (neznámý/nerozpoznaný content-type, komprimované nebo chunked
  tělo) se **celé zamaskuje na stejné délce** — nikdy neprojde jako čitelný
  plaintext jen proto, že mu nástroj nerozumí.

**Ostatní L2/L3 protokoly pro viditelnost infrastruktury, ne identitu koncového
uživatele.** **VRRP** — mapuje se jen virtuální IP (jediná adresa, která je z
pohledu redundančního protokolu „identita"); verze, VRID, priorita a interval
advertisementů jsou mechanika protokolu, ne identita, zůstávají beze změny, takže
analýza failoveru zůstává validní. **STP/RSTP/MSTP** — mapuje se jen MAC část
Root/Bridge ID; prioritní část i všechny časovače (hello/max-age/forward-delay)
jsou topologické/ladicí parametry, nedotčené, takže konvergence a přebírání role
kořene zůstávají analyzovatelné. **CDP** — Device-ID a VTP doména (identifikující
řetězce) se redigují; MAC vložená uvnitř Device-ID Cisco IP telefonu (formát
`SEP<mac>`) se záměrně mapuje **stejnou** identitou jako reálná Ethernet MAC téhož
telefonu jinde v zachytu, takže „tohle CDP oznámení souseda a tenhle Ethernet rámec
patří stejnému fyzickému telefonu" zůstává korelovatelné.

**Kontrolní součty — shrnutí.** IP hlavičkový checksum, TCP/UDP (pseudo-hlavička),
ICMPv4/ICMPv6, VRRP, CDP — všechny se přepočítávají při exportu, průchodem zevnitř
ven přes případné tunelové zapouzdření (nejdřív vnitřní checksumy, pak vnější,
protože ty pokrývají už opravený vnitřní obsah). Tohle je nezávislé na kryptografických
vedlejších účincích výše — checksum je vždy platný, i když se STIR/STUN/TLS podpis
nad stejnými bajty už nesedí.

**Časování.** Diagnostická úroveň ukotví celý zachyt k novému náhodnému počátku
(`relative`), ale rozestupy mezi pakety zůstávají bajt přesně stejné — RTT, jitter
i analýza retransmisí zůstávají plně validní, ztrácí se jen vazba na reálné
kalendářní datum/čas. Vysoké soukromí nahradí reálné rozestupy syntetickým pevným
krokem (`enumerated`) — časování je pryč úplně, používá se, jen když je i hrubá
časová korelace považována za identifikující. Pořadí paketů se **nemění v žádném
režimu** — přeuspořádání by samo o sobě rozbilo analýzu TCP retransmisí a
reorderingu. Podporovány jsou oba kontejnerové formáty (klasický PCAP i PCAPNG
vč. více sekcí); metadata bloky PCAPNG (jména rozhraní, komentáře) se ve výchozím
nastavení zahazují — mohou nést hostname, uživatelská jména nebo cesty k souborům.

### Diagnostická vs. vysoké soukromí — shrnutí kompromisu

| | **Diagnostická** (výchozí) | **Vysoké soukromí** |
|---|---|---|
| Topologie IP adres | topology-preserving kandidát v pevném `/16` (ne AES Crypto-PAn; kolize → jiný slot) | čistě náhodné, žádný topologický signál |
| Nepodporovaný/poškozený obsah | maskován na místě, paket zůstává | zkrácen / celý paket zahozen |
| RTP/RTCP médium | payload maskován, paket zůstává | **celý paket zahozen** |
| Počet a délka paketů | garantovaně beze změny | zahazování a zkracování očekávané |
| TTL / TCP okno / MSS / volby (otisk OS) | zachováno beze změny | **normalizováno** |
| Časování | `relative` (přesné rozestupy) | `enumerated` (syntetický krok) |
| Heuristický skener neznámého obsahu | zapnutý | **vypnutý** |

Obě úrovně mapují stejné kategorie identit stejným mechanismem (kapitola 1) — liší
se jen v tom, co dělat s obsahem, který nejde bezpečně strukturálně přepsat, jak
moc se drží rozpoznatelná topologie sítě, a jak agresivně se potlačuje otisk
OS/zásobníku a přesné časování.

<div style="page-break-before: always"></div>

## 7. Zpětná obnova (deanonymizace) — princip

Obnova **není** matematická inverze anonymizační funkce a **není** dešifrování. Je
to nezávislý, kompletní paralelní archiv originálního zachytu — indexovaný podle
identity, svázaný s jedním konkrétním anonymizovaným exportem čistě otiskem
(SHA-256), ne šifrováním.

**Co obnovovací soubor obsahuje:**

- **Kompletní doslovnou kopii originálního zachytu** — ne diff proti anonymizovanému
  souboru, ale nezávislý druhý průchod přes originál se všemi originálními bajty.
- **Vyhledávací index** — pro každou anonymizovanou hodnotu (IP, MAC, VLAN, port,
  hostname, SIP Call-ID/uživatel/token, RTP SSRC…) originální hodnotu, originální
  i anonymizované číslo paketu a bajtový rozsah výskytu.
- **Manifest** — originální i anonymizovaný SHA-256 hash a délku, použitou úroveň
  anonymizace.

Export s volbou „obnovovací soubor" vytvoří tenhle obsah jako **druhý, samostatný
soubor** vedle běžného anonymizovaného výstupu; zapnutí volby nijak nemění samotný
anonymizovaný výstup — je bit-identický, ať je obnova zapnutá, nebo ne.

**Nešifrovaný formát je záměrné rozhodnutí.** PCAP recovery v4 i JSON mapping bundle
zůstávají bez šifrování a bez hesla; jeho zavedení se neplánuje. SHA-256 slouží ke kontrole,
že soubory patří k sobě a že obnova odpovídá očekávaným bajtům. Hash ani CRC nezajišťuje
utajení nebo autentizaci proti útočníkovi, který může upravit obsah i kontrolní součty.
Obnovovací soubor je citlivý jako originál a mapping obsahuje původní hodnoty; oba zůstávají
privátní a nikdy nepatří do balíku pro AI nebo externí sdílení.

Protože byla každá substituce interně konzistentní (kapitola 1) a archiv drží
kompletní index originál↔anonymizovaná hodnota + originál↔anonymizované číslo
paketu, jakoukoliv anonymizovanou hodnotu nebo číslo paketu, na které ukáže AI nebo
analytik, jde dohledat **přímo** — ne odhadem, ne hrubou silou — zpátky na přesné
originální bajty a na přesně ty pakety, které je v originále obklopují.

### Workflow: od AI nálezu k originálnímu paketu a jeho okolí

### Výsledek anonymizace (panel + report)

Po analýze (ještě před exportem) aplikace ukáže panel **Výsledek anonymizace**: jednu
souhrnnou větu, AI stav ve třech úrovních (`AI_READY` / `AI_READY_WITH_GAPS` /
`NOT_AI_READY`) a tabulku protokolových rodin se stavem (anonymizováno, zamaskováno
bez analýzy, šifrované ponecháno, vyžaduje zásah, zpracování selhalo) včetně doporučení.
Stejná struktura jde do `.report.json` a `ai-diagnostics.json` jako sekce
`anonymizationOutcome` — včetně kompaktních rozsahů čísel zamaskovaných paketů
(např. `317-320`), aby AI agent věděl, které pakety nemá interpretovat. Originální
hodnoty ani privátní mapa se do panelu ani do reportu nedostanou.

1. Vyexportujeme anonymizovaný PCAP **a** `ai-diagnostics.json` (bezpečný sidecar —
   obsahuje jen anonymizovaná čísla/statistiky a `anonymizationOutcome`, nikdy originální
   hodnoty) a předáme oboje AI nástroji k analýze.
2. AI vrátí nález odkazující se na **anonymizovanou** hodnotu a/nebo číslo paketu
   (např. „podezřelá komunikace na anonymizované IP … v paketu 317").
3. My (kdo má obnovovací soubor, který AI nikdy neviděl) vložíme anonymizovaný
   PCAP **spolu s** obnovovacím souborem zpět do aplikace. Aplikace ověří pár podle
   SHA-256 a jedním „Odemknout" načte a ověří celý index — dál už se nic
   neověřuje opakovaně.
4. Text AI nálezu **vložíme rovnou** do vyhledávacího pole — nemusíme ručně
   vybírat, jde o IP, MAC, Call-ID nebo číslo paketu. Nástroj si sám z textu
   vytáhne všechny rozpoznatelné hodnoty a dohledá je v indexu.
5. Pro každou nalezenou hodnotu se zobrazí originální hodnota **a** číslo paketu
   (přepočtené originální↔anonymizované číslování — u vysokého soukromí se liší,
   protože zahozené pakety číslování posouvají). Kliknutím na „Otevřít originální
   paket" se otevře stejný side-by-side (originál/anonymizováno) pohled jako
   v běžném editoru — **a odsud už procházíme okolní pakety normálně**, přesně
   pro dohledání kontextu kolem nálezu.
6. Lze také stáhnout mini-capture jen daného paketu, nebo kompletně obnovit celý
   originální soubor (vždy ověřeno délkou a SHA-256 proti manifestu, než se
   nabídne ke stažení).

**Jak úplná je obnova.** Se správným párem jde obnovit originál **bajt po bajtu**,
včetně všeho, co „Vysoké soukromí" v anonymizovaném souboru trvale smazalo
(zahozená RTP média, zkrácený obsah, normalizovaný TTL/TCP otisk) — obnovovací
soubor totiž nevychází z anonymizovaného výstupu, takže se ho tahle ztráta netýká.
Jediné, co je skutečně nevratné: obnovovací soubor se při exportu vůbec
nevygeneroval, nebo se ztratil či oddělil od svého páru. U hodnot exportovaných
jako sdílená fixní maska (ICE hesla, šifrovací klíče, STIR/STUN podpisy, neznámé
vendor hlavičky) vyhledávání podle hodnoty vědomě odmítne uhodnout, které originály
se za maskou skrývají — ale originální bajty daného paketu zůstávají plně dostupné
otevřením paketu podle jeho čísla, jen ne přes textové vyhledávání masky.
