# Jak anonymizujeme síťový záchyt

Zachováváme vztahy potřebné pro diagnostiku a odstraňujeme obsah, který k ní není nutný. Technicky jde o **diagnostickou pseudonymizaci a sanitizaci**, nikoli o důkaz nevratné anonymizace: časování, délky, graf komunikace nebo otisk zařízení mohou stále umožnit korelaci s jiným zachytem.

Celý průchod probíhá lokálně v prohlížeči: **načtení → rozpoznání vrstev a identit → společné mapování → plán zásahů → kontrola → export**. Níže sledujeme tento průchod od souboru až k bajtům, které skutečně předáme dál. Popis odpovídá implementaci; rozpoznaný název protokolu sám neznamená, že umíme strukturovaně zpracovat všechny jeho varianty.

## Nejdřív rozhodneme, jakou diagnostiku chceme zachovat

Výchozí úroveň **Diagnostické pro AI** zachovává pořadí a délky paketů i relativní časové rozestupy. Posune absolutní počátek záchytu, ale ponechá podklady pro RTT, jitter a retransmise. Zachovává také TTL, TCP window, MSS a další TCP options. Identifikátory se mapují; nerozpoznaný nebo poškozený aplikační obsah se zpravidla přepíše výplní stejné délky. Zachovaný otisk síťového stacku a část topologických vztahů jsou vědomou cenou za diagnostickou hodnotu.

Úroveň **Vysoké soukromí** používá syntetické pořadové časování, potlačuje původní vztahy adres a normalizuje síťový otisk. Nepodporovaný obsah ořezává, poškozené pakety a hlasová média RTP/RTCP zahazuje podle politiky. Může proto změnit počet i zachycenou délku paketů; z takového výstupu už nelze vyvozovat původní RTT nebo úplnost mediálního toku. Ani tato úroveň neskrývá automaticky všechny provozní vztahy a nerozšifrovává provoz.

Obě úrovně jsou pevně definované v `src/pcap/profile/pcapAnonymizationLevel.ts`. Textové profily s vlastními pravidly jsou samostatný mechanismus; nemění tyto dvě PCAP politiky.

## Ze souboru nejprve odstraníme kontejnerové identifikátory

Čteme classic PCAP 2.4 v obou pořadích bajtů a s µs/ns časováním i PCAPNG s více sekcemi a rozhraními. Kontejner může prozradit informace ještě před prvním paketem: například komentáře, překlady jmen nebo dešifrovací tajemství. Z PCAPNG proto odstraňujeme NRB, DSB, ISB a komentáře; výstup není bezeztrátovou kopií původních metadat.

Soubor zůstává lokální. Pracovník prohlížeče čte paketové bajty po omezených dávkách a uchovává popisy záznamů, nálezy a plán zásahů. Náhled a export si potřebné bajty znovu načtou ze zdrojového souboru. Nemusíme kvůli každému panelu držet další úplnou kopii zachytu.

Příponu neposuzujeme izolovaně: `.gz` se rozbalí lokálně a limity se vztahují na **rozbalenou velikost**. PCAP má limit 100 MiB; textový log 90 MiB a 400 000 řádků. ZIP/TAR/TAR.GZ support bundle má navíc limity počtu položek, cest a celkového rozbalení; vynechané položky se hlásí. Šifrovaný ZIP, ZIP64, vnořené archivy a xz/bzip2/zstd nepodporujeme. Export archivu používá anonymní názvy a `REPORT.json`; gzip jméno, komentář a mtime nejsou součástí rozbaleného originálu pro náhled a obnovu.

## Rozpoznáme pole a přidělíme jim společné identity

Nestačí nahradit IP adresy v Ethernet/IP hlavičce. Stejná adresa může být v SIP URI, SDP, DNS odpovědi, ICMP citaci nebo uvnitř tunelu. Dekodéry proto procházejí vrstvy, rozpoznávají aplikační zprávy a evidují konkrétní rozsahy bajtů, jejich význam a požadovanou ochranu. Port je vodítko; používáme také obsah a stav toku, například SDP pro rozpoznání RTP.

**Mapování** přidělí identitě stabilní pseudonym. Tentýž rozpoznaný účastník se tak dá sledovat přes související zprávy. Kategorie jsou oddělené: IP adresa, telefon, Call-ID, SSRC nebo rádiové ID nejsou jedna společná číselná doména. U relačních identifikátorů může být součástí klíče také endpoint nebo generace relace, aby opakovaně použité číslo nespojilo nesouvisející hovory. Čistě číselný SIP user se bez telefonního kontextu automaticky neslučuje s `tel:`.

Společnou autoritu drží `src/mapping/mappingAuthority.ts`. Soubory zpracované společně mohou sdílet mapu, samostatné relace mohou dostat jiné aliasy. Konzistence platí v rámci kategorie a reprezentace: binární IPv4 má vždy čtyři bajty, ale textová adresa v SIP může mít pevně omezený počet znaků. Pokud se základní alias do pole nevejde, používá se délkově vyhovující reprezentace; neslibujeme proto vždy doslova stejný řetězec v binární hlavičce a textu. Vazbu reprezentací eviduje mapovací autorita.

**Maskování** naproti tomu původní obsah přepíše bez nároku na jedinečný pseudonym. Používá se pro hesla, klíče, média a neprůhledná těla. `maskFill` je deterministická výplň založená na FNV a xorshift, nikoli šifra ani CSPRNG. Stejná maska není důkaz totožnosti původních hodnot a nelze podle ní jednoznačně dohledat účastníka.

Konečné aliasové domény popisuje `mappingDomainRegistry`. Například jeden IPv4 blok /16 nabízí 65 536 pozic před omezeními; to je méně než obecný strop 500 000 identit a topologické či délkové podmínky prostor dále zmenšují. Alokátor řeší kolize a nepřipouští tichý návrat originálu při vyčerpání: nemožná bezpečná náhrada se musí projevit incidentem nebo ochranným zásahem.

## Paket projdeme od linkové vrstvy až do tunelu

### Ethernet, sousedé a linkové řízení

**Ethernet a ARP:** běžné unicast MAC dostanou lokálně spravovaný alias `02:…`, zbývající část se vybírá pomocí CSPRNG. Protokolové broadcast/multicast konstanty a virtuální VRRP MAC se zachovávají. ARP používá stejné mapy MAC a IP jako ostatní vrstvy, takže se nerozpojí vazba mezi dotazem, odpovědí a následným IP provozem. Ethernet, Linux SLL/SLL2, raw IPv4/IPv6 a NULL/LOOP jsou různé vstupní obálky nad stejným dalším průchodem; u neznámého typu se nepředstírá dekódování.

**VLAN/QinQ, STP, CDP, LLDP a LACP:** VLAN ID 1–4094 se mapují se zohledněním kontextu, PCP/DEI a rezervované 0/4095 zůstávají. STP bridge/root MAC a CDP Device-ID včetně tvaru SEP-MAC se chrání. LLDP mapuje chassis/port/system identity a inventární údaje, polohu vždy maskuje. LACP mapuje Actor/Partner System MAC a zachovává porty, priority a stavové příznaky. Neznámé varianty nebo citlivý volný popis dostávají odpovídající masku.

**PPP/PPPoE a EAPOL/802.1X:** session/peer identity, IPCP adresy a EAP Identity se nahrazují; hesla PAP, challenge/response CHAP, nonce, MIC a klíčový materiál se maskují. Kódy vyjednávání zůstávají pro diagnostiku. Komprimovaný PPP nebo tělo EAP-TLS/PEAP/TTLS bez úplného dekódování nepovažujeme za zpracovaný plaintext.

**802.11/Radiotap a Bluetooth/BLE:** mapují se MAC/BD_ADDR, SSID a názvy zařízení, zatímco kanál a RSSI mohou zůstat. GPS/vendor metadata, WPS/SAE a SMP klíče se maskují; chráněné bezdrátové tělo se nerozšifrovává. Vysoké soukromí navíc maskuje SSID v Probe Request. Rozlišení BLE privátní adresy bez IRK ani úplné zpracování všech agregací 802.11 neslibujeme.

### IP, ICMP a zapouzdření

**IPv4:** privátní adresy se mapují do `10.254.0.0/16`, veřejné do `198.51.0.0/16`. Diagnostika používá topology-preserving kandidát a alokaci v /24 koších uvnitř cílového /16, aby držela implementované vztahy prefix–host i při kolizích; jde o vlastní mechanismus, ne standardní AES Crypto-PAn ani úplné zachování libovolné subnetové topologie. Vysoké soukromí používá alokaci bez této vazby. Unspecified, broadcast a IPv4 multicast mají pravidla zachování. Cílový `198.51.0.0/16` nelze celý zaměňovat s dokumentačním `198.51.100.0/24`; export není určen k odesílání do skutečné sítě.

**IPv6:** běžná link-local adresa dostává ULA alias pod `fd00::`, ostatní běžné unicast identity alias pod `2001:db8::`; přechodové tvary mají vlastní postup. IPv4-mapped, NAT64, 6to4, ISATAP a Teredo respektují vloženou adresní identitu. EUI-64 a solicited-node multicast se zpracovávají s vazbou na alias MAC/IP, včetně MAC `33:33:ff:…`. Neplatí obecné pravidlo, že celý multicast `ff00::/8` zůstává původní.

**ICMPv4, ICMPv6 a NDP:** chráníme také adresy v citovaných původních paketech a v sousedských zprávách, nikoli jen vnější hlavičku. Po úpravě citovaného IP/transportu se nejprve opraví jeho checksum a až potom součet vnějšího ICMP. Diagnostický typ a kód zprávy tak mohou zůstat použitelné bez původních identit.

**IP-in-IP, GRE, VXLAN, Geneve, L2TP, MPLS, ERSPAN, PBB a NFLOG:** rozpoznané vnější i vnitřní vrstvy předáváme stejným handlerům. Mapují se příslušné VNI, labely nebo tunnel/session ID; citlivé a neznámé options/AVP/TLV se maskují. ERSPAN předává zrcadlený Ethernet, L2TP data PPP a NFLOG rozpoznaný IP obsah; PBB zachovává I-SID a mapuje zákaznické MAC. Hloubka tunelového průchodu je omezena na 4. Neznámý pseudowire, hlubší zanoření nebo nerozpoznané zapouzdření je omezením pokrytí. U MACsec chráníme čitelnou SCI/MAC; samotná přítomnost MACsec nedokazuje utajení, protože existuje i režim integrity bez šifrování.

**OSPF, BGP, IS-IS, EIGRP, RIP/RIPng, LDP, PIM, IGMP, BFD, VRRP a HSRP/GLBP:** mapují se implementované router/area/system ID, ASN, virtuální IP, next-hop nebo skupinové adresy. Autentizační pole a neznámé LSA/TLV/NLRI se maskují; u RIPng a PIM je velká část těla maskovaná. BFD ponechává diskriminátory a maskuje autentizaci. Zachování hlavičky nelze chápat jako úplnou anonymizaci všech směrovacích záznamů ani garanci oprav všech protokolových digestů; například plný LSA/LSP slovník a Fletcher ověření nejsou pokryté.

## Transport zachováme tak, aby stále vysvětloval průběh toku

**UDP a TCP:** porty neposuzujeme pravidlem „pod 1024 se nemění“. Katalog známých služeb a rozpoznaný obsah rozhodují, co potřebujeme zachovat pro disekci. Dynamické porty se mapují; RTP/RTCP porty se permutují po dvojicích, takže vztah **RTCP = RTP + 1 zůstává zachovaný**, pokud jde o takto vyjednanou dvojici. Stejné vazby se promítají do SDP a ICE `raddr/rport`. Diagnostika zachovává také obsahově rozpoznaný signalizační port, vysoké soukromí jej může permutovat.

IPv4 ID a IPv6 flow label se pseudonymizují, ve vysokém soukromí se flow label normalizuje. TCP seq/ack/SACK dostávají konzistentní posun modulo 2³² podle směru toku, aby šlo dál sledovat potvrzování a retransmise. Vysoké soukromí navíc normalizuje TTL, window a TCP options včetně MSS/Window Scale; proto už původní otisk stacku nezůstává diagnosticky věrný. TCP MD5/AO se maskuje, bez klíče nelze obnovit autentizaci.

**SCTP:** transportní průchod podporuje předávání úplných DATA zpráv aplikačním handlerům podle PPID a kontextu. Segmentace vyžaduje omezené skládání; chybějící nebo nepodporované fragmenty neznamenají strukturovaně zpracovaný aplikační obsah. Pro podporovanou úpravu se opravuje CRC32c.

Fragmentovaný IP datagram nebo SIP/HTTP zpráva přes více TCP segmentů se nejprve skládá v omezeném bufferu. Náhrady se následně promítají zpět do původních segmentů, včetně retransmisí; nepřepisujeme tok na nově sestavenou konverzaci. Neúplný záchyt, konfliktní překryv nebo překročení limitu vede podle úrovně k masce, oříznutí či zahození. Typické limity jsou 256 současných toků a 256 KiB na tok; nejde o neomezený síťový reassembler (`src/pcap/reassembly/limits.ts`).

## U hlasového hovoru propojíme signalizaci s médii

Představme si SIP INVITE s SDP a následný RTP tok. IP v hlavičce, host v Contact, adresa v SDP `c=` a příslušný mediální endpoint musí projít společným mapováním. Call-ID a tagy mají držet dialog pohromadě, ale jméno volajícího, heslo nebo hlas se předávat nemají. Tím se řídí i následující protokolové handlery.

**SIP:** mapujeme URI user/host/telefon, Call-ID, From/To tagy a Via branch včetně hlaviček Contact, Route/Record-Route, Refer/Reply-To, P-identity, Diversion/History-Info a Path/Service-Route. Zobrazovaná jména se maskují, včetně neuzavřených jmen a escapovaných uvozovek; chráníme i identifikátory se zanořenou IP. Metody, statusy, CSeq a struktura transakcí zůstávají. Digest autentizace, STIR/SHAKEN Identity, identifikující User-Agent/Server/Organization a citlivá geolokační pole se chrání maskou nebo specializovaným handlerem; Supported/Require/Privacy zůstávají pro vyjednávání. Změněný podpis STIR už není původní platný podpis.

SIP tělo zpracujeme podle Content-Type: SDP strukturovaně, multipart po jednotlivých částech. SIPREC metadata, neznámé nebo poškozené části a nepodporované SIP-I ISUP tělo se maskují na původní délce a vykazují omezení. Částečný sipfrag nemá automaticky plnou podporu. Discovery i export vycházejí ze stejných rozpoznaných rozsahů.

**SDP a ICE:** mapujeme adresy v `o=`/`c=`, mediální porty, candidates a related address/port; kodeky a směry média zůstávají. Username v `o=` se chrání a session-id se nahradí číslem stejné délky v kategorii `sdp-session-id`. Session-version se posouvá o stejnou konstantu v rámci session; přírůstky v re-INVITE zůstávají čitelné modulo danou číselnou šířku. ICE ufrag/pwd a SDP crypto klíče se maskují.

**STUN/TURN:** mapujeme rozpoznané adresní atributy včetně XOR-MAPPED, chráníme USERNAME/REALM a maskujeme tajné hodnoty. Po změně zprávy nelze bez klíče obnovit MESSAGE-INTEGRITY; označení kryptografické integrity se liší od stavu běžného síťového checksumu.

**RTP/RTCP a SRTP:** mediální klasifikace využívá SDP a tokový kontext, nikoli jen podobnost náhodného UDP s RTP hlavičkou. Diagnostika mapuje SSRC/CSRC společně pro RTP i RTCP, zachovává RTP sequence/timestamp a RTCP SR/RR statistiky ztrát, jitteru a časování. RTP payload včetně DTMF a citlivých extension se maskuje na místě; „strip-payload“ v této úrovni neznamená zkrácení paketu. RTCP chrání SDES, BYE reason a soukromá APP data. Vysoké soukromí zahazuje hlasová média RTP/RTCP podle politiky. SRTP nerozšifrováváme a signalizované klíče maskujeme; z RTP timestampu ani RTCP časových polí neslibujeme odstranění všech časových otisků.

**MGCP a H.248:** MGCP přes UDP 2427/2727 zachovává verb, transaction ID, status a známé codec/QoS parametry. Mapuje endpoint host, IPv4/IPv6 NotifiedEntity, CallId/ConnectionId/RequestIdentifier a caller ID; maskuje DTMF, klíče, volný text a DigitMap literály mimo znakové třídy jako `[2-9]`. Zpracuje vložené SDP i piggyback zprávy. TCP bez podporovaného framingu se hlásí jako `unsupported:mgcp`. Textový H.248/MEGACO mapuje MID IP/host, maskuje číslice a zpracovává Local/Remote SDP; binární ASN.1 varianta se jen identifikuje a maskuje. SSDP a H.248 mají strukturovanou podporu pro konkrétní implementované varianty, nikoli pro všechny možné tvary.

**RTSP, IAX2, Skinny a H.323:** RTSP mapuje URI, Session a transportní porty, chrání auth a předává SDP; interleaved `$` rámec sám nedokazuje RTP. IAX2 chrání čísla/jména a autentizaci a maskuje hlas. Skinny mapuje SEP MAC/IP, CallInfo identity a mediální endpointy, keypad a neznámé zprávy maskuje. H.323 zpracuje Q.931 čísla/display a cause, ale H.225/H.245 PER bez příslušného schématu maskuje; úplné mediální párování neslibuje.

**CSTA/uaCSTA, Asterisk AMI/ARI a MRCPv2:** XML CSTA mapuje device/call/monitor identity a drží implementované vazby monitorování; ASN.1 ROSE/ACSE varianta je mask-only. AMI zachovává Action/Event/Response a mapuje channel/call identity, tajemství a neznámé hodnoty maskuje. ARI používá HTTP/JSON ochranu ID a maskování api_key i media URI. MRCPv2 zachovává metodu, stav a příčinu dokončení, mapuje session část Channel-Identifier a vždy maskuje rozpoznávaný text, gramatiky, SSML/NLSML, voiceprint i waveform URI.

**MCPTT, MSRP, BFCP, ZRTP a T.38:** MCPTT identity se mapují, poloha a DTMF maskují. MSRP chrání path/Message-ID/CPIM identity a maskuje zprávu; BFCP mapuje conference/user/floor ID. ZRTP mapuje ZID/client a maskuje handshake tajemství, takže po zásahu není provozně funkční. T.38 ponechává sekvenci a maskuje faxová IFP/page i FEC data bez přepočtu parity; úplné T.30 mapování TSI/CSI není součástí podpory.

**Q.921/LAPD, Q.931/QSIG a IUA:** mapujeme TEI, call reference se zachováním směrového bitu, telefonní čísla a display. QSIG Facility má omezenou množinu ROSE operací pro jména, transfer a diversion; ostatní argumenty, User-User a keypad se maskují. IUA předává podporovaná Protocol Data do Q.931/LAPD a mapuje interface identity. FCS upravujeme jen tehdy, když je jeho přítomnost doložená.

## Stejný princip použijeme na ostatní aplikační protokoly

Následující přehled popisuje rozpoznané varianty zejména v diagnostické úrovni. Vysoké soukromí nad nimi může uplatnit přísnější masku, oříznutí či zahození; přesné varianty a výjimky eviduje referenční matice ve zdroji `src/pcap/docs/protocolSupportMatrix.ts`. U každé rodiny rozlišujeme konkrétní zpracované pole od těla, které pouze odstraníme.

### Jmenné služby, správa a telemetrie

**DNS/mDNS a LLMNR:** délkově stabilně mapujeme jména a A/AAAA adresy, aby zůstaly čitelné dotazy, odpovědi a vazby na IP. **DHCPv4/v6** mapuje rozpoznané adresy, hostname a klientské identifikátory; parametry lease a typ zprávy ponechá, ostatní options (vendor, relay agent, URL, cíle statických tras, delegované prefixy) maskuje. **NBNS/NetBIOS** dekóduje first-level jména, mapuje IP/MAC včetně zdrojové IP datagramu; vadné nebo nepodporovaně kódované jméno dostane bezpečný zakódovaný náhradní tvar, neznámý datagramový obsah masku. **SSDP** chrání HOST/LOCATION/USN a maskuje SERVER; **WS-Discovery** mapuje UUID a rozpoznané URL, ale neslibuje úplné pochopení libovolného obsahu Scopes.

**Syslog** mapuje hostname a posouvá jednoznačný čas. Volný text MSG a hodnoty STRUCTURED-DATA (kromě mapované IP a hostname) by textové detektory nepokryly — vlastní jména a identifikátory nepoznají — proto je PCAP export maskuje v obou úrovních; čitelný log anonymizujte v textovém režimu. **SNMP** maskuje community/auth/priv, mapuje sysName a engine-id, neznámé OCTET hodnoty maskuje; bez klíčů nečte authPriv PDU. **NTP** posouvá rozpoznané timestamps, mapuje nebo maskuje refid podle významu a maskuje digest i control body. **TFTP** chrání filename a maskuje DATA/ERROR text; transfer sleduje i přes vyjednaný TID.

**NetFlow v5, NetFlow v9/IPFIX a sFlow:** adresy a porty se mapují stejně jako v paketech, ASN/agent identity se chrání a diagnostické čítače mohou zůstat. IPFIX používá šablony v rámci exportní domény; bez šablony a u neznámého enterprise IE maskuje hodnotu. sFlow předává vzorkovanou Ethernet hlavičku stejnému enginu. Chybějící bajty ve zkráceném vzorku nepředstíráme jako kompletní paket; IPFIX TCP/SCTP framing není pokrytý touto variantou.

### Web, přihlašování a šifrované přenosy

**HTTP/1.x:** Host se mapuje, citlivý request target, Referer, User-Agent, Authorization a Cookie se maskují; Date/Last-Modified se posouvají společnou časovou deltou nebo maskují. JSON tělo používá strukturovanou ochranu identit a secrets. HTML/XHTML se celé maskuje v obou úrovních; u ostatních text/* je diagnostická ochrana heuristická a vysoké soukromí maskuje celé tělo. Nezpracovatelný typ, komprese nebo chunking spustí ochranný zásah.

**HTTP/2, WebSocket a gRPC:** u čitelného h2c zachováváme frame headers, HPACK blok se bezpečně maskuje, protože obecný délkově stabilní HPACK rewrite nemáme. WebSocket payload se odmaskuje, zpracuje jako podporovaný SIP/JSON a znovu maskuje; permessage-deflate bez dekódování dostává ochrannou masku. gRPC zachovává framing, ale bez schváleného `.proto` maskuje protobuf message bytes. HTTP/2 přes TLS ani WSS se tímto postupem nerozšifrují.

**TLS:** z čitelného handshake chráníme SNI, rozpoznané CN/SAN certifikátu, random/session ID a klíčový materiál; verze, cipher a ALPN mohou zůstat. Zašifrovaná application data lze ponechat jako ciphertext jen při doložené fázi protokolu. ECH a zašifrované TLS 1.3 certifikáty zůstávají neprůhledné; změna handshake navíc ruší původní kryptografické vazby. **DTLS** má omezený UDP handshake parser včetně jednoho úplného ClientHello, nikoli skládání celého flightu přes datagramy; nepodložené app data maskuje. **QUIC** mapuje CID a maskuje chráněný payload Initial: jeho klíče jsou veřejně odvoditelné, takže samotné označení „encrypted“ by nestačilo.

**SSH, IKE/IPsec, OpenVPN a WireGuard:** SSH může zachovat KEXINIT a diagnostický banner, ale klíče/signatury a obsah bez důkazu šifrovací fáze maskuje. IKE maskuje identity, certifikáty, auth, KE/nonce a NAT detekci; rozpoznané IKEv2 SK může klasifikovat jako šifrované. ESP bez znalosti SA je mask-only, protože existuje i NULL encryption; AH neposkytuje utajení. OpenVPN mapuje session-id a zpracuje čitelný control TLS, ostatní payload bez důkazu AEAD maskuje. WireGuard maskuje handshake pubkeys/MAC a pozitivně rozpoznaná transportní AEAD data může ponechat jako ciphertext. Port nebo zdánlivě náhodné bajty samotné nejsou důkaz ochrany.

**RADIUS, TACACS+, Diameter, LDAP/CLDAP a Kerberos:** mapují se uživatelé, host/realm, session a účastnické identity; autentizační materiál se maskuje. RADIUS chrání NAS/Station a předává podporované EAP; TACACS+ obfuskované tělo maskuje a nepovažuje MD5 pad za doložené šifrování. Diameter maskuje neznámé AVP. LDAP chrání DN a známé atributy, bind/password i neznámé atributy maskuje a umí předat NTLMSSP. Kerberos mapuje principal/realm, zachovává etype/kvno/error-code a maskuje EncryptedData i neznámá PA-DATA; tickety po zásahu nejsou přihlašovací materiál. StartTLS/LDAPS přechází do příslušné TLS cesty, nikoli do dešifrování.

### Podnikové aplikace, vzdálený přístup a zařízení

**SMTP, IMAP, POP3, FTP a Telnet/rlogin:** chráníme adresy či uživatele, hesla a autentizační výměny maskujeme. SMTP DATA a IMAP FETCH literals se maskují, FTP mapuje vyjednávané datové IP/porty a maskuje cesty i datový kanál, Telnet ponechává řídicí IAC kódy a maskuje uživatelský obsah. Šifrované varianty se řeší jako TLS. Podpora SMTP uvnitř PCAP neznamená podporu samostatných MIME/`.eml` souborů.

**SMB2/3, DCE/RPC, portmapper/rpcbind, NFS a iSCSI:** mapují se session/tree/GUID, UNC, AUTH_SYS hostname, známé názvy a IQN. Hesla, NTLM/SPNEGO auth materiál, file handles a přenášená data se chrání; RPC stub bez IDL a nepodporované NFS operace se maskují. Portmapper může dodat hint pro navazující dynamický port. SMB1 je identify+mask; SMB3 encryption transform používá vlastní klasifikaci. iSCSI maskuje CHAP a Data-In/Out, úplné přepočty všech vyjednaných digestů neslibujeme.

**RDP, VNC, X11, IPMI, Citrix a Intel AMT:** zachováváme rozpoznané negotiation/status hlavičky, chráníme mstshash, desktop name či RAKP username a maskujeme autentizaci, obraz, vstupy nebo neprůhledný obsah. X11 maskuje MIT-MAGIC-COOKIE a post-setup tělo. Citrix ICA/CGP je pouze identify+mask. AMT využívá HTTP ochranu; plné schéma SOAP příkazů nemá. Ani IPMI suite None nelze označit za šifrovaný obsah.

**PostgreSQL, MySQL/MariaDB, TDS/MS SQL, Redis a MongoDB:** chráníme rozpoznané user/database/host/session identity a vždy maskujeme auth a výsledková data. SQL cesta zpracovává literály; nepodporovaný nebo nejednoznačný příkaz může být maskován celý. Redis zachovává příkaz, v diagnostice mapuje klíče a maskuje hodnoty. MongoDB zachovává OP_MSG hlavičku, ale BSON bez schématu a komprimovaný obsah maskuje; nejde o anonymizaci libovolných dokumentových polí.

**MQTT, CoAP, AMQP 0-9-1, Kafka, NATS, STOMP a XMPP:** chráníme client/user, topic/subject/destination, token nebo JID a maskujeme přihlašovací tajemství. Podporovaná těla procházejí JSON ochranou, ostatní maskou; XMPP message body se maskuje. Hlavičky příkazů či korelace mohou zůstat, ale komprese, neznámé properties a nepodporované varianty se neschovají pod označení plná podpora. **GELF, Fluent Forward a OTLP** obdobně chrání podporovaný JSON/MessagePack; GELF chunky/komprese a OTLP protobuf bez schématu se maskují.

**Modbus/TCP, IEC 60870-5-104, DNP3 a OPC UA:** provozní hodnoty registrů, cívek či objektů se maskují, rozpoznané adresní identity se mapují a funkční kódy, typy či cause zůstávají pro diagnostiku. DNP3 má přepočet CRC-16. OPC UA chrání endpoint/cert/nonce a rozpoznaný RequestHeader; plné schéma služeb ani libovolný SignAndEncrypt kanál neumí číst. **CWMP/TR-069 a USP/TR-369** mapují device/session identity a chrání parametry podle rozpoznaného významu; credentials, konfigurace a neznámý nebo neplaintext obsah se maskují, bez stahování firmwaru nebo kontaktování řadiče.

### Operátorská signalizace, rádio a záchytové obálky

**M3UA/SIGTRAN, S1AP, NGAP a NAS EPS/5GS:** M3UA mapuje point codes, SCCP GT, ISUP čísla a rozpoznané IMSI/IMEI/MSISDN; auth, SMS/USSD a polohu maskuje. Nepodporované M2UA/SUA a neúplně složené zprávy nemají plnou analýzu. S1AP/NGAP používá omezený inventář APER procedur a IE: mapuje UE identifikátory a podporované TEID/transportní adresy, předává NAS a maskuje SecurityKey, polohu, transparentní RRC a neznámé IE. NAS chrání IMSI/IMEI/GUTI/TMSI, maskuje auth a polohová pole, šifrované části nerozšifruje a SUCI považuje za skrytou identitu k masce. Nejde o úplný ASN.1 katalog LTE/5G.

**GTP, PFCP a 5G SBI:** GTP mapuje TEID, účastnické identity a adresy; GTP-U předává vnitřní IP/Ethernet do stejného průchodu, neznámé IE a polohu maskuje. PFCP drží endpointově a generačně vymezené CP/UP F-SEID vazby odděleně od TEID, mapuje Node/UE/F-TEID a maskuje SDF/PFD i neznámá IE. SBI zpracuje vybranou množinu čitelných HTTP/JSON operací a typed multipart N1/N2, chrání SUPI/NF/session a maskuje tokeny, auth vektory i polohu. TLS samo nezpřístupní SBI JSON a automatické vazby při libovolném failoveru se neslibují. **SMPP** mapuje systémové identity, source/destination a message/SAR ID, hesla a celé SMS tělo maskuje.

**DMR, MOTOTRBO a GSMTAP:** DMR Homebrew/MMDVM `DMRD` handler mapuje zdrojové/cílové 24bit radio/talkgroup ID, ale **ponechává AMBE hlas a nemapuje automaticky všechna zbývající pole hlavičky**. Hlas se vykazuje jako `preserved-unsafe`; nelze tedy tvrdit, že tento handler odstranil obsah hovoru. MOTOTRBO IPSC má omezenou identifikaci a best-effort redakci payloadu, bez úplné veřejné specifikace. GSMTAP zachovává rozpoznaná měřicí pole a předává podporovaný LTE NAS, ostatní typy hlásí a maskuje. RND Dispatch Lite a Echo UDP jsou syntetické/demonstrační handlery, nikoli důkaz podpory skutečného proprietárního formátu.

**HEP/EEP a TZSP:** mapujeme také metadata záchytové obálky, tedy IP/port/capture/correlation nebo sensor MAC. HEP předává podporovaný SIP obsah jeho sanitizeru, TZSP předává rozpoznaný vnitřní rámec. Komprimovaný HEP payload, neznámé tagy nebo nespecifikovaný obsah se maskují; anonymizace jen vnějšího UDP by zde nestačila.

## Z rozpoznaných zásahů sestavíme jediný plán pro náhled i export

Discovery eviduje rozsahy, identity a potřebné operace. Po uzavření společné mapy se z nich sestaví neměnný plán: paket ponechat s náhradami, maskovat rozsah, oříznout nebo zahodit. Produkční cesta využívá zmrazené výsledky rozpoznání; při exportu se nesmí znovu náhodně přidělovat aliasy ani ztratit dříve rozhodnuté ochranné oříznutí. Plán i incidenty sdílí náhled a export (`processingPipeline.ts`, `deterministicPlanBuilder.ts`, `export/planSnapshot.ts`).

Bajtové náhrady na místě mají stejnou délku jako původní pole. Proto zpravidla není nutné měnit TCP segmentaci nebo Content-Length; maskovaný HTML dokument má například pořád stejný rozsah, jen jiný obsah. Při oříznutí se zmenší zachycená délka záznamu, zatímco délka původního paketu na drátě zůstává metadatem. Oříznutý záznam tak není nově vytvořený kratší síťový paket.

Po aplikaci změn opravujeme podporované kontrolní součty **od vnitřních vrstev k vnějším**, včetně pseudoheaders a vloženého IP v ICMP. Rozlišujeme původně platný/neplatný součet, pravděpodobný checksum offload, chybějící nulový UDP checksum i stav neověřitelný kvůli neúplnému záchytu. Ne každý checksum lze ověřit a oprava IP/TCP/UDP či CRC není opravou aplikační autentizace.

Kryptografické podpisy, HMAC a autentizační tagy po změně jejich vstupu nelze obnovit bez klíče: STIR, STUN MESSAGE-INTEGRITY, TLS integrita a další takové vazby mohou být označené **MODIFIED**. To je očekávaný důsledek sanitizace, nikoli samo o sobě únik. Export má vysvětlovat průběh komunikace; není určen k přehrání funkční přihlašovací nebo mediální relace.

## Nakonec ověříme výsledek a pojmenujeme, co neumíme zaručit

Pokrytí vede ke konkrétním rozsahům, nikoli jen k seznamu názvů protokolů. Rozlišujeme strukturovaně zpracované pole, maskovaný/oříznutý obsah bez plné analýzy, doložený ciphertext a obsah ponechaný bez dostatečné ochrany. Heuristický detektor zůstává heuristikou, i když našel některé IP nebo telefony. Neznámý obsah v diagnostice dostává `maskFill`; ve vysokém soukromí se ořezává či zahazuje podle politiky. Chyba handleru vyvolá ochranný zásah a incident bez originálních hodnot (**fail-closed**), nikoli tiché ponechání problematického obsahu.

Kontroly kombinují pokrytí, hledání známých uniklých hodnot, nepovolená metadata a invarianty zvolené úrovně. **AI_READY** říká, že tyto kontroly prošly; není zárukou odstranění všech osobních údajů. **AI_READY_WITH_GAPS** znamená chráněný výstup s diagnostickými mezerami nebo incidenty, například s maskovaným nepodporovaným tělem. **NOT_AI_READY** upozorňuje na možnou expozici, chybu nebo nesplněnou kontrolu. Samotný text štítku „Anonymizováno pro analytické účely, zkontrolujte“ nerozšiřuje podporu a nenahrazuje kontrolu doporučení. Případné potvrzení rizikového exportu obsah neopravuje.

V dialogu Výsledek kontrolujeme rodiny, počty a incidenty. Jeden SIP paket s SDP patří do více rodin, takže součty rodin nejsou počtem unikátních paketů. „Zobrazit pakety“ otevře odpovídající filtr. Vlevo je citlivý originál, vpravo skutečný exportní výsledek; výběr i posun příslušných panelů se synchronizují. „Pozice 34 B · délka 803 B“ znamená bajty 34 až 836 včetně, počítané od nuly; ve spodním panelu jsou offsety hexadecimálně. Strom vysvětluje strukturu a Změny ukazují zásahy. Zelená síťová hlavička sama nepotvrzuje ochranu aplikačního těla.

Report a `ai-diagnostics.json` obsahují anonymizované statistiky, `anonymizationOutcome`, incidenty a omezení. Ke sdílení vybíráme zkontrolovaný export a případně tento report. Přesné varianty handlerů, ochranné režimy a jejich omezení zůstávají dohledatelné ve zdroji `src/pcap/docs/protocolSupportMatrix.ts` (`npm run docs:protocol-matrix`). Tento souvislý výklad záměrně matici neopakuje.

## K originálu se vracíme odděleně od sdíleného záchytu

Volitelný `.rnd-pcap-recovery` v4 obsahuje úplné původní bajty, index, profil a manifest s rozměry a SHA-256. **Je nešifrovaný a bez hesla**, proto se neposílá společně s anonymizovaným záchytem. Umožní obnovit i oříznuté/zahozené pakety a celý originál; jeho vytvoření nemění anonymizované výstupní bajty. „Deanonymizovat PCAP“ ověřuje odpovídající pár, umožňuje hledat alias nebo číslo paketu a obnovit okolí či celý záchyt. SHA-256/CRC kontrolují shodu, nikoli autentizaci proti útočníkovi schopnému přepsat celý pár.

Také mapping bundle je nešifrovaný JSON s originálními hodnotami. Mapu i recovery si necháváme u sebe; bez nich nelze obecně vrátit pseudonymy, masky a odstraněný obsah. Nejedinečnou masku dohledáváme přes číslo paketu, nikoli jako unikátní identitu.

Stejný princip společného mapování využívají i textové logy v UTF-8, Windows-1250 a UTF-16. Detektory doplňuje ochrana secrets v podporovaných JSON/NDJSON, CSV/TSV, CEF/LEEF, logfmt, HAR, access log a tshark JSON. Vypnutá kategorie nebo hodnota zůstává původní. Vlastní profil lze vytvořit, upravit, kopírovat, importovat/exportovat a smazat; vestavěný smazat nelze. Profily a předvolby se uchovávají v úložišti prohlížeče. Výsledek textové anonymizace se také otevírá v dialogu. Základ pro rozhodnutí o sdílení je v obou režimech stejný: skutečné změněné bajty, doložené pokrytí a přiznaná omezení.
