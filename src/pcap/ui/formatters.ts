/** Display helpers for PCAP UX — never expose raw sensitive values in status copy. */

import type { PacketTimestamp } from '../domain/types'
import { CaptureFormat } from '../domain/types'

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`
}

export function formatPacketCount(n: number): string {
  return n.toLocaleString('cs-CZ')
}

export function formatDurationMmSs(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds))
  const minutes = Math.floor(s / 60)
  const seconds = s % 60
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}

export function formatCaptureFormat(format: number): string {
  return format === CaptureFormat.Pcapng ? 'PCAPNG' : 'PCAP'
}

export function formatTimestamp(ts: PacketTimestamp): string {
  const seconds = ts.offsetSeconds + ts.ticks / ts.unitsPerSecond
  const whole = Number(seconds)
  if (!Number.isFinite(whole)) return String(ts.ticks)
  const frac = Number(ts.ticks % ts.unitsPerSecond)
  const digits = ts.unitsPerSecond === 1_000_000_000n ? 9 : 6
  return `${Math.floor(whole)}.${String(frac).padStart(digits, '0')}`
}

export function formatMacBytes(bytes: Uint8Array, offset: number): string {
  return Array.from(bytes.slice(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
}

export function formatIpv4Bytes(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`
}

export function toHexDump(data: Uint8Array, maxBytes = 512): string {
  const lines: string[] = []
  const len = Math.min(data.length, maxBytes)
  for (let i = 0; i < len; i += 16) {
    const slice = data.slice(i, Math.min(i + 16, len))
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
      .padEnd(47, ' ')
    const ascii = Array.from(slice)
      .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.'))
      .join('')
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`)
  }
  if (data.length > maxBytes) {
    lines.push(`… (${data.length - maxBytes} further bytes omitted)`)
  }
  return lines.join('\n')
}

export function protocolLabel(id: string): string {
  const map: Record<string, string> = {
    ethernet: 'Ethernet',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    tcp: 'TCP',
    udp: 'UDP',
    arp: 'ARP',
    icmpv4: 'ICMPv4',
    icmpv6: 'ICMPv6',
    dns: 'DNS',
    dhcpv4: 'DHCPv4',
    dhcpv6: 'DHCPv6',
    sip: 'SIP',
    'sip-csta': 'SIP uaCSTA',
    csta: 'CSTA',
    'csta-xml': 'CSTA XML',
    'csta-device': 'CSTA device',
    'csta-secret': 'CSTA secret',
    'csta-asn1': 'CSTA ASN.1',
    'csta-body': 'CSTA body',
    ami: 'AMI',
    'ami-auth': 'AMI auth',
    'ami-id': 'AMI identity',
    'ami-var': 'AMI variable',
    'ami-body': 'AMI body',
    ari: 'ARI',
    'ari-auth': 'ARI auth',
    'ari-id': 'ARI identity',
    'ari-json': 'ARI JSON',
    'ari-body': 'ARI body',
    lapd: 'LAPD',
    'lapd-addr': 'LAPD address',
    'lapd-tei': 'LAPD TEI',
    'lapd-ctrl': 'LAPD control',
    'lapd-info': 'LAPD info',
    'lapd-cooked': 'LAPD cooked',
    'lapd-fcs': 'LAPD FCS',
    q931: 'Q.931',
    'q931-hdr': 'Q.931 header',
    'q931-cr': 'Q.931 call ref',
    'q931-msg': 'Q.931 message',
    'q931-number': 'Q.931 number',
    'q931-display': 'Q.931 display',
    'q931-facility': 'Q.931 facility',
    'q931-body': 'Q.931 body',
    iua: 'IUA',
    'iua-hdr': 'IUA header',
    'iua-id': 'IUA identity',
    'iua-body': 'IUA body',
    'iua-pdata': 'IUA protocol data',
    smpp: 'SMPP',
    'smpp-hdr': 'SMPP header',
    'smpp-auth': 'SMPP auth',
    'smpp-id': 'SMPP identity',
    'smpp-addr': 'SMPP address',
    'smpp-sm': 'SMPP message',
    'smpp-tlv': 'SMPP TLV',
    'smpp-tlv-hdr': 'SMPP TLV header',
    'smpp-body': 'SMPP body',
    'sip-pidf': 'SIP PIDF-LO',
    'sip-lost': 'SIP LoST',
    pidf: 'PIDF-LO',
    lost: 'LoST',
    mrcp: 'MRCPv2',
    'mrcp-hdr': 'MRCP header',
    'mrcp-id': 'MRCP identity',
    'mrcp-body': 'MRCP body',
    'mrcp-auth': 'MRCP auth',
    cwmp: 'CWMP',
    'cwmp-soap': 'CWMP SOAP',
    'cwmp-id': 'CWMP identity',
    'cwmp-secret': 'CWMP secret',
    'cwmp-body': 'CWMP body',
    usp: 'USP',
    'usp-msg': 'USP message',
    'usp-id': 'USP identity',
    'usp-secret': 'USP secret',
    'usp-auth': 'USP auth',
    'usp-body': 'USP body',
    s1ap: 'S1AP',
    's1ap-nas': 'S1AP NAS',
    's1ap-cause': 'S1AP Cause',
    's1ap-security-key': 'S1AP SecurityKey',
    's1ap-erab': 'S1AP E-RAB',
    's1ap-node-name': 'S1AP node name',
    's1ap-location': 'S1AP location',
    ngap: 'NGAP',
    'ngap-nas': 'NGAP NAS',
    'ngap-cause': 'NGAP Cause',
    'ngap-security-key': 'NGAP SecurityKey',
    'ngap-n2': 'NGAP N2 transfer',
    'ngap-pdu-session': 'NGAP PDU session',
    'ngap-node-name': 'NGAP node name',
    'ngap-location': 'NGAP location',
    'ngap-5g-s-tmsi': 'NGAP 5G-S-TMSI',
    sbi5g: '5G SBI',
    'sbi5g-nnrf': '5G SBI NRF',
    'sbi5g-namf': '5G SBI AMF',
    'sbi5g-nsmf': '5G SBI SMF',
    'sbi5g-json': '5G SBI JSON',
    'sbi5g-auth': '5G SBI token/auth',
    'sbi5g-multipart': '5G SBI multipart',
    'sbi5g-n1': '5G SBI N1 (NAS)',
    'sbi5g-n2': '5G SBI N2 transfer',
    'sbi5g-supi': '5G SBI SUPI',
    pfcp: 'PFCP',
    'pfcp-f-teid': 'PFCP F-TEID',
    'pfcp-f-seid': 'PFCP F-SEID',
    'pfcp-node-id': 'PFCP Node ID',
    'pfcp-ue-ip': 'PFCP UE IP',
    'pfcp-imsi': 'PFCP IMSI',
    'pfcp-imei': 'PFCP IMEI',
    'pfcp-msisdn': 'PFCP MSISDN',
    'pfcp-network-instance': 'PFCP Network Instance',
    'pfcp-secret': 'PFCP secret',
    'pfcp-recovery': 'PFCP recovery',
    nas: 'NAS',
    'nas-emm': 'EPS EMM',
    'nas-esm': 'EPS ESM',
    'nas-5gmm': '5GMM',
    'nas-5gsm': '5GSM',
    'nas-imsi': 'NAS IMSI',
    'nas-imei': 'NAS IMEI',
    'nas-guti': 'NAS GUTI',
    'nas-tmsi': 'NAS TMSI',
    'nas-suci': 'NAS SUCI',
    'nas-auth': 'NAS auth',
    'nas-location': 'NAS location',
    'nas-apn': 'NAS APN/DNN',
    'nas-secret': 'NAS secret',
    'nas-ciphered': 'NAS ciphered',
    sdp: 'SDP',
    rtp: 'RTP',
    rtcp: 'RTCP',
    srtp: 'SRTP',
    'sip-tls': 'SIP/TLS',
    sll: 'SLL',
    sll2: 'SLL2',
    vlan: 'VLAN',
    tls: 'TLS',
    'tls-clienthello': 'TLS ClientHello/SNI',
    'tls-serverhello': 'TLS ServerHello',
    'tls-certificate': 'TLS Certificate',
    'tls-handshake-unsupported': 'TLS handshake',
    'tls-encrypted-payload': 'TLS encrypted',
    'tls-1.2': 'TLS 1.2',
    'tls-1.3': 'TLS 1.3',
    'tls-ech': 'TLS ECH',
    'http-headers': 'HTTP hlavičky',
    'http-body': 'HTTP tělo',
    heuristic: 'Heuristický sken',
    dmr: 'DMR',
    'mototrbo-ipsc': 'MOTOTRBO IPSC',
    'rnd-dispatch-lite': 'RND Dispatch Lite',
    'rnd-dispatch-lite-body': 'RND Dispatch Lite (tělo)',
    vrrp: 'VRRP',
    ospf: 'OSPF',
    eigrp: 'EIGRP',
    pim: 'PIM',
    igmp: 'IGMP',
    rip: 'RIP',
    bfd: 'BFD',
    hsrp: 'HSRP',
    glbp: 'GLBP',
    bgp: 'BGP',
    isis: 'IS-IS',
    ldp: 'LDP',
    'tcp-md5': 'TCP MD5',
    'tcp-ao': 'TCP-AO',
    rdp: 'RDP',
    'rdp-cookie': 'RDP cookie',
    vnc: 'VNC',
    'vnc-auth': 'VNC auth',
    'vnc-desktop-name': 'VNC desktop',
    x11: 'X11',
    'x11-auth': 'X11 auth',
    ipmi: 'IPMI',
    'ipmi-rakp-user': 'IPMI RAKP user',
    'ipmi-rakp-auth': 'IPMI RAKP auth',
    citrix: 'Citrix',
    'amt-http': 'Intel AMT',
    radiotap: 'Radiotap',
    ieee80211: '802.11',
    'ieee80211-ssid': '802.11 SSID',
    'ieee80211-wps': '802.11 WPS',
    bluetooth: 'Bluetooth',
    'bluetooth-smp': 'Bluetooth SMP',
    gsmtap: 'GSMTAP',
    amqp: 'AMQP',
    'amqp-sasl': 'AMQP SASL',
    'amqp-body': 'AMQP body',
    kafka: 'Kafka',
    'kafka-sasl': 'Kafka SASL',
    'kafka-body': 'Kafka body',
    nats: 'NATS',
    'nats-connect': 'NATS CONNECT',
    'nats-auth': 'NATS auth',
    stomp: 'STOMP',
    'stomp-auth': 'STOMP auth',
    'stomp-login': 'STOMP login',
    xmpp: 'XMPP',
    'xmpp-sasl': 'XMPP SASL',
    'xmpp-jid': 'XMPP JID',
    'xmpp-body': 'XMPP body',
    gelf: 'GELF',
    'gelf-chunk': 'GELF chunk',
    'gelf-body': 'GELF body',
    fluent: 'Fluent Forward',
    'fluent-tag': 'Fluent tag',
    'fluent-body': 'Fluent body',
    otlp: 'OTLP',
    'otlp-protobuf': 'OTLP protobuf',
    'otlp-body': 'OTLP body',
    postgres: 'PostgreSQL',
    'postgres-auth': 'PostgreSQL auth',
    'postgres-sql': 'PostgreSQL SQL',
    'postgres-user': 'PostgreSQL user',
    'postgres-row': 'PostgreSQL row',
    mysql: 'MySQL',
    'mysql-auth': 'MySQL auth',
    'mysql-user': 'MySQL user',
    'mysql-sql': 'MySQL SQL',
    'mysql-row': 'MySQL row',
    tds: 'TDS / MS SQL',
    'tds-auth': 'TDS auth',
    'tds-user': 'TDS user',
    'tds-sql': 'TDS SQL',
    redis: 'Redis',
    'redis-auth': 'Redis AUTH',
    'redis-key': 'Redis key',
    mongodb: 'MongoDB',
    'mongodb-auth': 'MongoDB auth',
    'mongodb-body': 'MongoDB body',
    mqtt: 'MQTT',
    'mqtt-auth': 'MQTT auth',
    'mqtt-client-id': 'MQTT client ID',
    'mqtt-user': 'MQTT user',
    'mqtt-topic': 'MQTT topic',
    coap: 'CoAP',
    'coap-token': 'CoAP token',
    'coap-uri': 'CoAP URI',
    modbus: 'Modbus',
    'modbus-values': 'Modbus values',
    iec104: 'IEC 104',
    'iec104-ca': 'IEC 104 CA',
    'iec104-ioa': 'IEC 104 IOA',
    'iec104-values': 'IEC 104 values',
    dnp3: 'DNP3',
    'dnp3-addr': 'DNP3 address',
    'dnp3-values': 'DNP3 values',
    opcua: 'OPC UA',
    'opcua-auth': 'OPC UA auth',
    'opcua-url': 'OPC UA URL',
    'opcua-body': 'OPC UA body',
    dcerpc: 'DCE/RPC',
    'dcerpc-auth': 'DCE/RPC auth',
    'dcerpc-iface': 'DCE/RPC interface',
    'dcerpc-epm': 'DCE/RPC EPM',
    'dcerpc-netlogon': 'DCE/RPC NETLOGON',
    'dcerpc-drsuapi': 'DCE/RPC DRSUAPI',
    'dcerpc-body': 'DCE/RPC stub',
    iscsi: 'iSCSI',
    'iscsi-iqn': 'iSCSI IQN',
    'iscsi-chap': 'iSCSI CHAP',
    'iscsi-data': 'iSCSI data',
    'iscsi-body': 'iSCSI body',
    portmapper: 'Portmapper',
    'portmapper-auth': 'Portmapper auth',
    'portmapper-body': 'Portmapper body',
    nfs: 'NFS',
    'nfs-auth': 'NFS auth',
    'nfs-body': 'NFS body',
    'nfs-data': 'NFS data',
    ppi: 'PPI',
    stp: 'Spanning Tree (STP)',
    cdp: 'Cisco Discovery Protocol',
    lldp: 'LLDP',
    'lldp-med': 'LLDP-MED',
    lacp: 'LACP',
    'slow-protocols': 'Slow Protocols',
    eapol: 'EAPOL',
    eap: 'EAP',
    'eapol-key': 'EAPOL-Key',
  }
  return map[id] ?? id
}
