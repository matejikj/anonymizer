/**
 * Application-layer handler registry — single ordered dispatch for sanitize path.
 * New protocols register here (+ kernel manifest); do not add ad-hoc switches in engine.ts.
 */

export type ApplicationHandlerId =
  | 'dns'
  | 'dhcpv4'
  | 'dhcpv6'
  | 'tls'
  | 'ssh'
  | 'quic'
  | 'dtls'
  | 'openvpn'
  | 'ike'
  | 'wireguard'
  | 'sip'
  | 'csta'
  | 'ami'
  | 'ari'
  | 'mgcp'
  | 'h248'
  | 'rtsp'
  | 'iax2'
  | 'skinny'
  | 'h323'
  | 'lapd'
  | 'q931'
  | 'iua'
  | 'smpp'
  | 'pidf'
  | 'lost'
  | 'mrcp'
  | 'cwmp'
  | 'usp'
  | 'nas'
  | 'stun'
  | 'msrp'
  | 'bfcp'
  | 't38'
  | 'zrtp'
  | 'rtp'
  | 'rtcp'
  | 'http'
  | 'http2'
  | 'sbi5g'
  | 'websocket'
  | 'grpc'
  | 'syslog'
  | 'snmp'
  | 'ntp'
  | 'tftp'
  | 'llmnr'
  | 'nbns'
  | 'ssdp'
  | 'ws-discovery'
  | 'radius'
  | 'tacacs'
  | 'diameter'
  | 'hep'
  | 'tzsp'
  | 'netflow-v5'
  | 'ipfix'
  | 'sflow'
  | 'ldap'
  | 'kerberos'
  | 'gtp'
  | 'pfcp'
  | 'smtp'
  | 'imap'
  | 'pop3'
  | 'ftp'
  | 'telnet'
  | 'smb'
  | 'dmr'
  | 'mototrbo'
  | 'rnd-dispatch-lite'
  | 'rip'
  | 'bfd'
  | 'hsrp'
  | 'bgp'
  | 'ldp'
  | 'rdp'
  | 'vnc'
  | 'x11'
  | 'ipmi'
  | 'citrix'
  | 'amt'
  | 'gsmtap'
  | 'amqp'
  | 'kafka'
  | 'nats'
  | 'stomp'
  | 'xmpp'
  | 'gelf'
  | 'fluent'
  | 'otlp'
  | 'postgres'
  | 'mysql'
  | 'tds'
  | 'redis'
  | 'mongodb'
  | 'mqtt'
  | 'coap'
  | 'modbus'
  | 'iec104'
  | 'dnp3'
  | 'opcua'
  | 'dcerpc'
  | 'iscsi'
  | 'portmapper'
  | 'nfs'
  | 'heuristic'
  | 'echo-udp-example'

export interface ApplicationHandlerDescriptor {
  readonly id: ApplicationHandlerId
  readonly priority: number
  /** Port hints only — content validation decides claim. */
  readonly udpPorts?: readonly number[]
  readonly tcpPorts?: readonly number[]
  readonly contentProbe?: boolean
}

/**
 * Declared application handlers in probe order (highest priority first among peers).
 * engine.ts::handleApplicationPayload must follow this order; architecture tests enforce parity.
 */
export const APPLICATION_HANDLER_ORDER: readonly ApplicationHandlerDescriptor[] = [
  { id: 'dns', priority: 200, udpPorts: [53, 5353], tcpPorts: [53] },
  { id: 'dhcpv4', priority: 190, udpPorts: [67, 68] },
  { id: 'dhcpv6', priority: 190, udpPorts: [546, 547] },
  { id: 'tls', priority: 180, contentProbe: true },
  { id: 'ssh', priority: 175, tcpPorts: [22], contentProbe: true },
  { id: 'quic', priority: 174, udpPorts: [443, 4433, 853], contentProbe: true },
  { id: 'dtls', priority: 173, udpPorts: [443, 5684], contentProbe: true },
  { id: 'ike', priority: 172, udpPorts: [500, 4500], contentProbe: true },
  { id: 'openvpn', priority: 171, udpPorts: [1194], tcpPorts: [1194], contentProbe: true },
  { id: 'wireguard', priority: 170, udpPorts: [51820], contentProbe: true },
  { id: 'sip', priority: 170, udpPorts: [5060, 5061], tcpPorts: [5060, 5061], contentProbe: true },
  { id: 'csta', priority: 169, contentProbe: true },
  { id: 'ami', priority: 168, tcpPorts: [5038], contentProbe: true },
  { id: 'mgcp', priority: 165, udpPorts: [2427, 2727], contentProbe: true },
  { id: 'h248', priority: 164, udpPorts: [2944, 2945], tcpPorts: [2944, 2945], contentProbe: true },
  { id: 'rtsp', priority: 163, tcpPorts: [554, 8554], contentProbe: true },
  { id: 'iax2', priority: 162, udpPorts: [4569], contentProbe: true },
  { id: 'skinny', priority: 161, tcpPorts: [2000], contentProbe: true },
  { id: 'h323', priority: 160, udpPorts: [1719], tcpPorts: [1720], contentProbe: true },
  { id: 'stun', priority: 159, contentProbe: true },
  { id: 'lapd', priority: 158, contentProbe: true },
  { id: 'q931', priority: 157, contentProbe: true },
  { id: 'iua', priority: 156, contentProbe: true },
  { id: 'msrp', priority: 155, contentProbe: true },
  { id: 'bfcp', priority: 154, contentProbe: true },
  { id: 'zrtp', priority: 153, contentProbe: true },
  { id: 't38', priority: 152, contentProbe: true },
  { id: 'smpp', priority: 151, tcpPorts: [2775], contentProbe: true },
  { id: 'rtp', priority: 150, contentProbe: true },
  { id: 'rtcp', priority: 150, contentProbe: true },
  { id: 'pidf', priority: 149, contentProbe: true },
  { id: 'lost', priority: 148, contentProbe: true },
  { id: 'mrcp', priority: 147, tcpPorts: [3242], contentProbe: true },
  { id: 'cwmp', priority: 146, tcpPorts: [7547, 30005], contentProbe: true },
  { id: 'usp', priority: 145, contentProbe: true },
  { id: 'nas', priority: 144, contentProbe: true },
  { id: 'sbi5g', priority: 143, tcpPorts: [80, 8080], contentProbe: true },
  { id: 'ari', priority: 142, tcpPorts: [8088], contentProbe: true },
  { id: 'http2', priority: 141, tcpPorts: [80, 8080], contentProbe: true },
  { id: 'http', priority: 140, tcpPorts: [80, 8080, 8000, 8888, 7547], contentProbe: true },
  { id: 'websocket', priority: 139, contentProbe: true },
  { id: 'grpc', priority: 138, contentProbe: true },
  { id: 'syslog', priority: 137, udpPorts: [514, 601], tcpPorts: [514, 601], contentProbe: true },
  { id: 'snmp', priority: 136, udpPorts: [161, 162], contentProbe: true },
  { id: 'ntp', priority: 135, udpPorts: [123], contentProbe: true },
  { id: 'tftp', priority: 134, udpPorts: [69], contentProbe: true },
  { id: 'llmnr', priority: 133, udpPorts: [5355], tcpPorts: [5355], contentProbe: true },
  { id: 'nbns', priority: 132, udpPorts: [137, 138], contentProbe: true },
  { id: 'ssdp', priority: 131, udpPorts: [1900], contentProbe: true },
  { id: 'ws-discovery', priority: 130, udpPorts: [3702], contentProbe: true },
  { id: 'radius', priority: 129, udpPorts: [1812, 1813, 1645, 1646, 3799], contentProbe: true },
  { id: 'tacacs', priority: 128, tcpPorts: [49], contentProbe: true },
  { id: 'diameter', priority: 127, tcpPorts: [3868], contentProbe: true },
  { id: 'hep', priority: 126, udpPorts: [9060], tcpPorts: [9060], contentProbe: true },
  { id: 'tzsp', priority: 125, udpPorts: [37008], contentProbe: true },
  { id: 'netflow-v5', priority: 123, udpPorts: [2055, 9995, 9996], contentProbe: true },
  { id: 'ipfix', priority: 122, udpPorts: [4739, 2055, 9995, 9996], contentProbe: true },
  { id: 'sflow', priority: 121, udpPorts: [6343], contentProbe: true },
  { id: 'pfcp', priority: 120, udpPorts: [8805], contentProbe: true },
  { id: 'gtp', priority: 119, udpPorts: [2123, 2152], contentProbe: true },
  { id: 'ldap', priority: 118, udpPorts: [389], tcpPorts: [389, 3268], contentProbe: true },
  { id: 'kerberos', priority: 117, udpPorts: [88, 464], tcpPorts: [88, 464], contentProbe: true },
  { id: 'dmr', priority: 116, contentProbe: true },
  { id: 'mototrbo', priority: 115, contentProbe: true },
  { id: 'rnd-dispatch-lite', priority: 114, udpPorts: [49_992], contentProbe: true },
  { id: 'bgp', priority: 113, tcpPorts: [179], contentProbe: true },
  { id: 'ldp', priority: 112, udpPorts: [646], tcpPorts: [646], contentProbe: true },
  { id: 'rip', priority: 111, udpPorts: [520, 521], contentProbe: true },
  { id: 'bfd', priority: 110, udpPorts: [3784, 4784], contentProbe: true },
  { id: 'hsrp', priority: 109, udpPorts: [1985, 3222], contentProbe: true },
  { id: 'smtp', priority: 108, tcpPorts: [25, 587], contentProbe: true },
  { id: 'imap', priority: 108, tcpPorts: [143], contentProbe: true },
  { id: 'pop3', priority: 107, tcpPorts: [110], contentProbe: true },
  { id: 'ftp', priority: 106, tcpPorts: [21], contentProbe: true },
  { id: 'telnet', priority: 105, tcpPorts: [23, 513], contentProbe: true },
  { id: 'smb', priority: 104, tcpPorts: [445, 139], contentProbe: true },
  { id: 'rdp', priority: 103, tcpPorts: [3389], udpPorts: [3389], contentProbe: true },
  { id: 'vnc', priority: 102, tcpPorts: [5900, 5901, 5902, 5903], contentProbe: true },
  { id: 'x11', priority: 101, tcpPorts: [6000], contentProbe: true },
  { id: 'ipmi', priority: 100, udpPorts: [623], contentProbe: true },
  { id: 'citrix', priority: 99, tcpPorts: [1494, 2598], contentProbe: true },
  { id: 'amt', priority: 98, tcpPorts: [16_992, 16_993, 16_994, 16_995], contentProbe: true },
  { id: 'gsmtap', priority: 97, udpPorts: [4729], contentProbe: true },
  { id: 'amqp', priority: 96, tcpPorts: [5672], contentProbe: true },
  { id: 'kafka', priority: 95, tcpPorts: [9092], contentProbe: true },
  { id: 'nats', priority: 94, tcpPorts: [4222], contentProbe: true },
  { id: 'stomp', priority: 93, tcpPorts: [61613], contentProbe: true },
  { id: 'xmpp', priority: 92, tcpPorts: [5222, 5269], contentProbe: true },
  { id: 'gelf', priority: 91, udpPorts: [12201], tcpPorts: [12201], contentProbe: true },
  { id: 'fluent', priority: 90, tcpPorts: [24224], contentProbe: true },
  { id: 'otlp', priority: 89, tcpPorts: [4317, 4318], contentProbe: true },
  { id: 'postgres', priority: 88, tcpPorts: [5432], contentProbe: true },
  { id: 'mysql', priority: 87, tcpPorts: [3306], contentProbe: true },
  { id: 'tds', priority: 86, tcpPorts: [1433], contentProbe: true },
  { id: 'redis', priority: 85, tcpPorts: [6379], contentProbe: true },
  { id: 'mongodb', priority: 84, tcpPorts: [27_017], contentProbe: true },
  { id: 'mqtt', priority: 83, tcpPorts: [1883], contentProbe: true },
  { id: 'coap', priority: 82, udpPorts: [5683], contentProbe: true },
  { id: 'modbus', priority: 81, tcpPorts: [502], contentProbe: true },
  { id: 'iec104', priority: 80, tcpPorts: [2404], contentProbe: true },
  { id: 'dnp3', priority: 79, tcpPorts: [20_000], udpPorts: [20_000], contentProbe: true },
  { id: 'opcua', priority: 78, tcpPorts: [4840], contentProbe: true },
  { id: 'dcerpc', priority: 77, tcpPorts: [135], contentProbe: true },
  { id: 'iscsi', priority: 76, tcpPorts: [3260], contentProbe: true },
  { id: 'portmapper', priority: 75, tcpPorts: [111], udpPorts: [111], contentProbe: true },
  { id: 'nfs', priority: 74, tcpPorts: [2049], udpPorts: [2049], contentProbe: true },
  { id: 'echo-udp-example', priority: 50, udpPorts: [49_991], contentProbe: true },
  { id: 'heuristic', priority: 0, contentProbe: true },
] as const
