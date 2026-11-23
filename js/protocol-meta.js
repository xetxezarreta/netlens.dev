/* Shared protocol taxonomy — used by the stack map, page stack bars and homepage filter. */
window.PH_PROTOCOLS = {
  ipv4: {
    name: "IPv4",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "header · options · fragmentation",
    tone: "a",
    layerCode: "2",
    layerLabel: "Internet",
    layerNote: "network layer · RFC 791",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4", href: "ipv4.html", note: "internet", current: true },
      { label: "TCP · UDP · ICMP", note: "next header" }
    ]
  },
  ipv6: {
    name: "IPv6",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "40 B · ext chain · 128-bit",
    tone: "j",
    layerCode: "2",
    layerLabel: "Internet",
    layerNote: "fixed header · extension chain · RFC 8200",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv6", href: "ipv6.html", note: "internet", current: true },
      { label: "Extension headers", note: "next header chain" },
      { label: "TCP · UDP · ICMPv6", note: "upper layer" }
    ]
  },
  icmp: {
    name: "ICMP",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "errors · echo · PMTUD",
    tone: "i",
    layerCode: "2",
    layerLabel: "Internet / control",
    layerNote: "errors & diagnostics · RFC 792",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4", href: "ipv4.html", note: "internet" },
      { label: "ICMP", href: "icmp.html", note: "internet", current: true },
      { label: "Payload / quoted datagram", note: "type-specific" }
    ]
  },
  tcp: {
    name: "TCP",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "flags · options · checksum",
    tone: "d",
    layerCode: "3",
    layerLabel: "Transport",
    layerNote: "host-to-host · RFC 9293",
    family: "transport",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "TCP", href: "tcp.html", note: "transport", current: true },
      { label: "Application", note: "application" }
    ]
  },
  udp: {
    name: "UDP",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "ports · length · checksum",
    tone: "a",
    layerCode: "3",
    layerLabel: "Transport",
    layerNote: "datagram delivery · RFC 768",
    family: "transport",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "UDP", href: "udp.html", note: "transport", current: true },
      { label: "Application", note: "application" }
    ]
  },
  dns: {
    name: "DNS",
    layer: "application",
    modelLayer: "application",
    modelNote: "names · records · EDNS",
    tone: "g",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "name resolution · RFC 1035",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "UDP / TCP", href: "udp.html", note: "transport" },
      { label: "DNS", href: "dns.html", note: "application", current: true },
      { label: "Records · EDNS", note: "sections" }
    ]
  },
  dhcp: {
    name: "DHCP",
    layer: "application",
    modelLayer: "application",
    modelNote: "leases · options · BOOTP",
    tone: "i",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "address configuration · RFC 2131/2132",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4", href: "ipv4.html", note: "internet" },
      { label: "UDP 68 → 67", href: "udp.html", note: "transport" },
      { label: "DHCP", href: "dhcp.html", note: "application", current: true },
      { label: "Options · magic cookie", note: "TLVs" }
    ]
  },
  http: {
    name: "HTTP",
    layer: "application",
    modelLayer: "application",
    modelNote: "requests · HTTP/2 · HPACK",
    tone: "d",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "semantics · framing · RFC 9110/9112/9113",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "TCP/80 · TCP/443", href: "tcp.html", note: "transport" },
      { label: "HTTP", href: "http.html", note: "application", current: true },
      { label: "HTTP/2 frames · HPACK", note: "multiplexed" }
    ]
  },
  tls: {
    name: "TLS",
    layer: "application",
    modelLayer: "application",
    modelNote: "records · handshakes · AEAD",
    tone: "h",
    layerCode: "4",
    layerLabel: "Application / security",
    layerNote: "records & handshakes · RFC 8446",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "TCP/443", href: "tcp.html", note: "transport" },
      { label: "TLS", href: "tls.html", note: "application", current: true },
      { label: "Encrypted application data", note: "AEAD" }
    ]
  },
  quic: {
    name: "QUIC",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "encrypted transport · frames",
    tone: "c",
    layerCode: "3",
    layerLabel: "Transport / TLS",
    layerNote: "encrypted transport · RFC 9000",
    family: "transport",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "UDP", href: "udp.html", note: "transport" },
      { label: "QUIC", href: "quic.html", note: "transport", current: true },
      { label: "TLS 1.3 · Application", note: "encrypted" }
    ]
  },
  bgp: {
    name: "BGP",
    layer: "application",
    modelLayer: "application",
    modelNote: "routing · over TCP/179",
    tone: "b",
    layerCode: "4",
    layerLabel: "Routing / control",
    layerNote: "over TCP/179 · RFC 4271",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "TCP/179", href: "tcp.html", note: "transport" },
      { label: "BGP", href: "bgp.html", note: "routing", current: true },
      { label: "UPDATE · NLRI", note: "routing data" }
    ]
  },
  ethernet: {
    name: "Ethernet",
    layer: "link",
    modelLayer: "link",
    modelNote: "frames · MAC · EtherType",
    tone: "h",
    layerCode: "1",
    layerLabel: "Link",
    layerNote: "frames · FCS · IEEE 802.3",
    family: "link",
    path: [
      { label: "Physical", note: "preamble · SFD" },
      { label: "Ethernet", href: "ethernet.html", note: "link", current: true },
      { label: "ARP · IPv4 · IPv6", note: "payload" }
    ]
  },
  arp: {
    name: "ARP",
    layer: "link",
    modelLayer: "link",
    modelNote: "IPv4 ↔ MAC · broadcast",
    tone: "f",
    layerCode: "1",
    layerLabel: "Link / resolution",
    layerNote: "IPv4 ↔ MAC · RFC 826",
    family: "link",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "ARP", href: "arp.html", note: "link", current: true },
      { label: "IPv4 address", note: "resolution" }
    ]
  },
  icmpv6: {
    name: "ICMPv6",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "NDP · SLAAC · errors",
    tone: "c",
    layerCode: "2",
    layerLabel: "Internet / control",
    layerNote: "errors, NDP, SLAAC · RFC 4443/4861",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv6", href: "ipv6.html", note: "internet" },
      { label: "ICMPv6", href: "icmpv6.html", note: "control", current: true },
      { label: "NDP · MLD · errors", note: "type-specific" }
    ]
  },
  ospf: {
    name: "OSPF",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "routing · LSAs · areas",
    tone: "e",
    layerCode: "2",
    layerLabel: "Internet / routing",
    layerNote: "link-state routing · RFC 2328",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4", href: "ipv4.html", note: "internet" },
      { label: "OSPF", href: "ospf.html", note: "protocol 89", current: true },
      { label: "LSAs · SPF", note: "routing data" }
    ]
  },
  gre: {
    name: "GRE",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "tunnels · keys · checksums",
    tone: "g",
    layerCode: "2",
    layerLabel: "Internet / tunnel",
    layerNote: "generic encapsulation · RFC 2784/2890",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "outer internet" },
      { label: "GRE", href: "gre.html", note: "protocol 47", current: true },
      { label: "Inner IPv4 / IPv6 / Ethernet", note: "payload" }
    ]
  },
  ipsec: {
    name: "IPsec",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "AH · ESP · IKEv2",
    tone: "f",
    layerCode: "2",
    layerLabel: "Internet / security",
    layerNote: "packet protection · RFC 4302/4303",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "AH · ESP", href: "ipsec.html", note: "protocol 51/50", current: true },
      { label: "Inner IP / transport", note: "protected" }
    ]
  },
  vxlan: {
    name: "VXLAN",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "overlay · VNI · UDP 4789",
    tone: "j",
    layerCode: "2",
    layerLabel: "Overlay / tunnel",
    layerNote: "L2 over UDP · RFC 7348",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "outer internet" },
      { label: "UDP 4789", href: "udp.html", note: "transport" },
      { label: "VXLAN", href: "vxlan.html", note: "overlay", current: true },
      { label: "Inner Ethernet", note: "tenant frame" }
    ]
  },
  wireguard: {
    name: "WireGuard",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "Noise · UDP · transport data",
    tone: "d",
    layerCode: "2",
    layerLabel: "Internet / VPN",
    layerNote: "modern tunnel · UDP 51820",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "UDP 51820", href: "udp.html", note: "transport" },
      { label: "WireGuard", href: "wireguard.html", note: "VPN", current: true },
      { label: "Inner IP packet", note: "transport data" }
    ]
  },
  sctp: {
    name: "SCTP",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "chunks · streams · CRC32c",
    tone: "i",
    layerCode: "3",
    layerLabel: "Transport",
    layerNote: "message-oriented · RFC 9260",
    family: "transport",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "SCTP", href: "sctp.html", note: "protocol 132", current: true },
      { label: "Chunks · streams", note: "application" }
    ]
  },
  ntp: {
    name: "NTP",
    layer: "application",
    modelLayer: "application",
    modelNote: "time · stratum · 64-bit stamps",
    tone: "b",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "clock sync · RFC 5905",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "UDP 123", href: "udp.html", note: "transport" },
      { label: "NTP", href: "ntp.html", note: "application", current: true },
      { label: "Timestamps · extensions", note: "time sync" }
    ]
  },
  dhcpv6: {
    name: "DHCPv6",
    layer: "application",
    modelLayer: "application",
    modelNote: "stateful · SLAAC · DUID",
    tone: "a",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "IPv6 configuration · RFC 8415",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv6", href: "ipv6.html", note: "internet" },
      { label: "UDP 546 ↔ 547", href: "udp.html", note: "transport" },
      { label: "DHCPv6", href: "dhcpv6.html", note: "application", current: true },
      { label: "IA_NA · IA_PD · options", note: "TLVs" }
    ]
  },
  http3: {
    name: "HTTP/3",
    layer: "application",
    modelLayer: "application",
    modelNote: "QUIC streams · QPACK · frames",
    tone: "g",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "HTTP over QUIC · RFC 9114",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "UDP", href: "udp.html", note: "transport" },
      { label: "QUIC", href: "quic.html", note: "transport" },
      { label: "HTTP/3", href: "http3.html", note: "application", current: true },
      { label: "QPACK · request streams", note: "multiplexed" }
    ]
  },
  websocket: {
    name: "WebSocket",
    layer: "application",
    modelLayer: "application",
    modelNote: "frames · masking · upgrade",
    tone: "h",
    layerCode: "4",
    layerLabel: "Application",
    layerNote: "full-duplex over TCP · RFC 6455",
    family: "application",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", note: "internet" },
      { label: "TCP 80/443", href: "tcp.html", note: "transport" },
      { label: "HTTP Upgrade", href: "http.html", note: "handshake" },
      { label: "WebSocket", href: "websocket.html", note: "application", current: true },
      { label: "Frames · messages", note: "full-duplex" }
    ]
  },
  lldp: {
    name: "LLDP",
    layer: "link",
    modelLayer: "link",
    modelNote: "neighbours · TLVs · 30 s",
    tone: "c",
    layerCode: "1",
    layerLabel: "Link / discovery",
    layerNote: "neighbour discovery · IEEE 802.1AB",
    family: "link",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "LLDP", href: "lldp.html", note: "EtherType 0x88CC", current: true },
      { label: "Chassis · port · TTL TLVs", note: "TLVs" }
    ]
  },
  workbench: {
    name: "Workbench",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "pcap · filters · streams",
    tone: "b",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "capture → packet list → fields",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", href: "ipv4.html", note: "internet" },
      { label: "TCP / UDP / ICMP", href: "udp.html", note: "transport" },
      { label: "Application", href: "dns.html", note: "application" },
      { label: "Workbench", href: "workbench.html", note: "ALL", current: true }
    ]
  },
  subnet: {
    name: "Subnet calculator",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "CIDR · ranges · splitting",
    tone: "a",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "IPv4 and IPv6 address arithmetic",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "IPv4", href: "ipv4.html", note: "internet" },
      { label: "IPv6", href: "ipv6.html", note: "internet" },
      { label: "Subnet calculator", href: "subnet.html", note: "ALL", current: true },
      { label: "CIDR · masks · ranges", note: "tool" }
    ]
  },
  checksum: {
    name: "Checksum lab",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "Internet · CRC32 · CRC32c",
    tone: "e",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "checksums, CRCs and hashes",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "IPv4", href: "ipv4.html", note: "internet" },
      { label: "TCP / UDP", href: "tcp.html", note: "transport" },
      { label: "Checksum lab", href: "checksum.html", note: "ALL", current: true },
      { label: "RFC 1071 · CRC", note: "tool" }
    ]
  },
  ports: {
    name: "Port registry",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "well-known · services",
    tone: "j",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "IANA service names and ports",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "TCP / UDP", href: "tcp.html", note: "transport" },
      { label: "Port registry", href: "ports.html", note: "ALL", current: true },
      { label: "Service names", note: "tool" }
    ]
  },
  glossary: {
    name: "Glossary",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "terms · acronyms",
    tone: "g",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "networking vocabulary",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "Field guide", href: "index.html", note: "home" },
      { label: "Glossary", href: "glossary.html", note: "ALL", current: true },
      { label: "Acronyms · terms", note: "tool" }
    ]
  },
  learn: {
    name: "Learning paths",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "guided reading · progress",
    tone: "d",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "guided study · structured paths",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "Field guide", href: "index.html", note: "home" },
      { label: "Learning paths", href: "learn.html", note: "ALL", current: true },
      { label: "Read · build · capture", note: "tool" }
    ]
  },
  quiz: {
    name: "Packet quiz",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "field offsets · flags",
    tone: "f",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "reinforce the material through practice",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "Field guide", href: "index.html", note: "home" },
      { label: "Packet quiz", href: "quiz.html", note: "ALL", current: true },
      { label: "Offsets · flags · RFCs", note: "tool" }
    ]
  }
};

/* The homepage model is generated from this config plus PH_PROTOCOLS.
   To add a protocol later: add its object above with a modelLayer value.
   Planned labels disappear automatically once a matching protocol name exists. */
window.PH_STACK = [
  {
    key: "application",
    code: "4",
    name: "Application",
    note: "DNS, DHCP, HTTP, TLS, NTP, WebSocket",
    planned: []
  },
  {
    key: "transport",
    code: "3",
    name: "Transport",
    note: "TCP · UDP · QUIC · SCTP"
  },
  {
    key: "internet",
    code: "2",
    name: "Internet",
    note: "addressing · routing · tunnels · security"
  },
  {
    key: "link",
    code: "1",
    name: "Link",
    note: "frames · MAC · discovery",
    planned: []
  }
];
