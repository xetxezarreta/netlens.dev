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
  dissect: {
    name: "Dissector",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "one frame · every layer",
    tone: "h",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "link → network → transport → app",
    railLayer: "tool",
    family: "tools",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "link" },
      { label: "IPv4 / IPv6", href: "ipv4.html", note: "internet" },
      { label: "TCP / UDP / ICMP", href: "udp.html", note: "transport" },
      { label: "Application", href: "dns.html", note: "application" },
      { label: "HTTP / TLS", href: "http.html", note: "application" },
      { label: "Dissector", href: "dissect.html", note: "ALL", current: true }
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
    note: "routing, DNS, HTTP, TLS",
    planned: []
  },
  {
    key: "transport",
    code: "3",
    name: "Transport",
    note: "process-to-process delivery"
  },
  {
    key: "internet",
    code: "2",
    name: "Internet",
    note: "addressing · forwarding · control"
  },
  {
    key: "link",
    code: "1",
    name: "Link",
    note: "frames · MAC · address resolution",
    planned: ["Ethernet", "ARP"]
  }
];
