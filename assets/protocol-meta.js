/* Shared protocol taxonomy — used by the stack map, page stack bars and homepage filter. */
window.PH_PROTOCOLS = {
  ipv4: {
    name: "IPv4",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "header · options · fragmentation",
    tone: "a",
    layerCode: "L3",
    layerLabel: "Internet / IP",
    layerNote: "network layer · RFC 791",
    family: "internet",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4", href: "ipv4.html", note: "L3", current: true },
      { label: "TCP · UDP · ICMP", note: "next header" }
    ]
  },
  icmp: {
    name: "ICMP",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "errors · echo · PMTUD",
    tone: "i",
    layerCode: "L3",
    layerLabel: "Internet / control",
    layerNote: "errors & diagnostics · RFC 792",
    family: "internet",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4", href: "ipv4.html", note: "L3" },
      { label: "ICMP", href: "icmp.html", note: "L3", current: true },
      { label: "Payload / quoted datagram", note: "type-specific" }
    ]
  },
  ipv6: {
    name: "IPv6",
    layer: "internet",
    modelLayer: "internet",
    modelNote: "40 B · ext chain · 128-bit",
    tone: "j",
    layerCode: "L3",
    layerLabel: "Internet / IP",
    layerNote: "fixed header · extension chain · RFC 8200",
    family: "internet",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "L2" },
      { label: "IPv6", href: "ipv6.html", note: "L3", current: true },
      { label: "Extension headers", note: "next header chain" },
      { label: "TCP · UDP · ICMPv6", note: "upper layer" }
    ]
  },
  tcp: {
    name: "TCP",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "flags · options · checksum",
    tone: "d",
    layerCode: "L4",
    layerLabel: "Transport",
    layerNote: "host-to-host · RFC 9293",
    family: "transport",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4 / IPv6", note: "L3" },
      { label: "TCP", href: "tcp.html", note: "L4", current: true },
      { label: "Application", note: "L7" }
    ]
  },
  udp: {
    name: "UDP",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "ports · length · checksum",
    tone: "a",
    layerCode: "L4",
    layerLabel: "Transport",
    layerNote: "datagram delivery · RFC 768",
    family: "transport",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4 / IPv6", note: "L3" },
      { label: "UDP", href: "udp.html", note: "L4", current: true },
      { label: "Application", note: "L7" }
    ]
  },
  quic: {
    name: "QUIC",
    layer: "transport",
    modelLayer: "transport",
    modelNote: "encrypted transport · frames",
    tone: "c",
    layerCode: "L4+",
    layerLabel: "Transport / TLS",
    layerNote: "encrypted transport · RFC 9000",
    family: "transport",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4 / IPv6", note: "L3" },
      { label: "UDP", href: "udp.html", note: "L4" },
      { label: "QUIC", href: "quic.html", note: "L4+", current: true },
      { label: "TLS 1.3 · Application", note: "encrypted" }
    ]
  },
  bgp: {
    name: "BGP",
    layer: "application",
    modelLayer: "application",
    modelNote: "routing · over TCP/179",
    tone: "b",
    layerCode: "L7",
    layerLabel: "Routing / control",
    layerNote: "over TCP/179 · RFC 4271",
    family: "application",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4 / IPv6", note: "L3" },
      { label: "TCP/179", href: "tcp.html", note: "L4" },
      { label: "BGP", href: "bgp.html", note: "routing", current: true },
      { label: "UPDATE · NLRI", note: "routing data" }
    ]
  },
  wireguard: {
    name: "WireGuard",
    layer: "tunnel",
    modelLayer: "tunnel",
    modelNote: "inner IP over UDP",
    tone: "e",
    layerCode: "L3T",
    layerLabel: "Tunnel / overlay",
    layerNote: "inner IP over UDP · protocol v1",
    family: "tunnel",
    path: [
      { label: "Ethernet", note: "link" },
      { label: "IPv4 / IPv6", note: "L3" },
      { label: "UDP/51820", href: "udp.html", note: "L4" },
      { label: "WireGuard", href: "wireguard.html", note: "tunnel", current: true },
      { label: "Inner IPv4 / IPv6", note: "payload" }
    ]
  },
  ethernet: {
    name: "Ethernet",
    layer: "link",
    modelLayer: "link",
    modelNote: "frames · MAC · EtherType",
    tone: "h",
    layerCode: "L2",
    layerLabel: "Link",
    layerNote: "frames · FCS · IEEE 802.3",
    family: "link",
    path: [
      { label: "Physical", note: "preamble · SFD" },
      { label: "Ethernet", href: "ethernet.html", note: "L2", current: true },
      { label: "ARP · IPv4 · IPv6", note: "payload" }
    ]
  },
  arp: {
    name: "ARP",
    layer: "link",
    modelLayer: "link",
    modelNote: "IPv4 ↔ MAC · broadcast",
    tone: "f",
    layerCode: "L2.5",
    layerLabel: "Address resolution",
    layerNote: "IPv4 ↔ MAC · RFC 826",
    family: "link",
    path: [
      { label: "Ethernet", href: "ethernet.html", note: "L2" },
      { label: "ARP", href: "arp.html", note: "L2.5", current: true },
      { label: "IPv4 address", note: "resolution" }
    ]
  },
  tools: {
    name: "Toolbox",
    layer: "tools",
    modelLayer: "tools",
    modelNote: "checksums · varints · TLVs",
    tone: "g",
    layerCode: "ALL",
    layerLabel: "Cross-layer",
    layerNote: "byte-level utilities",
    family: "tools",
    path: []
  }
};

/* The homepage model is generated from this config plus PH_PROTOCOLS.
   To add a protocol later: add its object above with a modelLayer value.
   Planned labels disappear automatically once a matching protocol name exists. */
window.PH_STACK = [
  {
    key: "application",
    code: "L7",
    name: "Application / control",
    note: "routing, DNS, TLS",
    planned: ["DNS", "TLS"]
  },
  {
    key: "transport",
    code: "L4",
    name: "Transport",
    note: "process-to-process delivery"
  },
  {
    key: "tunnel",
    code: "L3T",
    name: "Tunnels / overlays",
    note: "cross-layer · inner IP over UDP",
    planned: ["GRE", "IPsec"],
    overlay: true
  },
  {
    key: "internet",
    code: "L3",
    name: "Internet / IP",
    note: "addressing · forwarding · control"
  },
  {
    key: "link",
    code: "L2",
    name: "Link",
    note: "frames · MAC · address resolution",
    planned: ["Ethernet", "ARP"]
  }
];
