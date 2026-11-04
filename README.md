# packet-headers.sh

A static, interactive field guide to network wire formats: IPv4 options, ICMP types, IPv6
extension chains, TCP flags and TLVs, UDP ports and checksums, DNS records and name
compression, HTTP/1.1 framing and HTTP/2 frames, TLS 1.3 records and handshakes, QUIC
headers and frames, BGP path attributes, and WireGuard messages.

Everything is plain HTML, CSS and JavaScript. There is no build step, no package manager,
and no network request after the page loads (external RFC links open only when clicked).

## Run it

```sh
python3 -m http.server 8000
# then open http://localhost:8000/
```

Opening `index.html` directly from disk also works in modern browsers, but a local server
is the least surprising option.

## Layout

```
index.html          landing page, protocol index, global search
ipv4.html           IPv4 header, fragmentation, options, encoder/decoder
icmp.html           ICMPv4 types, codes, checksums, embedded datagrams, encoder/decoder
ipv6.html           IPv6 header, addresses, extension chain, jumbograms, encoder/decoder
ethernet.html       Ethernet II frame, VLAN tags, FCS, encoder/decoder
arp.html            ARP message, opcodes, Ethernet wrapper, encoder/decoder
dissect.html        cross-layer packet walk: layer tree, hex sync, warnings
tcp.html            TCP header, flags, options, scan recipes, encoder/decoder
udp.html            UDP ports, length, IPv4/IPv6 checksum, encoder/decoder
dns.html            DNS header, flags, names, records, EDNS(0), encoder/decoder
http.html           HTTP/1.1 framing, HTTP/2 frames, HPACK, encoder/decoder
tls.html            TLS 1.3 records, handshakes, extensions, key schedule
quic.html           QUIC long/short headers, varints, frames, frame codec
bgp.html            BGP message/UPDATE layout, path attributes, encoder/decoder
wireguard.html      WireGuard message layouts, endianness, transport builder/decoder
tools.html          checksum, QUIC varint, TLV parser, hex/bits, bitmask
about.html          conventions, shortcuts, sources
assets/styles.css   design system and layout
assets/core.js      shared utilities, bit/byte diagram engines, search, theme
assets/protocol-meta.js  TCP/IP layer taxonomy and encapsulation paths
assets/ethernet-codec.js Ethernet/802.1Q/FCS codec
assets/arp-codec.js      ARP message codec
assets/icmp-codec.js     ICMPv4 message/packet codec
assets/ipv6-codec.js     IPv6 header, address and extension-chain codec
assets/udp-codec.js      UDP datagram and pseudo-header checksum codec
assets/dns-codec.js      DNS message, name compression and record codec
assets/http-codec.js     HTTP/1.1 framing, HTTP/2 frames and HPACK codec
assets/tls-codec.js      TLS record, handshake and extension codec
assets/dissect-codec.js  Cross-layer Ethernet/IP/transport/application dissector
assets/*.js         per-protocol pure codecs and page wiring
assets/search-index.js  static search index
fonts/              JetBrains Mono source file (SIL OFL) + license; CSS embeds it for file:// use
```

## Shareable state

Each protocol page has a **copy page link** button. It serializes the visible encoder and
decoder fields into the URL hash, so a built packet or a decoded frame can be bookmarked and
shared without a server. Restoring a link replays the form inputs; encoder panels rebuild their
output, and the DNS, UDP and dissector permalinks also re-run their decoders.

Every protocol page can also download its visible field values and outputs as JSON. DNS, UDP,
HTTP, TLS and the packet dissector add structured JSON exports and explicit permalinks, and
the dissector adds copy-as-BPF and copy-as-Scapy snippets. No state is stored anywhere except
the URL.

## Organization

Protocols are grouped with the TCP/IP model, with OSI numbers as orientation labels:
Application/control (BGP, DNS, HTTP, TLS), Transport (TCP, UDP, QUIC), Tunnels/overlays
(WireGuard), Internet/IP (IPv4, ICMP, IPv6), Link (Ethernet, ARP), and cross-layer tools plus
a packet dissector. The homepage renders the stack
map from `assets/protocol-meta.js`; adding a protocol with a `modelLayer` value places it in
the map automatically. Protocol pages also carry an encapsulation stack strip. URLs stay
flat so existing links keep working. The HTTP and TLS pages include their own field
inventories, encoder/decoder panels and RFC references alongside the cross-layer walk.

## Conventions

- Bit 0 is the MSB of the first octet.
- Offsets count from the first byte of the described structure.
- Network byte order is big-endian except WireGuard, which is little-endian. HTTP/1.1 is
text; HTTP/2 and TLS use big-endian integers.
- Encoders build structural bytes and Internet checksums where documented; they do not
  encrypt, authenticate, route, fragment, or negotiate capabilities.

RFCs are the source of truth. Verify against the current RFC, errata and your
implementation before putting anything on the wire.
