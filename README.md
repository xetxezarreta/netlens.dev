# packet-headers.sh

A static, interactive field guide to network wire formats: IPv4 options, ICMP types, IPv6
extension chains, TCP flags and TLVs, QUIC headers and frames, BGP path attributes, and
WireGuard messages.

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
tcp.html            TCP header, flags, options, scan recipes, encoder/decoder
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
assets/*.js         per-protocol pure codecs and page wiring
assets/search-index.js  static search index
fonts/              JetBrains Mono source file (SIL OFL) + license; CSS embeds it for file:// use
```

## Organization

Protocols are grouped with the TCP/IP model, with OSI numbers as orientation labels:
Application/control (BGP), Transport (TCP, QUIC), Tunnels/overlays (WireGuard),
Internet/IP (IPv4, ICMP, IPv6), Link (Ethernet, ARP), and cross-layer tools. The homepage renders the stack
map from `assets/protocol-meta.js`; adding a protocol with a `modelLayer` value places it in
the map automatically. Protocol pages also carry an encapsulation stack strip. URLs stay
flat so existing links keep working.

## Conventions

- Bit 0 is the MSB of the first octet.
- Offsets count from the first byte of the described structure.
- Network byte order is big-endian except WireGuard, which is little-endian.
- Encoders build structural bytes and Internet checksums where documented; they do not
  encrypt, authenticate, route, fragment, or negotiate capabilities.

RFCs are the source of truth. Verify against the current RFC, errata and your
implementation before putting anything on the wire.
