<p align="center">
  <img src="favicon.svg" alt="netlens.dev logo" width="72" height="72">
</p>

# netlens.dev

A static, interactive field guide to network wire formats. Read the header, inspect every
field, then build or decode real bytes in the browser.

Plain HTML, CSS and JavaScript. No build step, no dependencies, no tracking, and no runtime
network requests. External RFC links open only when clicked.

Site: <https://netlens.dev>

Source repository: <https://github.com/xetxezarreta/netlens.dev>

Contact: <contact@netlens.dev> · [GitHub Issues](https://github.com/xetxezarreta/netlens.dev/issues)

## Run it

```sh
python3 -m http.server 8000
# open http://localhost:8000/
```

Opening `index.html` directly from disk also works, but a local server is the least surprising
option.

## What is inside

- **13 protocol pages:** BGP, DNS, DHCP, HTTP, TLS, TCP, UDP, QUIC, IPv4, IPv6, ICMP, Ethernet, ARP
- **Packet dissector:** one frame, every layer, with offset-linked hex
- **Interactive diagrams:** bit and byte layouts with offsets, ranges and RFC citations
- **Encoders and decoders:** structural checks, checksums and copyable output
- **Search:** protocols, fields, flags, RFCs and hex
- **Shareable state:** permalinks and JSON export for page inputs and outputs
- **Mobile navigation:** protocol menu and “on this page” sections
- **Custom 404 page:** `404.html`

Protocols follow a strict four-layer TCP/IP model: Application, Transport, Internet and Link.

## Layout

```
index.html              homepage, TCP/IP model, protocol index and search
404.html                not-found page
about.html              conventions, shortcuts and RFC sources
dissect.html            cross-layer packet walk
*.html                  one flat-URL page per protocol
css/styles.css          design system and layout
js/core.js              shared utilities, diagrams, search, theme and chrome
js/protocol-meta.js     TCP/IP taxonomy and stack model
js/search-index.js      static search index
js/*-codec.js           shared protocol codecs
js/*.js                 page wiring and page-local codecs
fonts/                  JetBrains Mono (SIL OFL) + license
```

## Notes

- Bit 0 is the MSB of the first octet; offsets start at the first byte of the described structure.
- Network byte order is big-endian. HTTP/1.1 is text; HTTP/2 and TLS use big-endian integers.
- URLs stay flat (`icmp.html`, not `/icmp`). Clean URLs require server rewrites.
- Serve `404.html` with a 404 status for missing paths. For nginx:
  `error_page 404 /404.html;`
- RFCs are the source of truth. Verify against the current RFC, errata and your implementation
  before putting anything on the wire.
