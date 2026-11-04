# AGENTS.md

Guidance for future coding sessions in `packet-headers.sh`.

## What this project is

A static, dependency-free field guide to network wire formats. Every protocol page has:

- bit- or byte-aligned diagrams with offsets and field ranges
- RFC citations and explanatory prose
- a valid encoder and a defensive decoder
- copyable hex, permalinks and JSON export

The site is plain HTML, CSS and JavaScript. There is no build step, package manager, framework,
backend, analytics, CDN or runtime network request. Do not introduce one.

Current snapshot: **17 pages**, **13 protocol pages**, **15 homepage cards**, **16 nav links**,
**280 search-index links**. Update these counts when they change.

## Run locally

```sh
python3 -m http.server 8000
# open http://localhost:8000/
```

`file://` must keep working. Fonts are embedded in `assets/styles.css` for that reason; do not
replace them with an external font URL.

## Architecture

```
index.html              homepage, protocol cards, filter, TCP/IP stack model, search
*.html                  one flat-URL page per protocol or tool
assets/styles.css       design system and all layout rules
assets/core.js          shared PH utilities, diagram engines, search, theme, permalinks
assets/protocol-meta.js PH_PROTOCOLS taxonomy + PH_STACK model
assets/search-index.js  static search index (every entry must resolve)
assets/*-codec.js       pure-ish codecs, exported on window for tests and other pages
assets/*.js             page wiring for one page
fonts/                  embedded JetBrains Mono source + license
```

Load order matters. `core.js` must load before page code. Codecs must load before any page
script that uses them. `dissect-codec.js` optionally uses `DNSCodec`, `TLSCodec` and
`HTTPCodec`; guard those lookups because some pages do not load every codec.

### Shared API

Use the existing `PH` helpers rather than reimplementing them:

- `PH.esc` for every decoded string injected into `innerHTML`
- `PH.parseHex`, `PH.bytesToHex`, `PH.concatBytes`
- `PH.hexdump(bytes, { highlight: [{ start, end }] })`
- `PH.diagram(target, spec)` for bit layouts
- `PH.byteLane(target, spec)` for byte-aligned layouts
- `PH.fieldTable(target, controller, { columns })`
- `PH.setStatus(el, text, "ok" | "warn" | "bad")`
- `PH.shareState(value, message)`, `PH.readHashState()`, `PH.downloadText(...)`
- `PH.captureFormState()` / `PH.applyFormState()`

Diagram fields accept `id`, `name`, `bits` (or `bytes` for lanes), `range`, `desc`, `rfc`,
`rfcUrl`, `tone`. `"var"` means variable width.

### Page scripts

- Guard initialization so a script can be loaded on a page without its markup:
  `if (!document.getElementById("tls-record-lane")) return;`
- Keep a `lastBuild` / `lastDecode` object for permalink and JSON export.
- Use `role="status" aria-live="polite"` for codec status elements.
- Do not use `display:none` for form groups; use the `hidden` attribute.
- Page-specific hash state uses keys such as `tls-enc`, `tls-dec`, `http-enc`, `http-dec`,
  `dns-enc`, `udp-dec`, `dissect`. The generic page actions use `page:"form"` and
  `page:"snapshot"`; do not break those keys.

## Non-negotiable conventions

- Bit 0 is the MSB of the first octet. Offsets start at the first byte of the described structure.
- Network byte order is big-endian except WireGuard, which is little-endian. HTTP/1.1 is text;
  HTTP/2 and TLS use big-endian integers.
- Every field shown in a diagram/table should have a valid range and an RFC or registry citation.
- Decoders should report malformed input as warnings where possible, and throw only when the
  input cannot be the claimed protocol at all.
- Encoders must validate lengths, ranges and required fields. Never silently emit a malformed
  header. If a value is illustrative (for example a TLS key share), say so in the UI.
- Keep URLs flat: `http.html`, `tls.html`, never a directory route.
- Keep the site static. No npm, bundler, service worker that requires a server, remote fetch,
  analytics or localStorage-backed accounts.
- Preserve decoded bytes exactly. DNS names, header values and certificate bytes are not
  normalised for display.

## Adding a protocol: complete checklist

Adding a page touches more than the new files. The chrome is currently duplicated manually.

1. **Codec** — add `assets/<name>-codec.js`, export a single `window.<Name>Codec` object, and
   write a Node round-trip/malformed-input test.
2. **Page** — add `<name>.html` with the shared header/nav/rail/footer, page-head, stack bar,
   diagrams, field tables, encoder, decoder, notes and RFC references.
3. **Wiring** — add `assets/<name>.js`, guard initialization, wire encoder/decoder, permalink,
   JSON export and hash restore.
4. **Taxonomy** — add an entry to `PH_PROTOCOLS` in `assets/protocol-meta.js` with `modelLayer`,
   `layerCode`, `layerLabel`, `layerNote`, `family` and a `path`.
5. **Homepage** — add a card to `index.html`; update hero counts, page counts, filter counts,
   `protocol-filter__status`, quick links and the search-index line.
6. **Chrome** — add the link to `<nav class="site-nav">`, the rail protocol list and
   `.foot-links` on **every** HTML page. Re-test nav overflow after adding links.
7. **Search** — add a `kind:"protocol"` entry plus field/tool entries in
   `assets/search-index.js`. Every `href` and `#anchor` must exist.
8. **Dissector** — if the protocol can appear inside a frame, teach
   `assets/dissect-codec.js` to identify it and link to the page. Add a dissector example if
   useful.
9. **Docs** — update `README.md` and `about.html` (page list, layer table, RFC sources,
   conventions).
10. **Verify** — run the quality gates below.

## Testing harness in this environment

Node and Playwright live under `/tmp/opencode`. If that path is absent, use any Node 22+ and
Playwright installation.

```sh
NODE=/tmp/opencode/node-v22.14.0-linux-x64/bin/node
export PATH=/tmp/opencode/node-v22.14.0-linux-x64/bin:$PATH
```

Start the test server on port 8123 (the Playwright scripts expect it):

```sh
python3 -m http.server 8123
```

Codec tests (all should exit 0):

```
test-udp.js  test-ipv6.js  test-icmp.js  test-icmp-vlan.js  test-l2.js
test-ipv4.js test-tcp.js   test-quic.js  test-bgp.js        test-wg.js
test-dns.js  test-tls.js   test-http.js  test-dissect.js    test-dissect2.js
```

Browser checks:

```
all17.js       all pages load, search smoke test, homepage filter
axe17.js       Axe desktop + mobile, including active codec states
overflow17.js  no horizontal overflow from 320px to 1440px
file17.js      file:// loading and codec interaction
network17.js   zero external requests and no 4xx responses
perm2.js       TLS/HTTP permalink and JSON export round trips
deeppages.js   TLS/HTTP packet envelopes and dissector examples
```

Also run:

```sh
for f in assets/*.js; do "$NODE" --check "$f" || echo "FAIL $f"; done
```

And validate links/anchors with the Python parser used in previous sessions, or an equivalent
check. Search-index links are part of the public surface; do not leave a stale `#anchor`.

## Known pitfalls

- **Nav width is tuned.** 16 links fit only with the media queries near the end of
  `assets/styles.css` (`1180px`, `1320px`, `1321px`, `901–940px`). Adding a link requires a
  fresh overflow test.
- **Manual chrome drift.** Nav, rail, footer, homepage cards, search and docs are not generated.
  Missing one page is the most common integration bug.
- **Duplicate IDs.** A status div and a status-code input previously both used
  `http-enc-status`; strict Playwright locators caught it. Validate IDs after adding forms.
- **`tcp.js` has a page guard** (`if (!document.getElementById("tcp-diagram")) return;`) so it
  can be loaded on DNS, HTTP, TLS and dissector pages without a TCP diagram.
- **IPv4 vs IPv6 builders differ.** `IPv4Codec.buildHeader` returns the header only;
  `IPv6Codec.buildHeader` returns header + payload.
- **UDP checksums.** IPv4 may use zero; IPv6 requires a checksum; a computed zero is transmitted
  as `0xFFFF`.
- **TCP checksum context.** `TCPCodec.decodeSegment` only supports an IPv4 pseudo-header.
  IPv6 checksum validation is skipped.
- **DNS 0x20.** Name compression must preserve label case. Do not lower-case the compression
  dictionary keys.
- **DNS auto-detection is permissive.** The dissector prioritises explicit port hints and
  rejects DNS candidates with severe parse warnings; otherwise TLS ClientHello bytes can look
  like a DNS header.
- **TLS 1.3 encrypted boundary.** Only ClientHello and ServerHello are plaintext. Everything
  after ServerHello is AEAD-protected Application Data. Do not fake a Certificate parse.
- **HTTP/2 preface looks like a request line.** Check the 24-byte preface before
  `looksLikeHttp1`, otherwise `PRI * HTTP/2.0` is parsed as an HTTP/1 request.
- **HPACK state is per connection.** Static table indices 1–61, dynamic entries share the
  connection, entry size is `name + value + 32`, eviction is oldest-first. The RFC 7541
  Huffman table in `http-codec.js` is exact; do not regenerate it by hand.
- **HPACK pseudo-headers.** `parseHeaderText` accepts `:method`/`:path` only with
  `{ allowPseudo: true }`. HTTP/1.1 build must reject pseudo-headers.
- **Long protocol names widen pages.** Keep `overflow-wrap: break-word` on prose; test 320px
  after adding `ClientHello/ServerHello/EncryptedExtensions`-style tokens.
- **Chunked framing ambiguity.** Reject or warn on both `Transfer-Encoding: chunked` and
  `Content-Length`; do not silently pick one in documentation.

## Quality gates

Before calling a change complete:

- all codec unit tests pass
- all pages load with zero console/page errors
- Axe reports 0 violations on desktop and mobile
- no horizontal overflow at 320, 360, 390, 430, 720, 768, 900, 1024, 1200, 1320 and 1440px
- `file://` loads and codecs work
- zero external requests
- every internal link, search link and `#anchor` resolves
- permalink and JSON export round-trip for any codec you changed
- README/About/page counts and search entries are in sync

Do not commit, rewrite history or remove user work unless explicitly asked.
