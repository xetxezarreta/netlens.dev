# AGENTS.md

Guidance for future coding sessions in `netlens.dev`.

## What this project is

A static, dependency-free field guide to network wire formats. Every protocol page has:

- bit- or byte-aligned diagrams with offsets and field ranges
- RFC citations and explanatory prose
- a valid encoder and a defensive decoder
- copyable hex, permalinks and JSON export

The site is plain HTML, CSS and JavaScript. There is no build step, package manager, framework,
backend, analytics, CDN or runtime network request. Do not introduce one.

## Run locally

```sh
python3 -m http.server 8000
# then open http://localhost:8000/
```

`file://` must keep working. Fonts are embedded in `assets/styles.css` for that reason; do not
replace them with an external font URL. Do not introduce `fetch()`-based includes or ES module
imports that only work over HTTP.

## Architecture

```
index.html              homepage, TCP/IP model, protocol cards, filter, global search
404.html                custom not-found page
about.html              conventions, shortcuts, sources; no rail protocol list
dissect.html            cross-layer packet walk: layer tree, hex sync, warnings
*.html                  one flat-URL protocol page per protocol
assets/styles.css       design system and all layout rules
assets/core.js          shared PH utilities, diagram engines, search, theme, chrome
assets/protocol-meta.js PH_PROTOCOLS taxonomy + PH_STACK four-layer model
assets/search-index.js  static search index (every entry must resolve)
assets/*-codec.js       pure-ish codecs, exported on window for tests and other pages
assets/*.js             page wiring for one page
fonts/                  embedded JetBrains Mono source + license
```

Load order matters. `core.js` must load before page code. Codecs must load before any page
script that uses them. `dissect-codec.js` optionally uses `DNSCodec`, `TLSCodec` and
`HTTPCodec`; guard those lookups because some pages do not load every codec.

### Generated chrome

Do not hardcode repeated navigation lists. The following are generated at runtime:

- **Header** — brand, search, about, GitHub and theme controls into `[data-site-header]`;
  the about link is omitted on `about.html`
- **Rail protocol list** — from `PH_PROTOCOLS` into `[data-rail-protocols]`
- **Footer** — from `PH_PROTOCOLS` plus About/Contact into `[data-site-footer]`
- **Mobile navigation** — from `PH_STACK` + `PH_PROTOCOLS`, injected into `.header-tools`
- **Mobile “on this page” TOC** — from rail hash links, or from `main section[id]` headings
  when a page has no rail

A protocol page should still provide:

```html
<div class="rail__group">
  <p class="rail__label">protocols</p>
  <div data-rail-protocols></div>
</div>
```

and:

```html
<footer class="site-footer" data-site-footer>
  <noscript>…minimal fallback…</noscript>
</footer>
```

`about.html` intentionally has no rail protocol list. Keep it that way.

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
- Network byte order is big-endian. HTTP/1.1 is text; HTTP/2 and TLS use big-endian integers.
- Every field shown in a diagram/table should have a valid range and an RFC or registry citation.
- Decoders should report malformed input as warnings where possible, and throw only when the
  input cannot be the claimed protocol at all.
- Encoders must validate lengths, ranges and required fields. Never silently emit a malformed
  header. If a value is illustrative, say so in the UI.
- Keep URLs flat: `http.html`, `tls.html`, never a directory route. Clean URLs need server
  rewrites; do not change internal links to extensionless routes without host support.
- Keep the site static. No npm, bundler, service worker that requires a server, remote fetch,
  analytics or localStorage-backed accounts.
- Preserve decoded bytes exactly. DNS names, header values and certificate bytes are not
  normalised for display.

### UI conventions

- The header is deliberately minimal: brand, search, about, GitHub, theme. On mobile, a menu
  button is injected at `≤980px`. Do not reintroduce the old 16-link desktop header nav.
- The left rail is the primary desktop protocol navigation. It is hidden at `≤980px`.
- The mobile menu and mobile “on this page” TOC are generated; do not add duplicate markup.
- The TCP/IP model has exactly four layers: Application, Transport, Internet, Link. Do not add
  OSI layer codes (`L2`, `L3`, `L4`, `L7`, `L3T`) or tunnel layers. Use layer names or `1–4`.
- The index hero grid has a subtle pointer parallax. Keep it subtle and respect
  `prefers-reduced-motion: reduce`.
- `about.html` intentionally has no protocol rail list.
- The index page intentionally omits the old “why this exists” and “conventions” sections.
- Mobile breakpoints to test: 320, 360, 390, 430, 720, 768, 900, 980, 981, 1024, 1200, 1440.
- The `404.html` page must be served with HTTP 404 status, not a redirect. GitHub Pages,
  Netlify and Cloudflare Pages usually use a root `404.html` automatically; nginx needs
  `error_page 404 /404.html;` and Apache needs `ErrorDocument 404 /404.html`.

## Adding a protocol: complete checklist

1. **Codec** — add `assets/<name>-codec.js`, export a single `window.<Name>Codec` object, and
   write a Node round-trip/malformed-input test.
2. **Page** — add `<name>.html` with the standard header, `data-rail-protocols` block,
   `data-site-footer` footer, page-head, stack bar, diagrams, field tables, encoder, decoder,
   notes and RFC references. Keep the “on this page” rail group and `.toc`.
3. **Wiring** — add `assets/<name>.js`, guard initialization, wire encoder/decoder, permalink,
   JSON export and hash restore.
4. **Taxonomy** — add an entry to `PH_PROTOCOLS` in `assets/protocol-meta.js` with `name`,
   `layer`, `modelLayer`, `modelNote`, `tone`, `layerCode` (`1`–`4`, or `ALL` for cross-layer
   tools), `layerLabel`, `layerNote`, `family` and a `path`. Add `railLayer` for cross-layer
   tools.
   Optional flags: `rail: false` hides the desktop rail entry; `footer: false` hides the footer
   entry.
5. **Homepage** — add a protocol card to `index.html` with the correct `data-layer`. Update the
   static chip/status counts and hero stats when the number of cards changes. The JS recalculates
   filter counts at runtime, but the static values should still match.
6. **Search** — add a `kind:"protocol"` entry plus field/tool entries in
   `assets/search-index.js`. Every `href` and `#anchor` must exist.
7. **Dissector** — if the protocol can appear inside a frame, teach `assets/dissect-codec.js`
   to identify it and link to the page. Add a dissector example if useful.
8. **Docs** — update `README.md` and `about.html` (page list, layer table, RFC sources,
   conventions).
9. **Chrome** — do **not** manually edit the header nav, footer links, rail protocol list, or
   mobile nav. They are generated from `PH_PROTOCOLS`.
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

Codec tests (all should exit 0; `test-wg.js` is obsolete):

```
test-udp.js  test-ipv6.js  test-icmp.js  test-icmp-vlan.js  test-l2.js
test-ipv4.js test-tcp.js   test-quic.js  test-bgp.js        test-dns.js
test-tls.js  test-http.js  test-dissect.js test-dissect2.js  test-arp-vlan.js
```

Browser checks:

```
all16.js       all pages load, search smoke test, homepage filter
axe16.js       Axe desktop + mobile, including active codec states
overflow16.js  no horizontal overflow from 320px to 1440px
file17.js      file:// loading and codec interaction
network17.js   zero external requests and no 4xx responses
perm2.js       TLS/HTTP permalink and JSON export round trips
deeppages.js   TLS/HTTP packet envelopes and dissector examples
```

Some older harness files (`all17.js`, `axe17.js`, `overflow17.js`) still list the removed
`tools.html` and `wireguard.html`. Prefer the current page list:

```
index.html ipv4.html icmp.html ipv6.html tcp.html udp.html dns.html
http.html tls.html quic.html bgp.html ethernet.html arp.html
dissect.html about.html 404.html
```

Also run:

```sh
for f in assets/*.js; do "$NODE" --check "$f" || echo "FAIL $f"; done
```

And validate links/anchors with a Python parser or an equivalent check. Search-index links are
part of the public surface; do not leave a stale `#anchor`.

## Known pitfalls

- **Generated chrome drift.** Rail, footer and mobile nav come from `PH_PROTOCOLS`. If a new
  protocol is missing from navigation, check the taxonomy entry and `modelLayer`.
- **Counts drift.** Homepage cards, hero stats, search entries and README/About page counts are
  still partly manual. Update them when adding or removing pages.
- **Mobile breakpoint coupling.** The rail hides at `≤980px`; the mobile menu button appears
  there. The about link is hidden at `≤430px` and lives inside the mobile menu instead.
- **Mobile TOC source.** Protocol/about pages get it from rail hash links; the index gets it
  from `main section[id]` headings. Do not duplicate it manually.
- **Duplicate IDs.** A status div and a status-code input previously shared an ID. Validate IDs
  after adding forms.
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

- all relevant codec unit tests pass
- all 16 pages load with zero console/page errors
- Axe reports 0 violations on desktop and mobile
- no horizontal overflow at 320, 360, 390, 430, 720, 768, 900, 980, 981, 1024, 1200 and 1440px
- `file://` loads and codecs work
- zero external requests
- every internal link, search link and `#anchor` resolves
- mobile menu and mobile “on this page” TOC open, navigate and close correctly
- permalink and JSON export round-trip for any codec you changed
- README/About/page counts and search entries are in sync
- `404.html` exists and is not a redirect target

Do not commit, rewrite history or remove user work unless explicitly asked.
