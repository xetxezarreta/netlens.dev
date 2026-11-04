/* IPv6 explorer — RFC 8200 header, address tools, extension chain, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const C = window.IPv6Codec;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc8200",
    addr: "https://www.rfc-editor.org/rfc/rfc4291",
    text: "https://www.rfc-editor.org/rfc/rfc5952",
    scope: "https://www.rfc-editor.org/rfc/rfc4007",
    flow: "https://www.rfc-editor.org/rfc/rfc6437",
    jumbo: "https://www.rfc-editor.org/rfc/rfc2675",
    pmtu: "https://www.rfc-editor.org/rfc/rfc8201",
    icmpv6: "https://www.rfc-editor.org/rfc/rfc4443",
    srh: "https://www.rfc-editor.org/rfc/rfc8754",
    ah: "https://www.rfc-editor.org/rfc/rfc4302",
    esp: "https://www.rfc-editor.org/rfc/rfc4303"
  };

  const baseFields = [
    { id: "version", name: "Version", bits: 4, range: "6 (IPv6)", rfc: "RFC 8200 §3", rfcUrl: RFC.base + "#section-3", desc: "IP version. This nibble is <code>6</code> for IPv6. A value other than 6 is not an IPv6 header and should be handled by a different parser." },
    { id: "tc", name: "Traffic Class", bits: 8, range: "0–255", rfc: "RFC 8200 · RFC 2474 · RFC 3168", rfcUrl: RFC.base + "#section-3", desc: "The top six bits are the DSCP and the bottom two are ECN. It carries the same differentiated-services meaning as the IPv4 ToS octet, but there is no IPv4-style header checksum to update." },
    { id: "flow", name: "Flow Label", bits: 20, range: "0–1048575", rfc: "RFC 6437", rfcUrl: RFC.flow, desc: "A 20-bit flow identifier intended for stateless load balancing and flow classification. Zero means no flow label. Routers must not change it; it is not a port or a connection identifier." },
    { id: "plen", name: "Payload Length", bits: 16, range: "0–65535 B", rfc: "RFC 8200 · RFC 2675", rfcUrl: RFC.base + "#section-3", desc: "Length of everything after the fixed 40-byte header, including extension headers and the upper-layer payload. Zero is valid for an empty packet, or signals a jumbogram when a Hop-by-Hop Jumbo Payload option is present." },
    { id: "next", name: "Next Header", bits: 8, range: "0–255", rfc: "IANA protocol numbers", rfcUrl: "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml", desc: "The next protocol or extension header: <code>0</code> Hop-by-Hop, <code>43</code> Routing, <code>44</code> Fragment, <code>51</code> AH, <code>60</code> Destination Options, <code>58</code> ICMPv6, <code>6</code> TCP, <code>17</code> UDP, <code>59</code> No Next Header." },
    { id: "hop", name: "Hop Limit", bits: 8, range: "0–255", rfc: "RFC 8200 §3", rfcUrl: RFC.base + "#section-3", desc: "Decremented by every forwarding router. Reaching zero produces ICMPv6 Time Exceeded. It is the IPv6 replacement for IPv4 TTL; common initial values are 64, 128 and 255." },
    { id: "src", name: "Source Address", bits: 128, range: "128-bit address", rfc: "RFC 8200 · RFC 4291", rfcUrl: RFC.addr, desc: "The sending interface's 128-bit address. Link-local addresses require a zone identifier in local configuration, but the zone is not carried in the IPv6 header." },
    { id: "dst", name: "Destination Address", bits: 128, range: "128-bit address", rfc: "RFC 8200 · RFC 4291", rfcUrl: RFC.addr, desc: "The final destination. IPv6 has unicast, multicast and anycast semantics; there is no broadcast address. All-nodes multicast is <code>ff02::1</code>." }
  ];

  const hbhFields = [
    { id: "next", name: "Next Header", bits: 8, range: "0–255", rfc: "RFC 8200 §4.3", rfcUrl: RFC.base + "#section-4.3", desc: "The header or upper-layer protocol that follows this extension. The chain stops when this is not another extension header." },
    { id: "len", name: "Hdr Ext Len", bits: 8, range: "0–255 · ×8 B", rfc: "RFC 8200 §4.3", rfcUrl: RFC.base + "#section-4.3", desc: "Length of the extension header in 8-octet units, excluding the first eight octets. Total header length is <code>(value + 1) × 8</code> bytes." },
    { id: "options", name: "Options & Padding", bits: "var", varWidth: 48, range: "TLVs", rfc: "RFC 8200 §4.2", rfcUrl: RFC.base + "#section-4.2", desc: "Type-length-value options. Pad1 and PadN align the header; Router Alert, Jumbo Payload and Home Address are the options you are most likely to meet. Unknown options carry an action in the top two type bits." }
  ];

  const fragmentFields = [
    { id: "next", name: "Next Header", bits: 8, range: "0–255", rfc: "RFC 8200 §4.5", rfcUrl: RFC.base + "#section-4.5", desc: "Protocol of the fragmentable part of the original packet." },
    { id: "reserved", name: "Reserved", bits: 8, range: "0", rfc: "RFC 8200 §4.5", rfcUrl: RFC.base + "#section-4.5", desc: "Reserved; must be zero on transmission and ignored on receipt." },
    { id: "offset", name: "Fragment Offset", bits: 13, range: "0–8191 · ×8 B", rfc: "RFC 8200 §4.5", rfcUrl: RFC.base + "#section-4.5", desc: "Offset of this fragment in the original fragmentable part, in 8-byte units. The first fragment has offset 0." },
    { id: "res", name: "Res", bits: 2, range: "0", rfc: "RFC 8200 §4.5", rfcUrl: RFC.base + "#section-4.5", desc: "Two reserved bits." },
    { id: "m", name: "M", bits: 1, range: "0/1", rfc: "RFC 8200 §4.5", rfcUrl: RFC.base + "#section-4.5", desc: "More Fragments. Set on every fragment except the last. A fragment with offset 0 and M=0 is an atomic fragment." },
    { id: "id", name: "Identification", bits: 32, range: "0–4294967295", rfc: "RFC 8200 §4.5", rfcUrl: RFC.base + "#section-4.5", desc: "32-bit fragment identification, shared by all fragments of one original packet. It is not the IPv4 16-bit ID field." }
  ];

  const routingFields = [
    { id: "next", name: "Next Header", bits: 8, range: "0–255", rfc: "RFC 8200 §4.4", rfcUrl: RFC.base + "#section-4.4", desc: "The next header after the routing header." },
    { id: "len", name: "Hdr Ext Len", bits: 8, range: "0–255 · ×8 B", rfc: "RFC 8200 §4.4", rfcUrl: RFC.base + "#section-4.4", desc: "Routing header length in 8-octet units, excluding the first eight octets." },
    { id: "type", name: "Routing Type", bits: 8, range: "0–255", rfc: "RFC 8200 · IANA", rfcUrl: "https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml", desc: "Routing header type. Type 0 source routing is deprecated; type 4 is the Segment Routing Header (SRH)." },
    { id: "left", name: "Segments Left", bits: 8, range: "0–255", rfc: "RFC 8200 §4.4", rfcUrl: RFC.base + "#section-4.4", desc: "Number of route segments still to be processed. The packet is delivered locally when this reaches zero." },
    { id: "data", name: "Type-specific Data", bits: "var", varWidth: 32, range: "type-dependent", rfc: "RFC 8200 §4.4 · RFC 8754", rfcUrl: RFC.srh, desc: "Routing-type-specific data. For SRH it contains the last-entry index, flags, tag and the segment list of 128-bit addresses." }
  ];

  let baseController = null;

  function initDiagrams() {
    baseController = PH.diagram("#ipv6-diagram", {
      title: "<b>IPv6</b> · fixed header", badge: "RFC 8200", fields: baseFields,
      inspector: "#ipv6-inspector", table: "#ipv6-fields",
      note: "IPv6 headers are exactly 40 bytes. Extension headers and the upper-layer payload follow; Payload Length counts all of them but not the 40-byte base header. There is no header checksum."
    });
    PH.fieldTable("#ipv6-fields", baseController, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#ipv6-frame-lane", {
      title: "<b>IPv6 packet</b> · extension chain", badge: "40 B base header",
      fields: [
        { name: "IPv6 header", bytes: 40, range: "40 B", desc: "Version, traffic class, flow label, payload length, next header, hop limit and two 128-bit addresses.", rfc: "RFC 8200", rfcUrl: RFC.base, tone: "a" },
        { name: "Extension headers", bytes: "var", variable: true, range: "0+ B", desc: "Hop-by-Hop, Routing, Fragment, AH and Destination Options headers, linked by Next Header fields. Their lengths vary; AH counts 4-octet units, the others 8-octet units.", rfc: "RFC 8200", rfcUrl: RFC.base, tone: "c" },
        { name: "Upper-layer payload", bytes: "var", variable: true, range: "0+ B", desc: "TCP, UDP, ICMPv6, SCTP or another upper-layer protocol after the extension chain.", rfc: "RFC 8200", rfcUrl: RFC.base, tone: "d" }
      ],
      inspector: "#ipv6-frame-inspector",
      note: "Payload Length includes the extension headers and the upper-layer payload. The chain ends at the first Next Header that is not an extension header."
    });

    PH.diagram("#ipv6-hbh-diagram", {
      title: "<b>Hop-by-Hop / Destination Options</b>", badge: "8+ B", fields: hbhFields,
      inspector: "#ipv6-hbh-inspector",
      note: "Hop-by-Hop must be the first extension header if present. Destination Options may appear before routing and again before the upper layer."
    });
    PH.diagram("#ipv6-fragment-diagram", {
      title: "<b>Fragment</b> extension", badge: "8 B", fields: fragmentFields,
      inspector: "#ipv6-fragment-inspector",
      note: "IPv6 fragments only the fragmentable part, not the fixed header. The fragment header is always 8 bytes."
    });
    PH.diagram("#ipv6-routing-diagram", {
      title: "<b>Routing</b> extension", badge: "8+ B", fields: routingFields,
      inspector: "#ipv6-routing-inspector",
      note: "Routing Type 0 source routing is deprecated. Type 4 is the Segment Routing Header used by SRv6."
    });
  }

  function updateBaseDiagram(ip) {
    if (!baseController || !ip) return;
    baseController.setValues({
      version: String(ip.version),
      tc: ip.trafficClass + " · DSCP " + ip.dscp + " · ECN " + ip.ecn,
      flow: "0x" + PH.hex(ip.flowLabel, 5),
      plen: String(ip.payloadLength),
      next: ip.nextHeader + " " + ip.nextHeaderName,
      hop: String(ip.hopLimit),
      src: ip.src,
      dst: ip.dst
    });
  }

  function initFirstWord() {
    const dscp = document.getElementById("ipv6-dscp");
    const ecn = document.getElementById("ipv6-ecn");
    const flow = document.getElementById("ipv6-flow-label");
    if (!dscp) return;
    function update() {
      const d = Math.max(0, Math.min(63, Number(dscp.value) || 0));
      const e = Math.max(0, Math.min(3, Number(ecn.value) || 0));
      const label = PH.parseNumber(flow.value);
      const f = Math.max(0, Math.min(0xfffff, label == null ? 0 : label));
      dscp.value = d;
      const tc = (d << 2) | e;
      const word = (6 * 0x10000000) + (tc * 0x100000) + f;
      document.getElementById("ipv6-tc-value").textContent = `${tc} · 0x${PH.hex(tc, 2)}`;
      document.getElementById("ipv6-flow-value").textContent = `0x${PH.hex(f, 5)}`;
      document.getElementById("ipv6-first-word").textContent = "0x" + PH.hex(word >>> 0, 8);
      document.getElementById("ipv6-first-bits").textContent = PH.bin(word >>> 0, 32).replace(/(.{4})(?=.)/g, "$1 ");
    }
    [dscp, ecn, flow].forEach((el) => {
      el.addEventListener("input", update);
      el.addEventListener("change", update);
    });
    update();
  }

  function addressRows(info) {
    const rows = [
      ["Compressed", info.canonical, "RFC 5952 canonical form"],
      ["Expanded", info.expanded, "All eight groups, four hex digits each"],
      ["128-bit hex", info.hex, "16 bytes in wire order"],
      ["Prefix", "/" + info.prefix, "Length used for the network calculation"],
      ["Network", info.network, "Address masked to the prefix"],
      ["Scope", info.scope, "Special-use classification"],
      ["Zone", info.zone || "—", "Local interface identifier; never on the wire"]
    ];
    if (info.isMulticast) {
      rows.push(["Multicast scope", info.multicastScope, "Low nibble of the second octet"]);
      rows.push(["Multicast flags", "0x" + PH.hex(info.multicastFlags, 1), "High nibble of the second octet"]);
    }
    return rows;
  }

  function initAddressTool() {
    const input = document.getElementById("ipv6-addr-input");
    const prefix = document.getElementById("ipv6-addr-prefix");
    const status = document.getElementById("ipv6-addr-status");
    const host = document.getElementById("ipv6-addr-result");
    if (!input) return;

    function run(showErrors) {
      let parsed;
      try {
        parsed = C.parseIPv6Info(input.value);
        const p = input.value.includes("/") ? parsed.prefix : (prefix.value.trim() === "" ? parsed.prefix : Number(prefix.value));
        if (!Number.isInteger(p) || p < 0 || p > 128) throw new Error("Prefix length must be 0–128");
        const info = C.addressInfo(parsed.bytes, p, parsed.zone);
        const rows = addressRows(info);
        host.innerHTML =
          `<div class="decode-summary"><span class="pill">${PH.esc(info.canonical)}</span><span class="pill">${PH.esc(info.scope)}</span><span class="pill">/${info.prefix}</span></div>` +
          '<div class="table-wrap"><table class="data-table"><thead><tr><th>Property</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
          rows.map(([name, value, note]) => `<tr><td><b>${PH.esc(name)}</b></td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`).join("") +
          "</tbody></table></div>";
        PH.setStatus(status, `${info.canonical} · ${info.scope} · ${info.network}`, "ok");
      } catch (err) {
        if (showErrors !== false) PH.setStatus(status, "address error: " + err.message, "bad");
        host.innerHTML = "";
      }
    }

    document.getElementById("ipv6-addr-parse").addEventListener("click", () => run(true));
    document.querySelectorAll("[data-ipv6-addr]").forEach((btn) => {
      btn.addEventListener("click", () => {
        input.value = btn.getAttribute("data-ipv6-addr");
        prefix.value = btn.getAttribute("data-ipv6-prefix") || "64";
        run(true);
      });
    });
    [input, prefix].forEach((el) => {
      el.addEventListener("keydown", (event) => {
        if (event.key === "Enter") { event.preventDefault(); run(true); }
      });
    });
    run(false);
  }

  function bytesToAscii(text) {
    if (window.TextEncoder) return new TextEncoder().encode(text);
    const out = [];
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      out.push(c < 128 ? c : 63);
    }
    return Uint8Array.from(out);
  }

  function buildTcpPayload(src, dst) {
    const segment = new Uint8Array(20);
    PH.put16be(segment, 0, 12345);
    PH.put16be(segment, 2, 80);
    PH.put32be(segment, 4, 0x01020304);
    PH.put32be(segment, 8, 0);
    segment[12] = 0x50;
    segment[13] = 0x02;
    PH.put16be(segment, 14, 64240);
    PH.put16be(segment, 16, C.transportChecksum(src, dst, 6, segment));
    return segment;
  }

  function buildUdpPayload(src, dst) {
    const datagram = new Uint8Array(8);
    PH.put16be(datagram, 0, 12345);
    PH.put16be(datagram, 2, 53);
    PH.put16be(datagram, 4, 8);
    PH.put16be(datagram, 6, 0);
    let checksum = C.transportChecksum(src, dst, 17, datagram);
    if (checksum === 0) checksum = 0xffff;
    PH.put16be(datagram, 6, checksum);
    return datagram;
  }

  function buildIcmpv6Payload(src, dst) {
    const data = bytesToAscii("ipv6 echo");
    const message = new Uint8Array(8 + data.length);
    message[0] = 128;
    message[1] = 0;
    PH.put16be(message, 4, 0x1234);
    PH.put16be(message, 6, 1);
    message.set(data, 8);
    PH.put16be(message, 2, C.transportChecksum(src, dst, 58, message));
    return message;
  }

  function makePresetPayload(kind, src, dst) {
    if (kind === "empty") return { nextHeader: 59, payload: new Uint8Array(0) };
    if (kind === "tcp") return { nextHeader: 6, payload: buildTcpPayload(src, dst) };
    if (kind === "udp") return { nextHeader: 17, payload: buildUdpPayload(src, dst) };
    if (kind === "icmpv6") return { nextHeader: 58, payload: buildIcmpv6Payload(src, dst) };
    if (kind === "hbh") {
      const icmp = buildIcmpv6Payload(src, dst);
      return { nextHeader: 0, payload: PH.concatBytes(C.buildRouterAlert(58, 0), icmp) };
    }
    if (kind === "fragment") {
      const udp = buildUdpPayload(src, dst);
      return { nextHeader: 44, payload: PH.concatBytes(C.buildFragment(17, 0, false, 0x12345678), udp) };
    }
    if (kind === "dest") {
      return { nextHeader: 60, payload: C.buildDestinationOptions(59, new Uint8Array(0)) };
    }
    return { nextHeader: 59, payload: new Uint8Array(0) };
  }

  function syncNextHeader() {
    const next = Number(document.getElementById("ipv6-enc-next").value);
    document.getElementById("ipv6-enc-next-hint").textContent = next + " · " + C.nextHeaderName(next);
  }

  function updateAutoLength() {
    const el = document.getElementById("ipv6-enc-payload");
    const out = document.getElementById("ipv6-enc-payload-len");
    try {
      const bytes = el.value.trim() ? PH.parseHex(el.value) : new Uint8Array(0);
      out.value = String(bytes.length);
    } catch (_) {
      out.value = "?";
    }
  }

  function readEncoder() {
    const payloadText = document.getElementById("ipv6-enc-payload").value;
    return {
      version: Number(document.getElementById("ipv6-enc-version").value),
      dscp: Number(document.getElementById("ipv6-enc-dscp").value),
      ecn: Number(document.getElementById("ipv6-enc-ecn").value),
      flowLabel: PH.parseNumber(document.getElementById("ipv6-enc-flow").value),
      nextHeader: Number(document.getElementById("ipv6-enc-next").value),
      hopLimit: Number(document.getElementById("ipv6-enc-hop").value),
      src: document.getElementById("ipv6-enc-src").value,
      dst: document.getElementById("ipv6-enc-dst").value,
      payload: payloadText.trim() ? PH.parseHex(payloadText) : new Uint8Array(0)
    };
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("ipv6-enc-status");
    const output = document.getElementById("ipv6-enc-output");
    const summary = document.getElementById("ipv6-enc-summary");
    const tag = document.getElementById("ipv6-enc-tag");
    let built;
    try {
      built = C.buildHeader(readEncoder());
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(built.bytes);
    output.classList.remove("placeholder");
    tag.textContent = built.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">IPv${built.version}</span>`,
      `<span class="pill">payload <b>${built.payloadLength} B</b></span>`,
      `<span class="pill">next <b>${built.nextHeader} · ${PH.esc(built.nextHeaderName)}</b></span>`,
      `<span class="pill">hop <b>${built.hopLimit}</b></span>`,
      `<span class="pill">flow <b>0x${PH.hex(built.flowLabel, 5)}</b></span>`
    ].join("");
    document.getElementById("ipv6-enc-payload-len").value = String(built.payloadLength);
    PH.setStatus(
      status,
      `built ${built.bytes.length}-byte IPv${built.version} packet · ${built.payloadLength} B payload · next ${built.nextHeader} ${built.nextHeaderName}`,
      "ok"
    );
    updateBaseDiagram(built);
    return built;
  }

  function setPreset(kind) {
    const src = document.getElementById("ipv6-enc-src").value;
    const dst = document.getElementById("ipv6-enc-dst").value;
    let preset;
    try {
      preset = makePresetPayload(kind, src, dst);
    } catch (err) {
      PH.setStatus(document.getElementById("ipv6-enc-status"), "preset error: " + err.message, "bad");
      return;
    }
    document.getElementById("ipv6-enc-next").value = String(preset.nextHeader);
    document.getElementById("ipv6-enc-payload").value = PH.bytesToHex(preset.payload);
    syncNextHeader();
    updateAutoLength();
    buildFromForm(true);
  }

  function initEncoder() {
    document.getElementById("ipv6-enc-build").addEventListener("click", () => buildFromForm(true));
    document.getElementById("ipv6-enc-example").addEventListener("click", () => setPreset("hbh"));
    document.querySelectorAll("[data-ipv6-preset]").forEach((btn) => {
      btn.addEventListener("click", () => setPreset(btn.getAttribute("data-ipv6-preset")));
    });
    const live = ["ipv6-enc-version", "ipv6-enc-dscp", "ipv6-enc-ecn", "ipv6-enc-flow", "ipv6-enc-next", "ipv6-enc-hop", "ipv6-enc-src", "ipv6-enc-dst", "ipv6-enc-payload"];
    live.forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener("input", () => {
        if (id === "ipv6-enc-next") syncNextHeader();
        if (id === "ipv6-enc-payload") updateAutoLength();
        buildFromForm(false);
      });
      el.addEventListener("change", () => {
        if (id === "ipv6-enc-next") syncNextHeader();
        if (id === "ipv6-enc-payload") updateAutoLength();
        buildFromForm(false);
      });
    });
    syncNextHeader();
    updateAutoLength();
    buildFromForm(false);
  }

  function transportText(t) {
    if (!t) return "—";
    if (t.kind === "TCP") return `TCP ${t.source} → ${t.destination} · seq ${t.sequence} · flags 0x${PH.hex(t.flags, 2)}`;
    if (t.kind === "UDP") return `UDP ${t.source} → ${t.destination} · length ${t.length} · checksum 0x${PH.hex(t.checksum, 4)}`;
    if (t.kind === "ICMPv6") return `ICMPv6 ${t.type} · ${t.typeName} · code ${t.code}`;
    if (t.kind === "SCTP") return `SCTP ${t.source} → ${t.destination} · tag 0x${PH.hex(t.verificationTag, 8)}`;
    if (t.kind === "ESP") return "ESP · encrypted payload";
    if (t.kind === "IPv6-in-IPv6") return "inner IPv6 packet";
    return t.kind;
  }

  function detailTable(title, hint, headers, rows) {
    if (!rows.length) return "";
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") +
      "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") +
      "</tbody></table></div>";
  }

  function renderDecoded(result) {
    const host = document.getElementById("ipv6-decode-result");
    const ip = result.ip;
    const chain = result.chain;
    const extLength = chain.headers.reduce((n, h) => n + h.length, 0);
    const headerEnd = result.ipOffset + 40 + extLength;
    const pills = [
      `<span class="pill">IPv${ip.version}</span>`,
      `<span class="pill">payload <b>${ip.payloadLength} B</b></span>`,
      `<span class="pill">next <b>${ip.nextHeader} · ${PH.esc(ip.nextHeaderName)}</b></span>`,
      `<span class="pill">hop <b>${ip.hopLimit}</b></span>`,
      `<span class="pill">flow <b>0x${PH.hex(ip.flowLabel, 5)}</b></span>`,
      `<span class="pill">extensions <b>${chain.headers.length}</b></span>`,
      `<span class="pill">terminal <b>${PH.esc(chain.terminal.name)}</b></span>`
    ];
    if (ip.jumboPayloadLength != null) pills.push(`<span class="pill pill--warn">jumbo <b>${ip.jumboPayloadLength} B</b></span>`);
    if (result.ethernet) pills.push(`<span class="pill pill--good">Ethernet${result.ethernet.vlanTags.length ? " + VLAN" : ""}</span>`);
    if (chain.terminal.transport) pills.push(`<span class="pill">${PH.esc(chain.terminal.transport.kind)}</span>`);

    const baseRows = [
      ["Version", "4", "0–3", String(ip.version), "must be 6"],
      ["Traffic Class", "8", "4–11", `${ip.trafficClass} · DSCP ${ip.dscp} · ECN ${ip.ecn}`, "DSCP high 6 bits, ECN low 2"],
      ["Flow Label", "20", "12–31", "0x" + PH.hex(ip.flowLabel, 5), "0 means unlabelled"],
      ["Payload Length", "16", "32–47", `${ip.payloadLength} B`, ip.payloadLengthZero ? "zero / jumbogram case" : "extension headers + upper layer"],
      ["Next Header", "8", "48–55", `${ip.nextHeader} · ${ip.nextHeaderName}`, "first header in the chain"],
      ["Hop Limit", "8", "56–63", String(ip.hopLimit), "decremented by routers"],
      ["Source Address", "128", "64–191", ip.src, "canonical RFC 5952 form"],
      ["Destination Address", "128", "192–319", ip.dst, "unicast, multicast or anycast"]
    ];
    const baseTable = baseRows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    const addressRows = [
      ["Source", ip.src, ip.srcInfo.expanded, ip.srcInfo.scope],
      ["Destination", ip.dst, ip.dstInfo.expanded, ip.dstInfo.scope]
    ];
    const addressTable = detailTable(
      "addresses", "canonical form · expanded form · special-use scope",
      ["Role", "Canonical", "Expanded", "Scope"],
      addressRows.map(([role, canonical, expanded, scope]) =>
        [`<b>${PH.esc(role)}</b>`, `<code>${PH.esc(canonical)}</code>`, `<code>${PH.esc(expanded)}</code>`, `<span class="small">${PH.esc(scope)}</span>`]
      )
    );

    let chainHtml = "";
    if (chain.headers.length) {
      chainHtml = detailTable(
        "extension header chain", "offsets from the start of the IPv6 header",
        ["#", "Offset", "Header", "Length", "Next Header", "Decoded"],
        chain.headers.map((h, i) => [
          String(i + 1), `<span class="num">${h.offset}</span>`, `<b>${PH.esc(h.name)}</b>`,
          `<span class="num">${h.length} B</span>`, `<code>${h.nextHeader} · ${PH.esc(h.nextHeaderName)}</code>`,
          `<span class="small">${PH.esc(h.detail || "")}</span>`
        ])
      );
    } else {
      chainHtml = '<div class="callout"><div class="callout__title">no extension headers</div><p>The base header’s Next Header field points directly at the upper-layer protocol. Extension headers are optional except where a specific feature requires them.</p></div>';
    }

    const optionRows = [];
    chain.headers.forEach((h, i) => {
      (h.options || []).forEach((o) => {
        optionRows.push([
          String(i + 1), `<b>${PH.esc(o.name)}</b>`, `<code>0x${PH.hex(o.type, 2)}</code>`,
          `<span class="num">${o.length} B</span>`, `<span class="small">${PH.esc(o.detail)}</span>`
        ]);
      });
    });
    const optionsTable = detailTable(
      "extension options", "option type · total length including type and length octets",
      ["Header", "Option", "Type", "Length", "Decoded"], optionRows
    );

    const terminalRows = [
      ["Next Header", `${chain.terminal.nextHeader} · ${chain.terminal.name}`, "First non-extension header"],
      ["Offset", chain.terminal.offset + " B", "From the start of the IPv6 header"],
      ["Length", chain.terminal.length + " B", "Captured bytes after the extension chain"],
      ["Transport hint", transportText(chain.terminal.transport), "Derived from the first bytes of the upper layer"]
    ];
    const terminalTable = detailTable(
      "upper-layer boundary", "the chain stops here",
      ["Field", "Value", "Note"],
      terminalRows.map(([a, b, c]) => [`<b>${PH.esc(a)}</b>`, `<code>${PH.esc(b)}</code>`, `<span class="small">${PH.esc(c)}</span>`])
    );

    let preview = "";
    if (chain.terminal.bytes.length) {
      const take = Math.min(64, chain.terminal.bytes.length);
      preview = '<div class="output"><div class="output__label">first ' + take + ' B of upper-layer payload</div><pre>' +
        PH.esc(PH.bytesToHex(chain.terminal.bytes.subarray(0, take))) + (chain.terminal.bytes.length > take ? " …" : "") + "</pre></div>";
    }

    let context = "";
    if (result.ethernet) {
      const eth = result.ethernet;
      context = `<div class="callout"><div class="callout__title">Ethernet wrapper</div><p>${PH.esc(eth.srcMac)} → ${PH.esc(eth.dstMac)} · EtherType <code>0x86DD</code>${eth.vlanTags.length ? " · VLAN " + eth.vlanTags.map((v) => v.vid).join(" / ") : ""}. IPv6 is carried directly in the Ethernet payload; there is no IPv4 header in between. <a href="ethernet.html">Open the Ethernet explorer</a>.</p></div>`;
    }
    if (ip.payloadLengthZero) {
      context += '<div class="callout"><div class="callout__title">Payload Length = 0</div><p>An empty IPv6 packet is valid, and a jumbogram also uses zero here with a Hop-by-Hop Jumbo Payload option. The decoder uses the captured bytes when the payload length is zero and reports any jumbo option it finds.</p></div>';
    }
    if (ip.jumboPayloadLength != null) {
      context += `<div class="callout"><div class="callout__title">Jumbogram</div><p>The Jumbo Payload option advertises <b>${ip.jumboPayloadLength}</b> bytes. This is an RFC 2675 extension; it is not available on every path and must be explicitly supported.</p></div>`;
    }

    const warnings = ip.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        ip.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean header chain</div><p>Lengths and extension offsets agree. Upper-layer checksums are not validated here; TCP, UDP and ICMPv6 checksums require an IPv6 pseudo-header.</p></div>';

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${PH.esc(result.detectedAs)}</span><span>${result.bytes.length} B · base header + ${extLength} B extensions</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: result.ipOffset, end: headerEnd }] })}</div>` +
      '<div class="decoded-head"><h3>IPv6 base header</h3><span class="dim">offsets relative to the IPv6 header</span></div>' +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${baseTable}</tbody></table></div>` +
      addressTable + chainHtml + optionsTable + terminalTable + preview + context + warnings;
  }

  function makeBasicExample() {
    const src = "2001:db8::1";
    const dst = "2001:db8::2";
    const udp = buildUdpPayload(src, dst);
    return C.buildHeader({ version: 6, dscp: 0, ecn: 0, flowLabel: 0x12345, nextHeader: 17, hopLimit: 64, src, dst, payload: udp });
  }

  function makeExtensionExample() {
    const src = "2001:db8::1";
    const dst = "2001:db8::2";
    const udp = buildUdpPayload(src, dst);
    const payload = PH.concatBytes(
      C.buildRouterAlert(60, 0),
      C.buildDestinationOptions(44, new Uint8Array(0)),
      C.buildFragment(17, 0, false, 0x12345678),
      udp
    );
    return C.buildHeader({ version: 6, dscp: 0, ecn: 0, flowLabel: 0x12345, nextHeader: 0, hopLimit: 64, src, dst, payload });
  }

  function initDecoder() {
    const input = document.getElementById("ipv6-decode-input");
    const status = document.getElementById("ipv6-decode-status");
    const host = document.getElementById("ipv6-decode-result");
    if (!input) return;

    function run(showErrors) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      let result;
      try { result = C.decodePacket(bytes); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      renderDecoded(result);
      updateBaseDiagram(result.ip);
      PH.setStatus(
        status,
        `${result.ip.src} → ${result.ip.dst} · ${result.ip.payloadLength} B payload · ${result.chain.headers.length} extension header(s) · ${result.chain.terminal.name}${result.ip.warnings.length ? " · " + result.ip.warnings.length + " note(s)" : ""}`,
        result.ip.warnings.length ? "warn" : "ok"
      );
    }

    document.getElementById("ipv6-decode").addEventListener("click", () => run(true));
    document.getElementById("ipv6-decode-example").addEventListener("click", () => {
      input.value = PH.bytesToHex(makeBasicExample().bytes);
      run(true);
    });
    document.getElementById("ipv6-decode-ext-example").addEventListener("click", () => {
      input.value = PH.bytesToHex(makeExtensionExample().bytes);
      run(true);
    });
    document.getElementById("ipv6-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No IPv6 packet decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run(true);
    });
  }

  function init() {
    if (!document.getElementById("ipv6-diagram")) return;
    initDiagrams();
    initFirstWord();
    initAddressTool();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();


})();
