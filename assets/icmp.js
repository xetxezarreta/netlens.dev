/* ICMPv4 explorer — RFC 792 message layout, type/code explorer, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const C = window.ICMPCodec;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc792",
    ext: "https://www.rfc-editor.org/rfc/rfc4884",
    pmtu: "https://www.rfc-editor.org/rfc/rfc1191",
    rfc1122: "https://www.rfc-editor.org/rfc/rfc1122",
    rfc1812: "https://www.rfc-editor.org/rfc/rfc1812",
    iana: "https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml",
    rfc4443: "https://www.rfc-editor.org/rfc/rfc4443"
  };

  const SAMPLE_INNER =
    "45 00 00 1c 1c 46 40 00 40 11 32 39 c0 00 02 0a c6 33 64 14 " +
    "30 39 00 35 00 08 00 00";
  const SAMPLE_ECHO = "packet-headers.sh ping";
  const SAMPLE_TIMESTAMPS = "00 00 00 00 00 00 00 64 00 00 00 c8";

  const fields = [
    {
      id: "type", name: "Type", bits: 8, range: "0–255",
      rfc: "RFC 792", rfcUrl: RFC.base,
      desc: "Message class. <code>0</code> echo reply, <code>3</code> destination unreachable, <code>5</code> redirect, <code>8</code> echo request, <code>11</code> time exceeded, <code>12</code> parameter problem. IANA maintains the full registry."
    },
    {
      id: "code", name: "Code", bits: 8, range: "0–255",
      rfc: "RFC 792", rfcUrl: RFC.base,
      desc: "Sub-type within the message type. For example, type 3 uses <code>3</code> for port unreachable and <code>4</code> for fragmentation needed with DF set. The code space is type-specific."
    },
    {
      id: "checksum", name: "Checksum", bits: 16, range: "0–65535",
      rfc: "RFC 1071 · RFC 792", rfcUrl: "https://www.rfc-editor.org/rfc/rfc1071",
      desc: "Internet checksum over the entire ICMP message: common header plus all data. ICMPv4 has no pseudo-header. A receiver that sums the message including the checksum sees <code>0xFFFF</code> when it is valid."
    },
    {
      id: "rest", name: "Rest of Header", bits: 32, range: "type-specific",
      rfc: "RFC 792 · RFC 4884", rfcUrl: RFC.base,
      desc: "Four bytes whose meaning depends on the type and code: echo identifier and sequence, a redirect gateway, a parameter pointer, a next-hop MTU, or an RFC 4884 original-datagram length. The rest-of-header table on this page enumerates the common forms."
    },
    {
      id: "data", name: "Data", bits: "var", varWidth: 32, range: "0–65527 B",
      rfc: "RFC 792", rfcUrl: RFC.base,
      desc: "Message body. Echo requests and replies carry arbitrary payload; error messages normally quote the original IPv4 header and at least eight bytes of its payload; timestamp messages carry three 32-bit timestamps. The actual length is bounded by the enclosing IPv4 datagram."
    }
  ];

  let diagramController = null;

  function initDiagrams() {
    diagramController = PH.diagram("#icmp-diagram", {
      title: "<b>ICMPv4</b> · common message header", badge: "RFC 792",
      fields, inspector: "#icmp-inspector", table: "#icmp-fields",
      note: "The first eight bytes are common to every ICMPv4 message. The diagram draws Data at a nominal 32 bits; real bodies range from zero bytes to the IPv4 payload limit. Bit 0 is the MSB of the Type octet."
    });
    PH.fieldTable("#icmp-fields", diagramController, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#icmp-frame-lane", {
      title: "<b>ICMP in IPv4</b> · packet shape", badge: "protocol 1",
      fields: [
        { name: "IPv4 header", bytes: 20, range: "20–60 B", desc: "The IPv4 header. Options, if present, extend it to 60 bytes and shift the ICMP header right.", rfc: "RFC 791", rfcUrl: "https://www.rfc-editor.org/rfc/rfc791", tone: "a" },
        { name: "ICMP header", bytes: 8, range: "8 B", desc: "Type, code, checksum and the type-specific rest-of-header word.", rfc: "RFC 792", rfcUrl: RFC.base, tone: "c" },
        { name: "ICMP data", bytes: "var", variable: true, range: "0–65507 B", desc: "Echo payload, timestamp fields, a subnet mask, or the quoted original datagram in an error message.", rfc: "RFC 792", rfcUrl: RFC.base, tone: "d" }
      ],
      inspector: "#icmp-frame-inspector",
      note: "IPv4 Protocol is 1 for ICMP. The IPv4 total length includes both headers and the ICMP data. IPv6 uses ICMPv6 with next header 58 and a different checksum."
    });
  }

  function updateDiagram(result) {
    if (!diagramController || !result) return;
    diagramController.setValues({
      type: String(result.type),
      code: String(result.code),
      checksum: "0x" + PH.hex(result.checksum, 4) + (result.checksumOk ? " ✓" : " ✗"),
      rest: result.restSummary,
      data: result.dataLength + " B"
    });
  }

  function bytesToAscii(text) {
    if (window.TextEncoder) return new TextEncoder().encode(text);
    const out = [];
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      out.push(code < 128 ? code : 63);
    }
    return Uint8Array.from(out);
  }

  function dataFromInput() {
    const mode = document.getElementById("icmp-enc-data-mode").value;
    const raw = document.getElementById("icmp-enc-data").value;
    if (mode === "ascii") return bytesToAscii(raw);
    return raw.trim() ? PH.parseHex(raw) : new Uint8Array(0);
  }

  function syncEncoderFields() {
    const type = Number(document.getElementById("icmp-enc-type").value);
    const code = Number(document.getElementById("icmp-enc-code").value);
    const info = C.typeInfo(type);
    const kind = C.kindOf(type);
    document.getElementById("icmp-enc-type-hint").textContent = `${type} · ${info.name}`;
    document.getElementById("icmp-enc-code-hint").textContent = `${code} · ${C.codeName(type, code)}`;
    document.getElementById("icmp-enc-echo-group").hidden = !["echo", "timestamp", "information", "address-mask", "extended-echo-request", "extended-echo-reply"].includes(kind);
    document.getElementById("icmp-enc-mtu-group").hidden = !(type === 3 && code === 4);
    document.getElementById("icmp-enc-gateway-group").hidden = kind !== "redirect";
    document.getElementById("icmp-enc-pointer-group").hidden = kind !== "parameter";
    const label = document.getElementById("icmp-enc-data-label");
    if (kind === "error" || kind === "source-quench" || kind === "redirect" || kind === "parameter") {
      label.textContent = "original datagram";
    } else if (kind === "timestamp") {
      label.textContent = "timestamps · 12 bytes";
    } else if (kind === "address-mask") {
      label.textContent = "subnet mask · 4 bytes";
    } else if (kind === "echo") {
      label.textContent = "echo payload";
    } else {
      label.textContent = "message body";
    }
    const note = document.getElementById("icmp-enc-rest-note");
    if (note) note.textContent = C.restDescription(type) + ".";
  }

  function readEncoder() {
    return {
      type: Number(document.getElementById("icmp-enc-type").value),
      code: Number(document.getElementById("icmp-enc-code").value),
      identifier: PH.parseNumber(document.getElementById("icmp-enc-id").value),
      sequence: PH.parseNumber(document.getElementById("icmp-enc-seq").value),
      nextHopMtu: Number(document.getElementById("icmp-enc-mtu").value),
      gateway: document.getElementById("icmp-enc-gateway").value,
      pointer: Number(document.getElementById("icmp-enc-pointer").value),
      data: dataFromInput()
    };
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("icmp-enc-status");
    const output = document.getElementById("icmp-enc-output");
    const summary = document.getElementById("icmp-enc-summary");
    const tag = document.getElementById("icmp-enc-tag");
    let built;
    let decoded;
    let packet = null;
    try {
      built = C.buildIcmp(readEncoder());
      decoded = C.decodeIcmp(built.bytes);
      if (document.getElementById("icmp-enc-wrap").checked) {
        packet = C.wrapIPv4(built.bytes, {
          src: document.getElementById("icmp-enc-src").value,
          dst: document.getElementById("icmp-enc-dst").value,
          ttl: Number(document.getElementById("icmp-enc-ttl").value),
          id: PH.parseNumber(document.getElementById("icmp-enc-ip-id").value)
        });
      }
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    const bytes = packet ? packet.bytes : built.bytes;
    output.textContent = PH.bytesToHex(bytes);
    output.classList.remove("placeholder");
    tag.textContent = bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">${PH.esc(built.type)} · ${PH.esc(built.typeName)}</span>`,
      `<span class="pill">code ${PH.esc(built.code)} · ${PH.esc(built.codeName)}</span>`,
      `<span class="pill pill--good">checksum <b>0x${PH.hex(built.checksum, 4)}</b></span>`,
      `<span class="pill">ICMP <b>${built.messageLength} B</b></span>`,
      `<span class="pill">${packet ? "IPv4 <b>" + packet.totalLength + " B</b>" : "raw message"}</span>`
    ].join("");
    PH.setStatus(
      status,
      `built ${built.typeName.toLowerCase()} · ${built.codeName.toLowerCase()} · ${built.messageLength} B ICMP${packet ? " · " + packet.totalLength + " B IPv4 packet" : " (raw)"}`,
      "ok"
    );
    updateDiagram(decoded);
    return built;
  }

  function setPreset(name) {
    const type = document.getElementById("icmp-enc-type");
    const code = document.getElementById("icmp-enc-code");
    const data = document.getElementById("icmp-enc-data");
    const mode = document.getElementById("icmp-enc-data-mode");
    const mtu = document.getElementById("icmp-enc-mtu");
    const gateway = document.getElementById("icmp-enc-gateway");
    const pointer = document.getElementById("icmp-enc-pointer");
    const id = document.getElementById("icmp-enc-id");
    const seq = document.getElementById("icmp-enc-seq");
    if (name === "echo") {
      type.value = "8"; code.value = "0"; id.value = "0x1234"; seq.value = "1";
      mode.value = "ascii"; data.value = SAMPLE_ECHO;
    } else if (name === "reply") {
      type.value = "0"; code.value = "0"; id.value = "0x1234"; seq.value = "1";
      mode.value = "ascii"; data.value = SAMPLE_ECHO;
    } else if (name === "unreachable") {
      type.value = "3"; code.value = "3"; mode.value = "hex"; data.value = SAMPLE_INNER;
    } else if (name === "frag") {
      type.value = "3"; code.value = "4"; mtu.value = "1400"; mode.value = "hex"; data.value = SAMPLE_INNER;
    } else if (name === "time") {
      type.value = "11"; code.value = "0"; mode.value = "hex"; data.value = SAMPLE_INNER;
    } else if (name === "param") {
      type.value = "12"; code.value = "0"; pointer.value = "9"; mode.value = "hex"; data.value = SAMPLE_INNER;
    } else if (name === "redirect") {
      type.value = "5"; code.value = "1"; gateway.value = "192.0.2.1"; mode.value = "hex"; data.value = SAMPLE_INNER;
    } else if (name === "timestamp") {
      type.value = "13"; code.value = "0"; id.value = "7"; seq.value = "2";
      mode.value = "hex"; data.value = SAMPLE_TIMESTAMPS;
    }
    syncEncoderFields();
    buildFromForm(true);
  }

  function initEncoder() {
    ["icmp-enc-type", "icmp-enc-code"].forEach((id) => {
      const el = document.getElementById(id);
      el.addEventListener("input", () => { syncEncoderFields(); buildFromForm(false); });
      el.addEventListener("change", () => { syncEncoderFields(); buildFromForm(false); });
    });
    ["icmp-enc-data-mode", "icmp-enc-id", "icmp-enc-seq", "icmp-enc-mtu", "icmp-enc-gateway", "icmp-enc-pointer", "icmp-enc-src", "icmp-enc-dst", "icmp-enc-ttl", "icmp-enc-ip-id"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", () => buildFromForm(false));
      if (el) el.addEventListener("change", () => buildFromForm(false));
    });
    document.getElementById("icmp-enc-data").addEventListener("input", () => buildFromForm(false));
    document.getElementById("icmp-enc-wrap").addEventListener("change", () => {
      document.getElementById("icmp-enc-wrap-fields").hidden = !document.getElementById("icmp-enc-wrap").checked;
      buildFromForm(false);
    });
    document.getElementById("icmp-enc-build").addEventListener("click", () => buildFromForm(true));
    document.getElementById("icmp-enc-example").addEventListener("click", () => setPreset("echo"));
    document.querySelectorAll("[data-icmp-preset]").forEach((btn) => {
      btn.addEventListener("click", () => setPreset(btn.getAttribute("data-icmp-preset")));
    });
    document.getElementById("icmp-enc-wrap-fields").hidden = !document.getElementById("icmp-enc-wrap").checked;
    syncEncoderFields();
    buildFromForm(false);
  }

  function initTypeExplorer() {
    const typeSel = document.getElementById("icmp-type-select");
    const codeSel = document.getElementById("icmp-code-select");
    if (!typeSel || !codeSel) return;
    const types = Object.keys(C.TYPES).map(Number).sort((a, b) => a - b);
    typeSel.innerHTML = types.map((t) => `<option value="${t}">${t} · ${PH.esc(C.typeInfo(t).name)}</option>`).join("");

    function populateCodes(selected) {
      const type = Number(typeSel.value);
      const map = C.CODES[type] || {};
      const codes = Object.keys(map).map(Number).sort((a, b) => a - b);
      if (!codes.includes(0)) codes.unshift(0);
      codeSel.innerHTML = codes.map((c) => `<option value="${c}">${c} · ${PH.esc(C.codeName(type, c))}</option>`).join("");
      if (selected != null && codes.includes(Number(selected))) codeSel.value = String(selected);
    }

    function update() {
      const type = Number(typeSel.value);
      const code = Number(codeSel.value);
      const info = C.typeInfo(type);
      const typeLabel = document.getElementById("icmp-type-name");
      const codeLabel = document.getElementById("icmp-type-code-name");
      const restLabel = document.getElementById("icmp-type-rest");
      const bodyLabel = document.getElementById("icmp-type-body");
      const bytesLabel = document.getElementById("icmp-type-bytes");
      const note = document.getElementById("icmp-type-note");
      if (typeLabel) typeLabel.textContent = `${type} · ${info.name}`;
      if (codeLabel) codeLabel.textContent = `${code} · ${C.codeName(type, code)}`;
      if (restLabel) restLabel.textContent = C.restDescription(type);
      if (bodyLabel) bodyLabel.textContent = C.bodyDescription(type);
      if (bytesLabel) bytesLabel.textContent = `${PH.hex(type, 2)} ${PH.hex(code, 2)}`;
      if (note) note.textContent = info.rfc + (info.deprecated ? " · deprecated by " + info.deprecated : "");
    }

    typeSel.addEventListener("change", () => { populateCodes(0); update(); });
    codeSel.addEventListener("change", update);
    document.getElementById("icmp-type-use").addEventListener("click", () => {
      document.getElementById("icmp-enc-type").value = typeSel.value;
      document.getElementById("icmp-enc-code").value = codeSel.value;
      syncEncoderFields();
      buildFromForm(false);
      document.getElementById("icmp-enc-type").focus();
      document.getElementById("icmp-enc-type").scrollIntoView({ block: "center", behavior: "smooth" });
    });
    typeSel.value = "8";
    populateCodes(0);
    update();
  }

  function detailTable(title, rows, hint) {
    if (!rows.length) return "";
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint || "decoded from the rest-of-header and body")}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
      rows.map(([name, value, note]) => `<tr><td><b>${PH.esc(name)}</b></td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note || "")}</td></tr>`).join("") +
      "</tbody></table></div>";
  }

  function typeSpecificHtml(icmp) {
    const rows = [];
    if (icmp.identifier != null) rows.push(["Identifier", "0x" + PH.hex(icmp.identifier, 4), icmp.kind.startsWith("extended") ? "16 bits" : "echo / query matching"]);
    if (icmp.sequence != null) rows.push(["Sequence", String(icmp.sequence), icmp.kind.startsWith("extended") ? "8 bits" : "echo / query ordering"]);
    if (icmp.nextHopMtu != null) rows.push(["Next-Hop MTU", String(icmp.nextHopMtu) + " B", "RFC 1191 path-MTU signal"]);
    if (icmp.gateway) rows.push(["Gateway", icmp.gateway, "Recommended next-hop IPv4 address"]);
    if (icmp.pointer !== undefined && icmp.kind === "parameter") rows.push(["Pointer", String(icmp.pointer), "Octet in the original datagram where the error was detected"]);
    if (icmp.mask) rows.push(["Subnet Mask", icmp.mask, "Address mask reply payload"]);
    if (icmp.lengthWords != null && (icmp.kind === "error" || icmp.kind === "parameter")) {
      rows.push(["RFC 4884 Length", `${icmp.lengthWords} word(s) · ${icmp.lengthWords * 4} B`, icmp.lengthWords ? "Original datagram plus padding" : "No extension structure indicated"]);
    }
    if (icmp.kind === "router-solicit" && icmp.rest.reserved != null) rows.push(["Reserved", "0x" + PH.hex(icmp.rest.reserved, 8), "Must be zero"]);
    if (icmp.kind === "router-advert") {
      rows.push(["Number of Addresses", String(icmp.rest.numAddrs), "Router address entries"]);
      rows.push(["Entry Size", `${icmp.rest.entrySize} word(s) · ${icmp.rest.entrySize * 4} B`, "Usually 2 words (8 bytes)"]);
      rows.push(["Lifetime", String(icmp.rest.lifetime) + " s", "Default router lifetime"]);
    }
    if (icmp.kind === "traceroute") {
      rows.push(["ID", "0x" + PH.hex(icmp.rest.id || 0, 4), "Traceroute message identifier"]);
      rows.push(["Outbound Hops", String(icmp.rest.outboundHops || 0), "RFC 1393 hop counter"]);
    }
    if (icmp.kind === "extended-echo-request") rows.push(["Local (L)", String(icmp.rest.local), "Set when the probed interface is on the proxy node"]);
    if (icmp.kind === "extended-echo-reply") {
      rows.push(["State", String(icmp.rest.state), "Neighbor-cache state when L is clear"]);
      rows.push(["Flags", `A=${icmp.rest.active} 4=${icmp.rest.ipv4} 6=${icmp.rest.ipv6}`, "Active and address-family bits"]);
    }
    if (!rows.length && icmp.kind === "source-quench") rows.push(["Unused", "0x" + PH.hex(icmp.rest.unused || 0, 8), "Deprecated message"]);
    if (!rows.length && icmp.rest && icmp.rest.unused != null) rows.push(["Unused", "0x" + PH.hex(icmp.rest.unused, 8), "No defined interpretation for this type"]);
    return detailTable("type-specific fields", rows);
  }

  function timestampHtml(icmp) {
    if (!icmp.timestamp) return "";
    const ts = icmp.timestamp;
    return detailTable("timestamp fields", [
      ["Originate", `${ts.originateText} · 0x${PH.hex(ts.originate, 8)}`, "Time the sender created the request"],
      ["Receive", `${ts.receiveText} · 0x${PH.hex(ts.receive, 8)}`, "Time the receiver got the request"],
      ["Transmit", `${ts.transmitText} · 0x${PH.hex(ts.transmit, 8)}`, "Time the receiver sent the reply"]
    ], "milliseconds since midnight UTC; 32-bit values wrap roughly every 49.7 days");
  }

  function routerHtml(icmp) {
    if (!icmp.router || !icmp.router.entries.length) return "";
    return '<div class="decoded-head"><h3>router advertisement entries</h3><span class="dim">router address · preference</span></div>' +
      '<div class="table-wrap"><table class="data-table"><thead><tr><th class="num">#</th><th>Router</th><th>Preference</th></tr></thead><tbody>' +
      icmp.router.entries.map((entry, i) => `<tr><td class="num">${i + 1}</td><td><code>${PH.esc(entry.address)}</code></td><td>${entry.preference}</td></tr>`).join("") +
      "</tbody></table></div>";
  }

  function extensionsHtml(ext) {
    if (!ext) return "";
    const checksumText = ext.checksum === 0 ? "no checksum transmitted" : ext.checksumOk ? "checksum valid" : "checksum invalid";
    return '<div class="decoded-head"><h3>RFC 4884 extension structure</h3><span class="dim">version 2 · ' +
      checksumText + '</span></div>' +
      '<div class="table-wrap"><table class="data-table"><thead><tr><th class="num">Offset</th><th class="num">Length</th><th>Class</th><th class="num">C-Type</th><th>Object data</th></tr></thead><tbody>' +
      (ext.objects.length ? ext.objects.map((o) => `<tr><td class="num">${o.offset}</td><td class="num">${o.length} B</td><td><b>${PH.esc(o.className)}</b> <span class="dim">(${o.classNum})</span></td><td class="num">${o.cType}</td><td><code>${o.data.length ? PH.esc(PH.bytesToHex(o.data)) : "—"}</code></td></tr>`).join("") : '<tr><td colspan="5" class="dim">No extension objects</td></tr>') +
      "</tbody></table></div>";
  }

  function embeddedHtml(icmp) {
    const inner = icmp.embedded;
    if (!inner) return "";
    const rows = [
      ["Source", inner.src, "Quoted original source"],
      ["Destination", inner.dst, "Quoted original destination"],
      ["Protocol", `${inner.protocol} · ${inner.protocolName}`, "Next-layer protocol"],
      ["Total Length", `${inner.totalLength} B`, inner.truncated ? "Declared length exceeds capture" : "Includes the quoted IPv4 header"],
      ["Captured", `${inner.capturedLength} B`, `${inner.payloadLength} B after the header`],
      ["TTL", String(inner.ttl), ""],
      ["Identification", "0x" + PH.hex(inner.id, 4), ""],
      ["Header Checksum", `0x${PH.hex(inner.checksum, 4)} · ${inner.checksumOk ? "valid" : "invalid"}`, ""],
      ["Fragment Flags", `${inner.flagsWord & 0x4000 ? "DF " : ""}${inner.flagsWord & 0x2000 ? "MF" : ""}`.trim() || "none", inner.flagsWord & 0x1fff ? `${inner.flagsWord & 0x1fff} × 8 B offset` : "offset 0"]
    ];
    if (inner.ports) {
      rows.push(["Transport Ports", `${inner.ports.source} → ${inner.ports.destination}`, inner.protocol === 17 && inner.ports.udpLength ? `UDP length ${inner.ports.udpLength} B` : "first four bytes of the quoted transport header"]);
    }
    return detailTable("original datagram", rows, `quoted bytes: ${icmp.embeddedLength} B · the quote is evidence, not proof`) +
      '<div class="callout" style="margin-top:14px"><div class="callout__title">the quote is not a packet</div><p>An ICMP error quotes the leading bytes of the datagram that triggered it. The original header can be truncated, rewritten by NAT, or forged by an off-path sender. Use it to correlate a flow, not as proof that the quoted packet existed in exactly that form.</p></div>';
  }

  function renderDecoded(result) {
    const host = document.getElementById("icmp-decode-result");
    const icmp = result.icmp;
    const ip = result.ip;
    const eth = result.ethernet;
    const pills = [
      `<span class="pill">${PH.esc(icmp.type)} · ${PH.esc(icmp.typeName)}</span>`,
      `<span class="pill">code ${PH.esc(icmp.code)} · ${PH.esc(icmp.codeName)}</span>`,
      `<span class="pill">ICMP <b>${icmp.messageLength} B</b></span>`,
      `<span class="pill ${icmp.checksumOk ? "pill--good" : "pill--bad"}">checksum ${icmp.checksumOk ? "valid" : "invalid"}</span>`
    ];
    if (eth) pills.push(`<span class="pill pill--good">Ethernet${eth.vlanTags.length ? " + VLAN" : ""}</span>`);
    if (ip) pills.push(`<span class="pill">IPv4 ${PH.esc(ip.src)} → ${PH.esc(ip.dst)}</span>`);
    else pills.push(`<span class="pill pill--warn">raw ICMP</span>`);
    if (icmp.embedded) pills.push(`<span class="pill">original <b>${icmp.embeddedLength} B</b></span>`);
    if (icmp.extensions) pills.push(`<span class="pill">extensions <b>${icmp.extensions.objects.length}</b></span>`);

    const rows = [
      ["Type", "8", "0–7", `${icmp.type} · ${icmp.typeName}`, icmp.deprecated ? "deprecated by " + icmp.deprecated : ""],
      ["Code", "8", "8–15", `${icmp.code} · ${icmp.codeName}`, ""],
      ["Checksum", "16", "16–31", `0x${PH.hex(icmp.checksum, 4)} · ${icmp.checksumOk ? "valid" : "expected 0x" + PH.hex(icmp.expectedChecksum, 4)}`, "covers the whole ICMP message"],
      ["Rest of Header", "32", "32–63", icmp.restSummary, C.restDescription(icmp.type)],
      ["Data", String(icmp.dataLength * 8), "64–…", `${icmp.dataLength} B`, C.bodyDescription(icmp.type)]
    ];
    if (icmp.lengthWords != null && (icmp.kind === "error" || icmp.kind === "parameter")) {
      rows.push(["RFC 4884 Length", "8", "40–47", `${icmp.lengthWords} word(s) · ${icmp.lengthWords * 4} B`, icmp.lengthWords ? "extension structure follows the quoted datagram" : "no extension structure"]);
    }
    const table = rows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    const warnings = icmp.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        icmp.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean message</div><p>Length, checksum and the type-specific fields are internally consistent. A clean parse still says nothing about whether the sender was authorized to send this message.</p></div>';

    let context = "";
    if (eth) {
      context = `<div class="callout"><div class="callout__title">Ethernet wrapper</div><p>${PH.esc(eth.srcMac)} → ${PH.esc(eth.dstMac)} · EtherType <code>0x0800</code>${eth.vlanTags.length ? " · VLAN " + eth.vlanTags.map((v) => v.vid).join(" / ") : ""}. The IPv4 header carries Protocol 1. <a href="ethernet.html">Open the Ethernet explorer</a>.</p></div>`;
    } else if (!ip) {
      context = '<div class="callout callout--warn"><div class="callout__title">raw ICMP message</div><p>This input starts at the ICMP header. The checksum covers the ICMP message only; there is no IPv4 header to validate. ICMPv4 has no pseudo-header.</p></div>';
    }

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${PH.esc(result.detectedAs)}</span><span>${result.bytes.length} B · ICMP at +${result.icmpOffset}</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: result.icmpOffset, end: result.icmpOffset + result.icmpLength }] })}</div>` +
      `<div class="decoded-head"><h3>ICMP fields</h3><span class="dim">offsets relative to the ICMP header</span></div>` +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${table}</tbody></table></div>` +
      typeSpecificHtml(icmp) + timestampHtml(icmp) + routerHtml(icmp) + embeddedHtml(icmp) + extensionsHtml(icmp.extensions) + context + warnings;
  }

  function makeEchoExample() {
    const built = C.buildIcmp({ type: 8, code: 0, identifier: 0x1234, sequence: 1, data: bytesToAscii(SAMPLE_ECHO) });
    return C.wrapIPv4(built.bytes, { src: "192.0.2.10", dst: "198.51.100.20", ttl: 64, id: 0x1c46 });
  }

  function makeErrorExample() {
    const inner = PH.parseHex(SAMPLE_INNER);
    const built = C.buildIcmp({ type: 3, code: 3, data: inner });
    return C.wrapIPv4(built.bytes, { src: "198.51.100.20", dst: "192.0.2.10", ttl: 64, id: 0x1c46 });
  }

  function initDecoder() {
    const input = document.getElementById("icmp-decode-input");
    const status = document.getElementById("icmp-decode-status");
    const host = document.getElementById("icmp-decode-result");
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
      updateDiagram(result.icmp);
      const icmp = result.icmp;
      PH.setStatus(
        status,
        `${icmp.type} · ${icmp.typeName} / ${icmp.code} · ${icmp.codeName} · ${icmp.messageLength} B · checksum ${icmp.checksumOk ? "valid" : "invalid"}${icmp.warnings.length ? " · " + icmp.warnings.length + " note(s)" : ""}`,
        !icmp.checksumOk ? "bad" : icmp.warnings.length ? "warn" : "ok"
      );
    }

    function loadExample(kind) {
      const packet = kind === "error" ? makeErrorExample() : makeEchoExample();
      input.value = PH.bytesToHex(packet.bytes);
      run(true);
    }

    document.getElementById("icmp-decode").addEventListener("click", () => run(true));
    document.getElementById("icmp-decode-example").addEventListener("click", () => loadExample("echo"));
    document.getElementById("icmp-decode-error-example").addEventListener("click", () => loadExample("error"));
    document.getElementById("icmp-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No ICMP message decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run(true);
    });
  }

  function init() {
    if (!document.getElementById("icmp-diagram")) return;
    initDiagrams();
    initTypeExplorer();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
