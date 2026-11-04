/* UDP explorer — RFC 768 header, ports, pseudo-header checksum, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const U = window.UDPCodec;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc768",
    checksum: "https://www.rfc-editor.org/rfc/rfc1071",
    ipv6: "https://www.rfc-editor.org/rfc/rfc8200",
    usage: "https://www.rfc-editor.org/rfc/rfc8085",
    zero: "https://www.rfc-editor.org/rfc/rfc6936",
    ports: "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"
  };

  const fields = [
    {
      id: "src", name: "Source Port", bits: 16, range: "0–65535",
      rfc: "RFC 768", rfcUrl: RFC.base,
      desc: "The sending socket's port. Clients usually choose an ephemeral port in the dynamic range (49152–65535), but nothing requires it. The port is not authenticated and can be spoofed."
    },
    {
      id: "dst", name: "Destination Port", bits: 16, range: "0–65535",
      rfc: "RFC 768 · IANA", rfcUrl: RFC.ports,
      desc: "The receiving service's port: <code>53</code> DNS, <code>123</code> NTP, <code>161</code> SNMP, <code>51820</code> WireGuard. The four-tuple of source/destination addresses and ports identifies a UDP flow."
    },
    {
      id: "len", name: "Length", bits: 16, range: "8–65535 B",
      rfc: "RFC 768", rfcUrl: RFC.base,
      desc: "Length of the UDP header plus data, in bytes. The header is eight bytes, so a zero-length payload has Length <code>8</code>. The field is not present in UDP-Lite’s partial-checksum format."
    },
    {
      id: "sum", name: "Checksum", bits: 16, range: "0–65535",
      rfc: "RFC 768 · RFC 1071 · RFC 8200", rfcUrl: RFC.checksum,
      desc: "One's-complement checksum over the IP pseudo-header, UDP header and UDP data. In IPv4 a zero value means the checksum was not computed. In IPv6 the checksum is mandatory and zero is invalid."
    },
    {
      id: "data", name: "Data", bits: "var", varWidth: 32, range: "0–65527 B",
      rfc: "RFC 768", rfcUrl: RFC.base,
      desc: "Application payload. It can be empty, a DNS query, a QUIC packet, a WireGuard message or anything else. UDP itself assigns no structure to these bytes."
    }
  ];

  let diagramController = null;

  function initDiagrams() {
    diagramController = PH.diagram("#udp-diagram", {
      title: "<b>UDP</b> · datagram header", badge: "RFC 768",
      fields, inspector: "#udp-inspector", table: "#udp-fields",
      note: "The UDP header is always eight bytes. Data is drawn at a nominal 32 bits; the actual length is Length minus 8. Bit 0 is the MSB of the Source Port field."
    });
    PH.fieldTable("#udp-fields", diagramController, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#udp-frame-lane", {
      title: "<b>UDP in IP</b> · datagram shape", badge: "protocol 17",
      fields: [
        { name: "IP header", bytes: 20, range: "20 / 40 B", desc: "IPv4 header (20–60 bytes with options) or IPv6 header (40 bytes plus any extension headers). The IP protocol/next header is 17.", rfc: "RFC 791 · RFC 8200", rfcUrl: RFC.ipv6, tone: "a" },
        { name: "UDP header", bytes: 8, range: "8 B", desc: "Source port, destination port, UDP Length and checksum.", rfc: "RFC 768", rfcUrl: RFC.base, tone: "c" },
        { name: "UDP data", bytes: "var", variable: true, range: "0–65527 B", desc: "Application payload. The UDP Length includes the eight-byte header.", rfc: "RFC 768", rfcUrl: RFC.base, tone: "d" }
      ],
      inspector: "#udp-frame-inspector",
      note: "The IP header shown is a nominal IPv4 20-byte header. IPv6 adds a 40-byte base header and possibly extension headers before the UDP header."
    });

    PH.byteLane("#udp-v4-pseudo-lane", {
      title: "<b>IPv4 UDP pseudo-header</b>", badge: "12 bytes", compact: true,
      fields: [
        { name: "Source IPv4", bytes: 4, range: "4 B", desc: "IPv4 source address from the enclosing packet.", rfc: "RFC 768", rfcUrl: RFC.base, tone: "a" },
        { name: "Destination IPv4", bytes: 4, range: "4 B", desc: "IPv4 destination address from the enclosing packet.", rfc: "RFC 768", rfcUrl: RFC.base, tone: "b" },
        { name: "Zero", bytes: 1, range: "1 B", desc: "Always zero.", rfc: "RFC 768", rfcUrl: RFC.base, tone: "c" },
        { name: "Protocol 17", bytes: 1, value: "17", range: "17", desc: "IP protocol number for UDP.", rfc: "IANA", rfcUrl: "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml", tone: "d" },
        { name: "UDP Length", bytes: 2, range: "2 B", desc: "The UDP Length field, not the IP payload length.", rfc: "RFC 768", rfcUrl: RFC.base, tone: "e" }
      ],
      inspector: "#udp-v4-pseudo-inspector",
      note: "This pseudo-header is prepended only for checksum computation; it is never transmitted as part of the datagram."
    });

    PH.byteLane("#udp-v6-pseudo-lane", {
      title: "<b>IPv6 UDP pseudo-header</b>", badge: "40 bytes", compact: true,
      fields: [
        { name: "Source IPv6", bytes: 16, range: "16 B", desc: "IPv6 source address from the enclosing packet.", rfc: "RFC 8200", rfcUrl: RFC.ipv6, tone: "a" },
        { name: "Destination IPv6", bytes: 16, range: "16 B", desc: "IPv6 destination address from the enclosing packet.", rfc: "RFC 8200", rfcUrl: RFC.ipv6, tone: "b" },
        { name: "UDP Length", bytes: 4, range: "32-bit", desc: "UDP Length as a 32-bit value, even though the UDP header field itself is 16 bits.", rfc: "RFC 8200", rfcUrl: RFC.ipv6, tone: "c" },
        { name: "Zero", bytes: 3, range: "3 B", desc: "Three zero bytes.", rfc: "RFC 8200", rfcUrl: RFC.ipv6, tone: "d" },
        { name: "Next Header 17", bytes: 1, value: "17", range: "17", desc: "IPv6 next header value for UDP.", rfc: "RFC 8200", rfcUrl: RFC.ipv6, tone: "e" }
      ],
      inspector: "#udp-v6-pseudo-inspector",
      note: "IPv6 uses a 40-byte pseudo-header and makes the UDP checksum mandatory. A zero checksum is invalid."
    });
  }

  function updateDiagram(result) {
    if (!diagramController || !result) return;
    diagramController.setValues({
      src: String(result.srcPort),
      dst: String(result.dstPort),
      len: String(result.length),
      sum: "0x" + PH.hex(result.checksum, 4),
      data: result.payloadLength + " B"
    });
  }

  function updatePortHints(srcEl, dstEl, srcHint, dstHint) {
    const src = Math.max(0, Math.min(65535, Number(srcEl.value) || 0));
    const dst = Math.max(0, Math.min(65535, Number(dstEl.value) || 0));
    const source = U.portInfo(src);
    const dest = U.portInfo(dst);
    srcHint.textContent = source.service ? src + " · " + source.service : src + " · " + source.range;
    dstHint.textContent = dest.service ? dst + " · " + dest.service : dst + " · " + dest.range;
    return { source, dest };
  }

  function initPortExplorer() {
    const src = document.getElementById("udp-port-src");
    const dst = document.getElementById("udp-port-dst");
    if (!src) return;
    function update() {
      const info = updatePortHints(src, dst, document.getElementById("udp-port-src-info"), document.getElementById("udp-port-dst-info"));
      document.getElementById("udp-port-pair").textContent = src.value + " → " + dst.value;
      document.getElementById("udp-port-service").textContent = info.dest.service || info.dest.range;
    }
    [src, dst].forEach((el) => {
      el.addEventListener("input", update);
      el.addEventListener("change", update);
    });
    update();
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

  const DNS_QUERY = "12 34 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01";
  const WIREGUARD_SAMPLE = "01 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d";

  function presetPayload(kind) {
    if (kind === "dns") return { srcPort: 53000, dstPort: 53, mode: "hex", data: DNS_QUERY };
    if (kind === "ntp") {
      const ntp = new Uint8Array(48);
      ntp[0] = 0x23;
      return { srcPort: 123, dstPort: 123, mode: "hex", data: PH.bytesToHex(ntp) };
    }
    if (kind === "syslog") return { srcPort: 53000, dstPort: 514, mode: "ascii", data: "<134>Oct 11 22:14:15 host app: udp test" };
    if (kind === "wireguard") return { srcPort: 51820, dstPort: 51820, mode: "hex", data: WIREGUARD_SAMPLE };
    return { srcPort: 53000, dstPort: 53, mode: "ascii", data: "" };
  }

  function syncContext() {
    const v = Number(document.getElementById("udp-enc-ip-version").value);
    document.getElementById("udp-enc-v4-fields").hidden = v !== 4;
    document.getElementById("udp-enc-v6-fields").hidden = v !== 6;
    document.getElementById("udp-enc-zero-group").hidden = v !== 4;
    if (v !== 4) document.getElementById("udp-enc-zero").checked = false;
  }

  function payloadBytesFromInput() {
    const mode = document.getElementById("udp-enc-data-mode").value;
    const raw = document.getElementById("udp-enc-data").value;
    if (mode === "ascii") return bytesToAscii(raw);
    return raw.trim() ? PH.parseHex(raw) : new Uint8Array(0);
  }

  function updateAutoLength() {
    try {
      const length = 8 + payloadBytesFromInput().length;
      document.getElementById("udp-enc-length").value = String(length);
    } catch (_) {
      document.getElementById("udp-enc-length").value = "?";
    }
  }

  function readEncoder() {
    const version = Number(document.getElementById("udp-enc-ip-version").value);
    return {
      srcPort: Number(document.getElementById("udp-enc-src-port").value),
      dstPort: Number(document.getElementById("udp-enc-dst-port").value),
      ipVersion: version,
      srcIp: version === 4 ? document.getElementById("udp-enc-v4-src").value : document.getElementById("udp-enc-v6-src").value,
      dstIp: version === 4 ? document.getElementById("udp-enc-v4-dst").value : document.getElementById("udp-enc-v6-dst").value,
      ttl: Number(document.getElementById("udp-enc-ttl").value),
      outputMode: document.getElementById("udp-enc-output-mode").value,
      zeroChecksum: version === 4 && document.getElementById("udp-enc-zero").checked,
      payload: payloadBytesFromInput()
    };
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("udp-enc-status");
    const output = document.getElementById("udp-enc-output");
    const summary = document.getElementById("udp-enc-summary");
    const tag = document.getElementById("udp-enc-tag");
    let input;
    let udp;
    let packet = null;
    try {
      input = readEncoder();
      udp = U.buildUdp(input);
      if (input.outputMode === "ip") {
        if (input.ipVersion === 4) {
          const header = window.IPv4Codec.buildHeader({
            version: 4, dscp: 0, ecn: 0, id: 0x1234, ttl: input.ttl, protocol: 17,
            fragmentOffset: 0, payloadLength: udp.length, reserved: false, df: true, mf: false,
            src: input.srcIp, dst: input.dstIp, options: ""
          });
          packet = Object.assign({}, header, { bytes: PH.concatBytes(header.bytes, udp.bytes) });
        } else {
          packet = window.IPv6Codec.buildHeader({
            version: 6, dscp: 0, ecn: 0, flowLabel: 0, nextHeader: 17,
            hopLimit: input.ttl, src: input.srcIp, dst: input.dstIp, payload: udp.bytes
          });
        }
      }
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    const bytes = packet ? packet.bytes : udp.bytes;
    output.textContent = PH.bytesToHex(bytes);
    output.classList.remove("placeholder");
    tag.textContent = bytes.length + " B";
    document.getElementById("udp-enc-length").value = String(udp.length);
    document.getElementById("udp-enc-checksum").value = udp.ipVersion == null
      ? "not set"
      : udp.checksumState === "zero-ipv4" ? "0x0000 (absent)" : "0x" + PH.hex(udp.checksum, 4);
    summary.innerHTML = [
      `<span class="pill">${udp.srcPort} → ${udp.dstPort}</span>`,
      `<span class="pill">UDP <b>${udp.length} B</b></span>`,
      `<span class="pill">payload <b>${udp.payloadLength} B</b></span>`,
      `<span class="pill ${udp.checksumState === "zero-ipv4" ? "pill--warn" : "pill--good"}">checksum <b>${udp.checksumState === "zero-ipv4" ? "absent" : "0x" + PH.hex(udp.checksum, 4)}</b></span>`,
      `<span class="pill">IPv${udp.ipVersion} context</span>`,
      `<span class="pill">${packet ? "full IP packet" : "raw datagram"}</span>`
    ].join("");
    PH.setStatus(
      status,
      `built ${udp.length}-byte UDP datagram · ${udp.srcPort} → ${udp.dstPort} · ${udp.payloadLength} B payload · checksum ${udp.checksumState === "zero-ipv4" ? "omitted (IPv4)" : "0x" + PH.hex(udp.checksum, 4)}${packet ? " · inside IPv" + udp.ipVersion : ""}`,
      "ok"
    );
    updateDiagram(udp);
    return udp;
  }

  function setPreset(kind) {
    const preset = presetPayload(kind);
    document.getElementById("udp-enc-src-port").value = String(preset.srcPort);
    document.getElementById("udp-enc-dst-port").value = String(preset.dstPort);
    document.getElementById("udp-enc-data-mode").value = preset.mode;
    document.getElementById("udp-enc-data").value = preset.data;
    document.getElementById("udp-enc-zero").checked = false;
    updatePortHints(
      document.getElementById("udp-enc-src-port"), document.getElementById("udp-enc-dst-port"),
      document.getElementById("udp-enc-src-hint"), document.getElementById("udp-enc-dst-hint")
    );
    syncContext();
    updateAutoLength();
    buildFromForm(true);
  }

  function initEncoder() {
    const src = document.getElementById("udp-enc-src-port");
    const dst = document.getElementById("udp-enc-dst-port");
    if (!src) return;
    src.addEventListener("input", () => {
      updatePortHints(src, dst, document.getElementById("udp-enc-src-hint"), document.getElementById("udp-enc-dst-hint"));
      buildFromForm(false);
    });
    dst.addEventListener("input", () => {
      updatePortHints(src, dst, document.getElementById("udp-enc-src-hint"), document.getElementById("udp-enc-dst-hint"));
      buildFromForm(false);
    });
    document.getElementById("udp-enc-ip-version").addEventListener("change", () => {
      syncContext();
      buildFromForm(false);
    });
    document.getElementById("udp-enc-data-mode").addEventListener("change", () => {
      updateAutoLength();
      buildFromForm(false);
    });
    ["udp-enc-v4-src", "udp-enc-v4-dst", "udp-enc-v6-src", "udp-enc-v6-dst", "udp-enc-ttl", "udp-enc-output-mode", "udp-enc-zero"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", () => buildFromForm(false));
      if (el) el.addEventListener("input", () => buildFromForm(false));
    });
    document.getElementById("udp-enc-data").addEventListener("input", () => {
      updateAutoLength();
      buildFromForm(false);
    });
    document.getElementById("udp-enc-build").addEventListener("click", () => buildFromForm(true));
    document.getElementById("udp-enc-example").addEventListener("click", () => setPreset("dns"));
    document.querySelectorAll("[data-udp-preset]").forEach((btn) => {
      btn.addEventListener("click", () => setPreset(btn.getAttribute("data-udp-preset")));
    });
    updatePortHints(src, dst, document.getElementById("udp-enc-src-hint"), document.getElementById("udp-enc-dst-hint"));
    syncContext();
    updateAutoLength();
    buildFromForm(false);
  }

  function ethernetType(bytes) {
    if (bytes.length < 14) return null;
    let offset = 12;
    let type = PH.u16be(bytes, offset);
    while ((type === 0x8100 || type === 0x88a8) && bytes.length >= offset + 6) {
      offset += 4;
      type = PH.u16be(bytes, offset);
    }
    return type;
  }

  function looksLikeIPv4(bytes) {
    if (bytes.length < 20) return false;
    const version = bytes[0] >> 4;
    const ihl = bytes[0] & 15;
    if (version !== 4 || ihl < 5) return false;
    const headerLen = ihl * 4;
    return bytes.length >= headerLen && bytes[9] === 17 && PH.u16be(bytes, 2) >= headerLen;
  }

  function looksLikeIPv6(bytes) {
    if (bytes.length < 40 || (bytes[0] >> 4) !== 6) return false;
    const next = bytes[6];
    const extensions = window.IPv6Codec ? window.IPv6Codec.EXTENSION_HEADERS : null;
    if (next !== 17 && !(extensions && extensions.has(next))) return false;
    const payloadLength = PH.u16be(bytes, 4);
    return payloadLength === 0 || payloadLength >= 8;
  }

  function decodeIPv4(bytes) {
    const ip = window.IPv4Codec.decode(bytes);
    if (ip.protocol !== 17) throw new Error("IPv4 Protocol is " + ip.protocol + " (" + ip.protocolLabel + "), not 17 (UDP)");
    if (ip.fragmentOffset > 0) throw new Error("UDP is not present in a non-initial IPv4 fragment");
    const udp = U.decodeUdp(ip.payloadBytes, { ipVersion: 4, srcIp: ip.src, dstIp: ip.dst });
    return {
      udp, ipVersion: 4, ip, ipv6: null,
      ethernet: ip.ethernet ? { ethernet: true, vlan: ip.vlan } : null,
      udpOffset: ip.base + ip.headerLen,
      detectedAs: ip.ethernet ? "Ethernet frame with IPv4/UDP" : "IPv4 packet with UDP",
      contextWarnings: ip.mf ? ["IPv4 MF is set; this is the first fragment and the UDP payload may be incomplete"] : []
    };
  }

  function decodeIPv6(bytes) {
    const packet = window.IPv6Codec.decodePacket(bytes);
    if (packet.chain.terminal.nextHeader !== 17) {
      throw new Error("IPv6 terminal Next Header is " + packet.chain.terminal.nextHeader + " (" + packet.chain.terminal.name + "), not 17 (UDP)");
    }
    const udp = U.decodeUdp(packet.chain.terminal.bytes, {
      ipVersion: 6, srcIp: packet.ip.src, dstIp: packet.ip.dst
    });
    return {
      udp, ipVersion: 6, ip: packet.ip, ipv6: packet, ethernet: packet.ethernet,
      udpOffset: packet.chain.terminal.offset,
      detectedAs: packet.detectedAs,
      contextWarnings: packet.ip.warnings.slice()
    };
  }

  function rawUdp(bytes) {
    const udp = U.decodeUdp(bytes);
    return {
      udp, ipVersion: null, ip: null, ipv6: null, ethernet: null, udpOffset: 0,
      detectedAs: "raw UDP datagram", contextWarnings: []
    };
  }

  function decodeAny(bytes, kind) {
    const ethType = ethernetType(bytes);
    const mode = kind || "auto";
    if (mode === "ipv4" || (mode === "auto" && ethType === 0x0800)) return decodeIPv4(bytes);
    if (mode === "ipv6" || (mode === "auto" && ethType === 0x86dd)) return decodeIPv6(bytes);
    if (mode === "raw") return rawUdp(bytes);
    if (bytes.length >= 8 && PH.u16be(bytes, 4) === bytes.length) return rawUdp(bytes);
    if (looksLikeIPv4(bytes)) return decodeIPv4(bytes);
    if (looksLikeIPv6(bytes)) return decodeIPv6(bytes);
    return rawUdp(bytes);
  }

  function checksumPill(udp) {
    if (udp.checksumState === "valid") return '<span class="pill pill--good">checksum valid</span>';
    if (udp.checksumState === "absent") return '<span class="pill pill--warn">checksum absent (IPv4)</span>';
    if (udp.checksumState === "invalid") return '<span class="pill pill--bad">checksum invalid</span>';
    if (udp.checksumState === "not-checked") return '<span class="pill pill--warn">checksum not checked</span>';
    return '<span class="pill pill--warn">checksum not checkable</span>';
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
    const host = document.getElementById("udp-decode-result");
    const udp = result.udp;
    const pills = [
      `<span class="pill">${udp.srcPort} → ${udp.dstPort}</span>`,
      `<span class="pill">UDP <b>${udp.length} B</b></span>`,
      `<span class="pill">payload <b>${udp.payloadLength} B</b></span>`,
      checksumPill(udp)
    ];
    if (udp.src.service) pills.push(`<span class="pill">src ${PH.esc(udp.src.service)}</span>`);
    if (udp.dst.service) pills.push(`<span class="pill">dst ${PH.esc(udp.dst.service)}</span>`);
    pills.push(`<span class="pill">${result.ipVersion ? "IPv" + result.ipVersion + " context" : "raw UDP"}</span>`);
    if (result.ethernet) pills.push(`<span class="pill pill--good">Ethernet</span>`);

    const headerRows = [
      ["Source Port", "16", "0–15", `${udp.srcPort} · ${udp.src.service || udp.src.range}`, "sending endpoint"],
      ["Destination Port", "16", "16–31", `${udp.dstPort} · ${udp.dst.service || udp.dst.range}`, "receiving service"],
      ["Length", "16", "32–47", `${udp.length} B`, udp.length >= 8 ? "header + data" : "shorter than the header"],
      ["Checksum", "16", "48–63", "0x" + PH.hex(udp.checksum, 4), udp.checksumState],
      ["Data", String(udp.payloadLength * 8), "64–…", `${udp.payloadLength} B`, "application payload"]
    ];
    const headerTable = headerRows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    const contextRows = [
      ["IP context", result.ipVersion ? "IPv" + result.ipVersion : "not supplied", result.ipVersion ? "Pseudo-header available" : "Checksum cannot be validated from the datagram alone"],
      ["Source address", result.ip ? result.ip.src : "—", "Part of the checksum pseudo-header"],
      ["Destination address", result.ip ? result.ip.dst : "—", "Part of the checksum pseudo-header"],
      ["UDP Length", `${udp.length} B`, "Also placed in the pseudo-header"],
      ["Transmitted checksum", "0x" + PH.hex(udp.checksum, 4), udp.checksumState],
      ["Computed checksum", udp.expectedChecksum == null ? "—" : "0x" + PH.hex(udp.expectedChecksum, 4), udp.expectedChecksum == null ? "No IP context" : "one's-complement result"]
    ];
    const contextTable = detailTable("checksum context", "pseudo-header inputs and validation result", ["Field", "Value", "Note"],
      contextRows.map(([a, b, c]) => [`<b>${PH.esc(a)}</b>`, `<code>${PH.esc(b)}</code>`, `<span class="small">${PH.esc(c)}</span>`])
    );

    const ipPayloadLength = result.ip
      ? (result.ipVersion === 4 ? result.ip.payloadBytes.length : result.ipv6.chain.terminal.length)
      : udp.bytes.length;
    const lengthRows = [
      ["UDP Length", `${udp.length} B`, udp.length >= 8 ? "Includes the 8-byte header" : "Invalid"],
      ["UDP payload", `${udp.payloadLength} B`, "Captured bytes after the header"],
      ["IP payload", `${ipPayloadLength} B`, result.ipVersion ? "IP length after the IP header" : "Raw input length"],
      ["Captured UDP bytes", `${udp.bytes.length} B`, udp.length === udp.bytes.length ? "Matches UDP Length" : "Does not match UDP Length"]
    ];
    const lengthTable = detailTable("length accounting", "three different lengths to keep straight", ["Field", "Value", "Note"],
      lengthRows.map(([a, b, c]) => [`<b>${PH.esc(a)}</b>`, `<code>${PH.esc(b)}</code>`, `<span class="small">${PH.esc(c)}</span>`])
    );

    const previewBytes = udp.payload.subarray(0, Math.min(128, udp.payload.length));
    const preview = udp.payload.length
      ? '<div class="hexdump-wrap"><div class="hexdump-head"><span>UDP payload · first ' + previewBytes.length + ' B</span><span>' + (udp.payload.length > previewBytes.length ? "truncated preview" : "complete") + '</span></div>' +
        PH.hexdump(previewBytes) + '<div class="output" style="margin-top:8px"><div class="output__label">ASCII</div><pre>' + PH.esc(PH.bytesToAscii(previewBytes)) + '</pre></div></div>'
      : '<div class="callout"><div class="callout__title">zero-length payload</div><p>The UDP Length is 8 and the datagram contains only its header.</p></div>';

    let context = "";
    if (result.ipVersion === 4) {
      context = `<div class="callout"><div class="callout__title">IPv4 wrapper</div><p>${PH.esc(result.ip.src)} → ${PH.esc(result.ip.dst)} · Protocol <code>17</code> · IPv4 header checksum ${result.ip.checksumOk ? "valid" : "invalid"}${result.ip.ethernet ? " · Ethernet" + (result.ip.vlan ? " + VLAN" : "") : ""}. <a href="ipv4.html">Open the IPv4 explorer</a>.</p></div>`;
    } else if (result.ipVersion === 6) {
      context = `<div class="callout"><div class="callout__title">IPv6 wrapper</div><p>${PH.esc(result.ip.src)} → ${PH.esc(result.ip.dst)} · next header <code>17</code> after ${result.ipv6.chain.headers.length} extension header(s). ${result.ethernet ? "Ethernet carrier. " : ""}<a href="ipv6.html">Open the IPv6 explorer</a>.</p></div>`;
    } else {
      context = '<div class="callout callout--warn"><div class="callout__title">raw UDP datagram</div><p>The checksum cannot be validated because the IPv4/IPv6 source and destination addresses are missing. Paste an IP packet to supply the pseudo-header context.</p></div>';
    }

    const warnings = udp.warnings.length || result.contextWarnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        udp.warnings.concat(result.contextWarnings).map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean datagram</div><p>The UDP Length, captured bytes and checksum context agree. UDP itself does not validate application data or establish that the sender owns the source address.</p></div>';

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${PH.esc(result.detectedAs)}</span><span>${result.udp.bytes.length} B UDP · header at +${result.udpOffset}</span></div>${PH.hexdump(result.udp.bytes, { highlight: [{ start: 0, end: 8 }] })}</div>` +
      '<div class="decoded-head"><h3>UDP header</h3><span class="dim">offsets relative to the UDP header</span></div>' +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${headerTable}</tbody></table></div>` +
      contextTable + lengthTable + preview + context + warnings;
  }

  function wrapPacket(udp, version, src, dst, ttl) {
    if (version === 4) {
      const header = window.IPv4Codec.buildHeader({
        version: 4, dscp: 0, ecn: 0, id: 0x1234, ttl, protocol: 17,
        fragmentOffset: 0, payloadLength: udp.length, reserved: false, df: true, mf: false,
        src, dst, options: ""
      });
      return Object.assign({}, header, { bytes: PH.concatBytes(header.bytes, udp.bytes) });
    }
    return window.IPv6Codec.buildHeader({ version: 6, dscp: 0, ecn: 0, flowLabel: 0, nextHeader: 17, hopLimit: ttl, src, dst, payload: udp.bytes });
  }

  function makeExample(version) {
    const dns = U.buildUdp({
      srcPort: 53000, dstPort: 53, payload: DNS_QUERY, ipVersion: version,
      srcIp: version === 4 ? "192.0.2.10" : "2001:db8::1",
      dstIp: version === 4 ? "198.51.100.20" : "2001:db8::2"
    });
    return wrapPacket(dns, version, version === 4 ? "192.0.2.10" : "2001:db8::1", version === 4 ? "198.51.100.20" : "2001:db8::2", 64);
  }

  function initDecoder() {
    const input = document.getElementById("udp-decode-input");
    const status = document.getElementById("udp-decode-status");
    const host = document.getElementById("udp-decode-result");
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
      try { result = decodeAny(bytes, document.getElementById("udp-decode-kind").value); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      renderDecoded(result);
      updateDiagram(result.udp);
      const udp = result.udp;
      PH.setStatus(
        status,
        `${udp.srcPort} → ${udp.dstPort} · ${udp.length} B · ${udp.payloadLength} B payload · checksum ${udp.checksumState}${udp.warnings.length ? " · " + udp.warnings.length + " note(s)" : ""}`,
        udp.checksumState === "invalid" ? "bad" : udp.warnings.length ? "warn" : "ok"
      );
    }

    document.getElementById("udp-decode").addEventListener("click", () => run(true));
    document.getElementById("udp-decode-v4-example").addEventListener("click", () => {
      input.value = PH.bytesToHex(makeExample(4).bytes);
      run(true);
    });
    document.getElementById("udp-decode-v6-example").addEventListener("click", () => {
      input.value = PH.bytesToHex(makeExample(6).bytes);
      run(true);
    });
    document.getElementById("udp-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No UDP datagram decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run(true);
    });
  }

  function init() {
    if (!document.getElementById("udp-diagram")) return;
    initDiagrams();
    initPortExplorer();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();


})();
