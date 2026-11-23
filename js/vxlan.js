/* VXLAN and Geneve page: headers, overlay path, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const V = window.VXLANCodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc7348";
  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#vxlan-diagram", {
      title: "<b>VXLAN</b> · header", badge: "RFC 7348",
      fields: [
        { id: "flags", name: "Flags", bits: 8, value: "0x08", range: "I bit 0x08", rfc: "RFC 7348 §5", rfcUrl: RFC, desc: "The I bit (0x08) marks a valid VNI. The other seven bits are reserved and must be zero." },
        { id: "reserved", name: "Reserved", bits: 24, value: "0", range: "0", rfc: "RFC 7348 §5", rfcUrl: RFC, desc: "24 reserved bits. Must be zero on transmission and ignored on receipt." },
        { id: "vni", name: "VXLAN Network Identifier", bits: 24, value: "42", range: "0–16777215", rfc: "RFC 7348 §5", rfcUrl: RFC, desc: "24-bit segment identifier. It is not an 802.1Q VLAN ID; a frame can carry both." },
        { id: "reserved2", name: "Reserved", bits: 8, value: "0", range: "0", rfc: "RFC 7348 §5", rfcUrl: RFC, desc: "Reserved byte after the VNI. Must be zero." }
      ],
      inspector: "#vxlan-inspector", table: "#vxlan-fields",
      note: "The VXLAN header is exactly eight bytes. The inner Ethernet frame starts immediately after it. UDP destination port 4789 is the IANA assignment; 8472 appears in some legacy deployments."
    });
    PH.fieldTable("#vxlan-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#geneve-lane", {
      title: "<b>Geneve</b> · base header and options", badge: "RFC 8926",
      fields: [
        { name: "Version + Opt Len", bytes: 1, value: "v0 · 1", range: "2 + 6 bits", desc: "Version 0 and the option length in four-byte units (0–63).", rfc: "RFC 8926 §3.5", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8926", tone: "a" },
        { name: "OAM + Critical", bytes: 1, value: "0", range: "1 + 1 + 6 bits", desc: "OAM packet bit, critical bit and six reserved bits.", rfc: "RFC 8926 §3.5", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8926", tone: "b" },
        { name: "Protocol Type", bytes: 2, value: "0x6558", range: "EtherType", desc: "Inner payload type. 0x6558 is transparent Ethernet.", rfc: "RFC 8926 §3.5", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8926", tone: "c" },
        { name: "VNI", bytes: 3, value: "42", range: "24-bit", desc: "Virtual network identifier.", rfc: "RFC 8926 §3.5", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8926", tone: "d" },
        { name: "Reserved", bytes: 1, value: "0", range: "0", desc: "Reserved byte after the VNI.", rfc: "RFC 8926 §3.5", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8926", tone: "e" },
        { name: "Options", bytes: "var", variable: true, range: "4-byte units", desc: "Option TLVs: class 16, type 8 (critical bit is the top type bit), length 8 in four-byte units, value.", rfc: "RFC 8926 §3.5", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8926", tone: "f" }
      ],
      inspector: "#geneve-inspector",
      note: "The base header is eight bytes. Options are padded to four-byte units and counted by Opt Len. The inner payload begins after the option area."
    });

    PH.byteLane("#vxlan-path-lane", {
      title: "<b>VXLAN in the stack</b> · outer and inner", badge: "UDP 4789",
      fields: [
        { name: "Outer Ethernet", bytes: 14, range: "14 B", desc: "Underlay link header between VTEPs.", rfc: "IEEE 802.3", tone: "a" },
        { name: "Outer IP", bytes: 20, range: "20 / 40 B", desc: "Underlay IPv4 or IPv6 header. Adds 20 or 40 bytes before UDP.", rfc: "RFC 791 · RFC 8200", tone: "b" },
        { name: "UDP", bytes: 8, value: "4789", range: "8 B", desc: "UDP source and destination ports. Destination 4789 identifies VXLAN.", rfc: "RFC 7348", rfcUrl: RFC, tone: "c" },
        { name: "VXLAN", bytes: 8, range: "8 B", desc: "Flags, VNI and reserved bytes.", rfc: "RFC 7348", rfcUrl: RFC, tone: "d" },
        { name: "Inner Ethernet", bytes: 14, range: "14 B", desc: "Tenant destination and source MACs plus EtherType.", rfc: "IEEE 802.3", tone: "e" },
        { name: "Inner payload", bytes: "var", variable: true, range: "rest", desc: "The tenant IPv4/IPv6/ARP payload, exactly as it would appear on a physical segment.", tone: "f" }
      ],
      inspector: "#vxlan-path-inspector",
      note: "VXLAN adds 50 bytes over IPv4 and 70 over IPv6 before the inner Ethernet frame. The underlay MTU must accommodate the whole stack."
    });
  }

  function readEncoder() {
    const mode = document.getElementById("vxlan-enc-mode").value;
    const options = [];
    if (mode === "geneve" && document.getElementById("vxlan-enc-opt").checked) {
      options.push({
        class: PH.parseNumber(document.getElementById("vxlan-enc-opt-class").value),
        type: document.getElementById("vxlan-enc-critical").checked ? 0x80 : 0,
        critical: document.getElementById("vxlan-enc-critical").checked,
        value: document.getElementById("vxlan-enc-opt-value").value
      });
    }
    return {
      mode,
      vni: Number(document.getElementById("vxlan-enc-vni").value),
      protocol: Number(document.getElementById("vxlan-enc-proto").value),
      inner: document.getElementById("vxlan-enc-inner").value,
      options
    };
  }

  function build(showErrors) {
    const status = document.getElementById("vxlan-encode-status");
    const output = document.getElementById("vxlan-enc-output");
    const tag = document.getElementById("vxlan-enc-tag");
    const summary = document.getElementById("vxlan-enc-summary");
    let result;
    try {
      const input = readEncoder();
      result = input.mode === "geneve" ? V.buildGeneve(input) : V.buildVxlan(input);
      result.mode = input.mode;
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">${result.mode === "geneve" ? "Geneve" : "VXLAN"}</span>`,
      `<span class="pill">VNI <b>${result.vni}</b></span>`,
      `<span class="pill">header <b>${result.headerLength} B</b></span>`,
      `<span class="pill">inner <b>${result.inner.length} B</b></span>`
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte ${result.mode} packet · VNI ${result.vni} · ${result.headerLength}-byte header`, "ok");
    if (diagram && result.mode === "vxlan") diagram.setValues({ flags: "0x08", reserved: "0", vni: String(result.vni), reserved2: "0" });
    return result;
  }

  function encoderState() {
    const ids = ["vxlan-enc-mode", "vxlan-enc-vni", "vxlan-enc-proto", "vxlan-enc-opt-class", "vxlan-enc-opt-value", "vxlan-enc-inner"];
    const state = { page: "vxlan-enc", opt: document.getElementById("vxlan-enc-opt").checked, critical: document.getElementById("vxlan-enc-critical").checked };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => {
      const el = document.getElementById(key);
      if (el) el.value = state[key];
    });
    const opt = document.getElementById("vxlan-enc-opt");
    const critical = document.getElementById("vxlan-enc-critical");
    if (opt) opt.checked = state.opt !== false;
    if (critical) critical.checked = !!state.critical;
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("vxlan-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("vxlan-build").addEventListener("click", () => build(true));
    document.getElementById("vxlan-permalink").addEventListener("click", () => {
      if (build(true)) PH.shareState(encoderState(), "VXLAN encoder permalink copied");
    });
    document.getElementById("vxlan-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("vxlan-packet.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), mode: result.mode, vni: result.vni,
        headerLength: result.headerLength, innerLength: result.inner.length, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") +
      "</tbody></table></div>";
  }

  function render(result, mode) {
    const host = document.getElementById("vxlan-decode-result");
    const pills = [
      `<span class="pill">${mode === "geneve" ? "Geneve" : "VXLAN"}</span>`,
      `<span class="pill">VNI <b>${result.vni}</b></span>`,
      `<span class="pill">header <b>${result.headerLength} B</b></span>`,
      `<span class="pill">inner <b>${result.inner.length} B</b></span>`,
      result.innerTypeName ? `<span class="pill">${PH.esc(result.innerTypeName)}</span>` : ""
    ];
    const rows = mode === "geneve" ? [
      ["Version", "2", "0–1", String(result.version), "must be 0"],
      ["Opt Len", "6", "2–7", String(result.optionLength), "four-byte units"],
      ["OAM", "1", "8", result.oam ? "1" : "0", "OAM packet"],
      ["Critical", "1", "9", result.critical ? "1" : "0", "unknown critical options must be rejected"],
      ["Protocol Type", "16", "16–31", "0x" + PH.hex(result.protocol, 4) + " · " + PH.esc(result.protocolName), "inner payload"],
      ["VNI", "24", "32–55", String(result.vni), "virtual network"],
      ["Options", "var", "64–…", result.options.length + " option(s)", "TLVs"]
    ] : [
      ["Flags", "8", "0–7", "0x" + PH.hex(result.flags, 2), result.flags & 0x08 ? "I bit set" : "I bit not set"],
      ["Reserved", "24", "8–31", "0x" + PH.hex((result.bytes[1] << 16) | (result.bytes[2] << 8) | result.bytes[3], 6), "must be zero"],
      ["VNI", "24", "32–55", String(result.vni), "segment identifier"],
      ["Reserved", "8", "56–63", String(result.reserved), "must be zero"]
    ];
    let options = "";
    if (mode === "geneve" && result.options.length) {
      options = detailTable("Geneve options", "class / type / length / value", ["Class", "Type", "Length", "Value"],
        result.options.map((opt) => [`<code>0x${PH.hex(opt.class, 4)}</code>`, `<code>0x${PH.hex(opt.type, 2)}</code>${opt.critical ? " · critical" : ""}`, `${opt.length} B`, `<code>${PH.esc(PH.bytesToHex(opt.value)) || "empty"}</code>`]));
    }
    let innerInfo = "";
    const peer = V.peer(result.inner);
    if (peer) {
      innerInfo = detailTable("inner Ethernet", "the tenant frame", ["Field", "Value"], [
        ["Destination MAC", `<code>${PH.esc(peer.dst)}</code>`],
        ["Source MAC", `<code>${PH.esc(peer.src)}</code>`],
        ["EtherType", `<code>${PH.esc(peer.type)}</code>`]
      ]);
    }
    const innerHex = result.inner.length
      ? '<div class="hexdump-wrap"><div class="hexdump-head"><span>inner frame</span><span>' + result.inner.length + ' B · first ' + Math.min(128, result.inner.length) + ' shown</span></div>' + PH.hexdump(result.inner.subarray(0, Math.min(128, result.inner.length))) + "</div>"
      : "";
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean overlay header</div><p>The VNI and reserved fields agree. Encapsulation does not provide encryption or tenant authentication.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${mode === "geneve" ? "Geneve" : "VXLAN"} header</span><span>${result.headerLength} B</span></div>${PH.hexdump(result.bytes.subarray(0, result.headerLength))}</div>` +
      detailTable(mode === "geneve" ? "Geneve header" : "VXLAN header", "offsets relative to the overlay header", ["Field", "Bits", "Offset", "Value", "Note"],
        rows.map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      options + innerInfo + innerHex + warnings;
    if (diagram && mode === "vxlan") diagram.setValues({ flags: "0x" + PH.hex(result.flags, 2), reserved: "0", vni: String(result.vni), reserved2: String(result.reserved) });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("vxlan-decode-input");
    const status = document.getElementById("vxlan-decode-status");
    const host = document.getElementById("vxlan-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    const mode = document.getElementById("vxlan-decode-mode").value;
    let result;
    try { result = mode === "geneve" ? V.decodeGeneve(bytes) : V.decodeVxlan(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result, mode);
    PH.setStatus(status, `${mode} · VNI ${result.vni} · ${result.headerLength} B header · ${result.inner.length} B inner${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("vxlan-decode-input");
    if (!input) return;
    document.getElementById("vxlan-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("vxlan-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("vxlan-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("vxlan-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("vxlan-decode-example").addEventListener("click", () => {
      const inner = "ff ff ff ff ff ff 02 00 00 00 00 01 08 00 45 00 00 14 00 00 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02";
      const mode = document.getElementById("vxlan-decode-mode").value;
      const result = mode === "geneve"
        ? V.buildGeneve({ vni: 42, protocol: 0x6558, inner, options: [{ class: 0x0108, type: 0x80, critical: true, value: "00 01 02 03" }] })
        : V.buildVxlan({ vni: 42, inner });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "vxlan-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("vxlan-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
