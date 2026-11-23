/* GRE page: flags diagram, optional fields, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const G = window.GRECodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc2784";
  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#gre-diagram", {
      title: "<b>GRE</b> · flags, version and optional fields", badge: "RFC 2784",
      fields: [
        { id: "c", name: "C", bits: 1, value: "1", range: "0/1", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "Checksum present. Adds a two-byte checksum and a two-byte reserved field." },
        { id: "r", name: "R", bits: 1, value: "0", range: "0/1", rfc: "RFC 1701", rfcUrl: RFC, desc: "Routing present. Adds checksum/reserved and routing information; obsolete in most deployments." },
        { id: "k", name: "K", bits: 1, value: "1", range: "0/1", rfc: "RFC 2890 §2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc2890", desc: "Key present. Adds a 32-bit key used to identify a tunnel or flow." },
        { id: "s", name: "S", bits: 1, value: "1", range: "0/1", rfc: "RFC 2890 §3", rfcUrl: "https://www.rfc-editor.org/rfc/rfc2890", desc: "Sequence present. Adds a 32-bit per-direction sequence number." },
        { id: "ss", name: "s", bits: 1, value: "0", range: "0/1", rfc: "RFC 1701", rfcUrl: RFC, desc: "Strict source route. Historic and should be zero." },
        { id: "recur", name: "Recur", bits: 3, value: "0", range: "0–7", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "Recursion control. Must be zero for RFC 2784 GRE." },
        { id: "flags", name: "Flags", bits: 5, value: "0", range: "0–31", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "Reserved flags. Must be zero." },
        { id: "version", name: "Version", bits: 3, value: "0", range: "0/1", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "0 is GRE (RFC 2784); 1 is the PPTP variant (RFC 2637)." },
        { id: "proto", name: "Protocol Type", bits: 16, value: "0x0800", range: "EtherType", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "EtherType of the inner payload: 0x0800 IPv4, 0x86DD IPv6, 0x6558 transparent Ethernet, 0x8847 MPLS." },
        { id: "checksum", name: "Checksum", bits: 16, value: "0x0000", range: "optional", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "Internet checksum over the GRE header and payload, present only when C or R is set. Zeroed during computation." },
        { id: "reserved", name: "Reserved1", bits: 16, value: "0", range: "0", rfc: "RFC 2784 §2", rfcUrl: RFC, desc: "Present with the checksum. Must be zero." },
        { id: "key", name: "Key", bits: 32, value: "42", range: "optional", rfc: "RFC 2890 §2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc2890", desc: "Opaque tunnel/flow identifier. Not a cryptographic key." },
        { id: "seq", name: "Sequence Number", bits: 32, value: "1", range: "optional", rfc: "RFC 2890 §3", rfcUrl: "https://www.rfc-editor.org/rfc/rfc2890", desc: "Per-direction sequence number. GRE does not retransmit; this is for ordering/diagnostics." }
      ],
      inspector: "#gre-inspector", table: "#gre-fields",
      note: "The diagram shows every optional field at its widest. A real header contains only the fields selected by C, R, K and S. Read the flags first, then compute the header length."
    });
    PH.fieldTable("#gre-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#gre-frame-lane", {
      title: "<b>GRE in IP</b> · tunnel shape", badge: "protocol 47",
      fields: [
        { name: "Outer IP header", bytes: 20, range: "20 / 40 B", desc: "IPv4 or IPv6 header that routes between the tunnel endpoints.", rfc: "RFC 791 · RFC 8200", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8200", tone: "a" },
        { name: "GRE header", bytes: "var", variable: true, range: "4–16+ B", desc: "Flags/version, protocol type and any optional checksum, key, sequence or routing fields.", rfc: "RFC 2784 · RFC 2890", rfcUrl: RFC, tone: "b" },
        { name: "Inner packet", bytes: "var", variable: true, range: "rest", desc: "The encapsulated IPv4, IPv6, Ethernet or MPLS payload. GRE does not alter it.", rfc: "RFC 2784", rfcUrl: RFC, tone: "c" }
      ],
      inspector: "#gre-frame-inspector",
      note: "Outer addresses belong to the tunnel endpoints. Inner addresses belong to the tunnelled network and are invisible to the outer path."
    });
  }

  function readEncoder() {
    const version = Number(document.getElementById("gre-enc-version").value);
    const payload = document.getElementById("gre-enc-payload").value;
    const input = {
      version,
      protocol: Number(document.getElementById("gre-enc-proto").value),
      payload,
      checksum: document.getElementById("gre-enc-csum").checked,
      routing: document.getElementById("gre-enc-routing").checked
    };
    const numberOrNull = (id) => {
      const value = document.getElementById(id).value.trim();
      return value === "" ? null : Number(PH.parseNumber(value));
    };
    input.key = numberOrNull("gre-enc-key");
    input.sequence = numberOrNull("gre-enc-seq");
    if (version === 1) {
      input.callId = numberOrNull("gre-enc-callid") || 0;
      input.ack = numberOrNull("gre-enc-ack");
    }
    return input;
  }

  function build(showErrors) {
    const status = document.getElementById("gre-encode-status");
    const output = document.getElementById("gre-enc-output");
    const tag = document.getElementById("gre-enc-tag");
    const summary = document.getElementById("gre-enc-summary");
    let result;
    try { result = G.buildGre(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">version <b>${result.version}</b></span>`,
      `<span class="pill">protocol <b>${PH.esc(result.protocolName)}</b></span>`,
      `<span class="pill">header <b>${result.headerLength} B</b></span>`,
      result.key != null ? `<span class="pill">key <b>${result.key}</b></span>` : "",
      result.sequence != null ? `<span class="pill">sequence <b>${result.sequence}</b></span>` : "",
      result.checksumState === "built" ? `<span class="pill pill--good">checksum <b>0x${PH.hex(result.checksum, 4)}</b></span>` : '<span class="pill pill--warn">no checksum</span>'
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte GRE packet · ${result.headerLength}-byte header · ${result.protocolName}`, "ok");
    if (diagram) diagram.setValues({
      c: result.checksumState === "built" ? "1" : "0", r: "0",
      k: result.key != null ? "1" : "0", s: result.sequence != null ? "1" : "0",
      version: String(result.version), proto: "0x" + PH.hex(result.protocol, 4),
      key: result.key == null ? "—" : String(result.key), seq: result.sequence == null ? "—" : String(result.sequence)
    });
    return result;
  }

  function encoderState() {
    const ids = ["gre-enc-proto", "gre-enc-version", "gre-enc-key", "gre-enc-seq", "gre-enc-payload", "gre-enc-callid", "gre-enc-ack"];
    const state = { page: "gre-enc", csum: document.getElementById("gre-enc-csum").checked, routing: document.getElementById("gre-enc-routing").checked };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => {
      const el = document.getElementById(key);
      if (el) el.value = state[key];
    });
    const csum = document.getElementById("gre-enc-csum");
    const routing = document.getElementById("gre-enc-routing");
    if (csum) csum.checked = state.csum !== false;
    if (routing) routing.checked = !!state.routing;
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("gre-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("gre-build").addEventListener("click", () => build(true));
    document.getElementById("gre-permalink").addEventListener("click", () => {
      if (build(true)) PH.shareState(encoderState(), "GRE encoder permalink copied");
    });
    document.getElementById("gre-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("gre-packet.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), version: result.version, protocol: result.protocol,
        protocolName: result.protocolName, headerLength: result.headerLength,
        key: result.key, sequence: result.sequence, checksum: result.checksum,
        input: readEncoder()
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

  function render(result) {
    const host = document.getElementById("gre-decode-result");
    const flags = [
      result.checksumPresent ? "C" : "", result.routingPresent ? "R" : "",
      result.keyPresent ? "K" : "", result.sequencePresent ? "S" : "",
      result.strictSourceRoute ? "s" : ""
    ].filter(Boolean).join(" ") || "none";
    const pills = [
      `<span class="pill">version <b>${result.version}</b></span>`,
      `<span class="pill">${PH.esc(result.protocolName)}</span>`,
      `<span class="pill">header <b>${result.headerLength} B</b></span>`,
      result.checksumState === "valid" ? '<span class="pill pill--good">checksum valid</span>' :
        result.checksumState === "invalid" ? '<span class="pill pill--bad">checksum invalid</span>' :
          '<span class="pill pill--warn">no checksum</span>',
      `<span class="pill">payload ${result.payload.length} B</span>`
    ];
    const rows = [
      ["Flags", "16", "0–15", flags, "C R K S s Recur Flags Version"],
      ["Version", "3", "13–15", String(result.version), result.version === 0 ? "GRE" : result.version === 1 ? "PPTP" : "reserved"],
      ["Protocol Type", "16", "16–31", "0x" + PH.hex(result.protocol, 4) + " · " + PH.esc(result.protocolName), "inner payload"],
      ["Header length", "—", "—", result.headerLength + " B", "derived from the flags"],
      ["Checksum", "16", "optional", result.checksum == null ? "—" : "0x" + PH.hex(result.checksum, 4), result.checksumState],
      ["Key", "32", "optional", result.key == null ? "—" : String(result.key), "tunnel identifier"],
      ["Sequence", "32", "optional", result.sequence == null ? "—" : String(result.sequence), "per direction"],
      ["Payload", String(result.payload.length * 8), String(result.headerLength * 8) + "–…", result.payload.length + " B", "inner packet"]
    ];
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean header</div><p>The flags, header length and inner protocol agree. GRE itself provides no confidentiality or authentication.</p></div>';
    let inner = "";
    if (result.payload.length) {
      inner = '<div class="hexdump-wrap"><div class="hexdump-head"><span>inner payload</span><span>' + result.payload.length + ' B · first ' + Math.min(96, result.payload.length) + ' shown</span></div>' + PH.hexdump(result.payload.subarray(0, Math.min(96, result.payload.length))) + "</div>";
    }
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>GRE header</span><span>${result.headerLength} B</span></div>${PH.hexdump(result.bytes.subarray(0, result.headerLength))}</div>` +
      detailTable("GRE header", "optional fields are only present when their flag is set", ["Field", "Bits", "Offset", "Value", "Note"],
        rows.map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      inner + warnings;
    if (diagram) diagram.setValues({
      c: result.checksumPresent ? "1" : "0", r: result.routingPresent ? "1" : "0",
      k: result.keyPresent ? "1" : "0", s: result.sequencePresent ? "1" : "0",
      version: String(result.version), proto: "0x" + PH.hex(result.protocol, 4),
      checksum: result.checksum == null ? "—" : "0x" + PH.hex(result.checksum, 4),
      key: result.key == null ? "—" : String(result.key), seq: result.sequence == null ? "—" : String(result.sequence)
    });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("gre-decode-input");
    const status = document.getElementById("gre-decode-status");
    const host = document.getElementById("gre-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = G.decodeGre(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `GREv${result.version} · ${result.protocolName} · ${result.headerLength} B header · checksum ${result.checksumState}${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.checksumState === "invalid" ? "bad" : result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("gre-decode-input");
    if (!input) return;
    document.getElementById("gre-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("gre-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("gre-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("gre-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("gre-decode-example").addEventListener("click", () => {
      const result = G.buildGre({
        protocol: 0x0800, key: 42, sequence: 7, checksum: true,
        payload: "45 00 00 14 00 01 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02"
      });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "gre-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("gre-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
