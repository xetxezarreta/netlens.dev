/* DHCPv6 page: header diagram, option TLV, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const D = window.DHCPv6Codec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc8415";
  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#dhcpv6-diagram", {
      title: "<b>DHCPv6</b> · message header", badge: "RFC 8415",
      fields: [
        { id: "type", name: "Message Type", bits: 8, value: "1", range: "1–13", rfc: "RFC 8415 §8", rfcUrl: RFC, desc: "1 SOLICIT, 2 ADVERTISE, 3 REQUEST, 5 RENEW, 6 REBIND, 7 REPLY, 11 INFORMATION-REQUEST, 12/13 relay." },
        { id: "xid", name: "Transaction ID", bits: 24, value: "0x123456", range: "24-bit", rfc: "RFC 8415 §8", rfcUrl: RFC, desc: "Client-chosen transaction identifier, echoed by the server. It matches requests and replies; it is not a sequence number." }
      ],
      inspector: "#dhcpv6-inspector", table: "#dhcpv6-fields",
      note: "The message header is four bytes. Options follow immediately. Relay messages use a different 34-byte header (hop count, link address, peer address) followed by options."
    });
    PH.fieldTable("#dhcpv6-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#dhcpv6-option-lane", {
      title: "<b>DHCPv6 option</b> · TLV", badge: "4-byte header",
      fields: [
        { name: "Option Code", bytes: 2, value: "1", range: "0–65535", desc: "16-bit option code. 1 client ID, 2 server ID, 3 IA_NA, 5 IA Address, 6 ORO, 23 DNS servers, 25 IA_PD.", rfc: "RFC 8415 §21", rfcUrl: RFC, tone: "a" },
        { name: "Option Length", bytes: 2, value: "14 B", range: "0–65535", desc: "Length of the option data, excluding the four-byte option header.", rfc: "RFC 8415 §21", rfcUrl: RFC, tone: "b" },
        { name: "Option Data", bytes: "var", variable: true, range: "length B", desc: "Code-specific value. Some options contain nested options, such as IA_NA, IA_PD and IA Address.", rfc: "RFC 8415 §21", rfcUrl: RFC, tone: "c" }
      ],
      inspector: "#dhcpv6-option-inspector",
      note: "Unlike DHCPv4, DHCPv6 has no PAD/END option terminators. Options fill the message until the captured length ends; the length fields are the only boundaries."
    });
  }

  function optionList() {
    const options = [];
    const type = Number(document.getElementById("dhcpv6-enc-type").value);
    const mac = document.getElementById("dhcpv6-enc-duid").value;
    options.push({ code: 1, duid: { type: 3, hardwareType: 1, linkLayerAddress: mac } });
    if (type === 2 || type === 7 || type === 10) {
      options.push({ code: 2, duid: { type: 3, hardwareType: 1, linkLayerAddress: document.getElementById("dhcpv6-enc-server-duid").value } });
    }
    if (document.getElementById("dhcpv6-enc-ia").checked) {
      options.push({
        code: 3,
        iaid: PH.parseNumber(document.getElementById("dhcpv6-enc-iaid").value) || 0,
        t1: 0, t2: 0,
        options: [{
          code: 5,
          address: document.getElementById("dhcpv6-enc-address").value,
          preferred: Number(document.getElementById("dhcpv6-enc-preferred").value),
          valid: Number(document.getElementById("dhcpv6-enc-valid").value)
        }]
      });
    }
    if (document.getElementById("dhcpv6-enc-oro").checked) options.push({ code: 6, codes: [23, 24] });
    if (document.getElementById("dhcpv6-enc-rapid").checked) options.push({ code: 14 });
    if (document.getElementById("dhcpv6-enc-status").checked) options.push({ code: 13, status: 0, message: "success" });
    if (document.getElementById("dhcpv6-enc-dns").value.trim()) options.push({ code: 23, servers: [document.getElementById("dhcpv6-enc-dns").value] });
    if (document.getElementById("dhcpv6-enc-domain").value.trim()) options.push({ code: 24, domains: [document.getElementById("dhcpv6-enc-domain").value] });
    return options;
  }

  function readEncoder() {
    return {
      type: Number(document.getElementById("dhcpv6-enc-type").value),
      transactionId: PH.parseNumber(document.getElementById("dhcpv6-enc-xid").value) || 0x123456,
      options: optionList()
    };
  }

  function build(showErrors) {
    const status = document.getElementById("dhcpv6-encode-status");
    const output = document.getElementById("dhcpv6-enc-output");
    const tag = document.getElementById("dhcpv6-enc-tag");
    const summary = document.getElementById("dhcpv6-enc-summary");
    let result;
    try { result = D.buildDhcpv6(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">${result.type} · ${PH.esc(result.typeName)}</span>`,
      `<span class="pill">xid <b>0x${PH.hex(result.transactionId, 6)}</b></span>`,
      `<span class="pill">${result.options} option(s)</span>`,
      `<span class="pill">${result.bytes.length} B</span>`
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte ${result.typeName} · transaction 0x${PH.hex(result.transactionId, 6)} · ${result.options} option(s)`, "ok");
    if (diagram) diagram.setValues({ type: String(result.type), xid: "0x" + PH.hex(result.transactionId, 6) });
    return result;
  }

  function encoderState() {
    const ids = ["dhcpv6-enc-type", "dhcpv6-enc-xid", "dhcpv6-enc-duid", "dhcpv6-enc-server-duid", "dhcpv6-enc-iaid", "dhcpv6-enc-address", "dhcpv6-enc-preferred", "dhcpv6-enc-valid", "dhcpv6-enc-dns", "dhcpv6-enc-domain"];
    const state = { page: "dhcpv6-enc", ia: document.getElementById("dhcpv6-enc-ia").checked, oro: document.getElementById("dhcpv6-enc-oro").checked, rapid: document.getElementById("dhcpv6-enc-rapid").checked, status: document.getElementById("dhcpv6-enc-status").checked };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    document.getElementById("dhcpv6-enc-ia").checked = state.ia !== false;
    document.getElementById("dhcpv6-enc-oro").checked = state.oro !== false;
    document.getElementById("dhcpv6-enc-rapid").checked = !!state.rapid;
    document.getElementById("dhcpv6-enc-status").checked = !!state.status;
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("dhcpv6-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("dhcpv6-build").addEventListener("click", () => build(true));
    document.getElementById("dhcpv6-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "DHCPv6 encoder permalink copied"); });
    document.getElementById("dhcpv6-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("dhcpv6-message.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), type: result.type, typeName: result.typeName,
        transactionId: result.transactionId, length: result.bytes.length, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function optionSummary(opt) {
    if (opt.duid) return `${PH.esc(opt.duid.name)} · ${opt.duid.linkLayerAddress || opt.duid.uuid || opt.duid.enterpriseNumber || "—"}`;
    if (opt.iaType) return `${opt.iaType} IAID ${opt.iaid} · ${opt.options ? opt.options.length : 0} nested`;
    if (opt.address) return opt.address + (opt.preferred != null ? " · pref " + opt.preferred + "s val " + opt.valid + "s" : "");
    if (opt.prefix) return opt.prefix + "/" + opt.prefixLength;
    if (opt.requested) return opt.requested.map((r) => r.code).join(", ");
    if (opt.servers) return opt.servers.join(", ");
    if (opt.domains) return opt.domains.join(", ");
    if (opt.status != null) return `${opt.statusName}${opt.message ? " · " + opt.message : ""}`;
    if (opt.url) return opt.url;
    if (opt.interfaceId) return opt.interfaceId;
    if (opt.preference != null) return String(opt.preference);
    if (opt.elapsed != null) return opt.elapsed + " (0.01 s)";
    return PH.bytesToHex(opt.data).slice(0, 80) || "empty";
  }

  function render(result) {
    const host = document.getElementById("dhcpv6-decode-result");
    const pills = [
      `<span class="pill">${result.type} · ${PH.esc(result.typeName)}</span>`,
      result.transactionId != null ? `<span class="pill">xid <b>0x${PH.hex(result.transactionId, 6)}</b></span>` : "",
      `<span class="pill">${result.options ? result.options.length : 0} option(s)</span>`,
      `<span class="pill">${result.bytes.length} B</span>`
    ];
    let relay = "";
    if (result.relay) {
      relay = detailTable("relay header", "relay-forward / relay-reply", ["Field", "Value"], [
        ["Hop count", `<code>${result.relay.hopCount}</code>`],
        ["Link address", `<code>${PH.esc(result.relay.linkAddress)}</code>`],
        ["Peer address", `<code>${PH.esc(result.relay.peerAddress)}</code>`],
        ["Nested message", result.relay.message ? `<code>${PH.esc(result.relay.message.typeName)}</code>` : "—"]
      ]);
    }
    const rows = (result.options || []).map((opt, i) => [`<b>${i + 1}</b>`, `<code>${opt.code}</code>`, PH.esc(opt.name), `${opt.length} B`, `<span class="small">${optionSummary(opt)}</span>`]);
    let nested = "";
    (result.options || []).forEach((opt) => {
      if (opt.options && opt.options.length) {
        nested += detailTable(opt.name + " nested options", "IA containers", ["#", "Code", "Name", "Length", "Value"],
          opt.options.map((inner, i) => [`<b>${i + 1}</b>`, `<code>${inner.code}</code>`, PH.esc(inner.name), `${inner.length} B`, `<span class="small">${optionSummary(inner)}</span>`]));
      }
    });
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean option chain</div><p>The message type, transaction ID and option lengths agree. DHCPv6 authentication and server policy are separate from framing.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>DHCPv6 message</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 0, end: 4 }] })}</div>` +
      detailTable("message", "offsets relative to the DHCPv6 message", ["Field", "Bits", "Offset", "Value", "Note"], [
        ["Message Type", "8", "0–7", `${result.type} · ${PH.esc(result.typeName)}`, "message kind"],
        ["Transaction ID", "24", "8–31", result.transactionId == null ? "—" : "0x" + PH.hex(result.transactionId, 6), "request/reply matching"],
        ["Options", "—", "32–…", String(result.options ? result.options.length : 0), "TLV chain"]
      ].map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      relay +
      detailTable("options", "code, length and decoded value", ["#", "Code", "Name", "Length", "Value"], rows) +
      nested + warnings;
    if (diagram) diagram.setValues({ type: String(result.type), xid: result.transactionId == null ? "—" : "0x" + PH.hex(result.transactionId, 6) });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("dhcpv6-decode-input");
    const status = document.getElementById("dhcpv6-decode-status");
    const host = document.getElementById("dhcpv6-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = D.decodeDhcpv6(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `${result.typeName} · ${result.bytes.length} B · ${result.options ? result.options.length : 0} option(s)${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("dhcpv6-decode-input");
    if (!input) return;
    document.getElementById("dhcpv6-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("dhcpv6-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("dhcpv6-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("dhcpv6-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("dhcpv6-decode-example").addEventListener("click", () => {
      const result = D.buildDhcpv6({
        type: 1, transactionId: 0x123456,
        options: [
          { code: 1, duid: { type: 3, hardwareType: 1, linkLayerAddress: "02:00:00:00:00:01" } },
          { code: 8, elapsed: 0 },
          { code: 6, codes: [23, 24] },
          { code: 3, iaid: 1, t1: 0, t2: 0, options: [{ code: 5, address: "2001:db8::100", preferred: 3600, valid: 7200 }] }
        ]
      });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "dhcpv6-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("dhcpv6-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
