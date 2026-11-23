/* NTPv4 page: header diagram, timestamp conversion, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const N = window.NTPCodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc5905";
  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#ntp-diagram", {
      title: "<b>NTPv4</b> · packet header", badge: "RFC 5905",
      fields: [
        { id: "li", name: "LI", bits: 2, value: "0", range: "0–3", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Leap indicator: 0 no warning, 1 last minute has 61 s, 2 last minute has 59 s, 3 clock not synchronised." },
        { id: "vn", name: "VN", bits: 3, value: "4", range: "3–4", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "NTP version. 4 is current; 3 is still common." },
        { id: "mode", name: "Mode", bits: 3, value: "3", range: "0–7", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "3 client, 4 server, 1 symmetric active, 2 symmetric passive, 5 broadcast, 6 control, 7 private." },
        { id: "stratum", name: "Stratum", bits: 8, value: "0", range: "0–16", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "0 unspecified or kiss-o'-death, 1 primary, 2–15 secondary, 16 unsynchronised." },
        { id: "poll", name: "Poll", bits: 8, value: "6", range: "−128–127", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Signed log2 of the maximum poll interval in seconds. 6 means 64 seconds." },
        { id: "precision", name: "Precision", bits: 8, value: "−20", range: "−128–127", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Signed log2 of the clock precision. −20 is about one microsecond." },
        { id: "rootdelay", name: "Root Delay", bits: 32, value: "0.0 s", range: "16.16 fixed", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Total round-trip delay to the reference clock, 16.16 fixed point seconds." },
        { id: "rootdisp", name: "Root Dispersion", bits: 32, value: "0.0 s", range: "16.16 fixed", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Total dispersion to the reference clock, 16.16 fixed point seconds." },
        { id: "refid", name: "Reference ID", bits: 32, value: "LOCL", range: "4 bytes", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Stratum 1: four-character source code. Stratum 2–15: IPv4 address of the upstream server. Stratum 0: kiss-o'-death code." },
        { id: "reftime", name: "Reference Timestamp", bits: 64, value: "—", range: "NTP 64-bit", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Time the system clock was last set or corrected." },
        { id: "origin", name: "Origin Timestamp", bits: 64, value: "—", range: "NTP 64-bit", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Client transmit timestamp echoed by the server. Zero in a client request." },
        { id: "receive", name: "Receive Timestamp", bits: 64, value: "—", range: "NTP 64-bit", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Server time when the request arrived." },
        { id: "transmit", name: "Transmit Timestamp", bits: 64, value: "—", range: "NTP 64-bit", rfc: "RFC 5905 §7.3", rfcUrl: RFC, desc: "Server time when the response left." }
      ],
      inspector: "#ntp-inspector", table: "#ntp-fields",
      note: "The header is 48 bytes. Each timestamp is 32 bits of seconds since 1900-01-01 plus 32 bits of binary fraction. The diagram is 384 bits, or 12 32-bit rows."
    });
    PH.fieldTable("#ntp-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });
  }

  function parseDate(text) {
    if (!text || !text.trim()) return null;
    const date = new Date(text.trim());
    if (Number.isNaN(date.getTime())) throw new Error("Invalid ISO date: " + text);
    return date;
  }

  function readEncoder() {
    return {
      mode: Number(document.getElementById("ntp-enc-mode").value),
      version: Number(document.getElementById("ntp-enc-version").value),
      stratum: Number(document.getElementById("ntp-enc-stratum").value),
      poll: Number(document.getElementById("ntp-enc-poll").value),
      precision: Number(document.getElementById("ntp-enc-precision").value),
      referenceIdText: document.getElementById("ntp-enc-refid").value,
      reference: parseDate(document.getElementById("ntp-enc-ref").value),
      transmit: parseDate(document.getElementById("ntp-enc-transmit").value),
      extensions: document.getElementById("ntp-enc-ext").value.trim()
        ? [{ type: 0x0104, value: document.getElementById("ntp-enc-ext").value }]
        : []
    };
  }

  function build(showErrors) {
    const status = document.getElementById("ntp-encode-status");
    const output = document.getElementById("ntp-enc-output");
    const tag = document.getElementById("ntp-enc-tag");
    const summary = document.getElementById("ntp-enc-summary");
    let result;
    try { result = N.buildNtp(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">mode <b>${result.mode}</b> · ${PH.esc(result.modeName)}</span>`,
      `<span class="pill">version <b>${result.version}</b></span>`,
      `<span class="pill">stratum <b>${result.stratum}</b></span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      result.extensions ? `<span class="pill">${result.extensions} extension(s)</span>` : ""
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte NTPv${result.version} ${result.modeName} packet · stratum ${result.stratum}`, "ok");
    if (diagram) {
      diagram.setValues({
        li: String(result.leap), vn: String(result.version), mode: String(result.mode),
        stratum: String(result.stratum), poll: String(result.poll), precision: String(result.precision),
        refid: result.referenceId || "—", reftime: N.stampText(result.reference),
        origin: "—", receive: "—", transmit: N.stampText(result.transmit)
      });
    }
    return result;
  }

  function encoderState() {
    const ids = ["ntp-enc-mode", "ntp-enc-version", "ntp-enc-stratum", "ntp-enc-poll", "ntp-enc-precision", "ntp-enc-refid", "ntp-enc-ref", "ntp-enc-transmit", "ntp-enc-ext"];
    const state = { page: "ntp-enc" };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("ntp-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("ntp-build").addEventListener("click", () => build(true));
    document.getElementById("ntp-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "NTP encoder permalink copied"); });
    document.getElementById("ntp-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("ntp-packet.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), mode: result.mode, modeName: result.modeName,
        version: result.version, stratum: result.stratum, length: result.bytes.length, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function stampRow(name, stamp) {
    return [`<b>${PH.esc(name)}</b>`, `<code>${stamp ? PH.esc(stamp.date.toISOString()) : "zero"}</code>`, `<code>${stamp ? stamp.seconds : "—"}</code>`, `<code>${stamp ? stamp.fraction.toFixed(9) : "—"}</code>`];
  }

  function updateOffsetPanel(result) {
    const panel = document.getElementById("ntp-offset-panel");
    if (!panel) return;
    panel.innerHTML =
      `<div class="row"><span>T1 origin (client transmit, echoed)</span><b>${result.origin ? PH.esc(result.origin.date.toISOString()) : "zero / absent"}</b></div>` +
      `<div class="row"><span>T2 server receive</span><b>${result.receive ? PH.esc(result.receive.date.toISOString()) : "zero"}</b></div>` +
      `<div class="row"><span>T3 server transmit</span><b>${result.transmit ? PH.esc(result.transmit.date.toISOString()) : "zero"}</b></div>` +
      `<div class="row"><span>T4 client receive</span><b>local capture timestamp, not in the packet</b></div>` +
      `<div class="row"><span>offset / delay</span><b>requires T4 from the capture</b></div>`;
  }

  function render(result) {
    const host = document.getElementById("ntp-decode-result");
    const pills = [
      `<span class="pill">v<b>${result.version}</b> · mode ${result.mode} · ${PH.esc(result.modeName)}</span>`,
      `<span class="pill">stratum <b>${result.stratum}</b></span>`,
      `<span class="pill">LI <b>${result.leap}</b> · ${PH.esc(result.leapText)}</span>`,
      `<span class="pill">${result.bytes.length} B</span>`
    ];
    const rows = [
      ["LI", "2", "0–1", String(result.leap), result.leapText],
      ["Version", "3", "2–4", String(result.version), result.version === 4 ? "NTPv4" : result.version === 3 ? "NTPv3" : "other"],
      ["Mode", "3", "5–7", result.mode + " · " + result.modeName, "packet role"],
      ["Stratum", "8", "8–15", String(result.stratum), result.stratum === 0 ? "kiss-o'-death or unspecified" : result.stratum === 1 ? "primary" : result.stratum <= 15 ? "secondary" : "unsynchronised"],
      ["Poll", "8", "16–23", String(result.poll), "log2 seconds"],
      ["Precision", "8", "24–31", String(result.precision), "log2 seconds"],
      ["Root delay", "32", "32–63", result.rootDelay.toFixed(6) + " s", "16.16 fixed point"],
      ["Root dispersion", "32", "64–95", result.rootDispersion.toFixed(6) + " s", "16.16 fixed point"],
      ["Reference ID", "32", "96–127", result.referenceId || "—", result.kissCode || "source identifier"]
    ];
    const timestamps = [
      stampRow("Reference", result.reference),
      stampRow("Origin (T1)", result.origin),
      stampRow("Receive (T2)", result.receive),
      stampRow("Transmit (T3)", result.transmit)
    ];
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean header</div><p>The header, mode and timestamps parse. NTP authentication and server trust are separate.</p></div>';
    let extensions = "";
    if (result.extensions.length || result.mac) {
      extensions = detailTable("extensions and MAC", "trailing fields after byte 48", ["Field", "Value"],
        result.extensions.map((ext) => [`Extension 0x${PH.hex(ext.type, 4)}`, `<code>${ext.length} B · ${PH.esc(PH.bytesToHex(ext.value))}</code>`]).concat(
          result.mac ? [["MAC", `<code>key ${result.mac.keyId} · ${result.mac.length} B</code>`]] : []
        ));
    }
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>NTP packet</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 16, end: 48 }] })}</div>` +
      detailTable("NTP header", "offsets relative to the NTP header", ["Field", "Bits", "Offset", "Value", "Note"],
        rows.map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      detailTable("timestamps", "NTP epoch 1900 · seconds + binary fraction", ["Field", "UTC", "Seconds", "Fraction"], timestamps) +
      extensions + warnings;
    updateOffsetPanel(result);
    if (diagram) diagram.setValues({
      li: String(result.leap), vn: String(result.version), mode: String(result.mode),
      stratum: String(result.stratum), poll: String(result.poll), precision: String(result.precision),
      refid: result.referenceId || "—", reftime: N.stampText(result.reference),
      origin: N.stampText(result.origin), receive: N.stampText(result.receive), transmit: N.stampText(result.transmit)
    });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("ntp-decode-input");
    const status = document.getElementById("ntp-decode-status");
    const host = document.getElementById("ntp-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = N.decodeNtp(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `NTPv${result.version} · ${result.modeName} · stratum ${result.stratum} · ${result.bytes.length} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("ntp-decode-input");
    if (!input) return;
    document.getElementById("ntp-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("ntp-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("ntp-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("ntp-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("ntp-decode-example").addEventListener("click", () => {
      const now = new Date();
      const result = N.buildNtp({ mode: 4, stratum: 1, referenceIdText: "GPS", reference: new Date(now.getTime() - 3600 * 1000), receive: now, transmit: now });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "ntp-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("ntp-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
