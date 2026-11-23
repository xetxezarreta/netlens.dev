/* HTTP/3 page: varint and frame lanes, SETTINGS, QPACK table, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const H = window.HTTP3Codec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc9114";
  let frameLane = null;

  function initLanes() {
    PH.byteLane("#h3-varint-lane", {
      title: "<b>QUIC varint</b> · 2-bit width prefix", badge: "RFC 9000 §16",
      fields: [
        { name: "Prefix", bytes: 1, value: "00/01/10/11", range: "2 bits", desc: "00 = 1 byte, 01 = 2 bytes, 10 = 4 bytes, 11 = 8 bytes. The remaining 6 bits of the first byte are the high bits of the value.", tone: "a" },
        { name: "Value", bytes: "var", variable: true, range: "1/2/4/8 B", desc: "Big-endian value after the prefix. The maximum is 2⁶² − 1. HTTP/3 uses varints for frame types, lengths, stream types and setting identifiers.", tone: "b" }
      ],
      note: "The width is not stored separately: the two high bits of the first byte choose it. A parser must read those bits before it knows how many bytes belong to the integer."
    });

    frameLane = PH.byteLane("#h3-frame-lane", {
      title: "<b>HTTP/3 frame</b> · stream-local", badge: "RFC 9114 §7.2",
      fields: [
        { name: "Frame Type", bytes: "var", variable: true, value: "0x00", range: "varint", desc: "DATA 0x00, HEADERS 0x01, SETTINGS 0x04, GOAWAY 0x07, MAX_PUSH_ID 0x0d.", rfc: "RFC 9114 §7.2", rfcUrl: RFC, tone: "a" },
        { name: "Frame Length", bytes: "var", variable: true, value: "5 B", range: "varint", desc: "Length of the frame payload in bytes. The type and length fields themselves are not included.", rfc: "RFC 9114 §7.2", rfcUrl: RFC, tone: "b" },
        { name: "Frame Payload", bytes: "var", variable: true, range: "length B", desc: "Type-specific payload: body bytes, a QPACK field section, SETTINGS pairs or a varint value.", rfc: "RFC 9114 §7.2", rfcUrl: RFC, tone: "c" }
      ],
      inspector: "#h3-frame-inspector",
      note: "The frame header is not fixed-width. Type and length are QUIC varints and may each be one, two, four or eight bytes."
    });
  }

  function initStaticTable() {
    const body = document.getElementById("h3-static-table");
    if (!body) return;
    body.innerHTML = H.STATIC_TABLE.map((entry, index) =>
      `<tr><td class="num">${index}</td><td><code>${PH.esc(entry[0])}</code></td><td><code>${PH.esc(entry[1]) || "—"}</code></td></tr>`
    ).join("");
  }

  function parseSettings(text) {
    return String(text || "").split(/\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
      const match = /^(0x[0-9a-f]+|\d+)\s*[=:]\s*(0x[0-9a-f]+|\d+)$/i.exec(line);
      if (!match) throw new Error("SETTINGS line must be 'id = value': " + line);
      return { id: Number(PH.parseNumber(match[1])), value: Number(PH.parseNumber(match[2])) };
    });
  }

  function readEncoder() {
    const type = Number(document.getElementById("h3-enc-type").value);
    let payload;
    if (type === 4) {
      payload = H.buildSettings(parseSettings(document.getElementById("h3-enc-settings").value));
      /* buildSettings already returns a complete frame; unwrap its payload. */
      const decoded = H.decodeFrames(payload);
      payload = decoded.frames[0].payload;
    } else if (type === 7 || type === 13) {
      payload = H.varint(PH.parseNumber(document.getElementById("h3-enc-payload").value) || 0);
    } else {
      const mode = document.getElementById("h3-enc-mode").value;
      const text = document.getElementById("h3-enc-payload").value;
      payload = mode === "text" ? new TextEncoder().encode(text) : PH.parseHex(text);
    }
    return { type, payload };
  }

  function build(showErrors) {
    const status = document.getElementById("h3-encode-status");
    const output = document.getElementById("h3-enc-output");
    const tag = document.getElementById("h3-enc-tag");
    const summary = document.getElementById("h3-enc-summary");
    let bytes;
    try { bytes = H.buildFrame(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(bytes);
    output.classList.remove("placeholder");
    tag.textContent = bytes.length + " B";
    const frames = H.decodeFrames(bytes);
    const frame = frames.frames[0];
    summary.innerHTML = [
      `<span class="pill">${frame ? PH.esc(frame.typeName) : "frame"}</span>`,
      `<span class="pill">type <b>0x${PH.hex(frame ? frame.type : 0, 2)}</b></span>`,
      `<span class="pill">length <b>${frame ? frame.length : 0} B</b></span>`,
      `<span class="pill">${bytes.length} B</span>`
    ].join("");
    PH.setStatus(status, `built ${bytes.length}-byte HTTP/3 frame${frame ? " · " + frame.typeName + " · payload " + frame.length + " B" : ""}`, "ok");
    if (frameLane) frameLane.setValues({ "b3": String(frame ? frame.length : 0) + " B" });
    return bytes;
  }

  function encoderState() {
    const ids = ["h3-enc-type", "h3-enc-mode", "h3-enc-payload", "h3-enc-settings"];
    const state = { page: "h3-enc" };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("h3-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select, textarea").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("h3-build").addEventListener("click", () => build(true));
    document.getElementById("h3-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "HTTP/3 encoder permalink copied"); });
    document.getElementById("h3-export").addEventListener("click", () => {
      const bytes = build(true);
      if (!bytes) return;
      PH.downloadText("http3-frame.json", JSON.stringify({ hex: PH.bytesToHex(bytes), length: bytes.length, input: readEncoder() }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function render(result) {
    const host = document.getElementById("h3-decode-result");
    const pills = [
      `<span class="pill">${result.frames.length} frame(s)</span>`,
      `<span class="pill">${result.consumed} B consumed</span>`
    ];
    result.frames.forEach((frame) => pills.push(`<span class="pill">${PH.esc(frame.typeName)}</span>`));
    const rows = result.frames.map((frame, i) => [
      `<b>${i + 1}</b>`, `+${frame.offset}`, `<code>0x${PH.hex(frame.type, 2)}</code>`,
      PH.esc(frame.typeName), `${frame.length} B`, frame.settings ? `${frame.settings.length} setting(s)` : frame.fields ? `${frame.fields.length} field(s)` : "—"
    ]);
    let extra = "";
    result.frames.forEach((frame, index) => {
      if (frame.settings) {
        extra += detailTable(`frame ${index + 1} SETTINGS`, "identifier/value pairs", ["ID", "Name", "Value"],
          frame.settings.map((s) => [`<code>0x${PH.hex(s.id, 2)}</code>`, PH.esc(s.name), `<code>${PH.esc(s.value)}</code>`]));
      }
      if (frame.fields) {
        extra += detailTable(`frame ${index + 1} QPACK fields`, "static table and literals only", ["Name", "Value", "Index", "Table"],
          frame.fields.map((f) => [`<code>${PH.esc(f.name)}</code>`, `<code>${PH.esc(f.value) || "—"}</code>`, f.index == null ? "—" : String(f.index), PH.esc(f.table || "literal")]));
        if (frame.qpackWarnings && frame.qpackWarnings.length) {
          extra += '<div class="callout callout--warn" style="margin-top:8px"><div class="callout__title">QPACK notes</div><ul class="dashed" style="margin:0">' + frame.qpackWarnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>";
        }
      }
      if (frame.data) {
        extra += detailTable(`frame ${index + 1} DATA`, "body bytes", ["Length", "ASCII"],
          [["Bytes", `<code>${frame.data.length}</code>`], ["Preview", `<code>${PH.esc(PH.bytesToAscii(frame.data.subarray(0, 96))) || "—"}</code>`]]);
      }
    });
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean frame chain</div><p>Frame types and varint lengths agree. HTTP/3 semantics and QPACK dynamic state are separate from framing.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>HTTP/3 bytes</span><span>${result.consumed} B consumed</span></div>${PH.hexdump(result.frames.length ? result.frames[0].payload.subarray(0, Math.min(96, result.frames[0].payload.length)) : new Uint8Array(0))}</div>` +
      detailTable("frames", "type, offset, length and decoded payload", ["#", "Offset", "Type", "Name", "Length", "Payload"], rows) +
      extra + warnings;
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("h3-decode-input");
    const status = document.getElementById("h3-decode-status");
    const host = document.getElementById("h3-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = H.decodeFrames(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `${result.frames.length} frame(s) · ${result.consumed} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("h3-decode-input");
    if (!input) return;
    document.getElementById("h3-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("h3-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("h3-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("h3-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("h3-decode-example").addEventListener("click", () => {
      const settings = H.buildSettings([{ id: 1, value: 4096 }, { id: 3, value: 16 }]);
      const data = H.buildFrame({ type: 0, payload: "68 65 6c 6c 6f" });
      const headersPayload = Uint8Array.from([0x91, 0x51, 0x00]);
      const headers = H.buildFrame({ type: 1, payload: headersPayload });
      input.value = PH.bytesToHex(PH.concatBytes(settings, headers, data));
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "h3-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("h3-varint-lane")) return;
    initLanes();
    initStaticTable();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
