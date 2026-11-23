/* WebSocket page: handshake builder/parser, frame diagram, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const W = window.WebSocketCodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc6455";
  let diagram = null;

  function initDiagram() {
    diagram = PH.diagram("#ws-diagram", {
      title: "<b>WebSocket</b> · frame header", badge: "RFC 6455",
      fields: [
        { id: "fin", name: "FIN", bits: 1, value: "1", range: "0/1", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Final fragment of a message. Control frames must set FIN." },
        { id: "rsv1", name: "RSV1", bits: 1, value: "0", range: "0/1", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Reserved unless an extension such as permessage-deflate defines it." },
        { id: "rsv2", name: "RSV2", bits: 1, value: "0", range: "0/1", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Reserved for extensions." },
        { id: "rsv3", name: "RSV3", bits: 1, value: "0", range: "0/1", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Reserved for extensions." },
        { id: "opcode", name: "Opcode", bits: 4, value: "1", range: "0x0–0xF", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "0 continuation, 1 text, 2 binary, 8 close, 9 ping, 10 pong. 3–7 and 11–15 are reserved." },
        { id: "mask", name: "MASK", bits: 1, value: "1", range: "0/1", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Payload is masked. Client-to-server frames must be masked; server-to-client frames must not be." },
        { id: "len", name: "Payload Length", bits: 7, value: "17", range: "0–125", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "0–125 is the literal length. 126 selects a 16-bit extended length; 127 selects a 64-bit extended length." },
        { id: "extlen", name: "Extended Length", bits: 16, value: "—", range: "16/64 bits", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Present only when the 7-bit length is 126 or 127. The diagram shows the 16-bit form; 127 uses eight bytes." },
        { id: "maskkey", name: "Masking Key", bits: 32, value: "37 fa 21 3d", range: "4 B", rfc: "RFC 6455 §5.3", rfcUrl: RFC, desc: "Present when MASK is 1. The payload is XORed with this four-byte key, repeating every four bytes." },
        { id: "payload", name: "Payload", bits: "var", varWidth: 32, value: "17 B", range: "0–2⁶³−1", rfc: "RFC 6455 §5.2", rfcUrl: RFC, desc: "Application bytes, masked or unmasked. Text payloads must be valid UTF-8 across the complete message." }
      ],
      inspector: "#ws-inspector", table: "#ws-fields",
      note: "The first two bytes are fixed. A 16-bit extended length appears only when the 7-bit length is 126; a 64-bit length appears when it is 127. The masking key follows the length and precedes the payload."
    });
    PH.fieldTable("#ws-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });
  }

  function readEncoder() {
    const mode = document.getElementById("ws-enc-mode").value;
    const opcode = Number(document.getElementById("ws-enc-opcode").value);
    const raw = document.getElementById("ws-enc-payload").value;
    const common = {
      opcode,
      fin: document.getElementById("ws-enc-fin").checked,
      mask: document.getElementById("ws-enc-use-mask").checked,
      rsv1: document.getElementById("ws-enc-rsv1").checked,
      maskKey: document.getElementById("ws-enc-mask").value
    };
    if (opcode === 8 && document.getElementById("ws-enc-close").value !== "") {
      const code = Number(document.getElementById("ws-enc-close").value);
      const reason = new TextEncoder().encode(mode === "text" ? raw : "");
      common.payload = PH.concatBytes(Uint8Array.from([code >> 8, code & 255]), reason);
      return common;
    }
    if (mode === "text") common.text = raw;
    else common.payload = raw;
    return common;
  }

  function build(showErrors) {
    const status = document.getElementById("ws-encode-status");
    const output = document.getElementById("ws-enc-output");
    const tag = document.getElementById("ws-enc-tag");
    const summary = document.getElementById("ws-enc-summary");
    let result;
    try { result = W.buildFrame(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">opcode <b>${result.opcode}</b> · ${PH.esc(result.opcodeName)}</span>`,
      `<span class="pill">${result.fin ? "FIN" : "fragment"}</span>`,
      `<span class="pill">${result.mask ? "masked" : "unmasked"}</span>`,
      `<span class="pill">payload <b>${result.payloadLength} B</b></span>`,
      `<span class="pill">${result.bytes.length} B total</span>`
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte ${result.opcodeName} frame · payload ${result.payloadLength} B · ${result.mask ? "masked" : "unmasked"}`, "ok");
    if (diagram) diagram.setValues({
      fin: result.fin ? "1" : "0", opcode: String(result.opcode), mask: result.mask ? "1" : "0",
      len: result.payloadLength < 126 ? String(result.payloadLength) : result.payloadLength <= 0xffff ? "126" : "127",
      extlen: result.payloadLength < 126 ? "—" : String(result.payloadLength),
      maskkey: result.maskKey ? PH.bytesToHex(result.maskKey) : "—",
      payload: result.payloadLength + " B"
    });
    return result;
  }

  function encoderState() {
    const ids = ["ws-enc-opcode", "ws-enc-mode", "ws-enc-payload", "ws-enc-mask", "ws-enc-close"];
    const state = { page: "ws-enc", fin: document.getElementById("ws-enc-fin").checked, useMask: document.getElementById("ws-enc-use-mask").checked, rsv1: document.getElementById("ws-enc-rsv1").checked };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    document.getElementById("ws-enc-fin").checked = state.fin !== false;
    document.getElementById("ws-enc-use-mask").checked = state.useMask !== false;
    document.getElementById("ws-enc-rsv1").checked = !!state.rsv1;
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("ws-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("ws-build").addEventListener("click", () => build(true));
    document.getElementById("ws-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "WebSocket encoder permalink copied"); });
    document.getElementById("ws-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("websocket-frame.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), opcode: result.opcode, opcodeName: result.opcodeName,
        fin: result.fin, mask: result.mask, payloadLength: result.payloadLength, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function render(result) {
    const host = document.getElementById("ws-decode-result");
    const pills = [
      `<span class="pill">${result.frames.length} frame(s)</span>`,
      `<span class="pill">${result.length} B</span>`
    ];
    result.frames.forEach((frame) => {
      pills.push(`<span class="pill">${frame.opcodeName}${frame.mask ? " · masked" : ""}${frame.fin ? "" : " · fragment"}</span>`);
    });
    const rows = result.frames.map((frame, i) => [
      `<b>${i + 1}</b>`, `+${frame.offset}`, `${frame.opcode} · ${PH.esc(frame.opcodeName)}`,
      frame.fin ? "1" : "0", `${frame.rsv1 ? 1 : 0}${frame.rsv2 ? 1 : 0}${frame.rsv3 ? 1 : 0}`,
      frame.mask ? "1" : "0", `${frame.payloadLength} B`, `${frame.headerLength} B`
    ]);
    let extra = "";
    result.frames.forEach((frame, index) => {
      if (frame.text != null) {
        extra += detailTable(`frame ${index + 1} text`, "UTF-8 payload", ["Field", "Value"], [
          ["Text", `<code>${PH.esc(frame.text)}</code>`],
          ["Payload", `<code>${PH.esc(PH.bytesToHex(frame.payload)) || "empty"}</code>`]
        ]);
      } else if (frame.close) {
        extra += detailTable(`frame ${index + 1} close`, "close handshake", ["Field", "Value"], [
          ["Code", `<code>${frame.close.code == null ? "—" : frame.close.code + " · " + PH.esc(frame.close.name)}</code>`],
          ["Reason", `<code>${PH.esc(frame.close.reason) || "—"}</code>`]
        ]);
      } else {
        extra += detailTable(`frame ${index + 1} payload`, "binary or control payload", ["Field", "Value"], [
          ["Bytes", `<code>${frame.payloadLength}</code>`],
          ["Hex", `<code>${PH.esc(PH.bytesToHex(frame.payload.subarray(0, 96))) || "empty"}</code>`]
        ]);
      }
    });
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean frame chain</div><p>FIN, RSV, opcode, mask and lengths agree. The frame is not authenticated; a WebSocket over ws:// is plaintext.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>WebSocket bytes</span><span>${result.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 0, end: Math.min(2, result.length) }] })}</div>` +
      detailTable("frames", "offset, opcode, FIN, RSV, mask and lengths", ["#", "Offset", "Opcode", "FIN", "RSV", "Mask", "Payload", "Header"], rows) +
      extra + warnings;
    const first = result.frames[0];
    if (diagram && first) diagram.setValues({
      fin: first.fin ? "1" : "0", opcode: String(first.opcode), mask: first.mask ? "1" : "0",
      len: first.payloadLength < 126 ? String(first.payloadLength) : first.payloadLength <= 0xffff ? "126" : "127",
      extlen: first.payloadLength < 126 ? "—" : String(first.payloadLength),
      maskkey: first.maskKey || "—", payload: first.payloadLength + " B"
    });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("ws-decode-input");
    const status = document.getElementById("ws-decode-status");
    const host = document.getElementById("ws-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = W.decodeFrames(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `${result.frames.length} frame(s) · ${result.length} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("ws-decode-input");
    if (!input) return;
    document.getElementById("ws-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("ws-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("ws-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("ws-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("ws-decode-example").addEventListener("click", () => {
      const frame = W.buildFrame({ opcode: 1, text: "Hello, WebSocket", mask: true, maskKey: "37 fa 21 3d" });
      input.value = PH.bytesToHex(frame.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function initHandshake() {
    const host = document.getElementById("ws-hs-host");
    if (!host) return;
    function buildPair() {
      const key = document.getElementById("ws-hs-key").value;
      const request = W.buildHandshake({ host: host.value, path: document.getElementById("ws-hs-path").value, key, protocol: document.getElementById("ws-hs-protocol").value });
      const response = W.buildResponse({ key, protocol: document.getElementById("ws-hs-protocol").value });
      document.getElementById("ws-hs-request").textContent = request.text;
      document.getElementById("ws-hs-response").textContent = response.text;
      document.getElementById("ws-hs-input").value = request.text;
    }
    document.getElementById("ws-hs-build").addEventListener("click", buildPair);
    document.getElementById("ws-hs-example").addEventListener("click", () => {
      buildPair();
      parseHandshake(true);
    });
    document.getElementById("ws-hs-parse").addEventListener("click", () => parseHandshake(true));
    function parseHandshake(showErrors) {
      const text = document.getElementById("ws-hs-input").value;
      const status = document.getElementById("ws-hs-status");
      const result = document.getElementById("ws-hs-result");
      let parsed;
      try { parsed = W.parseHandshake(text); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "parse error: " + err.message, "bad");
        result.innerHTML = "";
        return;
      }
      const rows = parsed.order.map((name) => [`<code>${PH.esc(name)}</code>`, `<code>${PH.esc(parsed.headers[name].join(", "))}</code>`]);
      result.innerHTML = detailTable("parsed handshake", parsed.kind, ["Field", "Value"], [
        ["Kind", `<code>${PH.esc(parsed.kind)}</code>`],
        ["Start line", `<code>${PH.esc(parsed.start)}</code>`],
        parsed.accept ? ["Accept", `<code>${PH.esc(parsed.accept)}</code>`] : ["Accept", "—"],
        ["Protocol", `<code>${PH.esc(parsed.protocol || "—")}</code>`]
      ].concat(rows));
      PH.setStatus(status, `${parsed.kind} handshake · ${parsed.order.length} header(s)${parsed.warnings.length ? " · " + parsed.warnings.length + " warning(s)" : ""}`,
        parsed.warnings.length ? "warn" : "ok");
      if (parsed.warnings.length) {
        result.innerHTML += '<div class="callout callout--warn" style="margin-top:12px"><div class="callout__title">handshake warnings</div><ul class="dashed" style="margin:0">' + parsed.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>";
      }
    }
    buildPair();
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "ws-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("ws-diagram")) return;
    initDiagram();
    initEncoder();
    initDecoder();
    initHandshake();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
