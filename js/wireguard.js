/* WireGuard page: message layouts, structural encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const W = window.WireGuardCodec;

  function initLanes() {
    PH.byteLane("#wg-type-lane", {
      title: "<b>WireGuard</b> · message type", badge: "little-endian",
      fields: [
        { name: "Type", bytes: 1, value: "4", range: "1–4", desc: "1 Handshake Initiation, 2 Handshake Response, 3 Cookie Reply, 4 Transport Data.", tone: "a" },
        { name: "Reserved", bytes: 3, value: "0", range: "0", desc: "Three reserved bytes. Must be zero. The four-byte value is little-endian, so the type is the first byte on the wire.", tone: "b" }
      ],
      note: "The message type is a 32-bit little-endian value. The low byte is 1–4 and the upper three bytes are reserved zeros."
    });

    PH.byteLane("#wg-init-lane", {
      title: "<b>Handshake Initiation</b> · 148 bytes", badge: "type 1",
      fields: [
        { name: "Type + Reserved", bytes: 4, value: "1", desc: "Little-endian type 1 plus three zero bytes.", tone: "a" },
        { name: "Sender Index", bytes: 4, value: "1", desc: "Local session handle chosen by the initiator.", tone: "b" },
        { name: "Ephemeral Public Key", bytes: 32, value: "32 B", desc: "X25519 ephemeral public key.", tone: "c" },
        { name: "Encrypted Static", bytes: 48, value: "48 B", desc: "Initiator's static public key encrypted and authenticated.", tone: "d" },
        { name: "Encrypted Timestamp", bytes: 28, value: "28 B", desc: "TAI64N timestamp, encrypted; used for replay protection.", tone: "e" },
        { name: "MAC1", bytes: 16, value: "16 B", desc: "BLAKE2s keyed MAC over the message with the responder's static key.", tone: "f" },
        { name: "MAC2", bytes: 16, value: "16 B", desc: "Cookie MAC; zero unless the responder requested a cookie.", tone: "g" }
      ],
      note: "The message is fixed at 148 bytes. Field sizes are not negotiable; a different length is malformed."
    });

    PH.byteLane("#wg-response-lane", {
      title: "<b>Handshake Response</b> · 92 bytes", badge: "type 2",
      fields: [
        { name: "Type + Reserved", bytes: 4, value: "2", desc: "Little-endian type 2 plus three zero bytes.", tone: "a" },
        { name: "Sender Index", bytes: 4, value: "1", desc: "Responder's local session handle.", tone: "b" },
        { name: "Receiver Index", bytes: 4, value: "1", desc: "Echoes the initiator's sender index.", tone: "c" },
        { name: "Ephemeral Public Key", bytes: 32, value: "32 B", desc: "Responder's X25519 ephemeral public key.", tone: "d" },
        { name: "Encrypted Empty", bytes: 16, value: "16 B", desc: "AEAD tag over an empty plaintext; confirms the handshake.", tone: "e" },
        { name: "MAC1", bytes: 16, value: "16 B", desc: "BLAKE2s keyed MAC.", tone: "f" },
        { name: "MAC2", bytes: 16, value: "16 B", desc: "Cookie MAC.", tone: "g" }
      ],
      note: "The response is fixed at 92 bytes. It completes the Noise handshake and derives the transport keys."
    });

    PH.byteLane("#wg-data-lane", {
      title: "<b>Transport Data</b> · header + ciphertext", badge: "type 4",
      fields: [
        { name: "Type + Reserved", bytes: 4, value: "4", desc: "Little-endian type 4 plus three zero bytes.", tone: "a" },
        { name: "Receiver Index", bytes: 4, value: "1", desc: "The receiver's session handle. Not an IP address.", tone: "b" },
        { name: "Counter", bytes: 8, value: "0", desc: "64-bit little-endian nonce. Must never repeat under the same key.", tone: "c" },
        { name: "Encrypted Payload", bytes: "var", variable: true, range: "≥ 16 B", desc: "ChaCha20-Poly1305 ciphertext; the first 16 bytes are the tag, then the inner IP packet.", tone: "d" }
      ],
      note: "The minimum transport message is 32 bytes: 16 bytes of header plus the 16-byte AEAD tag for an empty inner packet. The inner packet is invisible without keys."
    });
  }

  function readEncoder() {
    const type = Number(document.getElementById("wg-enc-type").value);
    const input = {
      type,
      senderIndex: Number(PH.parseNumber(document.getElementById("wg-enc-sender").value) || 0),
      receiverIndex: Number(PH.parseNumber(document.getElementById("wg-enc-receiver").value) || 0),
      counter: document.getElementById("wg-enc-counter").value
    };
    if (type === 4) input.payload = document.getElementById("wg-enc-payload").value;
    if (type === 3) {
      input.nonce = document.getElementById("wg-enc-nonce").value.trim() || "00".repeat(24);
      input.encryptedCookie = "00".repeat(32);
    }
    return input;
  }

  function build(showErrors) {
    const status = document.getElementById("wg-encode-status");
    const output = document.getElementById("wg-enc-output");
    const tag = document.getElementById("wg-enc-tag");
    const summary = document.getElementById("wg-enc-summary");
    let result;
    try { result = W.buildWireguard(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">type <b>${result.type}</b> · ${PH.esc(result.typeName)}</span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      result.counter != null ? `<span class="pill">counter <b>${result.counter.toString()}</b></span>` : "",
      result.receiverIndex != null ? `<span class="pill">receiver <b>${result.receiverIndex}</b></span>` : ""
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte ${result.typeName} · structural only, no cryptography`, "warn");
    return result;
  }

  function encoderState() {
    const ids = ["wg-enc-type", "wg-enc-sender", "wg-enc-receiver", "wg-enc-counter", "wg-enc-payload", "wg-enc-nonce"];
    const state = { page: "wg-enc" };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("wg-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("wg-build").addEventListener("click", () => build(true));
    document.getElementById("wg-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "WireGuard permalink copied"); });
    document.getElementById("wg-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("wireguard-message.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), type: result.type, typeName: result.typeName,
        length: result.bytes.length, note: result.note, input: readEncoder()
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
    const host = document.getElementById("wg-decode-result");
    const pills = [
      `<span class="pill">type <b>${result.type}</b> · ${PH.esc(result.typeName)}</span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      result.senderIndex != null ? `<span class="pill">sender <b>${result.senderIndex}</b></span>` : "",
      result.receiverIndex != null ? `<span class="pill">receiver <b>${result.receiverIndex}</b></span>` : "",
      result.counter != null ? `<span class="pill">counter <b>${result.counter.toString()}</b></span>` : ""
    ];
    const rows = result.fields || [];
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">shape matches</div><p>The message length and index fields match the declared type. Cryptographic validity is not checked and cannot be checked without keys.</p></div>';
    const preview = result.encryptedPayload && result.encryptedPayload.length
      ? '<div class="hexdump-wrap"><div class="hexdump-head"><span>encrypted payload</span><span>' + result.encryptedPayload.length + ' B · first ' + Math.min(96, result.encryptedPayload.length) + ' shown</span></div>' + PH.hexdump(result.encryptedPayload.subarray(0, Math.min(96, result.encryptedPayload.length))) + "</div>"
      : "";
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>WireGuard message</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 0, end: Math.min(16, result.bytes.length) }] })}</div>` +
      detailTable("message fields", "field names are protocol names, not decoded secrets", ["Field", "Value"],
        rows.map(([name, value]) => [`<b>${PH.esc(name)}</b>`, `<code>${PH.esc(value)}</code>`])) +
      preview + warnings;
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("wg-decode-input");
    const status = document.getElementById("wg-decode-status");
    const host = document.getElementById("wg-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = W.decodeWireguard(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `${result.typeName} · ${result.bytes.length} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`, result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("wg-decode-input");
    if (!input) return;
    document.getElementById("wg-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("wg-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("wg-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("wg-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("wg-decode-example").addEventListener("click", () => {
      const result = W.buildWireguard({ type: 4, receiverIndex: 7, counter: "9", payload: "00".repeat(16) + "45 00 00 14" });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "wg-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("wg-type-lane")) return;
    initLanes();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
