/* WireGuard message layouts — pure codec + page wiring */
(function () {
  "use strict";

  const PH = window.PH;
  const WG_SPEC = "https://www.wireguard.com/protocol/";

  const TYPES = {
    1: { name: "Handshake Initiation", size: 148, section: "Handshake Initiation" },
    2: { name: "Handshake Response", size: 92, section: "Handshake Response" },
    3: { name: "Cookie Reply", size: 64, section: "Cookie Reply" },
    4: { name: "Transport Data", size: 32, section: "Transport Data Message" }
  };

  function concat(parts) { return PH.concatBytes.apply(null, parts); }
  function u64(value) {
    let v;
    try { v = BigInt(String(value).trim()); } catch (_) { throw new Error("counter must be an integer"); }
    if (v < 0n || v > 0xffffffffffffffffn) throw new Error("counter must fit in 64 bits");
    return v;
  }
  function index(value) {
    if (value == null || value === "") throw new Error("index is required");
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error("index must be 0–4294967295");
    return n >>> 0;
  }

  function buildTransport(input) {
    const receiver = index(input.receiver);
    const counter = u64(input.counter);
    const payload = input.payload ? PH.parseHex(input.payload) : new Uint8Array(0);
    if (payload.length < 16) throw new Error("encrypted payload must include a 16-byte AEAD tag");
    const bytes = new Uint8Array(16 + payload.length);
    bytes[0] = 4;
    bytes[1] = 0;
    bytes[2] = 0;
    bytes[3] = 0;
    PH.put32le(bytes, 4, receiver);
    PH.put64le(bytes, 8, counter);
    bytes.set(payload, 16);
    return { bytes, receiver, counter, payload, ciphertext: payload.subarray(0, payload.length - 16), tag: payload.subarray(payload.length - 16) };
  }

  function decodeMessage(bytes) {
    if (bytes.length < 4) throw new Error("WireGuard message needs at least 4 bytes");
    const type = bytes[0];
    const reserved = bytes[1] | (bytes[2] << 8) | (bytes[3] << 16);
    const info = TYPES[type];
    const warnings = [];
    const fields = [];
    function hexField(name, start, length, desc) {
      const raw = bytes.subarray(start, start + length);
      fields.push({ name, offset: start, size: length, value: raw.length ? PH.bytesToHex(raw) : "—", desc });
    }
    if (!info) throw new Error("Unknown WireGuard message type " + type);
    if (reserved !== 0) warnings.push("Reserved bytes are not zero: 0x" + PH.hex(reserved, 6));
    fields.push({ name: "Message Type", offset: 0, size: 1, value: String(type) + " · " + info.name, desc: "1 initiation, 2 response, 3 cookie reply, 4 transport data." });
    fields.push({ name: "Reserved", offset: 1, size: 3, value: reserved === 0 ? "00 00 00" : "0x" + PH.hex(reserved, 6), desc: "Must be zero in protocol v1." });

    if (type === 1) {
      if (bytes.length !== 148) warnings.push(`Handshake Initiation must be 148 bytes; got ${bytes.length}`);
      const sender = bytes.length >= 8 ? PH.u32le(bytes, 4) : 0;
      fields.push({ name: "Sender Index", offset: 4, size: 4, value: "0x" + PH.hex(sender, 8) + " (" + sender + ")", desc: "Little-endian 32-bit index chosen by the initiator." });
      hexField("Ephemeral Public Key", 8, 32, "Curve25519 ephemeral public key, little-endian coordinates on the wire.");
      hexField("Encrypted Static Public Key", 40, 48, "32-byte encrypted static public key plus 16-byte AEAD tag.");
      hexField("Encrypted Timestamp", 88, 28, "12-byte TAI64N timestamp plus 16-byte AEAD tag.");
      hexField("MAC1", 116, 16, "BLAKE2s keyed by the receiver's static public key hash.");
      hexField("MAC2", 132, 16, "BLAKE2s keyed by the cookie. Zero when no cookie is in use.");
    } else if (type === 2) {
      if (bytes.length !== 92) warnings.push(`Handshake Response must be 92 bytes; got ${bytes.length}`);
      const sender = bytes.length >= 8 ? PH.u32le(bytes, 4) : 0;
      const receiver = bytes.length >= 12 ? PH.u32le(bytes, 8) : 0;
      fields.push({ name: "Sender Index", offset: 4, size: 4, value: "0x" + PH.hex(sender, 8) + " (" + sender + ")", desc: "Little-endian index chosen by the responder." });
      fields.push({ name: "Receiver Index", offset: 8, size: 4, value: "0x" + PH.hex(receiver, 8) + " (" + receiver + ")", desc: "Echoes the initiator's sender index." });
      hexField("Ephemeral Public Key", 12, 32, "Responder's ephemeral Curve25519 public key.");
      hexField("Encrypted Nothing", 44, 16, "AEAD tag over an empty payload; proves possession of the handshake key.");
      hexField("MAC1", 60, 16, "Keyed BLAKE2s over the message with MAC2 excluded.");
      hexField("MAC2", 76, 16, "Cookie-keyed BLAKE2s; zero when no cookie is in use.");
    } else if (type === 3) {
      if (bytes.length !== 64) warnings.push(`Cookie Reply must be 64 bytes; got ${bytes.length}`);
      const receiver = bytes.length >= 8 ? PH.u32le(bytes, 4) : 0;
      fields.push({ name: "Receiver Index", offset: 4, size: 4, value: "0x" + PH.hex(receiver, 8) + " (" + receiver + ")", desc: "Index from the message that triggered the cookie reply." });
      hexField("Nonce", 8, 24, "24-byte XChaCha20 nonce.");
      hexField("Encrypted Cookie", 32, 32, "16-byte cookie plus 16-byte AEAD tag.");
    } else {
      if (bytes.length < 32) warnings.push(`Transport Data must be at least 32 bytes; got ${bytes.length}`);
      const receiver = bytes.length >= 8 ? PH.u32le(bytes, 4) : 0;
      const counter = bytes.length >= 16 ? PH.u64le(bytes, 8) : 0n;
      fields.push({ name: "Receiver Index", offset: 4, size: 4, value: "0x" + PH.hex(receiver, 8) + " (" + receiver + ")", desc: "Little-endian index of the receiving peer." });
      fields.push({ name: "Counter", offset: 8, size: 8, value: counter.toString() + " (0x" + counter.toString(16) + ")", desc: "64-bit little-endian nonce / replay counter." });
      if (bytes.length > 16) {
        const payload = bytes.subarray(16);
        const ciphertext = payload.subarray(0, Math.max(0, payload.length - 16));
        const tag = payload.subarray(Math.max(0, payload.length - 16));
        fields.push({ name: "Encrypted Payload", offset: 16, size: payload.length, value: ciphertext.length + " B ciphertext + 16 B tag", desc: "AEAD ciphertext followed by a 16-byte Poly1305 tag. Padding is inside the plaintext." });
        fields.push({ name: "Ciphertext", offset: 16, size: ciphertext.length, value: ciphertext.length ? PH.bytesToHex(ciphertext) : "—", desc: "ChaCha20-Poly1305 ciphertext; not decryptable without the session key." });
        fields.push({ name: "Authentication Tag", offset: 16 + ciphertext.length, size: 16, value: PH.bytesToHex(tag), desc: "Poly1305 tag. A structural parser cannot validate it." });
        if (ciphertext.length % 16) warnings.push("Ciphertext length is not a multiple of 16; WireGuard pads plaintext to 16-byte blocks before encryption");
      }
    }
    return { type, name: info.name, length: bytes.length, expectedSize: info.size, reserved, fields, warnings, bytes };
  }

  window.WireGuardCodec = { buildTransport, decodeMessage, TYPES };

  /* ---------- field data ---------- */
  const typeFields = [
    { id: "type", name: "Message Type", bits: 8, value: "4", range: "1–4", rfc: "WireGuard protocol", rfcUrl: WG_SPEC, desc: "1 handshake initiation, 2 handshake response, 3 cookie reply, 4 transport data. There is no version field." },
    { id: "reserved", name: "Reserved", bits: 24, value: "0", range: "0", rfc: "WireGuard protocol", rfcUrl: WG_SPEC, desc: "Three reserved bytes. They must be zero; they are not an extension point in protocol v1. Receivers should discard non-zero values." }
  ];

  function laneFields(spec) {
    return spec.map((f) => Object.assign({ rfc: "WireGuard protocol", rfcUrl: WG_SPEC }, f));
  }

  const INIT_FIELDS = laneFields([
    { name: "Message Type", bytes: 1, value: "0x01", range: "1", desc: "Handshake Initiation." },
    { name: "Reserved", bytes: 3, range: "0", desc: "Three zero bytes." },
    { name: "Sender Index", bytes: 4, range: "u32 LE", desc: "Initiator's 32-bit little-endian index. The responder echoes it as Receiver Index." },
    { name: "Ephemeral Public Key", bytes: 32, range: "32 B", desc: "Curve25519 ephemeral public key. The corresponding private key is used for the handshake DH." },
    { name: "Encrypted Static Public Key", bytes: 48, range: "32 + 16 B", desc: "The initiator's static public key encrypted with AEAD, followed by the 16-byte tag." },
    { name: "Encrypted Timestamp", bytes: 28, range: "12 + 16 B", desc: "TAI64N timestamp (12 bytes) plus AEAD tag (16 bytes), used for replay protection." },
    { name: "MAC1", bytes: 16, range: "16 B", desc: "BLAKE2s keyed with a hash of the responder's static public key. Lets the responder cheaply reject packets not addressed to it." },
    { name: "MAC2", bytes: 16, range: "16 B", desc: "BLAKE2s keyed with the cookie from a Cookie Reply. Zero when no cookie is in use." }
  ]);
  const RESP_FIELDS = laneFields([
    { name: "Message Type", bytes: 1, value: "0x02", range: "2", desc: "Handshake Response." },
    { name: "Reserved", bytes: 3, range: "0", desc: "Three zero bytes." },
    { name: "Sender Index", bytes: 4, range: "u32 LE", desc: "Responder's little-endian index." },
    { name: "Receiver Index", bytes: 4, range: "u32 LE", desc: "Echoes the initiator's Sender Index." },
    { name: "Ephemeral Public Key", bytes: 32, range: "32 B", desc: "Responder's ephemeral Curve25519 public key." },
    { name: "Encrypted Nothing", bytes: 16, range: "0 + 16 B", desc: "An AEAD tag over an empty plaintext, confirming the handshake key." },
    { name: "MAC1", bytes: 16, range: "16 B", desc: "Receiver-keyed BLAKE2s over the message, excluding MAC2." },
    { name: "MAC2", bytes: 16, range: "16 B", desc: "Cookie-keyed BLAKE2s; zero without a cookie." }
  ]);
  const COOKIE_FIELDS = laneFields([
    { name: "Message Type", bytes: 1, value: "0x03", range: "3", desc: "Cookie Reply." },
    { name: "Reserved", bytes: 3, range: "0", desc: "Three zero bytes." },
    { name: "Receiver Index", bytes: 4, range: "u32 LE", desc: "Index from the message that triggered the reply." },
    { name: "Nonce", bytes: 24, range: "24 B", desc: "XChaCha20 nonce for the encrypted cookie." },
    { name: "Encrypted Cookie", bytes: 32, range: "16 + 16 B", desc: "16-byte cookie followed by a 16-byte AEAD tag." }
  ]);
  const DATA_FIELDS = laneFields([
    { name: "Message Type", bytes: 1, value: "0x04", range: "4", desc: "Transport Data." },
    { name: "Reserved", bytes: 3, range: "0", desc: "Three zero bytes." },
    { name: "Receiver Index", bytes: 4, range: "u32 LE", desc: "Index of the peer receiving this transport message." },
    { name: "Counter", bytes: 8, range: "u64 LE", desc: "64-bit little-endian nonce and anti-replay counter." },
    { name: "Encrypted Payload", bytes: "var", variable: true, range: "ciphertext + 16 B tag", desc: "AEAD-protected IP packet. The plaintext is padded to a multiple of 16 bytes; the 16-byte tag is at the end." }
  ]);

  function initDiagrams() {
    PH.diagram("#wg-type-diagram", {
      title: "<b>WireGuard</b> · common first word", badge: "protocol v1", bitsPerRow: 32,
      fields: typeFields, inspector: "#wg-inspector",
      note: "The message type is the first byte. The next three bytes are reserved and must be zero. Integer fields after the header are little-endian."
    });
    PH.byteLane("#wg-init-lane", { title: "<b>Handshake Initiation</b> · 148 bytes", badge: "type 1", fields: INIT_FIELDS, inspector: "#wg-inspector", note: "Fixed size. The encrypted fields are ciphertext plus 16-byte AEAD tags; the MACs are BLAKE2s values." });
    PH.byteLane("#wg-resp-lane", { title: "<b>Handshake Response</b> · 92 bytes", badge: "type 2", fields: RESP_FIELDS, inspector: "#wg-inspector", note: "Fixed size. The receiver index echoes the initiator's sender index." });
    PH.byteLane("#wg-cookie-lane", { title: "<b>Cookie Reply</b> · 64 bytes", badge: "type 3", fields: COOKIE_FIELDS, inspector: "#wg-inspector", note: "Stateless DoS mitigation. The cookie is encrypted with a key derived from the source address and the challenged MAC1." });
    PH.byteLane("#wg-data-lane", { title: "<b>Transport Data</b> · ≥ 32 bytes", badge: "type 4", fields: DATA_FIELDS, inspector: "#wg-inspector", note: "Variable length. The payload is ciphertext plus a 16-byte AEAD tag; the header is associated data." });
  }

  function initEndian() {
    const input = document.getElementById("wg-endian-input");
    const out = document.getElementById("wg-endian-out");
    if (!input) return;
    function update() {
      try {
        const bytes = PH.parseHex(input.value);
        if (bytes.length !== 4) throw new Error("need exactly 4 bytes");
        const le = PH.u32le(bytes, 0);
        const be = PH.u32be(bytes, 0);
        out.innerHTML =
          `<div class="row"><span>bytes</span><b>${PH.bytesToHex(bytes)}</b></div>` +
          `<div class="row"><span>little-endian</span><b>0x${PH.hex(le, 8)} · ${le}</b></div>` +
          `<div class="row"><span>big-endian</span><b>0x${PH.hex(be, 8)} · ${be}</b></div>`;
      } catch (err) {
        out.innerHTML = '<span class="err">' + PH.esc(err.message) + "</span>";
      }
    }
    input.addEventListener("input", update);
    update();
  }

  function initEncoder() {
    const receiver = document.getElementById("wg-enc-receiver");
    if (!receiver) return;
    function build(showErrors = true) {
      const status = document.getElementById("wg-enc-status");
      const out = document.getElementById("wg-enc-output");
      const summary = document.getElementById("wg-enc-summary");
      const tag = document.getElementById("wg-enc-tag");
      let r;
      try {
        r = buildTransport({
          receiver: PH.parseNumber(receiver.value),
          counter: document.getElementById("wg-enc-counter").value.trim(),
          payload: document.getElementById("wg-enc-payload").value
        });
      } catch (err) {
        if (showErrors) PH.setStatus(status, "error: " + err.message, "bad");
        tag.textContent = "error";
        return null;
      }
      out.textContent = PH.bytesToHex(r.bytes);
      out.classList.remove("placeholder");
      tag.textContent = r.bytes.length + " bytes";
      summary.innerHTML = [
        `<span class="pill">type <b>4</b></span>`,
        `<span class="pill">receiver <b>0x${PH.hex(r.receiver, 8)}</b></span>`,
        `<span class="pill">counter <b>${r.counter.toString()}</b></span>`,
        `<span class="pill">ciphertext <b>${r.ciphertext.length} B</b></span>`,
        `<span class="pill">tag <b>16 B</b></span>`
      ].join("");
      const warnings = [];
      if (r.ciphertext.length % 16) warnings.push("ciphertext is not a multiple of 16 bytes");
      PH.setStatus(status, `built ${r.bytes.length}-byte type 4 message · header 16 B · payload ${r.payload.length} B${warnings.length ? " · " + warnings.join(" · ") : ""}`, warnings.length ? "warn" : "ok");
      return r;
    }
    document.getElementById("wg-enc-build").addEventListener("click", () => build());
    document.getElementById("wg-enc-example").addEventListener("click", () => {
      receiver.value = "0x00000001";
      document.getElementById("wg-enc-counter").value = "1";
      document.getElementById("wg-enc-payload").value = "8f 1e 2b 3c 4d 5e 6f 70 81 92 a3 b4 c5 d6 e7 f8 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10";
      build();
    });
    build(false);
  }

  function renderDecoded(r) {
    const host = document.getElementById("wg-decode-result");
    if (!r) { host.innerHTML = ""; return; }
    const pills = [
      `<span class="pill">type <b>${r.type}</b> · ${PH.esc(r.name)}</span>`,
      `<span class="pill">length <b>${r.length} B</b></span>`,
      `<span class="pill ${r.reserved === 0 ? "pill--good" : "pill--bad"}">reserved ${r.reserved === 0 ? "zero" : "non-zero"}</span>`
    ];
    if (r.type === 4) {
      const payload = r.bytes.subarray(16);
      const c = payload.subarray(0, Math.max(0, payload.length - 16));
      pills.push(`<span class="pill">ciphertext <b>${c.length} B</b></span>`);
      pills.push(`<span class="pill">tag <b>16 B</b></span>`);
    }
    const rows = r.fields.map((f) =>
      `<tr><td><b>${PH.esc(f.name)}</b></td><td class="num">${f.offset}</td><td class="num">${f.size}</td><td><code>${PH.esc(f.value)}</code></td><td class="small">${PH.esc(f.desc || "")}</td></tr>`
    ).join("");
    const warnings = r.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + r.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">structurally valid</div><p>The length and reserved bytes match the message type. This says nothing about authenticity: MACs and AEAD tags were not verified.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>message bytes</span><span>${r.length} B</span></div>${PH.hexdump(r.bytes)}</div>` +
      `<div class="decoded-head"><h3>fields</h3><span class="dim">offsets from the first byte</span></div>` +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Offset</th><th class="num">Size</th><th>Value</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table></div>` +
      warnings;
  }

  function initDecoder() {
    const input = document.getElementById("wg-decode-input");
    const status = document.getElementById("wg-decode-status");
    const host = document.getElementById("wg-decode-result");
    if (!input) return;
    function run(showErrors = true) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      let r;
      try { r = decodeMessage(bytes); }
      catch (err) {
        if (showErrors) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      renderDecoded(r);
      PH.setStatus(status, `${r.name} · ${r.length} B${r.warnings.length ? " · " + r.warnings.length + " note(s)" : ""}`, r.warnings.length ? "warn" : "ok");
    }
    document.getElementById("wg-decode").addEventListener("click", () => run());
    document.getElementById("wg-decode-example").addEventListener("click", () => {
      const r = buildTransport({
        receiver: 1, counter: "1",
        payload: "8f 1e 2b 3c 4d 5e 6f 70 81 92 a3 b4 c5 d6 e7 f8 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
      });
      input.value = PH.bytesToHex(r.bytes);
      run();
    });
    document.getElementById("wg-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No message decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
  }

  function init() {
    if (!document.getElementById("wg-type-diagram")) return;
    initDiagrams();
    initEndian();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
