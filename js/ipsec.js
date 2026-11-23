/* IPsec page: AH diagram, ESP and IKEv2 lanes, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const I = window.IPsecCodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc4303";
  let ahDiagram = null;

  function initDiagrams() {
    ahDiagram = PH.diagram("#ah-diagram", {
      title: "<b>AH</b> · Authentication Header", badge: "RFC 4302",
      fields: [
        { id: "next", name: "Next Header", bits: 8, value: "6", range: "0–255", rfc: "RFC 4302 §2.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4302", desc: "Protocol of the protected payload: 6 TCP, 17 UDP, 58 ICMPv6, 4 IPv4-in-IP." },
        { id: "len", name: "Payload Length", bits: 8, value: "4", range: "0–255", rfc: "RFC 4302 §2.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4302", desc: "AH length in 32-bit words minus two. A 12-byte header with a 12-byte ICV has Payload Length 4." },
        { id: "reserved", name: "Reserved", bits: 16, value: "0", range: "0", rfc: "RFC 4302 §2.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4302", desc: "Must be zero." },
        { id: "spi", name: "SPI", bits: 32, value: "0x1000", range: "32-bit", rfc: "RFC 4302 §2.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4302", desc: "Security parameter index. Together with the destination address and protocol, it selects the SA." },
        { id: "seq", name: "Sequence Number", bits: 32, value: "1", range: "32-bit", rfc: "RFC 4302 §2.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4302", desc: "Monotonically increasing anti-replay counter. It must not wrap while the SA is active." },
        { id: "icv", name: "ICV", bits: "var", varWidth: 96, value: "12 B", range: "algorithm-specific", rfc: "RFC 4302 §2.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4302", desc: "Integrity Check Value. Its length and algorithm are selected by the SA; 96 or 128 bits are common." }
      ],
      inspector: "#ah-inspector", table: "#ah-fields",
      note: "AH is 12 bytes before the ICV. Payload Length counts 32-bit words minus two; the ICV is part of that length. AH authenticates the immutable outer IP fields, which is why NAT breaks it."
    });
    PH.fieldTable("#ah-fields", ahDiagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#esp-lane", {
      title: "<b>ESP</b> · header, ciphertext, trailer and ICV", badge: "RFC 4303",
      fields: [
        { name: "SPI", bytes: 4, value: "0x2000", range: "32-bit", desc: "Security parameter index, sent in the clear.", rfc: "RFC 4303 §2.1", rfcUrl: RFC, tone: "a" },
        { name: "Sequence", bytes: 4, value: "1", range: "32-bit", desc: "Anti-replay counter, sent in the clear.", rfc: "RFC 4303 §2.1", rfcUrl: RFC, tone: "b" },
        { name: "Ciphertext", bytes: "var", variable: true, range: "rest − ICV", desc: "Encrypted payload, padding, Pad Length and Next Header. Opaque without keys.", rfc: "RFC 4303 §2.1", rfcUrl: RFC, tone: "c" },
        { name: "ICV", bytes: "var", variable: true, range: "algorithm-specific", desc: "Integrity check value over the ESP packet. Its length is an SA property, not a field.", rfc: "RFC 4303 §2.1", rfcUrl: RFC, tone: "d" }
      ],
      inspector: "#esp-inspector",
      note: "The encrypted trailer is inside the ciphertext. Without keys, the Next Header value, padding and inner packet are invisible."
    });

    PH.byteLane("#ike-lane", {
      title: "<b>IKEv2</b> · header and payload chain", badge: "RFC 7296",
      fields: [
        { name: "Initiator SPI", bytes: 8, value: "8 B", range: "64-bit", desc: "Chosen by the original initiator. Zero in the first message before the responder answers.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "a" },
        { name: "Responder SPI", bytes: 8, value: "8 B", range: "64-bit", desc: "Chosen by the responder. Zero in the first request.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "b" },
        { name: "Next Payload", bytes: 1, value: "33", range: "0–255", desc: "Type of the first payload: 33 SA, 34 KE, 39 AUTH, 45 TSi, 46 TSr, 48 SK.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "c" },
        { name: "Version", bytes: 1, value: "0x20", range: "0x20", desc: "Major 2, minor 0. The high nibble is the major version.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "d" },
        { name: "Exchange Type", bytes: 1, value: "34", range: "34–37", desc: "IKE_SA_INIT 34, IKE_AUTH 35, CREATE_CHILD_SA 36, INFORMATIONAL 37.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "e" },
        { name: "Flags", bytes: 1, value: "0x08", range: "I V R", desc: "I = initiator, V = version, R = response. Reserved bits must be zero.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "f" },
        { name: "Message ID", bytes: 4, value: "0", range: "32-bit", desc: "Request/response matching. Each exchange uses a new message ID.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "g" },
        { name: "Length", bytes: 4, value: "28 B", range: "28–…", desc: "Total IKE message length including the header.", rfc: "RFC 7296 §3.1", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "h" },
        { name: "Payloads", bytes: "var", variable: true, range: "payload chain", desc: "Generic payload headers (next, critical, length) followed by type-specific data.", rfc: "RFC 7296 §3.2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc7296", tone: "i" }
      ],
      inspector: "#ike-inspector",
      note: "The IKEv2 header is 28 bytes. Payloads chain through their Next Payload bytes. SK payloads are encrypted, so later exchanges look opaque without keys."
    });
  }

  function readEncoder() {
    const mode = document.getElementById("ipsec-enc-mode").value;
    const common = {
      spi: PH.parseNumber(document.getElementById("ipsec-enc-spi").value),
      sequence: PH.parseNumber(document.getElementById("ipsec-enc-seq").value),
      icv: document.getElementById("ipsec-enc-icv").value,
      payload: document.getElementById("ipsec-enc-payload").value
    };
    if (mode === "ah") {
      return { mode, ah: { nextHeader: Number(document.getElementById("ipsec-enc-next").value), spi: common.spi, sequence: common.sequence, icv: common.icv } };
    }
    if (mode === "esp") {
      return { mode, esp: { spi: common.spi, sequence: common.sequence, payload: common.payload, nextHeader: Number(document.getElementById("ipsec-enc-next").value), icv: common.icv } };
    }
    return {
      mode,
      ike: {
        initiatorSpi: "01".repeat(8), responderSpi: "02".repeat(8),
        exchangeType: Number(document.getElementById("ipsec-enc-exchange").value),
        initiator: true, messageId: 0,
        payloads: [{ type: Number(document.getElementById("ipsec-enc-ike-payload").value), value: common.payload }]
      }
    };
  }

  function build(showErrors) {
    const status = document.getElementById("ipsec-encode-status");
    const output = document.getElementById("ipsec-enc-output");
    const tag = document.getElementById("ipsec-enc-tag");
    const summary = document.getElementById("ipsec-enc-summary");
    let result;
    try {
      const input = readEncoder();
      if (input.mode === "ah") result = I.buildAh(input.ah);
      else if (input.mode === "esp") result = I.buildEsp(input.esp);
      else result = I.buildIkev2(input.ike);
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
      `<span class="pill">${result.mode.toUpperCase()}</span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      result.spi != null ? `<span class="pill">SPI <b>0x${PH.hex(result.spi, 8)}</b></span>` : "",
      result.sequence != null ? `<span class="pill">seq <b>${result.sequence}</b></span>` : "",
      result.mode === "esp" ? '<span class="pill pill--warn">layout only · not encrypted</span>' : ""
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte ${result.mode.toUpperCase()} structure`, result.mode === "esp" ? "warn" : "ok");
    if (ahDiagram && result.mode === "ah") ahDiagram.setValues({ next: String(result.nextHeader), len: String(Math.floor(result.totalLength / 4) - 2), spi: "0x" + PH.hex(result.spi, 8), seq: String(result.sequence), icv: result.icvLength + " B" });
    return result;
  }

  function encoderState() {
    const ids = ["ipsec-enc-mode", "ipsec-enc-spi", "ipsec-enc-seq", "ipsec-enc-next", "ipsec-enc-icv", "ipsec-enc-payload", "ipsec-enc-exchange", "ipsec-enc-ike-payload"];
    const state = { page: "ipsec-enc" };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("ipsec-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("ipsec-build").addEventListener("click", () => build(true));
    document.getElementById("ipsec-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "IPsec encoder permalink copied"); });
    document.getElementById("ipsec-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("ipsec-structure.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), mode: result.mode, length: result.bytes.length, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function render(result, mode) {
    const host = document.getElementById("ipsec-decode-result");
    let pills = [];
    let rows = [];
    let extra = "";
    if (mode === "ah") {
      pills = [
        `<span class="pill">AH</span>`, `<span class="pill">SPI <b>0x${PH.hex(result.spi, 8)}</b></span>`,
        `<span class="pill">seq <b>${result.sequence}</b></span>`, `<span class="pill">${result.totalLength} B</span>`,
        `<span class="pill">ICV ${result.icvLength} B</span>`
      ];
      rows = [
        ["Next Header", "8", "0–7", result.nextHeader + " · " + result.nextHeaderName, "inner protocol"],
        ["Payload Length", "8", "8–15", String(result.payloadLength), "32-bit words minus two"],
        ["Reserved", "16", "16–31", String(result.reserved), "must be zero"],
        ["SPI", "32", "32–63", "0x" + PH.hex(result.spi, 8), "security association"],
        ["Sequence", "32", "64–95", String(result.sequence), "anti-replay"],
        ["ICV", String(result.icvLength * 8), "96–…", PH.bytesToHex(result.icv) || "—", "not verified"]
      ];
    } else if (mode === "esp") {
      pills = [`<span class="pill">ESP</span>`, `<span class="pill">SPI <b>0x${PH.hex(result.spi, 8)}</b></span>`, `<span class="pill">seq <b>${result.sequence}</b></span>`, `<span class="pill">${result.bytes.length} B</span>`, '<span class="pill pill--warn">payload opaque</span>'];
      rows = [
        ["SPI", "32", "0–31", "0x" + PH.hex(result.spi, 8), "security association"],
        ["Sequence", "32", "32–63", String(result.sequence), "anti-replay"],
        ["Ciphertext", String(result.ciphertextLength * 8), "64–…", result.ciphertextLength + " B", "payload + trailer + ICV"],
        ["Press", "—", "—", "trailer inside ciphertext", "Next Header is not visible"]
      ];
    } else {
      pills = [`<span class="pill">IKEv2</span>`, `<span class="pill">${PH.esc(result.exchangeName)}</span>`, `<span class="pill">${result.payloads.length} payload(s)</span>`, `<span class="pill">${result.length} B</span>`];
      rows = [
        ["Initiator SPI", "64", "0–63", result.initiatorSpiText, "initiator"],
        ["Responder SPI", "64", "64–127", result.responderSpiText, "responder"],
        ["Next Payload", "8", "128–135", result.nextPayload + " · " + result.nextPayloadName, "first payload"],
        ["Version", "8", "136–143", "0x" + PH.hex(result.version, 2), "major 2"],
        ["Exchange", "8", "144–151", result.exchangeType + " · " + result.exchangeName, "exchange kind"],
        ["Flags", "8", "152–159", "0x" + PH.hex(result.flags, 2), [result.initiator ? "I" : "", result.versionFlag ? "V" : "", result.response ? "R" : ""].filter(Boolean).join(" ") || "none"],
        ["Message ID", "32", "160–191", String(result.messageId), "exchange matching"],
        ["Length", "32", "192–223", String(result.length), "total message"]
      ];
      if (result.payloads.length) {
        extra = detailTable("IKEv2 payloads", "generic payload chain", ["#", "Type", "Next", "Critical", "Length"],
          result.payloads.map((p, i) => [`<b>${i + 1}</b>`, `${p.type} · ${PH.esc(p.name)}`, String(p.next), p.critical ? "1" : "0", `${p.length} B`]));
      }
    }
    const warnings = result.warnings && result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean structure</div><p>The fields and lengths parse. IPsec integrity and confidentiality are only meaningful with the SA keys and negotiated algorithms.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${mode.toUpperCase()} bytes</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 0, end: Math.min(mode === "ah" ? 12 : mode === "esp" ? 8 : 28, result.bytes.length) }] })}</div>` +
      detailTable(mode === "ike" ? "IKEv2 header" : mode.toUpperCase() + " fields", "offsets relative to the structure", ["Field", "Bits", "Offset", "Value", "Note"],
        rows.map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      extra + warnings;
    if (ahDiagram && mode === "ah") ahDiagram.setValues({ next: String(result.nextHeader), len: String(result.payloadLength), spi: "0x" + PH.hex(result.spi, 8), seq: String(result.sequence), icv: result.icvLength + " B" });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("ipsec-decode-input");
    const status = document.getElementById("ipsec-decode-status");
    const host = document.getElementById("ipsec-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    const mode = document.getElementById("ipsec-decode-mode").value;
    let result;
    try { result = mode === "ah" ? I.decodeAh(bytes) : mode === "esp" ? I.decodeEsp(bytes) : I.decodeIkev2(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result, mode);
    const warns = result.warnings || [];
    PH.setStatus(status, `${mode.toUpperCase()} · ${result.bytes.length} B${warns.length ? " · " + warns.length + " note(s)" : ""}`, warns.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("ipsec-decode-input");
    if (!input) return;
    document.getElementById("ipsec-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("ipsec-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("ipsec-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("ipsec-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("ipsec-decode-example").addEventListener("click", () => {
      const mode = document.getElementById("ipsec-decode-mode").value;
      let result;
      if (mode === "ah") result = I.buildAh({ nextHeader: 6, spi: 0x1000, sequence: 1, icv: "00".repeat(12) });
      else if (mode === "esp") result = I.buildEsp({ spi: 0x2000, sequence: 1, payload: "de ad be ef", nextHeader: 6, icv: "00".repeat(16), ciphertext: "11".repeat(20) });
      else result = I.buildIkev2({ initiatorSpi: "01".repeat(8), responderSpi: "02".repeat(8), exchangeType: 34, initiator: true, payloads: [{ type: 33, value: "00 00 00 04" }, { type: 34, value: "00".repeat(8) }] });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "ipsec-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("ah-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
