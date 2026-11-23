/* SCTP page: header diagram, chunk lanes, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const S = window.SCTPCodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc9260";
  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#sctp-diagram", {
      title: "<b>SCTP</b> · common header", badge: "RFC 9260",
      fields: [
        { id: "sport", name: "Source Port", bits: 16, value: "5000", range: "0–65535", rfc: "RFC 9260 §3", rfcUrl: RFC, desc: "Sending endpoint's port. The pair of ports plus the association identifies the SCTP endpoint." },
        { id: "dport", name: "Destination Port", bits: 16, value: "5001", range: "0–65535", rfc: "RFC 9260 §3", rfcUrl: RFC, desc: "Receiving endpoint's port." },
        { id: "vtag", name: "Verification Tag", bits: 32, value: "0x11223344", range: "32-bit", rfc: "RFC 9260 §3", rfcUrl: RFC, desc: "Chosen during association setup. A packet with the wrong tag is discarded. It is not a checksum and not a secret." },
        { id: "checksum", name: "Checksum", bits: 32, value: "CRC-32c", range: "32-bit", rfc: "RFC 9260 §3 · RFC 3309", rfcUrl: "https://www.rfc-editor.org/rfc/rfc3309", desc: "CRC-32c (Castagnoli) over the whole packet with this field zeroed. Ethernet's CRC-32 is a different polynomial." }
      ],
      inspector: "#sctp-inspector", table: "#sctp-fields",
      note: "The common header is 12 bytes. Everything after it is a sequence of chunks, each padded to four bytes. The checksum covers the complete packet, not only the header."
    });
    PH.fieldTable("#sctp-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#sctp-chunk-lane", {
      title: "<b>SCTP chunk</b> · TLV", badge: "4-byte header",
      fields: [
        { name: "Chunk Type", bytes: 1, value: "0", range: "0–255", desc: "DATA 0, INIT 1, INIT ACK 2, SACK 3, HEARTBEAT 4, ABORT 6, SHUTDOWN 7, ERROR 9, COOKIE ECHO 10, AUTH 15, I-DATA 64.", rfc: "RFC 9260 §3.2", rfcUrl: RFC, tone: "a" },
        { name: "Chunk Flags", bytes: 1, value: "0x03", range: "type-specific", desc: "For DATA: I (0x08), U (0x04), B (0x02), E (0x01). Other chunks define their own bits.", rfc: "RFC 9260 §3.2", rfcUrl: RFC, tone: "b" },
        { name: "Chunk Length", bytes: 2, value: "20 B", range: "4–65535", desc: "Length of the chunk including this 4-byte header, excluding padding. Must be a multiple of four for most chunks.", rfc: "RFC 9260 §3.2", rfcUrl: RFC, tone: "c" },
        { name: "Chunk Value", bytes: "var", variable: true, range: "length − 4 B", desc: "Type-specific fields and payload. Padding to a four-byte boundary follows the chunk and is not counted in Length.", rfc: "RFC 9260 §3.2", rfcUrl: RFC, tone: "d" }
      ],
      inspector: "#sctp-chunk-inspector",
      note: "Chunk Length includes the four-byte header. Padding is outside the length. A parser that adds padding to the length will misplace the next chunk."
    });

    PH.byteLane("#sctp-data-lane", {
      title: "<b>DATA chunk</b> · fixed fields", badge: "type 0",
      fields: [
        { name: "Chunk Header", bytes: 4, value: "type 0", range: "4 B", desc: "Type 0, flags and chunk length.", rfc: "RFC 9260 §3.3.1", rfcUrl: RFC, tone: "a" },
        { name: "TSN", bytes: 4, value: "1", range: "32-bit", desc: "Transmission sequence number, per association. Acknowledged by SACK.", rfc: "RFC 9260 §3.3.1", rfcUrl: RFC, tone: "b" },
        { name: "Stream ID", bytes: 2, value: "0", range: "0–65535", desc: "Stream carrying this message, negotiated in INIT.", rfc: "RFC 9260 §3.3.1", rfcUrl: RFC, tone: "c" },
        { name: "Stream Sequence", bytes: 2, value: "0", range: "0–65535", desc: "Per-stream message sequence number.", rfc: "RFC 9260 §3.3.1", rfcUrl: RFC, tone: "d" },
        { name: "PPID", bytes: 4, value: "0", range: "32-bit", desc: "Payload protocol identifier. 0 is unspecified; other values identify the application protocol.", rfc: "RFC 9260 §3.3.1", rfcUrl: RFC, tone: "e" },
        { name: "User Data", bytes: "var", variable: true, range: "rest", desc: "Message bytes. Fragment flags describe whether this is the first/last fragment.", rfc: "RFC 9260 §3.3.1", rfcUrl: RFC, tone: "f" }
      ],
      inspector: "#sctp-data-inspector",
      note: "A DATA chunk's Length is 16 + payload length. The B/E flags mark the first and last fragments of a user message. The U flag selects unordered delivery."
    });
  }

  function readEncoder() {
    const type = Number(document.getElementById("sctp-enc-chunk").value);
    const input = {
      srcPort: Number(document.getElementById("sctp-enc-sport").value),
      dstPort: Number(document.getElementById("sctp-enc-dport").value),
      verificationTag: PH.parseNumber(document.getElementById("sctp-enc-vtag").value),
      chunks: []
    };
    if (type === 0) {
      input.chunks.push({
        type: 0,
        flags: (document.getElementById("sctp-enc-unordered").checked ? 0x04 : 0) |
          (document.getElementById("sctp-enc-begin").checked ? 0x02 : 0) |
          (document.getElementById("sctp-enc-fin").checked ? 0x01 : 0),
        tsn: PH.parseNumber(document.getElementById("sctp-enc-tsn").value),
        streamId: Number(document.getElementById("sctp-enc-stream").value),
        streamSequence: Number(document.getElementById("sctp-enc-streamseq").value),
        ppid: PH.parseNumber(document.getElementById("sctp-enc-ppid").value),
        payload: document.getElementById("sctp-enc-payload").value
      });
    } else if (type === 1) {
      input.chunks.push({
        type: 1, initiateTag: PH.parseNumber(document.getElementById("sctp-enc-init-tag").value),
        aRwnd: 65535, outboundStreams: 10, inboundStreams: 10, initialTsn: 100,
        params: [{ type: 5, value: "c0 00 02 01" }]
      });
    } else if (type === 3) {
      input.chunks.push({
        type: 3, cumulativeTsn: PH.parseNumber(document.getElementById("sctp-enc-cum").value),
        aRwnd: 65535, gapBlocks: [], duplicateTsns: []
      });
    } else if (type === 4) {
      input.chunks.push({ type: 4, value: document.getElementById("sctp-enc-heartbeat").value });
    } else {
      input.chunks.push({ type: 10, value: document.getElementById("sctp-enc-payload").value });
    }
    return input;
  }

  function build(showErrors) {
    const status = document.getElementById("sctp-encode-status");
    const output = document.getElementById("sctp-enc-output");
    const tag = document.getElementById("sctp-enc-tag");
    const summary = document.getElementById("sctp-enc-summary");
    let result;
    try { result = S.buildSctp(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">${result.srcPort} → ${result.dstPort}</span>`,
      `<span class="pill">tag <b>0x${PH.hex(result.verificationTag, 8)}</b></span>`,
      `<span class="pill">${result.chunks} chunk(s)</span>`,
      `<span class="pill pill--good">CRC32c <b>0x${PH.hex(result.checksum, 8)}</b></span>`
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte SCTP packet · ${result.chunks} chunk(s) · CRC32c 0x${PH.hex(result.checksum, 8)}`, "ok");
    if (diagram) diagram.setValues({
      sport: String(result.srcPort), dport: String(result.dstPort),
      vtag: "0x" + PH.hex(result.verificationTag, 8), checksum: "0x" + PH.hex(result.checksum, 8)
    });
    return result;
  }

  function encoderState() {
    const ids = ["sctp-enc-sport", "sctp-enc-dport", "sctp-enc-vtag", "sctp-enc-chunk", "sctp-enc-tsn",
      "sctp-enc-stream", "sctp-enc-streamseq", "sctp-enc-ppid", "sctp-enc-payload", "sctp-enc-init-tag",
      "sctp-enc-cum", "sctp-enc-heartbeat"];
    const state = { page: "sctp-enc", fin: document.getElementById("sctp-enc-fin").checked, begin: document.getElementById("sctp-enc-begin").checked, unordered: document.getElementById("sctp-enc-unordered").checked };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    ["fin", "begin", "unordered"].forEach((key) => {
      const el = document.getElementById("sctp-enc-" + key);
      if (el && state[key] != null) el.checked = !!state[key];
    });
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("sctp-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input, select").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("sctp-build").addEventListener("click", () => build(true));
    document.getElementById("sctp-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "SCTP encoder permalink copied"); });
    document.getElementById("sctp-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("sctp-packet.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), srcPort: result.srcPort, dstPort: result.dstPort,
        verificationTag: result.verificationTag, checksum: "0x" + PH.hex(result.checksum, 8),
        chunks: result.chunks, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function chunkDetail(chunk) {
    if (chunk.type === 0) {
      return detailTable("DATA chunk", `${chunk.payload ? chunk.payload.length : 0} B payload`, ["Field", "Value"], [
        ["Flags", `<code>${chunk.flags && chunk.flags.B ? "B " : ""}${chunk.flags && chunk.flags.E ? "E " : ""}${chunk.flags && chunk.flags.U ? "U " : ""}${chunk.flags && chunk.flags.I ? "I" : ""}</code>`],
        ["TSN", `<code>${chunk.tsn}</code>`],
        ["Stream ID", `<code>${chunk.streamId}</code>`],
        ["Stream sequence", `<code>${chunk.streamSequence}</code>`],
        ["PPID", `<code>${chunk.ppid}</code>`],
        ["Payload", `<code>${chunk.payload ? chunk.payload.length + " B" : "0 B"}</code>`]
      ]);
    }
    if (chunk.type === 1 || chunk.type === 2) {
      return detailTable("INIT / INIT ACK", "association parameters", ["Field", "Value"], [
        ["Initiate tag", `<code>0x${PH.hex(chunk.initiateTag, 8)}</code>`],
        ["a_rwnd", `<code>${chunk.aRwnd}</code>`],
        ["Outbound streams", `<code>${chunk.outboundStreams}</code>`],
        ["Inbound streams", `<code>${chunk.inboundStreams}</code>`],
        ["Initial TSN", `<code>${chunk.initialTsn}</code>`],
        ["Parameters", `<code>${chunk.params ? chunk.params.length : 0}</code>`]
      ]);
    }
    if (chunk.type === 3) {
      return detailTable("SACK", "gap acknowledgment", ["Field", "Value"], [
        ["Cumulative TSN", `<code>${chunk.cumulativeTsn}</code>`],
        ["a_rwnd", `<code>${chunk.aRwnd}</code>`],
        ["Gap blocks", `<code>${chunk.gapBlocks ? chunk.gapBlocks.length : 0}</code>`],
        ["Duplicate TSNs", `<code>${chunk.duplicateTsns ? chunk.duplicateTsns.length : 0}</code>`]
      ]);
    }
    return "";
  }

  function render(result) {
    const host = document.getElementById("sctp-decode-result");
    const pills = [
      `<span class="pill">${result.srcPort} → ${result.dstPort}</span>`,
      `<span class="pill">tag <b>0x${PH.hex(result.verificationTag, 8)}</b></span>`,
      result.checksumState === "valid" ? '<span class="pill pill--good">CRC32c valid</span>' :
        result.checksumState === "invalid" ? '<span class="pill pill--bad">CRC32c invalid</span>' :
          '<span class="pill pill--warn">CRC32c absent</span>',
      `<span class="pill">${result.chunks.length} chunk(s)</span>`
    ];
    const rows = result.chunks.map((chunk, i) => [
      `<b>${i + 1}</b>`, `<code>${chunk.type}</code>`, PH.esc(chunk.name), `${chunk.length} B`, `0x${PH.hex(chunk.flags, 2)}`,
      chunk.type === 0 ? `${chunk.streamId || 0} · seq ${chunk.streamSequence || 0}` : "—"
    ]);
    let extra = "";
    result.chunks.forEach((chunk) => { extra += chunkDetail(chunk); });
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean chunk chain</div><p>The common header, chunk lengths and CRC32c agree. SCTP association state, stream ordering and retransmission are separate.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>SCTP packet</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 0, end: 12 }] })}</div>` +
      detailTable("common header", "offsets relative to the SCTP header", ["Field", "Bits", "Offset", "Value", "Note"], [
        ["Source Port", "16", "0–15", String(result.srcPort), "endpoint"],
        ["Destination Port", "16", "16–31", String(result.dstPort), "endpoint"],
        ["Verification Tag", "32", "32–63", "0x" + PH.hex(result.verificationTag, 8), "association tag"],
        ["Checksum", "32", "64–95", "0x" + PH.hex(result.checksum, 8), result.checksumState]
      ].map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      detailTable("chunks", "chunk length includes the header, not the padding", ["#", "Type", "Name", "Length", "Flags", "Stream"], rows) +
      extra + warnings;
    if (diagram) diagram.setValues({
      sport: String(result.srcPort), dport: String(result.dstPort),
      vtag: "0x" + PH.hex(result.verificationTag, 8), checksum: "0x" + PH.hex(result.checksum, 8)
    });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("sctp-decode-input");
    const status = document.getElementById("sctp-decode-status");
    const host = document.getElementById("sctp-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let result;
    try { result = S.decodeSctp(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `${result.srcPort} → ${result.dstPort} · ${result.chunks.length} chunk(s) · CRC32c ${result.checksumState}${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.checksumState === "invalid" ? "bad" : result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("sctp-decode-input");
    if (!input) return;
    document.getElementById("sctp-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("sctp-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("sctp-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("sctp-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("sctp-decode-example").addEventListener("click", () => {
      const result = S.buildSctp({
        srcPort: 5000, dstPort: 5001, verificationTag: 0x11223344,
        chunks: [{ type: 0, flags: 0x03, tsn: 1, streamId: 0, streamSequence: 0, ppid: 0, payload: "de ad be ef" }]
      });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "sctp-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("sctp-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
