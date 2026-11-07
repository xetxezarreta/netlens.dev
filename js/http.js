/* HTTP explorer — HTTP/1.1 text framing, HTTP/2 frames and HPACK. */
(function () {
  "use strict";

  const PH = window.PH;
  const H = window.HTTPCodec;
  const RFC = {
    sem: "https://www.rfc-editor.org/rfc/rfc9110",
    h1: "https://www.rfc-editor.org/rfc/rfc9112",
    h2: "https://www.rfc-editor.org/rfc/rfc9113",
    hpack: "https://www.rfc-editor.org/rfc/rfc7541",
    h3: "https://www.rfc-editor.org/rfc/rfc9114"
  };

  const lanes = {};
  let frameDiagram = null;
  let intDiagram = null;
  let stringDiagram = null;

  function initDiagrams() {
    lanes.message = PH.byteLane("#http-message-lane", {
      title: "<b>HTTP/1.1 message</b> · start line to body", badge: "RFC 9112 §2",
      fields: [
        { id: "msg-start", name: "start-line", bytes: "var", variable: true, range: "request-line / status-line", desc: "Request line (method, target, version) or status line (version, status code, reason). Terminated by CRLF.", rfc: "RFC 9112 §3", rfcUrl: RFC.h1, tone: "a" },
        { id: "msg-headers", name: "field lines", bytes: "var", variable: true, range: "0 or more", desc: "One field per line: field-name ':' OWS field-value OWS CRLF. Field names are case-insensitive; values are opaque.", rfc: "RFC 9110 §5", rfcUrl: RFC.sem, tone: "b" },
        { id: "msg-crlf", name: "empty line", bytes: 2, range: "CRLF", desc: "The blank line ends the field section. It is a single CRLF after the last field line.", rfc: "RFC 9112 §2.1", rfcUrl: RFC.h1, tone: "c" },
        { id: "msg-body", name: "message body", bytes: "var", variable: true, range: "0 or more bytes", desc: "Framed by Content-Length, chunked transfer coding, the method/status rules, or connection close. The body is not self-describing.", rfc: "RFC 9112 §6", rfcUrl: RFC.h1, tone: "d" }
      ],
      inspector: "#http-message-inspector",
      note: "HTTP/1.1 is text, but header values are byte strings, not necessarily UTF-8. Do not normalise a value you intend to forward."
    });

    lanes.request = PH.byteLane("#http-request-lane", {
      title: "<b>Request line</b> · method · target · version", badge: "RFC 9112 §3.1",
      compact: true,
      fields: [
        { id: "req-method", name: "method", bytes: "var", variable: true, range: "token", desc: "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, CONNECT, or an extension method. Case-sensitive token.", rfc: "RFC 9110 §9", rfcUrl: RFC.sem, tone: "a" },
        { id: "req-sp1", name: "SP", bytes: 1, range: "0x20", desc: "A single space separates the request-line components.", rfc: "RFC 9112 §3", rfcUrl: RFC.h1, tone: "b" },
        { id: "req-target", name: "request-target", bytes: "var", variable: true, range: "origin / absolute / authority / asterisk", desc: "Usually an origin-form path such as /index.html?q=1. CONNECT uses authority-form and OPTIONS may use asterisk-form.", rfc: "RFC 9112 §3.2", rfcUrl: RFC.h1, tone: "c" },
        { id: "req-sp2", name: "SP", bytes: 1, range: "0x20", desc: "A single space before the HTTP version.", rfc: "RFC 9112 §3", rfcUrl: RFC.h1, tone: "d" },
        { id: "req-version", name: "HTTP-version", bytes: "var", variable: true, range: "HTTP/1.0 · HTTP/1.1", desc: "The message's protocol version. It is not a capability negotiation; it describes the framing rules in use.", rfc: "RFC 9112 §2.3", rfcUrl: RFC.h1, tone: "e" }
      ],
      inspector: "#http-request-inspector",
      note: "The request target is not a URL parser's playground. Forward it byte-for-byte or normalise it deliberately; inconsistent decoding is a security boundary."
    });

    lanes.status = PH.byteLane("#http-status-lane", {
      title: "<b>Status line</b> · version · code · reason", badge: "RFC 9112 §4",
      compact: true,
      fields: [
        { id: "status-version", name: "HTTP-version", bytes: "var", variable: true, range: "HTTP/1.0 · HTTP/1.1", desc: "The version of the response message, not necessarily the request version.", rfc: "RFC 9112 §4", rfcUrl: RFC.h1, tone: "a" },
        { id: "status-sp1", name: "SP", bytes: 1, range: "0x20", desc: "A single space after the version.", rfc: "RFC 9112 §4", rfcUrl: RFC.h1, tone: "b" },
        { id: "status-code", name: "status-code", bytes: 3, range: "100–599", desc: "Exactly three ASCII digits. The first digit defines the class; clients must not depend on the reason phrase.", rfc: "RFC 9110 §15", rfcUrl: RFC.sem, tone: "c" },
        { id: "status-sp2", name: "SP", bytes: 1, range: "0x20", desc: "A single space before the optional reason phrase.", rfc: "RFC 9112 §4", rfcUrl: RFC.h1, tone: "d" },
        { id: "status-reason", name: "reason-phrase", bytes: "var", variable: true, range: "optional text", desc: "Human-readable text. It may be empty, may contain spaces, and carries no protocol meaning.", rfc: "RFC 9112 §4", rfcUrl: RFC.h1, tone: "e" }
      ],
      inspector: "#http-status-inspector",
      note: "A status line is still line-oriented. A proxy that rewrites the reason phrase must preserve the code and the CRLF."
    });

    lanes.chunk = PH.byteLane("#http-chunk-lane", {
      title: "<b>Chunked body</b> · size · data · zero chunk", badge: "RFC 9112 §7.1",
      fields: [
        { id: "chunk-size", name: "chunk-size", bytes: "var", variable: true, range: "1*HEXDIG", desc: "Hexadecimal chunk length, optionally followed by ';' and chunk extensions. The value counts data bytes only.", rfc: "RFC 9112 §7.1", rfcUrl: RFC.h1, tone: "a" },
        { id: "chunk-crlf1", name: "CRLF", bytes: 2, range: "0D 0A", desc: "Terminates the chunk-size line.", rfc: "RFC 9112 §7.1", rfcUrl: RFC.h1, tone: "b" },
        { id: "chunk-data", name: "chunk-data", bytes: "var", variable: true, range: "chunk-size bytes", desc: "The chunk payload. Chunk boundaries are framing, not message boundaries; the decoded body is the concatenation.", rfc: "RFC 9112 §7.1", rfcUrl: RFC.h1, tone: "c" },
        { id: "chunk-crlf2", name: "CRLF", bytes: 2, range: "0D 0A", desc: "Terminates the chunk data.", rfc: "RFC 9112 §7.1", rfcUrl: RFC.h1, tone: "d" },
        { id: "chunk-last", name: "last-chunk + trailers", bytes: "var", variable: true, range: "0 CRLF [fields] CRLF", desc: "A zero chunk ends the body. Optional trailer fields follow, then a final empty line.", rfc: "RFC 9112 §7.1.2", rfcUrl: RFC.h1, tone: "e" }
      ],
      inspector: "#http-chunk-inspector",
      note: "The zero chunk is the terminator. A capture that ends before it has a truncated body, not a complete one."
    });

    frameDiagram = PH.diagram("#http2-frame-diagram", {
      title: "<b>HTTP/2 frame</b> · 9-byte header", badge: "RFC 9113 §4.1",
      bitsPerRow: 32,
      fields: [
        { id: "h2-length", name: "Length", bits: 24, range: "0–16777215", desc: "Payload length, excluding the 9-byte frame header. The default maximum frame size is 16384 bytes; SETTINGS_MAX_FRAME_SIZE can raise it.", rfc: "RFC 9113 §4.1", rfcUrl: RFC.h2, tone: "a" },
        { id: "h2-type", name: "Type", bits: 8, range: "0–255", desc: "Frame type: DATA (0), HEADERS (1), SETTINGS (4), PING (6), GOAWAY (7), WINDOW_UPDATE (8), CONTINUATION (9).", rfc: "RFC 9113 §4.1", rfcUrl: RFC.h2, tone: "b" },
        { id: "h2-flags", name: "Flags", bits: 8, range: "type-specific", desc: "Eight flag bits whose meaning depends on the frame type. END_STREAM, END_HEADERS, PADDED, PRIORITY and ACK are the common ones.", rfc: "RFC 9113 §4.1", rfcUrl: RFC.h2, tone: "c" },
        { id: "h2-r", name: "R", bits: 1, range: "0", desc: "Reserved bit. It must be zero when sending and ignored when receiving.", rfc: "RFC 9113 §4.1", rfcUrl: RFC.h2, tone: "d" },
        { id: "h2-stream", name: "Stream Identifier", bits: 31, range: "0–2³¹−1", desc: "Stream 0 is the connection. Client-initiated streams use odd IDs; server-initiated streams use even IDs.", rfc: "RFC 9113 §4.1", rfcUrl: RFC.h2, tone: "e" }
      ],
      inspector: "#http2-frame-inspector", table: "#http2-frame-fields",
      note: "The frame header is nine bytes: three length bytes, one type byte, one flags byte, then the reserved bit and 31-bit stream ID. All multi-byte integers are big-endian."
    });
    PH.fieldTable("#http2-frame-fields", frameDiagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    intDiagram = PH.diagram("#hpack-int-diagram", {
      title: "<b>HPACK integer</b> · prefix + continuation", badge: "RFC 7541 §5.1",
      bitsPerRow: 8,
      fields: [
        { id: "hpack-prefix", name: "Prefix", bits: 7, range: "N-bit value", desc: "The first byte reserves a variable number of high bits for the pattern and uses the remaining N bits (4, 5, 6 or 7) for the value. If the value is all ones, continuation bytes follow.", rfc: "RFC 7541 §5.1", rfcUrl: RFC.hpack, tone: "a" },
        { id: "hpack-cont", name: "Continuation", bits: 1, range: "0 / 1", desc: "The low bit of the first byte is the continuation marker for the integer's prefix. It is set when more bytes follow.", rfc: "RFC 7541 §5.1", rfcUrl: RFC.hpack, tone: "b" },
        { id: "hpack-more", name: "Continuation bytes", bits: "var", varWidth: 8, range: "base-128", desc: "Each continuation byte contributes seven bits, least-significant group first. The high bit says another byte follows.", rfc: "RFC 7541 §5.1", rfcUrl: RFC.hpack, tone: "c" }
      ],
      inspector: "#hpack-int-inspector",
      note: "The prefix width depends on the field representation: 7 for indexed fields, 6 for incremental indexing, 5 for table-size updates, 4 for literals without indexing."
    });

    stringDiagram = PH.diagram("#hpack-string-diagram", {
      title: "<b>HPACK string</b> · Huffman bit + length + bytes", badge: "RFC 7541 §5.2",
      bitsPerRow: 8,
      fields: [
        { id: "hpack-h", name: "H", bits: 1, range: "0 raw · 1 Huffman", desc: "When set, the string is encoded with the RFC 7541 Huffman code. When clear, the bytes are literal octets.", rfc: "RFC 7541 §5.2", rfcUrl: RFC.hpack, tone: "a" },
        { id: "hpack-len", name: "Length", bits: 7, range: "0–127 + continuation", desc: "Length of the encoded string in bytes, using the HPACK integer representation with a 7-bit prefix.", rfc: "RFC 7541 §5.2", rfcUrl: RFC.hpack, tone: "b" },
        { id: "hpack-data", name: "String Data", bits: "var", varWidth: 32, range: "Length bytes", desc: "Either raw octets or Huffman-coded bytes. Huffman coding changes the length; it is not encryption and does not preserve byte boundaries.", rfc: "RFC 7541 §5.2", rfcUrl: RFC.hpack, tone: "c" }
      ],
      inspector: "#hpack-string-inspector",
      note: "The encoded length is what appears on the wire. A Huffman-coded value usually occupies fewer bytes than the decoded string."
    });
  }

  function updateDiagrams(result) {
    if (!result) return;
    if (result.kind === "h1") {
      lanes.message.setValues({
        "msg-start": result.startLine,
        "msg-headers": result.headers.length + " fields",
        "msg-crlf": "CRLF",
        "msg-body": result.body.length + " B"
      });
      if (result.messageKind === "request") {
        lanes.request.setValues({
          "req-method": result.method,
          "req-target": result.target,
          "req-version": result.version
        });
      } else {
        lanes.status.setValues({
          "status-version": result.version,
          "status-code": String(result.status),
          "status-reason": result.reason || "—"
        });
      }
      if (result.chunked) {
        lanes.chunk.setValues({
          "chunk-size": result.chunks.length ? result.chunks[0].size + " B" : "0",
          "chunk-data": result.body.length + " B",
          "chunk-last": result.chunks.length + " chunks"
        });
      }
    } else if (result.kind === "h2" && result.frames.length) {
      const frame = result.frames[0];
      frameDiagram.setValues({
        "h2-length": frame.length + " B",
        "h2-type": frame.typeName,
        "h2-flags": "0x" + PH.hex(frame.flags, 2),
        "h2-r": "0",
        "h2-stream": String(frame.streamId)
      });
    }
  }

  /* ---------- encoder ---------- */

  function parseList(text) {
    return String(text == null ? "" : text).split(/[,\n]+/).map((value) => value.trim()).filter(Boolean);
  }

  function value(id, fallback) {
    const el = document.getElementById(id);
    return el ? el.value : fallback;
  }

  function checked(id) {
    const el = document.getElementById(id);
    return !!(el && el.checked);
  }

  function readEncoder() {
    return {
      kind: value("http-enc-kind", "request"),
      version: value("http-enc-version", "HTTP/1.1"),
      method: value("http-enc-method", "GET"),
      target: value("http-enc-target", "/"),
      host: value("http-enc-host", ""),
      status: Number(value("http-enc-status-code", "200")),
      reason: value("http-enc-reason", ""),
      headers: value("http-enc-headers", ""),
      body: value("http-enc-body", ""),
      bodyMode: value("http-enc-body-mode", "ascii"),
      chunked: checked("http-enc-chunked"),
      chunkSize: Number(value("http-enc-chunk-size", "16"))
    };
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("http-enc-status");
    const tag = document.getElementById("http-enc-tag");
    try {
      const input = readEncoder();
      const body = input.bodyMode === "hex"
        ? (input.body.trim() ? PH.parseHex(input.body) : new Uint8Array(0))
        : H.asciiBytes(input.body);
      const built = H.buildHttp1({
        kind: input.kind,
        version: input.version,
        method: input.method,
        target: input.target,
        host: input.host,
        status: input.status,
        reason: input.reason,
        headers: H.parseHeaderText(input.headers),
        body,
        chunked: input.chunked,
        chunkSize: input.chunkSize
      });
      const decoded = H.decodeHttp1(built.bytes);
      lastBuild = { input, built, decoded };
      updateEncoder(input, built, decoded);
      return lastBuild;
    } catch (err) {
      tag.textContent = "error";
      PH.setStatus(status, "error: " + err.message, "bad");
      return null;
    }
  }

  function updateEncoder(input, built, decoded) {
    document.getElementById("http-enc-output").textContent = PH.bytesToHex(built.bytes);
    document.getElementById("http-enc-output").classList.remove("placeholder");
    document.getElementById("http-enc-tag").textContent = built.bytes.length + " B";
    document.getElementById("http-enc-length").textContent = built.bytes.length + " B";
    document.getElementById("http-enc-headers-count").textContent = String(decoded.headers.length);
    document.getElementById("http-enc-body-count").textContent = decoded.body.length + " B";
    const pills = [
      `<span class="pill">${input.kind}</span>`,
      `<span class="pill">${PH.esc(decoded.startLine)}</span>`,
      `<span class="pill">${decoded.headers.length} header(s)</span>`,
      `<span class="pill">${decoded.framing}</span>`,
      `<span class="pill">${decoded.body.length} B body</span>`
    ];
    if (decoded.chunked) pills.push(`<span class="pill">${decoded.chunks.length} chunk(s)</span>`);
    if (decoded.warnings.length) pills.push(`<span class="pill pill--warn">${decoded.warnings.length} note(s)</span>`);
    document.getElementById("http-enc-summary").innerHTML = pills.join("");
    updateDiagrams(decoded);
    PH.setStatus(document.getElementById("http-enc-status"),
      built.bytes.length + " B · " + decoded.summary + (decoded.warnings.length ? " · " + decoded.warnings.length + " note(s)" : ""),
      decoded.warnings.length ? "warn" : "ok");
  }

  function syncMode() {
    const kind = value("http-enc-kind", "request");
    document.querySelectorAll("[data-http-group]").forEach((el) => {
      el.hidden = el.getAttribute("data-http-group") !== kind;
    });
  }

  function setFields(fields) {
    Object.keys(fields).forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      if (el.type === "checkbox") el.checked = !!fields[id];
      else el.value = fields[id];
    });
  }

  function applyPreset(key) {
    if (key === "request") {
      setFields({
        "http-enc-kind": "request", "http-enc-version": "HTTP/1.1", "http-enc-method": "GET",
        "http-enc-target": "/index.html", "http-enc-host": "example.com",
        "http-enc-headers": "User-Agent: netlens.dev/1.0\nAccept: text/html,application/xhtml+xml\nAccept-Encoding: gzip, br",
        "http-enc-body": "", "http-enc-body-mode": "ascii", "http-enc-chunked": false
      });
    } else if (key === "response") {
      setFields({
        "http-enc-kind": "response", "http-enc-version": "HTTP/1.1", "http-enc-status-code": "200",
        "http-enc-reason": "OK", "http-enc-headers": "Content-Type: application/json\nCache-Control: max-age=60\nServer: example",
        "http-enc-body": "{\"ok\":true,\"items\":[1,2,3]}\n", "http-enc-body-mode": "ascii", "http-enc-chunked": false
      });
    } else if (key === "chunked") {
      setFields({
        "http-enc-kind": "response", "http-enc-version": "HTTP/1.1", "http-enc-status-code": "200",
        "http-enc-reason": "OK", "http-enc-headers": "Content-Type: text/plain; charset=utf-8",
        "http-enc-body": "chunked transfer coding splits the body so the sender never needs a Content-Length\n",
        "http-enc-body-mode": "ascii", "http-enc-chunked": true, "http-enc-chunk-size": "24"
      });
    } else if (key === "post") {
      setFields({
        "http-enc-kind": "request", "http-enc-version": "HTTP/1.1", "http-enc-method": "POST",
        "http-enc-target": "/api/items", "http-enc-host": "example.com",
        "http-enc-headers": "Content-Type: application/json\nAccept: application/json",
        "http-enc-body": "{\"name\":\"widget\"}\n", "http-enc-body-mode": "ascii", "http-enc-chunked": false
      });
    }
    syncMode();
    buildFromForm(true);
  }

  function encoderState() {
    return { page: "http-enc", values: PH.captureFormState() };
  }

  function applyEncoderState(state) {
    if (!state || !state.values) return false;
    PH.applyFormState(state.values);
    syncMode();
    return true;
  }

  function initEncoder() {
    const build = document.getElementById("http-enc-build");
    if (!build) return;
    document.getElementById("http-enc-kind").addEventListener("change", () => {
      syncMode();
      buildFromForm(false);
    });
    ["http-enc-version", "http-enc-method", "http-enc-target", "http-enc-host", "http-enc-status-code",
      "http-enc-reason", "http-enc-headers", "http-enc-body", "http-enc-chunk-size"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", () => buildFromForm(false));
    });
    ["http-enc-body-mode", "http-enc-chunked"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", () => buildFromForm(false));
    });
    build.addEventListener("click", () => buildFromForm(true));
    document.getElementById("http-enc-example").addEventListener("click", () => applyPreset("request"));
    document.querySelectorAll("[data-http-preset]").forEach((button) => {
      button.addEventListener("click", () => applyPreset(button.getAttribute("data-http-preset")));
    });
    document.getElementById("http-enc-permalink").addEventListener("click", () => {
      if (lastBuild || buildFromForm(true)) PH.shareState(encoderState(), "HTTP encoder permalink copied");
    });
    document.getElementById("http-enc-export").addEventListener("click", () => {
      const current = lastBuild || buildFromForm(true);
      if (!current) return;
      PH.downloadText("http-message.json", JSON.stringify({
        hex: PH.bytesToHex(current.built.bytes),
        bytes: current.built.bytes.length,
        decoded: sanitize(current.decoded)
      }, null, 2), "application/json");
    });
    syncMode();
    buildFromForm(false);
  }

  /* decoder and rendering continue below */

  /* ---------- decoder ---------- */

  let lastBuild = null;
  let lastDecode = null;

  function contextFromDissect(result) {
    const ipv4 = result.layers.find((layer) => layer.proto === "ipv4");
    const ipv6 = result.layers.find((layer) => layer.proto === "ipv6");
    const tcp = result.layers.find((layer) => layer.proto === "tcp");
    const udp = result.layers.find((layer) => layer.proto === "udp");
    const ethernet = result.layers.find((layer) => layer.proto === "ethernet");
    const context = { transport: tcp ? "TCP" : udp ? "UDP" : "raw" };
    if (ipv4) {
      context.ip = ipv4.meta.ip;
      context.src = ipv4.meta.ip.src;
      context.dst = ipv4.meta.ip.dst;
      context.ipVersion = 4;
    }
    if (ipv6) {
      context.ipv6 = ipv6.meta;
      context.src = ipv6.meta.ip.src;
      context.dst = ipv6.meta.ip.dst;
      context.ipVersion = 6;
    }
    if (tcp) {
      context.srcPort = tcp.meta.parsed.sport;
      context.dstPort = tcp.meta.parsed.dport;
      context.checksumState = tcp.meta.parsed.checksumStatus;
    }
    if (udp) {
      context.srcPort = udp.meta.parsed.srcPort;
      context.dstPort = udp.meta.parsed.dstPort;
      context.checksumState = udp.meta.parsed.checksumState;
    }
    if (ethernet) {
      context.ethernet = {
        srcMac: ethernet.meta.eth.srcMac,
        dstMac: ethernet.meta.eth.dstMac,
        vlanTags: ethernet.meta.eth.vlanTags,
        fcsPresent: ethernet.meta.eth.fcsPresent,
        fcsOk: ethernet.meta.eth.fcsOk
      };
    }
    return context;
  }

  function resolveInput(bytes, kind) {
    if (kind === "h1" || kind === "h2" || kind === "hpack") {
      return { bytes, context: { transport: "raw" } };
    }
    if (bytes.length >= H.H2_PREFACE.length && H.asciiString(bytes.subarray(0, H.H2_PREFACE.length)) === H.H2_PREFACE) {
      return { bytes, context: { transport: "raw" } };
    }
    if (H.looksLikeHttp1(bytes)) return { bytes, context: { transport: "raw" } };
    if (window.Dissector) {
      try {
        const result = window.Dissector.dissect(bytes);
        const layer = result.layers.find((item) => item.proto === "http");
        if (layer) {
          return {
            bytes: bytes.subarray(layer.offset, layer.offset + layer.length),
            context: contextFromDissect(result)
          };
        }
      } catch (_) { /* fall through */ }
    }
    return { bytes, context: { transport: "raw" } };
  }

  function fieldsTable(fields) {
    if (!fields || !fields.length) return "";
    return '<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
      fields.map((field) => `<tr><td><b>${PH.esc(field.name)}</b></td><td><code>${PH.esc(field.value)}</code></td><td class="small">${PH.esc(field.note || "")}</td></tr>`).join("") +
      "</tbody></table></div>";
  }

  function headersTable(headers, h2) {
    if (!headers || !headers.length) return '<p class="dim">No header fields.</p>';
    const head = h2
      ? "<tr><th>Name</th><th>Value</th><th>Representation</th><th>Index</th><th>Coding</th></tr>"
      : "<tr><th>Name</th><th>Value</th></tr>";
    const rows = headers.map((header) => {
      if (h2) {
        return `<tr><td><b>${PH.esc(header.name)}</b></td><td><code>${PH.esc(header.value)}</code></td><td>${PH.esc(header.type)}${header.sensitive ? " · sensitive" : ""}</td><td class="num">${header.index == null ? "—" : header.index}</td><td>${header.huffman ? "Huffman" : "raw"}</td></tr>`;
      }
      return `<tr><td><b>${PH.esc(header.name)}</b></td><td><code>${PH.esc(header.value)}</code></td></tr>`;
    }).join("");
    return '<div class="table-wrap"><table class="data-table"><thead>' + head + "</thead><tbody>" + rows + "</tbody></table></div>";
  }

  function bodyPreview(bytes, label) {
    if (!bytes || !bytes.length) return "";
    const text = PH.bytesToAscii(bytes.subarray(0, Math.min(512, bytes.length)));
    const hex = PH.bytesToHex(bytes.subarray(0, Math.min(256, bytes.length)));
    return '<div class="output" style="margin-top:10px"><div class="output__label">' + PH.esc(label) + " · " + bytes.length + " B</div>" +
      "<pre>" + PH.esc(text) + (bytes.length > 512 ? " …" : "") + "</pre>" +
      "<pre>" + PH.esc(hex) + (bytes.length > 256 ? " …" : "") + "</pre></div>";
  }

  function transportCallout(context) {
    if (!context || context.transport === "raw") {
      return '<div class="callout callout--warn"><div class="callout__title">raw HTTP bytes</div><p>No IP or transport wrapper was supplied. The message decodes, but addresses, ports, TCP checksum and connection framing (pipelining, close-delimited bodies) cannot be verified from this input alone.</p></div>';
    }
    const parts = [];
    if (context.src && context.dst) parts.push(PH.esc(context.src) + " → " + PH.esc(context.dst));
    if (context.srcPort != null) parts.push("port " + context.srcPort + " → " + context.dstPort);
    parts.push(context.transport);
    if (context.checksumState) parts.push("checksum " + PH.esc(context.checksumState));
    if (context.ethernet) {
      parts.push("Ethernet " + PH.esc(context.ethernet.srcMac) + " → " + PH.esc(context.ethernet.dstMac) +
        (context.ethernet.vlanTags && context.ethernet.vlanTags.length ? " · " + context.ethernet.vlanTags.length + " VLAN tag(s)" : ""));
    }
    const links = [];
    if (context.ipVersion === 4) links.push('<a href="ipv4.html">IPv4 explorer</a>');
    if (context.ipVersion === 6) links.push('<a href="ipv6.html">IPv6 explorer</a>');
    if (context.transport === "TCP") links.push('<a href="tcp.html">TCP explorer</a>');
    return '<div class="callout"><div class="callout__title">transport context</div><p>' + parts.join(" · ") +
      (links.length ? ". " + links.join(" · ") : "") + ".</p></div>";
  }

  function renderH1(result, bytes) {
    const start = result.messageKind === "request"
      ? [
        ["Method", result.method],
        ["Request target", result.target],
        ["Version", result.version]
      ]
      : [
        ["Version", result.version],
        ["Status", result.status + " · " + result.reason],
        ["Reason", result.reason || "—"]
      ];
    const startTable = '<div class="table-wrap"><table class="data-table"><thead><tr><th>Start line</th><th>Value</th></tr></thead><tbody>' +
      start.map(([name, value]) => `<tr><td><b>${PH.esc(name)}</b></td><td><code>${PH.esc(value)}</code></td></tr>`).join("") +
      "</tbody></table></div>";
    const chunkTable = result.chunked && result.chunks.length
      ? '<div class="decoded-head"><h3>Chunks</h3><span class="dim">' + result.chunks.length + " chunk(s)</span></div>" +
        '<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Size</th><th>Offset</th><th>Preview</th></tr></thead><tbody>' +
        result.chunks.map((chunk, index) => `<tr><td>${index + 1}</td><td class="num">${chunk.size}</td><td class="num">+${chunk.offset}</td><td><code>${PH.esc(PH.bytesToAscii(chunk.data.subarray(0, 48)))}${chunk.data.length > 48 ? " …" : ""}</code></td></tr>`).join("") +
        "</tbody></table></div>"
      : "";
    const trailerTable = result.trailers.length
      ? '<div class="decoded-head"><h3>Trailers</h3><span class="dim">' + result.trailers.length + " field(s)</span></div>" + headersTable(result.trailers, false)
      : "";
    const framing = '<div class="callout"><div class="callout__title">framing · ' + PH.esc(result.framing) + "</div><p>" +
      (result.framing === "content-length"
        ? "The body ends after exactly " + result.contentLength + " bytes. A capture with fewer bytes is truncated; a capture with more bytes contains a pipelined message or padding."
        : result.framing === "chunked"
          ? "The body ends at the zero-length chunk. Chunk sizes are hexadecimal; the decoded body is the concatenation of the chunk data, not the raw wire bytes."
          : result.framing === "close-delimited"
            ? "No length was advertised. The body ends when the connection closes, so truncation and completion look the same without connection state."
            : result.framing === "body forbidden"
              ? "The method or status code forbids a body. Any bytes after the header block belong to the next message or are a protocol error."
              : result.framing === "invalid"
                ? "Transfer-Encoding is present but does not end in chunked. A request in this form has no determinable body length and should be rejected."
                : "No body is present. The message ends at the blank line.") + "</p></div>";
    return startTable +
      '<div class="decoded-head"><h3>Header fields</h3><span class="dim">' + result.headers.length + " field(s)</span></div>" +
      headersTable(result.headers, false) +
      bodyPreview(result.body, "body") +
      chunkTable + trailerTable + framing;
  }

  function frameCard(frame) {
    const warnings = frame.warnings && frame.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:8px"><div class="callout__title">frame notes</div><ul class="dashed" style="margin:0">' +
        frame.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : "";
    return '<div class="http-frame"><div class="decoded-head"><h3>' + PH.esc(frame.typeName) + '</h3><span class="dim">stream ' +
      frame.streamId + " · " + frame.length + " B · offset +" + frame.offset + (frame.flagNames.length ? " · " + frame.flagNames.join(" ") : "") + "</span></div>" +
      fieldsTable(frame.fields) +
      (frame.headers ? headersTable(frame.headers, true) : "") +
      (frame.data ? bodyPreview(frame.data, "DATA payload") : "") +
      warnings + "</div>";
  }

  function renderH2(result, bytes) {
    const preface = result.preface
      ? '<div class="callout"><div class="callout__title">client connection preface</div><p>The 24-byte preface <code>PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n</code> starts every client-initiated HTTP/2 connection. It is followed immediately by a SETTINGS frame. The server preface is a SETTINGS frame without the magic string.</p></div>'
      : '<div class="callout callout--warn"><div class="callout__title">no connection preface</div><p>This stream starts mid-connection. Frame parsing still works, but HPACK dynamic-table state may be incomplete and stream IDs may not begin at 1.</p></div>';
    const frames = result.frames.length
      ? '<div class="decoded-head"><h3>Frames</h3><span class="dim">' + result.frames.length + " frame(s)</span></div>" + result.frames.map(frameCard).join("")
      : '<div class="callout callout--warn"><div class="callout__title">no complete frames</div><p>The input does not contain a full nine-byte frame header plus payload.</p></div>';
    const settings = Object.keys(result.settings).length
      ? '<div class="decoded-head"><h3>Connection settings</h3><span class="dim">latest value per setting</span></div>' +
        '<div class="table-wrap"><table class="data-table"><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>' +
        Object.keys(result.settings).map((id) => `<tr><td><b>${PH.esc(H.settingName(Number(id)))}</b></td><td class="num">${result.settings[id]}</td></tr>`).join("") +
        "</tbody></table></div>"
      : "";
    const hpack = '<div class="callout"><div class="callout__title">HPACK state</div><p>Dynamic table: <b>' +
      result.hpack.dynamicCount + "</b> entr" + (result.hpack.dynamicCount === 1 ? "y" : "ies") +
      " · maximum " + result.hpack.maxSize + " B. HPACK state is shared by every stream on the connection; a block that starts mid-connection can reference entries you never saw.</p></div>";
    return preface + frames + settings + hpack;
  }

  function renderHpack(result) {
    const headers = result.headers.filter((header) => header.type !== "size-update");
    const updates = result.headers.filter((header) => header.type === "size-update");
    return '<div class="decoded-head"><h3>Header block</h3><span class="dim">' + headers.length + " field(s) · " + result.length + " B consumed</span></div>" +
      headersTable(headers, true) +
      (updates.length ? '<div class="callout"><div class="callout__title">dynamic table size update</div><p>' +
        updates.map((update) => PH.esc(update.value)).join(", ") + "</p></div>" : "") +
      '<div class="callout"><div class="callout__title">decoded without connection state</div><p>This standalone view starts with an empty dynamic table. Indexed fields that refer to entries established earlier in a real connection will be reported as missing.</p></div>';
  }

  function renderDecoded(result, context, bytes) {
    const host = document.getElementById("http-decode-result");
    const pills = [];
    if (result.kind === "h1") {
      pills.push(`<span class="pill pill--good">HTTP/1.1 ${result.messageKind}</span>`);
      pills.push(`<span class="pill">${PH.esc(result.startLine)}</span>`);
      pills.push(`<span class="pill">${result.headers.length} header(s)</span>`);
      pills.push(`<span class="pill">${result.framing}</span>`);
      pills.push(`<span class="pill">${result.body.length} B body</span>`);
    } else if (result.kind === "h2") {
      pills.push(`<span class="pill pill--good">HTTP/2</span>`);
      pills.push(`<span class="pill">${result.frames.length} frame(s)</span>`);
      pills.push(`<span class="pill">${result.headerCount} header field(s)</span>`);
      pills.push(`<span class="pill">${result.hpack.dynamicCount} dynamic entr${result.hpack.dynamicCount === 1 ? "y" : "ies"}</span>`);
    } else {
      pills.push(`<span class="pill pill--good">HPACK</span>`);
      pills.push(`<span class="pill">${result.headers.filter((header) => header.type !== "size-update").length} field(s)</span>`);
      pills.push(`<span class="pill">${result.length} B consumed</span>`);
    }
    if (result.warnings.length) pills.push(`<span class="pill pill--warn">${result.warnings.length} note(s)</span>`);
    const body = result.kind === "h1" ? renderH1(result, bytes) : result.kind === "h2" ? renderH2(result, bytes) : renderHpack(result);
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        result.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean parse</div><p>Start line, field lines, framing and lengths agree. A clean parse does not prove the message is safe to forward; semantic validation and an HTTP firewall are separate jobs.</p></div>';
    host.innerHTML = '<div class="decode-summary">' + pills.join("") + "</div>" +
      '<div class="hexdump-wrap"><div class="hexdump-head"><span>HTTP bytes</span><span>' + bytes.length + " B · " + result.kind.toUpperCase() + "</span></div>" +
      PH.hexdump(bytes) + "</div>" + body + transportCallout(context) + warnings;
  }

  function runDecode(showErrors) {
    const input = document.getElementById("http-decode-input");
    const status = document.getElementById("http-decode-status");
    const host = document.getElementById("http-decode-result");
    let bytes;
    try {
      bytes = PH.parseHex(input.value);
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return null;
    }
    try {
      const kind = document.getElementById("http-decode-kind").value;
      const resolved = resolveInput(bytes, kind);
      const result = H.decodeHttpMessage(resolved.bytes, { kind: kind === "auto" ? "auto" : kind });
      renderDecoded(result, resolved.context, resolved.bytes);
      updateDiagrams(result);
      lastDecode = { result, context: resolved.context, hex: PH.bytesToHex(bytes) };
      PH.setStatus(status,
        result.summary + " · " + resolved.bytes.length + " B" +
        (result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""),
        result.warnings.length ? "warn" : "ok");
      return lastDecode;
    } catch (err) {
      host.innerHTML = "";
      lastDecode = null;
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      return null;
    }
  }

  function loadExample(key) {
    let bytes;
    let kind;
    if (key === "h2") {
      bytes = H.examples().h2.bytes;
      kind = "h2";
    } else if (key === "hpack") {
      bytes = H.encodeHpack([
        { name: ":method", value: "GET" },
        { name: ":scheme", value: "https" },
        { name: ":authority", value: "example.com" },
        { name: ":path", value: "/index.html" },
        { name: "user-agent", value: "netlens.dev/1.0" }
      ]);
      kind = "hpack";
    } else {
      bytes = H.examples()[key].bytes;
      kind = "h1";
    }
    document.getElementById("http-decode-input").value = PH.bytesToHex(bytes);
    document.getElementById("http-decode-kind").value = kind;
    runDecode(true);
  }

  function decoderState() {
    return {
      page: "http-dec",
      kind: document.getElementById("http-decode-kind").value,
      hex: document.getElementById("http-decode-input").value
    };
  }

  function sanitize(value, depth) {
    const level = depth || 0;
    if (level > 8) return "…";
    if (value instanceof Uint8Array) return PH.bytesToHex(value);
    if (Array.isArray(value)) return value.map((item) => sanitize(item, level + 1));
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach((key) => {
        if (key === "body" || key === "bytes" || key === "payload" || key === "data" || key === "headerBlock") {
          if (value[key] instanceof Uint8Array) out[key + "Hex"] = PH.bytesToHex(value[key]);
          return;
        }
        out[key] = sanitize(value[key], level + 1);
      });
      return out;
    }
    return value;
  }

  function initHpackEncoder() {
    const build = document.getElementById("hpack-enc-build");
    if (!build) return;
    function run() {
      const status = document.getElementById("hpack-enc-status");
      const output = document.getElementById("hpack-enc-output");
      const decodedHost = document.getElementById("hpack-enc-decoded");
      try {
        const headers = H.parseHeaderText(document.getElementById("hpack-enc-input").value, { allowPseudo: true });
        const block = H.encodeHpack(headers);
        output.textContent = PH.bytesToHex(block);
        output.classList.remove("placeholder");
        const decoded = H.decodeHpack(block);
        decodedHost.innerHTML = '<div class="decoded-head"><h3>Decoded block</h3><span class="dim">' +
          decoded.headers.filter((header) => header.type !== "size-update").length + " field(s) · " +
          decoded.bytesUsed + " B</span></div>" + headersTable(decoded.headers, true) +
          (decoded.warnings.length ? '<div class="callout callout--warn"><div class="callout__title">HPACK notes</div><ul class="dashed" style="margin:0">' +
            decoded.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>" : "");
        PH.setStatus(status, block.length + " B · " + headers.length + " field(s) · " + decoded.dynamicCount + " dynamic entr" + (decoded.dynamicCount === 1 ? "y" : "ies"), "ok");
      } catch (err) {
        output.classList.add("placeholder");
        output.textContent = "no bytes built yet";
        decodedHost.innerHTML = "";
        PH.setStatus(status, "error: " + err.message, "bad");
      }
    }
    build.addEventListener("click", run);
    document.getElementById("hpack-enc-input").addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
    run();
  }

  function initDecoder() {
    const run = document.getElementById("http-decode");
    if (!run) return;
    run.addEventListener("click", () => runDecode(true));
    document.getElementById("http-decode-request").addEventListener("click", () => loadExample("request"));
    document.getElementById("http-decode-response").addEventListener("click", () => loadExample("response"));
    document.getElementById("http-decode-chunked").addEventListener("click", () => loadExample("chunked"));
    document.getElementById("http-decode-h2").addEventListener("click", () => loadExample("h2"));
    document.getElementById("http-decode-hpack").addEventListener("click", () => loadExample("hpack"));
    document.getElementById("http-decode-clear").addEventListener("click", () => {
      document.getElementById("http-decode-input").value = "";
      document.getElementById("http-decode-result").innerHTML = "";
      lastDecode = null;
      PH.setStatus(document.getElementById("http-decode-status"), "No HTTP message decoded yet.", "");
    });
    document.getElementById("http-decode-permalink").addEventListener("click", () => {
      if (lastDecode || runDecode(true)) PH.shareState(decoderState(), "HTTP decoder permalink copied");
    });
    document.getElementById("http-decode-export").addEventListener("click", () => {
      const current = lastDecode || runDecode(true);
      if (!current) return;
      PH.downloadText("http-decoded.json", JSON.stringify({
        hex: current.hex,
        transport: sanitize(current.context),
        decoded: sanitize(current.result)
      }, null, 2), "application/json");
    });
    document.getElementById("http-decode-input").addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runDecode(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state) return false;
    if (state.page === "http-enc" && applyEncoderState(state)) {
      buildFromForm(true);
      return true;
    }
    if (state.page === "http-dec") {
      document.getElementById("http-decode-kind").value = state.kind || "auto";
      document.getElementById("http-decode-input").value = state.hex || "";
      runDecode(true);
      return true;
    }
    return false;
  }

  function init() {
    if (!document.getElementById("http-message-lane")) return;
    initDiagrams();
    initEncoder();
    initHpackEncoder();
    initDecoder();
    if (!restoreState()) buildFromForm(false);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
