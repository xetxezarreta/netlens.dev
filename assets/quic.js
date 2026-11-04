/* QUIC v1 headers, varints and frames — pure codec + page wiring */
(function () {
  "use strict";

  const PH = window.PH;
  const MAX_VARINT = 4611686018427387903n;
  const QUIC_RFC = "https://www.rfc-editor.org/rfc/rfc9000";

  /* ---------- varints ---------- */
  function toBigInt(value) {
    if (typeof value === "bigint") return value;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error("not a finite number");
      return BigInt(Math.trunc(value));
    }
    const s = String(value).trim().replace(/_/g, "");
    if (!s) throw new Error("empty value");
    try { return BigInt(s); } catch (_) { throw new Error("not an integer: " + value); }
  }

  function varintEncode(value) {
    const v = toBigInt(value);
    if (v < 0n) throw new Error("varint cannot be negative");
    if (v > MAX_VARINT) throw new Error("varint exceeds 2^62-1");
    let size;
    if (v <= 63n) size = 1;
    else if (v <= 16383n) size = 2;
    else if (v <= 1073741823n) size = 4;
    else size = 8;
    const out = new Uint8Array(size);
    let n = v;
    for (let i = size - 1; i >= 0; i--) {
      out[i] = Number(n & 255n);
      n >>= 8n;
    }
    const prefix = size === 1 ? 0 : size === 2 ? 1 : size === 4 ? 2 : 3;
    out[0] = (prefix << 6) | (out[0] & 0x3f);
    return out;
  }

  function varintDecode(bytes, offset = 0) {
    if (offset >= bytes.length) throw new Error("no byte for varint at offset " + offset);
    const first = bytes[offset];
    const size = [1, 2, 4, 8][first >> 6];
    if (offset + size > bytes.length) throw new Error(`varint at offset ${offset} needs ${size} bytes, only ${bytes.length - offset} available`);
    let v = BigInt(first & 0x3f);
    for (let i = 1; i < size; i++) v = (v << 8n) | BigInt(bytes[offset + i]);
    return { value: v, size, offset, prefix: first >> 6 };
  }

  function fmtVarint(v) { return v.toString(); }

  function concat(parts) { return PH.concatBytes.apply(null, parts); }
  function vbytes(v) { return varintEncode(v); }

  /* ---------- frame metadata ---------- */
  const FRAME_DEFS = {
    "0x00": { name: "PADDING", section: "19.1", rfc: QUIC_RFC + "#section-19.1", fields: [
      { name: "Frame Type", bytes: 1, value: "0x00", desc: "PADDING frame type. A PADDING frame is one or more zero bytes." },
      { name: "Padding", bytes: "var", variable: true, range: "any count", desc: "Zero bytes used to increase packet size. The frame can be repeated; consecutive zeros are usually treated as one padding run." }
    ] },
    "0x01": { name: "PING", section: "19.2", rfc: QUIC_RFC + "#section-19.2", fields: [
      { name: "Frame Type", bytes: 1, value: "0x01", desc: "PING has no payload. It elicits an acknowledgment and keeps the connection alive." }
    ] },
    "0x02": { name: "ACK", section: "19.3", rfc: QUIC_RFC + "#section-19.3", fields: [
      { name: "Frame Type", bytes: 1, value: "0x02", desc: "0x02 is ACK without ECN counts; 0x03 is ACK with ECN counts." },
      { name: "Largest Acknowledged", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Largest packet number being acknowledged." },
      { name: "ACK Delay", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Delay in microseconds, scaled by the peer's max_ack_delay exponent." },
      { name: "ACK Range Count", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Number of additional ACK ranges after the first." },
      { name: "First ACK Range", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Number of contiguous packets below Largest Acknowledged." },
      { name: "ACK Ranges", bytes: "var", variable: true, range: "gap/length pairs", desc: "Each range is a gap (unacknowledged packets) followed by a length (acknowledged packets), both varints." },
      { name: "ECN Counts", bytes: "var", variable: true, range: "type 0x03 only", desc: "ECT0, ECT1 and CE counts, each a varint, when the frame type is 0x03." }
    ] },
    "0x04": { name: "RESET_STREAM", section: "19.4", rfc: QUIC_RFC + "#section-19.4", fields: [
      { name: "Frame Type", bytes: 1, value: "0x04", desc: "Abrupt termination of the sending part of a stream." },
      { name: "Stream ID", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Stream being reset." },
      { name: "Application Error Code", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Application-defined reason for the reset." },
      { name: "Final Size", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Final number of bytes sent on the stream." }
    ] },
    "0x05": { name: "STOP_SENDING", section: "19.5", rfc: QUIC_RFC + "#section-19.5", fields: [
      { name: "Frame Type", bytes: 1, value: "0x05", desc: "Requests that the peer stop sending on a stream." },
      { name: "Stream ID", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Stream to stop." },
      { name: "Application Error Code", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Application-defined reason." }
    ] },
    "0x06": { name: "CRYPTO", section: "19.6", rfc: QUIC_RFC + "#section-19.6", fields: [
      { name: "Frame Type", bytes: 1, value: "0x06", desc: "Carries TLS handshake data." },
      { name: "Offset", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Offset in the Crypto Stream." },
      { name: "Length", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Length of the Crypto Data field." },
      { name: "Crypto Data", bytes: "var", variable: true, range: "Length bytes", desc: "TLS handshake bytes at the given offset." }
    ] },
    "0x07": { name: "NEW_TOKEN", section: "19.7", rfc: QUIC_RFC + "#section-19.7", fields: [
      { name: "Frame Type", bytes: 1, value: "0x07", desc: "Provides an address validation token for a future connection." },
      { name: "Token Length", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Length of the token." },
      { name: "Token", bytes: "var", variable: true, range: "Token Length bytes", desc: "Opaque token; must be at least 1 byte." }
    ] },
    "0x08": { name: "STREAM", section: "19.8", rfc: QUIC_RFC + "#section-19.8", fields: [
      { name: "Frame Type", bytes: 1, value: "0x08-0x0f", desc: "Base 0x08 plus OFF (0x04), LEN (0x02) and FIN (0x01)." },
      { name: "Stream ID", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Stream carrying the data." },
      { name: "Offset (if OFF)", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Present only when the OFF bit (0x04) is set." },
      { name: "Length (if LEN)", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Present only when the LEN bit (0x02) is set. If absent, data extends to the end of the packet." },
      { name: "Stream Data", bytes: "var", variable: true, range: "Length or rest of packet", desc: "Application bytes. The FIN bit marks the final byte of the stream." }
    ] },
    "0x10": { name: "MAX_DATA", section: "19.9", rfc: QUIC_RFC + "#section-19.9", fields: [
      { name: "Frame Type", bytes: 1, value: "0x10", desc: "Connection-level flow-control limit." },
      { name: "Maximum Data", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Maximum number of bytes that may be sent on the connection." }
    ] },
    "0x11": { name: "MAX_STREAM_DATA", section: "19.10", rfc: QUIC_RFC + "#section-19.10", fields: [
      { name: "Frame Type", bytes: 1, value: "0x11", desc: "Stream-level flow-control limit." },
      { name: "Stream ID", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Stream whose limit is updated." },
      { name: "Maximum Stream Data", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Maximum bytes allowed on this stream." }
    ] },
    "0x12": { name: "MAX_STREAMS", section: "19.11", rfc: QUIC_RFC + "#section-19.11", fields: [
      { name: "Frame Type", bytes: 1, value: "0x12", desc: "0x12 bidirectional, 0x13 unidirectional stream limit." },
      { name: "Maximum Streams", bytes: "var", variable: true, range: "0 to 2^60", desc: "Maximum number of streams of this type that may be opened." }
    ] },
    "0x14": { name: "DATA_BLOCKED", section: "19.12", rfc: QUIC_RFC + "#section-19.12", fields: [
      { name: "Frame Type", bytes: 1, value: "0x14", desc: "Sender is blocked at the connection flow-control limit." },
      { name: "Maximum Data", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Limit at which the sender is blocked." }
    ] },
    "0x15": { name: "STREAM_DATA_BLOCKED", section: "19.13", rfc: QUIC_RFC + "#section-19.13", fields: [
      { name: "Frame Type", bytes: 1, value: "0x15", desc: "Sender is blocked at a stream flow-control limit." },
      { name: "Stream ID", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Blocked stream." },
      { name: "Maximum Stream Data", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Limit at which the sender is blocked." }
    ] },
    "0x16": { name: "STREAMS_BLOCKED", section: "19.14", rfc: QUIC_RFC + "#section-19.14", fields: [
      { name: "Frame Type", bytes: 1, value: "0x16", desc: "0x16 bidirectional, 0x17 unidirectional." },
      { name: "Maximum Streams", bytes: "var", variable: true, range: "0 to 2^60", desc: "Limit that prevented opening a new stream." }
    ] },
    "0x18": { name: "NEW_CONNECTION_ID", section: "19.15", rfc: QUIC_RFC + "#section-19.15", fields: [
      { name: "Frame Type", bytes: 1, value: "0x18", desc: "Provides an alternative connection ID." },
      { name: "Sequence Number", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Monotonic sequence number for this CID." },
      { name: "Retire Prior To", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Requests retirement of CIDs with sequence numbers below this value." },
      { name: "Connection ID Length", bytes: 1, range: "0-20", desc: "Length of Connection ID in bytes." },
      { name: "Connection ID", bytes: "var", variable: true, range: "0-20 bytes", desc: "New destination connection ID." },
      { name: "Stateless Reset Token", bytes: 16, range: "16 bytes", desc: "Token the peer can use for stateless reset." }
    ] },
    "0x19": { name: "RETIRE_CONNECTION_ID", section: "19.16", rfc: QUIC_RFC + "#section-19.16", fields: [
      { name: "Frame Type", bytes: 1, value: "0x19", desc: "Retires a connection ID previously issued by the peer." },
      { name: "Sequence Number", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Sequence number of the CID to retire." }
    ] },
    "0x1a": { name: "PATH_CHALLENGE", section: "19.17", rfc: QUIC_RFC + "#section-19.17", fields: [
      { name: "Frame Type", bytes: 1, value: "0x1a", desc: "Path validation challenge." },
      { name: "Data", bytes: 8, range: "8 bytes", desc: "Arbitrary data that the peer must echo in a PATH_RESPONSE." }
    ] },
    "0x1b": { name: "PATH_RESPONSE", section: "19.18", rfc: QUIC_RFC + "#section-19.18", fields: [
      { name: "Frame Type", bytes: 1, value: "0x1b", desc: "Response to a PATH_CHALLENGE." },
      { name: "Data", bytes: 8, range: "8 bytes", desc: "The challenge data, echoed unchanged." }
    ] },
    "0x1c": { name: "CONNECTION_CLOSE", section: "19.19", rfc: QUIC_RFC + "#section-19.19", fields: [
      { name: "Frame Type", bytes: 1, value: "0x1c/0x1d", desc: "0x1c transport-level close; 0x1d application-level close." },
      { name: "Error Code", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Transport or application error code." },
      { name: "Frame Type (app)", bytes: "var", variable: true, range: "0x1d only", desc: "Frame type that caused the close; present only in 0x1d." },
      { name: "Reason Phrase Length", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Length of the UTF-8 reason phrase." },
      { name: "Reason Phrase", bytes: "var", variable: true, range: "Length bytes", desc: "UTF-8 diagnostic text; not guaranteed printable." }
    ] },
    "0x1e": { name: "HANDSHAKE_DONE", section: "19.20", rfc: QUIC_RFC + "#section-19.20", fields: [
      { name: "Frame Type", bytes: 1, value: "0x1e", desc: "Server confirms the handshake is complete." }
    ] },
    "0x30": { name: "DATAGRAM", section: "RFC 9221 §4", rfc: "https://www.rfc-editor.org/rfc/rfc9221#section-4", fields: [
      { name: "Frame Type", bytes: 1, value: "0x30/0x31", desc: "0x30 has implicit length; 0x31 has an explicit Length varint." },
      { name: "Length (0x31)", bytes: "var", variable: true, range: "0 to 2^62-1", desc: "Only present for type 0x31." },
      { name: "Data", bytes: "var", variable: true, range: "rest or Length bytes", desc: "Application datagram payload." }
    ] }
  };

  const FRAME_KEYS = Object.keys(FRAME_DEFS);
  function frameInfo(key) { return FRAME_DEFS[key] || null; }
  function frameName(key) { const d = FRAME_DEFS[key]; return d ? d.name : "UNKNOWN"; }
  function frameLabel(key) { return key + " · " + frameName(key); }

  function normalizeKey(key) {
    const n = parseInt(String(key).replace(/^0x/i, ""), 16);
    if (n >= 0x08 && n <= 0x0f) return "0x08";
    if (n === 0x03) return "0x02";
    if (n === 0x13) return "0x12";
    if (n === 0x17) return "0x16";
    if (n === 0x31) return "0x30";
    if (n === 0x1d) return "0x1c";
    return "0x" + n.toString(16).padStart(2, "0");
  }
  function infoFor(key) { return FRAME_DEFS[normalizeKey(key)] || null; }
  function nameFor(key) { const d = infoFor(key); return d ? d.name : "UNKNOWN"; }

  function utf8(text) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text);
    const out = [];
    const s = unescape(encodeURIComponent(text));
    for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
    return new Uint8Array(out);
  }
  function checkHexLen(bytes, label, expected) {
    if (bytes.length !== expected) throw new Error(`${label} must be exactly ${expected} bytes (got ${bytes.length})`);
    return bytes;
  }

  /* ---------- frame builder definitions ---------- */
  const BUILD_DEFS = {
    "0x01": { label: "PING", fields: [], build: () => new Uint8Array([0x01]) },
    "0x00": {
      label: "PADDING", fields: [{ key: "count", label: "padding bytes", input: "number", def: "8", min: 1, max: 1200 }],
      build: (v) => new Uint8Array(Math.max(1, Math.min(1200, Number(v.count) || 1)))
    },
    "0x02": {
      label: "ACK", fields: [
        { key: "largest", label: "largest acknowledged", input: "varint", def: "0" },
        { key: "delay", label: "ACK delay", input: "varint", def: "0" },
        { key: "first", label: "first ACK range", input: "varint", def: "0" }
      ],
      build: (v) => concat([[0x02], vbytes(v.largest), vbytes(v.delay), vbytes(0), vbytes(v.first)])
    },
    "0x03": {
      label: "ACK + ECN", fields: [
        { key: "largest", label: "largest acknowledged", input: "varint", def: "0" },
        { key: "delay", label: "ACK delay", input: "varint", def: "0" },
        { key: "first", label: "first ACK range", input: "varint", def: "0" },
        { key: "ect0", label: "ECT(0) count", input: "varint", def: "0" },
        { key: "ect1", label: "ECT(1) count", input: "varint", def: "0" },
        { key: "ce", label: "CE count", input: "varint", def: "0" }
      ],
      build: (v) => concat([[0x03], vbytes(v.largest), vbytes(v.delay), vbytes(0), vbytes(v.first), vbytes(v.ect0), vbytes(v.ect1), vbytes(v.ce)])
    },
    "0x04": {
      label: "RESET_STREAM", fields: [
        { key: "stream", label: "stream ID", input: "varint", def: "0" },
        { key: "error", label: "application error", input: "varint", def: "0" },
        { key: "final", label: "final size", input: "varint", def: "0" }
      ],
      build: (v) => concat([[0x04], vbytes(v.stream), vbytes(v.error), vbytes(v.final)])
    },
    "0x05": {
      label: "STOP_SENDING", fields: [
        { key: "stream", label: "stream ID", input: "varint", def: "0" },
        { key: "error", label: "application error", input: "varint", def: "0" }
      ],
      build: (v) => concat([[0x05], vbytes(v.stream), vbytes(v.error)])
    },
    "0x06": {
      label: "CRYPTO", fields: [
        { key: "offset", label: "offset", input: "varint", def: "0" },
        { key: "data", label: "crypto data (hex)", input: "bytes", def: "16 03 03 00 00", span: 2 }
      ],
      build: (v) => { const data = PH.parseHex(v.data); return concat([[0x06], vbytes(v.offset), vbytes(data.length), data]); }
    },
    "0x07": {
      label: "NEW_TOKEN", fields: [
        { key: "token", label: "token (hex)", input: "bytes", def: "de ad be ef", span: 2 }
      ],
      build: (v) => { const token = PH.parseHex(v.token); if (!token.length) throw new Error("token must not be empty"); return concat([[0x07], vbytes(token.length), token]); }
    },
    "0x08": {
      label: "STREAM", fields: [
        { key: "stream", label: "stream ID", input: "varint", def: "0" },
        { key: "offset", label: "offset (if OFF)", input: "varint", def: "0" },
        { key: "data", label: "stream data (hex)", input: "bytes", def: "68 65 6c 6c 6f", span: 2 },
        { key: "off", label: "OFF bit", input: "check", def: true },
        { key: "len", label: "LEN bit", input: "check", def: true },
        { key: "fin", label: "FIN bit", input: "check", def: true }
      ],
      build: (v) => {
        const data = PH.parseHex(v.data);
        const type = 0x08 | (v.off ? 0x04 : 0) | (v.len ? 0x02 : 0) | (v.fin ? 0x01 : 0);
        const parts = [[type], vbytes(v.stream)];
        if (v.off) parts.push(vbytes(v.offset));
        if (v.len) parts.push(vbytes(data.length));
        parts.push(data);
        return concat(parts);
      }
    },
    "0x10": {
      label: "MAX_DATA", fields: [{ key: "max", label: "maximum data", input: "varint", def: "1048576" }],
      build: (v) => concat([[0x10], vbytes(v.max)])
    },
    "0x11": {
      label: "MAX_STREAM_DATA", fields: [
        { key: "stream", label: "stream ID", input: "varint", def: "0" },
        { key: "max", label: "maximum stream data", input: "varint", def: "65536" }
      ],
      build: (v) => concat([[0x11], vbytes(v.stream), vbytes(v.max)])
    },
    "0x12": {
      label: "MAX_STREAMS (bidi)", fields: [{ key: "max", label: "maximum streams", input: "varint", def: "100" }],
      build: (v) => concat([[0x12], vbytes(v.max)])
    },
    "0x13": {
      label: "MAX_STREAMS (uni)", fields: [{ key: "max", label: "maximum streams", input: "varint", def: "100" }],
      build: (v) => concat([[0x13], vbytes(v.max)])
    },
    "0x14": {
      label: "DATA_BLOCKED", fields: [{ key: "max", label: "maximum data", input: "varint", def: "1048576" }],
      build: (v) => concat([[0x14], vbytes(v.max)])
    },
    "0x15": {
      label: "STREAM_DATA_BLOCKED", fields: [
        { key: "stream", label: "stream ID", input: "varint", def: "0" },
        { key: "max", label: "maximum stream data", input: "varint", def: "65536" }
      ],
      build: (v) => concat([[0x15], vbytes(v.stream), vbytes(v.max)])
    },
    "0x18": {
      label: "NEW_CONNECTION_ID", fields: [
        { key: "seq", label: "sequence number", input: "varint", def: "1" },
        { key: "retire", label: "retire prior to", input: "varint", def: "0" },
        { key: "cid", label: "connection ID (hex, 0-20 B)", input: "bytes", def: "01 02 03 04 05 06 07 08", span: 2 },
        { key: "token", label: "stateless reset token (16 B)", input: "bytes", def: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", span: 2 }
      ],
      build: (v) => {
        const cid = PH.parseHex(v.cid); const token = PH.parseHex(v.token);
        if (cid.length > 20) throw new Error("connection ID exceeds 20 bytes");
        checkHexLen(token, "stateless reset token", 16);
        return concat([[0x18], vbytes(v.seq), vbytes(v.retire), [cid.length], cid, token]);
      }
    },
    "0x19": {
      label: "RETIRE_CONNECTION_ID", fields: [{ key: "seq", label: "sequence number", input: "varint", def: "0" }],
      build: (v) => concat([[0x19], vbytes(v.seq)])
    },
    "0x1a": {
      label: "PATH_CHALLENGE", fields: [{ key: "data", label: "challenge data (8 B)", input: "bytes", def: "00 01 02 03 04 05 06 07", span: 2 }],
      build: (v) => concat([[0x1a], checkHexLen(PH.parseHex(v.data), "challenge data", 8)])
    },
    "0x1b": {
      label: "PATH_RESPONSE", fields: [{ key: "data", label: "response data (8 B)", input: "bytes", def: "00 01 02 03 04 05 06 07", span: 2 }],
      build: (v) => concat([[0x1b], checkHexLen(PH.parseHex(v.data), "response data", 8)])
    },
    "0x1c": {
      label: "CONNECTION_CLOSE (transport)", fields: [
        { key: "error", label: "error code", input: "varint", def: "0" },
        { key: "reason", label: "reason phrase", input: "text", def: "closing", span: 2 }
      ],
      build: (v) => { const reason = utf8(v.reason); return concat([[0x1c], vbytes(v.error), vbytes(reason.length), reason]); }
    },
    "0x1d": {
      label: "CONNECTION_CLOSE (application)", fields: [
        { key: "error", label: "error code", input: "varint", def: "0" },
        { key: "frame", label: "frame type that caused close", input: "varint", def: "0" },
        { key: "reason", label: "reason phrase", input: "text", def: "closing", span: 2 }
      ],
      build: (v) => { const reason = utf8(v.reason); return concat([[0x1d], vbytes(v.error), vbytes(v.frame), vbytes(reason.length), reason]); }
    },
    "0x1e": { label: "HANDSHAKE_DONE", fields: [], build: () => new Uint8Array([0x1e]) },
    "0x30": {
      label: "DATAGRAM (implicit length)", fields: [{ key: "data", label: "datagram data (hex)", input: "bytes", def: "68 69", span: 2 }],
      build: (v) => concat([[0x30], PH.parseHex(v.data)])
    },
    "0x31": {
      label: "DATAGRAM (explicit length)", fields: [{ key: "data", label: "datagram data (hex)", input: "bytes", def: "68 69", span: 2 }],
      build: (v) => { const data = PH.parseHex(v.data); return concat([[0x31], vbytes(data.length), data]); }
    }
  };

  function buildFrame(key, values) {
    const def = BUILD_DEFS[key];
    if (!def) throw new Error("No builder for frame " + key);
    return def.build(values || {});
  }

  /* ---------- frame decoder ---------- */
  function shortHex(bytes, max = 80) {
    if (!bytes.length) return "—";
    const s = PH.bytesToHex(bytes.subarray(0, max));
    return bytes.length > max ? s + " … (" + bytes.length + " B)" : s;
  }
  function reasonText(bytes) {
    try {
      if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch (_) { /* noop */ }
    return PH.bytesToAscii(bytes);
  }

  function decodeFrames(bytes) {
    const frames = [];
    const warnings = [];
    let off = 0;

    function readVar(label) {
      const r = varintDecode(bytes, off);
      off += r.size;
      return r;
    }
    function readBytes(n, label) {
      if (off + n > bytes.length) throw new Error(`${label} wants ${n} bytes at offset ${off}, only ${bytes.length - off} remain`);
      const b = bytes.slice(off, off + n);
      off += n;
      return b;
    }
    function readU8(label) {
      if (off >= bytes.length) throw new Error(`${label} is truncated at offset ${off}`);
      return bytes[off++];
    }
    function f(name, value, offset, size) { return { name, value: String(value), offset, size }; }

    while (off < bytes.length) {
      const start = off;
      let typeR;
      try { typeR = readVar("frame type"); }
      catch (err) { warnings.push(err.message + " (frame start " + start + ")"); break; }
      const typeNum = Number(typeR.value);
      if (!Number.isSafeInteger(typeNum)) {
        warnings.push(`Frame type ${typeR.value.toString()} at offset ${start} is too large to be a v1 frame`);
        break;
      }
      const rawKey = "0x" + typeNum.toString(16).padStart(2, "0");
      const key = normalizeKey(rawKey);
      const info = FRAME_DEFS[key];
      if (!info) {
        warnings.push(`Unknown frame type ${rawKey} at offset ${start}; ${bytes.length - start} byte(s) left`);
        frames.push({ type: typeNum, key: rawKey, name: "UNKNOWN", offset: start, length: bytes.length - start, fields: [f("Frame Type", rawKey, start, typeR.size)], unknown: true, raw: bytes.slice(start) });
        off = bytes.length;
        break;
      }

      try {
        const fields = [f("Frame Type", "0x" + typeNum.toString(16).padStart(2, "0"), start, typeR.size)];
        let name = info.name;
        let note = "";
        switch (key) {
          case "0x00": {
            let count = 1;
            while (off < bytes.length && bytes[off] === 0) { off++; count++; }
            fields.push(f("Padding", count - 1 + " byte(s)", start + 1, count - 1));
            note = count === 1 ? "single padding byte" : count + " consecutive zero bytes";
            break;
          }
          case "0x01":
            break;
          case "0x02": {
            if (typeNum === 0x03) name = "ACK (ECN)";
            const largest = readVar("largest acknowledged");
            const delay = readVar("ACK delay");
            const count = readVar("ACK range count");
            const first = readVar("first ACK range");
            fields.push(f("Largest Acknowledged", largest.value.toString(), largest.offset, largest.size));
            fields.push(f("ACK Delay", delay.value.toString(), delay.offset, delay.size));
            fields.push(f("ACK Range Count", count.value.toString(), count.offset, count.size));
            fields.push(f("First ACK Range", first.value.toString(), first.offset, first.size));
            const n = Number(count.value);
            if (!Number.isSafeInteger(n) || n > 100000) throw new Error("ACK range count is unreasonable: " + count.value.toString());
            for (let i = 0; i < n; i++) {
              const gap = readVar("ACK gap");
              const len = readVar("ACK range length");
              fields.push(f(`ACK Range ${i + 1} gap`, gap.value.toString(), gap.offset, gap.size));
              fields.push(f(`ACK Range ${i + 1} length`, len.value.toString(), len.offset, len.size));
            }
            if (typeNum === 0x03) {
              const ect0 = readVar("ECT0 count");
              const ect1 = readVar("ECT1 count");
              const ce = readVar("CE count");
              fields.push(f("ECT0 Count", ect0.value.toString(), ect0.offset, ect0.size));
              fields.push(f("ECT1 Count", ect1.value.toString(), ect1.offset, ect1.size));
              fields.push(f("CE Count", ce.value.toString(), ce.offset, ce.size));
            }
            note = n ? `${n} additional range(s)` : "single range";
            break;
          }
          case "0x04": {
            const stream = readVar("stream ID");
            const error = readVar("application error");
            const final = readVar("final size");
            fields.push(f("Stream ID", stream.value.toString(), stream.offset, stream.size));
            fields.push(f("Application Error Code", error.value.toString(), error.offset, error.size));
            fields.push(f("Final Size", final.value.toString(), final.offset, final.size));
            break;
          }
          case "0x05": {
            const stream = readVar("stream ID");
            const error = readVar("application error");
            fields.push(f("Stream ID", stream.value.toString(), stream.offset, stream.size));
            fields.push(f("Application Error Code", error.value.toString(), error.offset, error.size));
            break;
          }
          case "0x06": {
            const offset = readVar("crypto offset");
            const length = readVar("crypto length");
            if (Number(length.value) > bytes.length - off) throw new Error("CRYPTO length " + length.value.toString() + " exceeds remaining bytes");
            const data = readBytes(Number(length.value), "crypto data");
            fields.push(f("Offset", offset.value.toString(), offset.offset, offset.size));
            fields.push(f("Length", length.value.toString(), length.offset, length.size));
            fields.push(f("Crypto Data", shortHex(data), off - data.length, data.length));
            note = data.length + " crypto byte(s)";
            break;
          }
          case "0x07": {
            const length = readVar("token length");
            const token = readBytes(Number(length.value), "token");
            fields.push(f("Token Length", length.value.toString(), length.offset, length.size));
            fields.push(f("Token", shortHex(token), off - token.length, token.length));
            break;
          }
          case "0x08": {
            const offBit = Boolean(typeNum & 0x04);
            const lenBit = Boolean(typeNum & 0x02);
            const finBit = Boolean(typeNum & 0x01);
            name = "STREAM" + (finBit ? " · FIN" : "");
            const stream = readVar("stream ID");
            fields.push(f("Stream ID", stream.value.toString(), stream.offset, stream.size));
            if (offBit) {
              const offset = readVar("stream offset");
              fields.push(f("Offset", offset.value.toString(), offset.offset, offset.size));
            }
            let data;
            if (lenBit) {
              const length = readVar("stream length");
              if (Number(length.value) > bytes.length - off) throw new Error("STREAM length " + length.value.toString() + " exceeds remaining bytes");
              fields.push(f("Length", length.value.toString(), length.offset, length.size));
              data = readBytes(Number(length.value), "stream data");
            } else {
              data = bytes.slice(off);
              off = bytes.length;
              fields.push(f("Length", "absent · rest of packet", off, 0));
            }
            fields.push(f("Stream Data", shortHex(data), off - data.length, data.length));
            note = [offBit ? "OFF" : "no OFF", lenBit ? "LEN" : "no LEN", finBit ? "FIN" : "no FIN"].join(" · ");
            if (!lenBit) note += " · data extends to packet end";
            break;
          }
          case "0x10":
          case "0x14": {
            const max = readVar("maximum data");
            fields.push(f("Maximum Data", max.value.toString(), max.offset, max.size));
            break;
          }
          case "0x11":
          case "0x15": {
            const stream = readVar("stream ID");
            const max = readVar("maximum stream data");
            fields.push(f("Stream ID", stream.value.toString(), stream.offset, stream.size));
            fields.push(f("Maximum Stream Data", max.value.toString(), max.offset, max.size));
            break;
          }
          case "0x12":
          case "0x16": {
            if (key === "0x12") name = typeNum === 0x13 ? "MAX_STREAMS (uni)" : "MAX_STREAMS (bidi)";
            else name = typeNum === 0x17 ? "STREAMS_BLOCKED (uni)" : "STREAMS_BLOCKED (bidi)";
            const max = readVar("maximum streams");
            fields.push(f("Maximum Streams", max.value.toString(), max.offset, max.size));
            break;
          }
          case "0x18": {
            const seq = readVar("sequence number");
            const retire = readVar("retire prior to");
            const len = readU8("connection ID length");
            if (len > 20) throw new Error("connection ID length " + len + " exceeds 20");
            const cid = readBytes(len, "connection ID");
            const token = readBytes(16, "stateless reset token");
            fields.push(f("Sequence Number", seq.value.toString(), seq.offset, seq.size));
            fields.push(f("Retire Prior To", retire.value.toString(), retire.offset, retire.size));
            fields.push(f("Connection ID Length", len, off - cid.length - token.length - 1, 1));
            fields.push(f("Connection ID", shortHex(cid), off - token.length - cid.length, cid.length));
            fields.push(f("Stateless Reset Token", shortHex(token), off - token.length, token.length));
            break;
          }
          case "0x19": {
            const seq = readVar("sequence number");
            fields.push(f("Sequence Number", seq.value.toString(), seq.offset, seq.size));
            break;
          }
          case "0x1a":
          case "0x1b": {
            const data = readBytes(8, "path data");
            fields.push(f("Data", shortHex(data), off - 8, 8));
            break;
          }
          case "0x1c": {
            const error = readVar("error code");
            let frameType = null;
            if (typeNum === 0x1d) frameType = readVar("frame type");
            const reasonLen = readVar("reason length");
            if (Number(reasonLen.value) > bytes.length - off) throw new Error("reason length exceeds remaining bytes");
            const reason = readBytes(Number(reasonLen.value), "reason phrase");
            fields.push(f("Error Code", error.value.toString(), error.offset, error.size));
            if (frameType) fields.push(f("Frame Type", frameType.value.toString(), frameType.offset, frameType.size));
            fields.push(f("Reason Phrase Length", reasonLen.value.toString(), reasonLen.offset, reasonLen.size));
            fields.push(f("Reason Phrase", reason.length ? reasonText(reason) : "(empty)", off - reason.length, reason.length));
            note = typeNum === 0x1d ? "application close" : "transport close";
            break;
          }
          case "0x1e":
            break;
          case "0x30": {
            let length = null;
            if (typeNum === 0x31) {
              length = readVar("datagram length");
              fields.push(f("Length", length.value.toString(), length.offset, length.size));
            }
            const data = length ? readBytes(Number(length.value), "datagram data") : bytes.slice(off);
            if (!length) off = bytes.length;
            fields.push(f("Data", shortHex(data), off - data.length, data.length));
            note = length ? "explicit length" : "implicit length · rest of packet";
            break;
          }
          default:
            throw new Error("Unhandled frame");
        }
        frames.push({ type: typeNum, key: rawKey, name, offset: start, length: off - start, fields, note, info });
      } catch (err) {
        warnings.push(`Frame ${rawKey} at offset ${start}: ${err.message}`);
        off = bytes.length;
        break;
      }
    }
    return { frames, warnings, total: bytes.length, consumed: off };
  }

  window.QUIC = {
    varintEncode, varintDecode, buildFrame, decodeFrames, frameInfo: infoFor,
    frameName: nameFor, FRAME_DEFS, BUILD_DEFS, normalizeKey
  };

  /* ---------- header layouts ---------- */
  function hf(name, bytes, desc, extra) {
    return Object.assign({ name, bytes, desc }, extra || {});
  }
  const LONG_FIRST = [
    { id: "lform", name: "Header Form", bits: 1, value: "1", range: "1", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2", desc: "Set to 1 for a long header. The bit is not protected, so it is visible on the wire." },
    { id: "lfixed", name: "Fixed Bit", bits: 1, value: "1", range: "1", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2", desc: "Must be 1 in QUIC v1. It exists to distinguish QUIC from other UDP traffic. A zero here is a protocol violation (except in negotiated extensions)." },
    { id: "ltype", name: "Long Packet Type", bits: 2, value: "00", range: "00/01/10/11", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2", desc: "00 Initial, 01 0-RTT, 10 Handshake, 11 Retry. The field is protected by header protection in Initial, 0-RTT and Handshake packets." },
    { id: "lts", name: "Type-Specific", bits: 4, value: "protected", range: "protected", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2", desc: "Four bits whose meaning depends on the packet type. They are protected by header protection. Do not trust them until protection is removed." }
  ];
  const SHORT_FIRST = [
    { id: "sform", name: "Header Form", bits: 1, value: "0", range: "0", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3", desc: "Set to 0 for a short header." },
    { id: "sfixed", name: "Fixed Bit", bits: 1, value: "1", range: "1", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3", desc: "Must be 1. Like the long-header fixed bit, it helps distinguish QUIC from other UDP payloads." },
    { id: "sspin", name: "Spin Bit", bits: 1, value: "0", range: "0/1", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3", desc: "Optional latency spin bit. It is not used for protocol correctness and can be disabled; it may leak RTT information." },
    { id: "sreserved", name: "Reserved Bits", bits: 2, value: "00", range: "00", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3", desc: "Reserved for future use. Receivers must treat a non-zero value as a connection error after removing header protection." },
    { id: "sphase", name: "Key Phase", bits: 1, value: "0", range: "0/1", rfc: "RFC 9001 §6", rfcUrl: "https://www.rfc-editor.org/rfc/rfc9001#section-6", desc: "Key phase bit for key updates. It flips when the sender updates its 1-RTT keys." },
    { id: "spnlen", name: "Packet Number Length", bits: 2, value: "00", range: "00–11", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3", desc: "Encoded as length minus one: 00 = 1 byte, 01 = 2, 10 = 3, 11 = 4. The packet number is not a varint." }
  ];

  const VERSION = hf("Version", 4, "QUIC version. 0x00000001 is QUIC v1; 0x00000000 is Version Negotiation. Version negotiation is not authenticated.", { range: "0x00000001 / 0x6b3343cf", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const DCID_LEN = hf("DCID Length", 1, "Destination Connection ID length in bytes, 0–20. A zero-length DCID is legal before a connection is established.", { range: "0–20", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const DCID = hf("DCID", "var", "Destination Connection ID. The receiver uses it to find the connection; it is visible even when the rest of the packet is protected.", { variable: true, range: "0–20 B", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const SCID_LEN = hf("SCID Length", 1, "Source Connection ID length, 0–20 bytes.", { range: "0–20", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const SCID = hf("SCID", "var", "Source Connection ID chosen by the sender. It becomes the destination CID in packets sent back.", { variable: true, range: "0–20 B", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const TOKEN_LEN = hf("Token Length", "var", "Length of the address validation token. Present only in Initial packets; it is a varint.", { variable: true, range: "0 to 2^62-1", rfc: "RFC 9000 §17.2.2", rfcUrl: QUIC_RFC + "#section-17.2.2" });
  const TOKEN = hf("Token", "var", "Opaque address validation token from a Retry or NEW_TOKEN. Its contents are not interpreted by QUIC.", { variable: true, range: "Token Length B", rfc: "RFC 9000 §17.2.2", rfcUrl: QUIC_RFC + "#section-17.2.2" });
  const LENGTH = hf("Length", "var", "Length of the packet number plus payload, in bytes, as a varint. It excludes the header and connection IDs. Retry and Version Negotiation do not have this field.", { variable: true, range: "0 to 2^62-1", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const PN = hf("Packet Number", "var", "Packet number, 1–4 bytes as selected by the packet-number-length bits. The number is reconstructed from the largest acknowledged value; it is not a varint and not a frame field.", { variable: true, range: "1–4 B", rfc: "RFC 9000 §17.1", rfcUrl: QUIC_RFC + "#section-17.1" });
  const PAYLOAD = hf("Payload", "var", "Protected frames. After header protection and AEAD removal, this is a sequence of frames. On the wire it is indistinguishable from random bytes.", { variable: true, range: "Length − PN bytes", rfc: "RFC 9000 §17.2", rfcUrl: QUIC_RFC + "#section-17.2" });
  const RETRY_TOKEN = hf("Retry Token", "var", "Opaque token the server wants echoed in the client's next Initial. It extends to the Retry Integrity Tag.", { variable: true, range: "rest after SCID", rfc: "RFC 9000 §17.2.5", rfcUrl: QUIC_RFC + "#section-17.2.5" });
  const RETRY_TAG = hf("Retry Integrity Tag", 16, "16-byte authentication tag over the Retry pseudo-packet. Retry has no packet number and no payload.", { range: "16 B", rfc: "RFC 9001 §5.8", rfcUrl: "https://www.rfc-editor.org/rfc/rfc9001#section-5.8" });
  const SHORT_DCID = hf("DCID", "var", "Destination Connection ID. A short header has no length field; its length is configured by the connection, 0–20 bytes.", { variable: true, range: "0–20 B", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3" });
  const SHORT_PN = hf("Packet Number", "var", "Protected packet number. Header protection masks the field; the length comes from the first byte (1–4 bytes).", { variable: true, range: "1–4 B", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3" });
  const SHORT_PAYLOAD = hf("Payload", "var", "AEAD-protected frames. The packet number is an input to the nonce and is not repeated in the payload.", { variable: true, range: "rest of datagram", rfc: "RFC 9000 §17.3", rfcUrl: QUIC_RFC + "#section-17.3" });

  function longFields(withToken) {
    const out = [VERSION, DCID_LEN, DCID, SCID_LEN, SCID];
    if (withToken) out.push(TOKEN_LEN, TOKEN);
    out.push(LENGTH, PN, PAYLOAD);
    return out;
  }

  let frameLane = null;

  /* ---------- DOM ---------- */
  function initHeaders() {
    PH.diagram("#quic-long-first", {
      title: "<b>Long header</b> · first byte", badge: "RFC 9000 §17.2", bitsPerRow: 8,
      fields: LONG_FIRST, inspector: "#quic-header-inspector",
      note: "The lower four bits and the packet type are protected by header protection. This diagram shows the unprotected values."
    });
    PH.diagram("#quic-short-first", {
      title: "<b>Short header</b> · first byte", badge: "RFC 9000 §17.3", bitsPerRow: 8,
      fields: SHORT_FIRST, inspector: "#quic-header-inspector",
      note: "Spin, reserved, key phase and packet-number length are protected on the wire. Reserved bits must be zero after unprotection."
    });
    PH.byteLane("#quic-long-lane", {
      title: "<b>Initial</b> · long header", badge: "type 00", startByte: 1, fields: longFields(true),
      inspector: "#quic-structure-inspector",
      note: "The token fields exist only in Initial packets. Length covers the packet number and payload but not the header itself."
    });
    PH.byteLane("#quic-0rtt-lane", {
      title: "<b>0-RTT</b> · long header", badge: "type 01", startByte: 1, fields: longFields(false),
      inspector: "#quic-structure-inspector",
      note: "0-RTT has no token. It is replayed data and must only carry application data permitted by the session ticket."
    });
    PH.byteLane("#quic-handshake-lane", {
      title: "<b>Handshake</b> · long header", badge: "type 10", startByte: 1, fields: longFields(false),
      inspector: "#quic-structure-inspector",
      note: "The handshake packet carries TLS handshake frames. It has no token and is protected at the handshake encryption level."
    });
    PH.byteLane("#quic-retry-lane", {
      title: "<b>Retry</b> · long header", badge: "type 11", startByte: 1,
      fields: [VERSION, DCID_LEN, DCID, SCID_LEN, SCID, RETRY_TOKEN, RETRY_TAG],
      inspector: "#quic-structure-inspector",
      note: "Retry has no Length, packet number, or payload. The 16-byte integrity tag authenticates the server's Retry."
    });
    PH.byteLane("#quic-short-lane", {
      title: "<b>Short header</b> · 1-RTT", badge: "RFC 9000 §17.3", startByte: 1,
      fields: [SHORT_DCID, SHORT_PN, SHORT_PAYLOAD],
      inspector: "#quic-structure-inspector",
      note: "The destination CID length is not on the wire; endpoints agree on it. The packet number and payload follow immediately."
    });
  }

  function initVarint() {
    PH.diagram("#quic-varint-first", {
      title: "<b>Varint</b> · first byte", badge: "RFC 9000 §16", bitsPerRow: 8,
      fields: [
        { id: "vprefix", name: "Prefix", bits: 2, value: "01", range: "00/01/10/11", rfc: "RFC 9000 §16", rfcUrl: QUIC_RFC + "#section-16", desc: "Length selector: 00 = 1 byte, 01 = 2, 10 = 4, 11 = 8. The length includes the first byte." },
        { id: "vvalue", name: "Value bits", bits: 6, value: "…", range: "6/14/30/62 total", rfc: "RFC 9000 §16", rfcUrl: QUIC_RFC + "#section-16", desc: "For a 2-byte varint this is the high 6 bits of a 14-bit value. For 4 and 8 bytes, the remaining bits continue in subsequent bytes." }
      ],
      note: "The diagram shows the 1-byte form. The prefix determines whether 0, 1, 3 or 7 more bytes follow. The value is big-endian."
    });

    const input = document.getElementById("quic-varint-input");
    const status = document.getElementById("quic-varint-status");
    const out = document.getElementById("quic-varint-out");
    if (!input) return;
    document.getElementById("quic-varint-encode").addEventListener("click", () => {
      try {
        const raw = input.value.trim();
        const v = toBigInt(raw);
        const bytes = varintEncode(v);
        out.textContent = PH.bytesToHex(bytes) + "\n" + bytes.length + " byte(s), prefix " + ["00", "01", "10", "11"][bytes[0] >> 6] + ", value " + v.toString();
        PH.setStatus(status, "encoded " + v.toString() + " into " + bytes.length + " byte(s)", "ok");
      } catch (err) {
        PH.setStatus(status, "encode error: " + err.message, "bad");
        out.textContent = "no result";
      }
    });
    document.getElementById("quic-varint-decode").addEventListener("click", () => {
      try {
        const bytes = PH.parseHex(input.value);
        const r = varintDecode(bytes, 0);
        const left = bytes.length - r.size;
        out.textContent = "value " + r.value.toString() + "\n" + r.size + " byte(s), prefix " + ["00", "01", "10", "11"][r.prefix] + (r.value > 0xffffffffn ? "\nhex 0x" + r.value.toString(16) : "") + (left ? "\n" + left + " trailing byte(s)" : "");
        PH.setStatus(status, "decoded " + r.size + "-byte varint" + (left ? " · " + left + " trailing byte(s)" : ""), left ? "warn" : "ok");
      } catch (err) {
        PH.setStatus(status, "decode error: " + err.message, "bad");
        out.textContent = "no result";
      }
    });
  }

  function initFrameExplorer() {
    const select = document.getElementById("quic-frame-select");
    if (!select) return;
    const extras = [
      ["0x03", "ACK + ECN"],
      ["0x13", "MAX_STREAMS (uni)"],
      ["0x17", "STREAMS_BLOCKED (uni)"],
      ["0x1d", "CONNECTION_CLOSE (app)"],
      ["0x31", "DATAGRAM (length)"]
    ];
    const keys = FRAME_KEYS.concat(extras.map(([k]) => k))
      .filter((k, i, arr) => arr.indexOf(k) === i)
      .sort((a, b) => parseInt(a.slice(2), 16) - parseInt(b.slice(2), 16));
    select.innerHTML = keys.map((k) => {
      const extra = extras.find(([x]) => x === k);
      const info = FRAME_DEFS[k] || infoFor(k);
      return `<option value="${k}">${k} · ${extra ? extra[1] : (info ? info.name : "frame")}</option>`;
    }).join("");
    select.value = "0x08";

    function render() {
      const key = select.value;
      const info = infoFor(key) || FRAME_DEFS["0x08"];
      const sectionLabel = String(info.section).startsWith("RFC") ? info.section : "RFC 9000 §" + info.section;
      const badge = document.getElementById("quic-frame-badge");
      if (badge) badge.textContent = sectionLabel;
      frameLane = PH.byteLane("#quic-frame-lane", {
        title: "<b>" + PH.esc(info.name) + "</b> · frame", badge: sectionLabel,
        fields: info.fields,
        inspector: "#quic-frame-inspector",
        note: info.name === "STREAM"
          ? "Optional fields are present only when the corresponding bit is set in the frame type. Without LEN, stream data consumes the rest of the packet."
          : "Frame types and most lengths are varints. Fields drawn at a nominal width may be shorter or longer on the wire."
      });
    }
    select.addEventListener("change", render);
    render();

    // Make exact-type rows in the reference table clickable.
    document.querySelectorAll("#frames table.data-table tbody tr").forEach((tr) => {
      const code = tr.querySelector("td code");
      if (!code) return;
      const key = code.textContent.trim();
      if (!FRAME_DEFS[key]) return;
      tr.style.cursor = "pointer";
      tr.title = "Inspect " + FRAME_DEFS[key].name;
      tr.addEventListener("click", () => {
        select.value = key;
        render();
        select.scrollIntoView({ block: "center", behavior: "smooth" });
      });
    });
  }

  function initStreamType() {
    PH.diagram("#quic-stream-type", {
      title: "<b>STREAM</b> · frame type octet", badge: "0x08–0x0f", bitsPerRow: 8,
      fields: [
        { name: "STREAM base", bits: 5, value: "01000", range: "0x08", rfc: "RFC 9000 §19.8", rfcUrl: QUIC_RFC + "#section-19.8", desc: "The base value 0x08 identifies a STREAM frame. The high three bits remain zero in the one-byte varint form." },
        { name: "OFF", bits: 1, value: "0x04", range: "0/1", rfc: "RFC 9000 §19.8", rfcUrl: QUIC_RFC + "#section-19.8", desc: "When set, an Offset field follows the Stream ID." },
        { name: "LEN", bits: 1, value: "0x02", range: "0/1", rfc: "RFC 9000 §19.8", rfcUrl: QUIC_RFC + "#section-19.8", desc: "When set, a Length field precedes the stream data. When clear, data runs to the end of the packet." },
        { name: "FIN", bits: 1, value: "0x01", range: "0/1", rfc: "RFC 9000 §19.8", rfcUrl: QUIC_RFC + "#section-19.8", desc: "Marks the final byte of the stream. FIN is independent of the LEN bit." }
      ],
      note: "The three low bits are independent. 0x0f means OFF+LEN+FIN; 0x08 means none of them. The frame type itself is a varint, but every v1 STREAM variant fits in one byte."
    });
  }

  function builderFieldId(key, fieldKey) { return "qb-" + key.replace(/^0x/, "") + "-" + fieldKey; }

  function renderBuilderFields(key) {
    const host = document.getElementById("quic-build-fields");
    const def = BUILD_DEFS[key];
    if (!host || !def) return;
    host.innerHTML = def.fields.map((f) => {
      const id = builderFieldId(key, f.key);
      const span = f.span ? " span-2" : "";
      if (f.input === "check") {
        return `<div class="inline-checks${span}"><label><input type="checkbox" id="${id}" ${f.def ? "checked" : ""}> ${PH.esc(f.label)}</label></div>`;
      }
      const inputType = f.input === "number" ? "number" : "text";
      const cls = f.input === "bytes" ? "hex-input" : "";
      const extra = f.input === "number" ? ` min="${f.min}" max="${f.max}"` : "";
      return `<div class="form-field${span}"><label for="${id}">${PH.esc(f.label)}</label>` +
        `<input type="${inputType}" id="${id}" class="${cls}" value="${PH.esc(f.def)}"${extra} spellcheck="false" autocomplete="off"></div>`;
    }).join("");
  }

  function readBuilderValues(key) {
    const def = BUILD_DEFS[key];
    const values = {};
    def.fields.forEach((f) => {
      const el = document.getElementById(builderFieldId(key, f.key));
      if (!el) { values[f.key] = f.def; return; }
      values[f.key] = f.input === "check" ? el.checked : el.value;
    });
    return values;
  }

  function buildFrameFromForm(showErrors = true) {
    const select = document.getElementById("quic-build-type");
    const status = document.getElementById("quic-build-status");
    const out = document.getElementById("quic-build-out");
    const summary = document.getElementById("quic-build-summary");
    const tag = document.getElementById("quic-build-tag");
    if (!select) return null;
    const key = select.value;
    let bytes;
    try {
      bytes = BUILD_DEFS[key].build(readBuilderValues(key));
    } catch (err) {
      if (showErrors) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    out.textContent = PH.bytesToHex(bytes);
    out.classList.remove("placeholder");
    tag.textContent = bytes.length + " bytes";
    summary.innerHTML = [
      `<span class="pill">type <b>${PH.esc(key)}</b></span>`,
      `<span class="pill">frame <b>${PH.esc(BUILD_DEFS[key].label)}</b></span>`,
      `<span class="pill">length <b>${bytes.length} B</b></span>`,
      `<span class="pill">varints <b>big-endian</b></span>`
    ].join("");
    PH.setStatus(status, "built " + BUILD_DEFS[key].label + " · " + bytes.length + " byte(s)", "ok");
    return bytes;
  }

  function initBuilder() {
    const select = document.getElementById("quic-build-type");
    if (!select) return;
    const keys = Object.keys(BUILD_DEFS);
    select.innerHTML = keys.map((k) => `<option value="${k}">${k} · ${BUILD_DEFS[k].label}</option>`).join("");
    select.value = "0x08";
    renderBuilderFields(select.value);
    select.addEventListener("change", () => renderBuilderFields(select.value));
    document.getElementById("quic-build").addEventListener("click", () => buildFrameFromForm());
    document.getElementById("quic-build-example").addEventListener("click", () => {
      select.value = "0x08";
      renderBuilderFields("0x08");
      const set = (id, value) => { const el = document.getElementById(id); if (el) el.value = value; };
      set(builderFieldId("0x08", "stream"), "4");
      set(builderFieldId("0x08", "offset"), "0");
      set(builderFieldId("0x08", "data"), "68 65 6c 6c 6f");
      const off = document.getElementById(builderFieldId("0x08", "off"));
      const len = document.getElementById(builderFieldId("0x08", "len"));
      const fin = document.getElementById(builderFieldId("0x08", "fin"));
      if (off) off.checked = true;
      if (len) len.checked = true;
      if (fin) fin.checked = true;
      buildFrameFromForm();
    });
    buildFrameFromForm(false);
  }

  function renderFrames(result, bytes) {
    const host = document.getElementById("quic-decode-result");
    if (!result) { host.innerHTML = ""; return; }
    const pills = [
      `<span class="pill">frames <b>${result.frames.length}</b></span>`,
      `<span class="pill">bytes <b>${result.total}</b></span>`,
      `<span class="pill">consumed <b>${result.consumed}/${result.total}</b></span>`,
      `<span class="pill">${result.warnings.length ? '<span class="warn-text">' + result.warnings.length + " note(s)</span>" : '<span class="good-text">clean walk</span>'}</span>`
    ];
    const cards = result.frames.map((fr) => {
      const fields = fr.fields.map((f) =>
        `<tr><td><b>${PH.esc(f.name)}</b></td><td><code>${PH.esc(f.value)}</code></td><td class="num">${f.offset}</td><td class="num">${f.size}</td></tr>`
      ).join("");
      return `<div class="frame-card${fr.unknown ? " frame-card--bad" : ""}">` +
        `<div class="frame-card__head"><div><span class="frame-card__type">${PH.esc(fr.name)}</span> <code>${PH.esc(fr.key)}</code></div>` +
        `<div class="dim">${fr.length} B · offset ${fr.offset}</div></div>` +
        (fr.note ? `<p class="frame-card__note">${PH.esc(fr.note)}</p>` : "") +
        `<div class="table-wrap" style="margin:0"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th class="num">Offset</th><th class="num">Size</th></tr></thead><tbody>${fields}</tbody></table></div>` +
        `</div>`;
    }).join("");
    const warningHtml = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : "";
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>frame bytes</span><span>${bytes.length} B</span></div>${PH.hexdump(bytes)}</div>` +
      `<div class="frame-list">${cards || '<p class="dim">No frames.</p>'}</div>` +
      warningHtml;
  }

  function initDecoder() {
    const input = document.getElementById("quic-decode-input");
    const status = document.getElementById("quic-decode-status");
    const host = document.getElementById("quic-decode-result");
    if (!input) return;

    function run(showErrors = true) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      const result = decodeFrames(bytes);
      renderFrames(result, bytes);
      PH.setStatus(status,
        `walked ${result.frames.length} frame(s) · ${result.consumed}/${result.total} bytes${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
        result.warnings.length ? "warn" : "ok");
    }

    document.getElementById("quic-decode").addEventListener("click", () => run());
    document.getElementById("quic-decode-example").addEventListener("click", () => {
      const frames = [
        buildFrame("0x01", {}),
        buildFrame("0x02", { largest: "3", delay: "0", first: "1" }),
        buildFrame("0x06", { offset: "0", data: "16 03 03 00 05 01 00 00 00 00" }),
        buildFrame("0x08", { stream: "4", offset: "0", off: true, len: true, fin: true, data: "68 65 6c 6c 6f" }),
        buildFrame("0x00", { count: "6" })
      ];
      input.value = PH.bytesToHex(PH.concatBytes.apply(null, frames));
      run();
    });
    document.getElementById("quic-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No frames decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
  }

  function init() {
    if (!document.getElementById("quic-long-first")) return;
    initHeaders();
    initVarint();
    initFrameExplorer();
    initStreamType();
    initBuilder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
