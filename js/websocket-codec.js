/* WebSocket (RFC 6455) frame and opening-handshake codec.
   Frame parsing is direction-agnostic; masking is reported, not enforced,
   because the same codec is used for both client and server bytes. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const OPCODES = {
    0x0: "Continuation", 0x1: "Text", 0x2: "Binary", 0x8: "Close",
    0x9: "Ping", 0xA: "Pong"
  };
  const CLOSE_CODES = {
    1000: "normal closure", 1001: "going away", 1002: "protocol error",
    1003: "unsupported data", 1005: "no status received", 1006: "abnormal closure",
    1007: "invalid frame payload data", 1008: "policy violation", 1009: "message too big",
    1010: "mandatory extension", 1011: "internal server error", 1012: "service restart",
    1013: "try again later", 1014: "bad gateway", 1015: "TLS handshake failure"
  };
  const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  function opcodeName(opcode) { return OPCODES[opcode] || "Reserved 0x" + opcode.toString(16); }

  function rotl(value, bits) { return ((value << bits) | (value >>> (32 - bits))) >>> 0; }

  function sha1(bytes) {
    const input = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    const bitLength = input.length * 8;
    const total = ((input.length + 9 + 63) & ~63);
    const padded = new Uint8Array(total);
    padded.set(input, 0);
    padded[input.length] = 0x80;
    PH.put32be(padded, total - 8, Math.floor(bitLength / 0x100000000));
    PH.put32be(padded, total - 4, bitLength >>> 0);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const w = new Uint32Array(80);
    for (let block = 0; block < total; block += 64) {
      for (let i = 0; i < 16; i++) w[i] = PH.u32be(padded, block + i * 4);
      for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        const temp = (rotl(a, 5) + (f >>> 0) + e + k + w[i]) >>> 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = temp;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }
    const out = new Uint8Array(20);
    [h0, h1, h2, h3, h4].forEach((h, i) => PH.put32be(out, i * 4, h));
    return out;
  }

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function base64(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i];
      const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      const n = (a << 16) | (b << 8) | c;
      out += B64[(n >>> 18) & 63] + B64[(n >>> 12) & 63];
      out += i + 1 < bytes.length ? B64[(n >>> 6) & 63] : "=";
      out += i + 2 < bytes.length ? B64[n & 63] : "=";
    }
    return out;
  }

  function secWebSocketAccept(key) {
    const text = String(key == null ? "" : key).trim();
    if (!text) throw new Error("Sec-WebSocket-Key is empty");
    return base64(sha1(new TextEncoder().encode(text + GUID)));
  }

  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (Array.isArray(value)) return Uint8Array.from(value);
    if (value == null || String(value).trim() === "") return new Uint8Array(0);
    return PH.parseHex(value);
  }

  function payloadBytes(input) {
    if (input == null) return new Uint8Array(0);
    if (input.payload != null) return toBytes(input.payload);
    if (input.text != null) return new TextEncoder().encode(String(input.text));
    return new Uint8Array(0);
  }

  function applyMask(bytes, key) {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % 4];
    return out;
  }

  function buildFrame(input) {
    const opcode = Number(input.opcode == null ? 1 : input.opcode);
    if (!(opcode in OPCODES)) throw new Error("Opcode must be 0x0, 0x1, 0x2, 0x8, 0x9 or 0xA");
    const control = opcode >= 0x8;
    const fin = input.fin !== false;
    if (control && !fin) throw new Error("Control frames must not be fragmented");
    const payload = payloadBytes(input);
    if (control && payload.length > 125) throw new Error("Control frame payload must be 125 bytes or fewer");
    const useMask = !!input.mask;
    const maskKey = input.maskKey instanceof Uint8Array ? input.maskKey : (toBytes(input.maskKey).length === 4 ? toBytes(input.maskKey) : Uint8Array.from([0x37, 0xfa, 0x21, 0x3d]));
    if (useMask && maskKey.length !== 4) throw new Error("Masking key must be 4 bytes");
    let header = 2;
    let lengthBytes = 0;
    if (payload.length >= 126 && payload.length <= 0xffff) lengthBytes = 2;
    else if (payload.length > 0xffff) lengthBytes = 8;
    const bytes = new Uint8Array(header + lengthBytes + (useMask ? 4 : 0) + payload.length);
    bytes[0] = (fin ? 0x80 : 0) | (input.rsv1 ? 0x40 : 0) | (input.rsv2 ? 0x20 : 0) | (input.rsv3 ? 0x10 : 0) | opcode;
    let pos = 2;
    const maskBit = useMask ? 0x80 : 0;
    if (lengthBytes === 0) bytes[1] = maskBit | payload.length;
    else if (lengthBytes === 2) {
      bytes[1] = maskBit | 126;
      PH.put16be(bytes, pos, payload.length); pos += 2;
    } else {
      bytes[1] = maskBit | 127;
      PH.put32be(bytes, pos, Math.floor(payload.length / 0x100000000)); pos += 4;
      PH.put32be(bytes, pos, payload.length >>> 0); pos += 4;
    }
    if (useMask) { bytes.set(maskKey, pos); pos += 4; }
    const body = useMask ? applyMask(payload, maskKey) : payload;
    bytes.set(body, pos);
    return {
      bytes, opcode, opcodeName: opcodeName(opcode), fin, mask: useMask, maskKey: useMask ? maskKey : null,
      payload, payloadLength: payload.length, headerLength: pos
    };
  }

  function decodeText(bytes) {
    try {
      if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (_) { /* fall through */ }
    return PH.bytesToAscii(bytes);
  }

  function decodeFrames(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const options = opts || {};
    const frames = [];
    const warnings = [];
    let pos = 0;
    while (pos + 2 <= bytes.length) {
      const b0 = bytes[pos];
      const b1 = bytes[pos + 1];
      const fin = !!(b0 & 0x80);
      const rsv1 = !!(b0 & 0x40);
      const rsv2 = !!(b0 & 0x20);
      const rsv3 = !!(b0 & 0x10);
      const opcode = b0 & 0x0f;
      const mask = !!(b1 & 0x80);
      let length = b1 & 0x7f;
      let cursor = pos + 2;
      if (length === 126) {
        if (cursor + 2 > bytes.length) { warnings.push("Frame at +" + pos + " has a truncated 16-bit length"); break; }
        length = PH.u16be(bytes, cursor); cursor += 2;
      } else if (length === 127) {
        if (cursor + 8 > bytes.length) { warnings.push("Frame at +" + pos + " has a truncated 64-bit length"); break; }
        const high = PH.u32be(bytes, cursor);
        const low = PH.u32be(bytes, cursor + 4);
        if (high > 0x1fffff) { warnings.push("Frame at +" + pos + " is larger than JavaScript can represent safely"); break; }
        length = high * 0x100000000 + low; cursor += 8;
      }
      let maskKey = null;
      if (mask) {
        if (cursor + 4 > bytes.length) { warnings.push("Frame at +" + pos + " has a truncated masking key"); break; }
        maskKey = bytes.subarray(cursor, cursor + 4); cursor += 4;
      }
      if (cursor + length > bytes.length) {
        warnings.push("Frame at +" + pos + " declares " + length + " B but only " + (bytes.length - cursor) + " B remain");
        break;
      }
      let payload = bytes.subarray(cursor, cursor + length);
      if (mask) payload = applyMask(payload, maskKey);
      const frame = {
        offset: pos, fin, rsv1, rsv2, rsv3, opcode, opcodeName: opcodeName(opcode),
        mask, maskKey: maskKey ? PH.bytesToHex(maskKey) : null, payload, payloadLength: length,
        headerLength: cursor - pos, warnings: []
      };
      if (rsv1 || rsv2 || rsv3) frame.warnings.push("RSV bit set without a negotiated extension");
      if (opcode >= 0x8) {
        if (!fin) frame.warnings.push("Control frame is fragmented");
        if (length > 125) frame.warnings.push("Control frame payload exceeds 125 bytes");
      }
      if (opcode === 0x1) {
        frame.text = decodeText(payload);
        if (frame.text.indexOf("\ufffd") !== -1 && payload.length) frame.warnings.push("Text payload is not valid UTF-8");
      } else if (opcode === 0x8) {
        if (length === 0) frame.close = { code: null, reason: "" };
        else if (length === 1) frame.warnings.push("Close frame has a 1-byte payload; a status code needs two bytes");
        else {
          const code = PH.u16be(payload, 0);
          frame.close = { code, reason: decodeText(payload.subarray(2)), name: CLOSE_CODES[code] || "code " + code };
          if (code < 1000 || code === 1004 || code === 1005 || code === 1006 || (code > 1015 && code < 3000)) {
            frame.warnings.push("Close status " + code + " is not a valid wire code");
          }
        }
      } else if (opcode === 0x2) {
        frame.binary = true;
      } else if (opcode === 0x0) {
        frame.continuation = true;
      }
      warnings.push.apply(warnings, frame.warnings);
      frames.push(frame);
      pos = cursor + length;
    }
    if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the last frame");
    return { bytes, frames, warnings, length: bytes.length };
  }

  function parseHandshake(text) {
    const raw = String(text == null ? "" : text).replace(/\r\n/g, "\n");
    const lines = raw.split("\n");
    const start = (lines.shift() || "").trim();
    const headers = {};
    const order = [];
    lines.forEach((line) => {
      if (!line.trim()) return;
      const colon = line.indexOf(":");
      if (colon < 1) return;
      const name = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (!headers[name]) { headers[name] = []; order.push(name); }
      headers[name].push(value);
    });
    const first = (name) => (headers[name] && headers[name][0]) || "";
    const out = { raw, start, headers, order, warnings: [] };
    let match;
    if ((match = /^GET\s+(\S+)\s+HTTP\/1\.1$/i.exec(start))) {
      out.kind = "request";
      out.method = "GET";
      out.path = match[1];
      const key = first("sec-websocket-key");
      if (!key) out.warnings.push("Request is missing Sec-WebSocket-Key");
      else {
        try { out.accept = secWebSocketAccept(key); }
        catch (err) { out.warnings.push(err.message); }
      }
      if (first("upgrade").toLowerCase() !== "websocket") out.warnings.push("Upgrade header is not 'websocket'");
      const connection = first("connection").toLowerCase();
      if (!connection.split(/\s*,\s*/).includes("upgrade")) out.warnings.push("Connection header does not include 'Upgrade'");
      if (first("sec-websocket-version") !== "13") out.warnings.push("Sec-WebSocket-Version is not 13");
      out.protocol = first("sec-websocket-protocol") || null;
    } else if ((match = /^HTTP\/1\.1\s+(\d{3})(?:\s+(.*))?$/i.exec(start))) {
      out.kind = "response";
      out.status = Number(match[1]);
      out.reason = match[2] || "";
      if (out.status !== 101) out.warnings.push("A WebSocket upgrade response should use status 101");
      if (first("upgrade").toLowerCase() !== "websocket") out.warnings.push("Response Upgrade header is not 'websocket'");
      out.accept = first("sec-websocket-accept") || null;
      out.protocol = first("sec-websocket-protocol") || null;
      out.extensions = first("sec-websocket-extensions") || null;
    } else {
      out.kind = "unknown";
      out.warnings.push("Start line is not a WebSocket HTTP/1.1 request or response");
    }
    return out;
  }

  function buildHandshake(input) {
    const key = input.key || "dGhlIHNhbXBsZSBub25jZQ==";
    const host = input.host || "example.com";
    const path = input.path || "/chat";
    const lines = [
      "GET " + path + " HTTP/1.1",
      "Host: " + host,
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Key: " + key,
      "Sec-WebSocket-Version: 13"
    ];
    if (input.protocol) lines.push("Sec-WebSocket-Protocol: " + input.protocol);
    lines.push("", "");
    return { text: lines.join("\r\n"), key, accept: secWebSocketAccept(key) };
  }

  function buildResponse(input) {
    const key = input.key || "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = secWebSocketAccept(key);
    const lines = [
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Accept: " + accept
    ];
    if (input.protocol) lines.push("Sec-WebSocket-Protocol: " + input.protocol);
    lines.push("", "");
    return { text: lines.join("\r\n"), key, accept };
  }

  global.WebSocketCodec = {
    OPCODES, CLOSE_CODES, GUID, opcodeName, sha1, base64, secWebSocketAccept,
    buildFrame, decodeFrames, parseHandshake, buildHandshake, buildResponse
  };
})(typeof window !== "undefined" ? window : globalThis);
