/* HTTP/3 (RFC 9114) frame and SETTINGS codec plus a deliberately small
   QPACK (RFC 9204) field-section reader. QPACK has a dynamic table and
   Huffman strings; this reader handles static-table indexed fields and
   plain literals, and reports anything it cannot decode instead of guessing. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const FRAME_TYPES = {
    0x00: "DATA", 0x01: "HEADERS", 0x03: "CANCEL_PUSH", 0x04: "SETTINGS",
    0x05: "PUSH_PROMISE", 0x07: "GOAWAY", 0x0d: "MAX_PUSH_ID", 0x0e: "DUPLICATE_PUSH"
  };
  const SETTINGS = {
    0x01: "QPACK_MAX_TABLE_CAPACITY", 0x02: "MAX_FIELD_SECTION_SIZE",
    0x03: "QPACK_BLOCKED_STREAMS", 0x04: "ENABLE_CONNECT_PROTOCOL",
    0x05: "H3_DATAGRAM", 0x06: "ENABLE_WEBTRANSPORT", 0x07: "GREASE"
  };
  const STREAM_TYPES = {
    0x00: "Control stream", 0x01: "Push stream", 0x02: "QPACK encoder stream",
    0x03: "QPACK decoder stream"
  };
  const ERROR_CODES = {
    0x0100: "H3_NO_ERROR", 0x0101: "H3_GENERAL_PROTOCOL_ERROR", 0x0102: "H3_INTERNAL_ERROR",
    0x0103: "H3_STREAM_CREATION_ERROR", 0x0104: "H3_CLOSED_CRITICAL_STREAM",
    0x0105: "H3_FRAME_UNEXPECTED", 0x0106: "H3_FRAME_ERROR", 0x0107: "H3_EXCESSIVE_LOAD",
    0x0108: "H3_ID_ERROR", 0x0109: "H3_SETTINGS_ERROR", 0x010a: "H3_MISSING_SETTINGS",
    0x010b: "H3_REQUEST_REJECTED", 0x010c: "H3_REQUEST_CANCELLED",
    0x010d: "H3_REQUEST_INCOMPLETE", 0x010e: "H3_MESSAGE_ERROR",
    0x010f: "H3_CONNECT_ERROR", 0x0110: "H3_VERSION_FALLBACK"
  };

  const STATIC_TABLE = [
    [":authority", ""], [":path", "/"], ["age", "0"], ["content-disposition", ""],
    ["content-length", "0"], ["cookie", ""], ["date", ""], ["etag", ""],
    ["if-modified-since", ""], ["if-none-match", ""], ["last-modified", ""], ["link", ""],
    ["location", ""], ["referer", ""], ["set-cookie", ""], [":method", "CONNECT"],
    [":method", "DELETE"], [":method", "GET"], [":method", "HEAD"], [":method", "OPTIONS"],
    [":method", "POST"], [":method", "PUT"], [":scheme", "http"], [":scheme", "https"],
    [":status", "103"], [":status", "200"], [":status", "304"], [":status", "404"],
    [":status", "503"], ["accept", "*/*"], ["accept", "application/dns-message"],
    ["accept-encoding", "gzip, deflate, br"], ["accept-ranges", "bytes"],
    ["access-control-allow-headers", "cache-control"], ["access-control-allow-headers", "content-type"],
    ["access-control-allow-origin", "*"], ["cache-control", "max-age=0"],
    ["cache-control", "max-age=2592000"], ["cache-control", "max-age=604800"],
    ["cache-control", "no-cache"], ["cache-control", "no-store"],
    ["cache-control", "public, max-age=31536000"], ["content-encoding", "br"],
    ["content-encoding", "gzip"], ["content-type", "application/dns-message"],
    ["content-type", "application/javascript"], ["content-type", "application/json"],
    ["content-type", "application/x-www-form-urlencoded"], ["content-type", "image/gif"],
    ["content-type", "image/jpeg"], ["content-type", "image/png"], ["content-type", "text/css"],
    ["content-type", "text/html; charset=utf-8"], ["content-type", "text/plain"],
    ["content-type", "text/plain;charset=utf-8"], ["range", "bytes=0-"],
    ["strict-transport-security", "max-age=31536000"],
    ["strict-transport-security", "max-age=31536000; includesubdomains"],
    ["strict-transport-security", "max-age=31536000; includesubdomains; preload"],
    ["vary", "accept-encoding"], ["vary", "origin"], ["x-content-type-options", "nosniff"],
    ["x-xss-protection", "1; mode=block"], [":status", "100"], [":status", "204"],
    [":status", "206"], [":status", "302"], [":status", "400"], [":status", "403"],
    [":status", "421"], [":status", "425"], [":status", "500"], ["accept-language", ""],
    ["access-control-allow-credentials", "FALSE"], ["access-control-allow-credentials", "TRUE"],
    ["access-control-allow-headers", "*"], ["access-control-allow-methods", "get"],
    ["access-control-allow-methods", "get, post, options"], ["access-control-allow-methods", "options"],
    ["access-control-expose-headers", "content-length"],
    ["access-control-request-headers", "content-type"],
    ["access-control-request-method", "get"], ["access-control-request-method", "post"],
    ["alt-svc", "clear"], ["authorization", ""],
    ["content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"],
    ["early-data", "1"], ["expect-ct", ""], ["forwarded", ""], ["if-range", ""],
    ["origin", ""], ["purpose", "prefetch"], ["server", ""], ["timing-allow-origin", "*"],
    ["upgrade-insecure-requests", "1"], ["user-agent", ""], ["x-forwarded-for", ""],
    ["x-frame-options", "deny"], ["x-frame-options", "sameorigin"]
  ];

  function frameTypeName(type) { return FRAME_TYPES[type] || "0x" + PH.hex(type, 2); }
  function settingName(id) { return SETTINGS[id] || "0x" + PH.hex(id, 2); }
  function streamTypeName(type) { return STREAM_TYPES[type] || "0x" + PH.hex(type, 2); }
  function errorName(code) { return ERROR_CODES[code] || "0x" + PH.hex(code, 4); }

  function toInt(value, name, min, max, fallback) {
    if (value == null || value === "") {
      if (fallback != null) return fallback;
      throw new Error(name + " is required");
    }
    const n = Number(value);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(name + " must be " + min + "–" + max);
    return n;
  }

  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (Array.isArray(value)) return Uint8Array.from(value);
    if (value == null || String(value).trim() === "") return new Uint8Array(0);
    return PH.parseHex(value);
  }

  function readVarint(bytes, offset) {
    if (offset >= bytes.length) throw new Error("QUIC varint is truncated");
    const first = bytes[offset];
    const prefix = first >> 6;
    const length = 1 << prefix;
    if (offset + length > bytes.length) throw new Error("QUIC varint declares " + length + " bytes but is truncated");
    if (length === 8) {
      let n = BigInt(first & 0x3f);
      for (let i = 1; i < 8; i++) n = (n << 8n) | BigInt(bytes[offset + i]);
      return { value: n <= 0x1fffffffffffffn ? Number(n) : n, length, offset };
    }
    let value = first & 0x3f;
    for (let i = 1; i < length; i++) value = value * 256 + bytes[offset + i];
    return { value, length, offset };
  }

  function varint(value) {
    const big = typeof value === "bigint" ? value : BigInt(value);
    if (big < 0n || big > 0x3fffffffffffffffn) throw new Error("QUIC varint must fit in 62 bits");
    if (big < 0x40n) return Uint8Array.from([Number(big)]);
    if (big < 0x4000n) return Uint8Array.from([0x40 | Number(big >> 8n), Number(big & 0xffn)]);
    if (big < 0x40000000n) {
      return Uint8Array.from([0x80 | Number(big >> 24n), Number((big >> 16n) & 0xffn), Number((big >> 8n) & 0xffn), Number(big & 0xffn)]);
    }
    const out = new Uint8Array(8);
    out[0] = 0xc0 | Number((big >> 56n) & 0x3fn);
    for (let i = 1; i < 8; i++) out[i] = Number((big >> BigInt((7 - i) * 8)) & 0xffn);
    return out;
  }

  function decodeSettings(bytes) {
    const settings = [];
    const warnings = [];
    let pos = 0;
    while (pos < bytes.length) {
      let id, value;
      try { id = readVarint(bytes, pos); pos += id.length; }
      catch (err) { warnings.push(err.message); break; }
      try { value = readVarint(bytes, pos); pos += value.length; }
      catch (err) { warnings.push(err.message); break; }
      settings.push({ id: Number(id.value), name: settingName(Number(id.value)), value: id.value instanceof BigInt ? String(value.value) : value.value, rawValue: value.value });
      if (Number(id.value) === 0x04 || Number(id.value) === 0x05 || Number(id.value) === 0x06) {
        if (Number(value.value) !== 0 && Number(value.value) !== 1) warnings.push(settingName(Number(id.value)) + " should be 0 or 1");
      }
    }
    if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) in SETTINGS");
    return { settings, warnings };
  }

  function readQpackInt(bytes, offset, prefix) {
    if (offset >= bytes.length) throw new Error("QPACK integer is truncated");
    const mask = (1 << prefix) - 1;
    let value = bytes[offset] & mask;
    let pos = offset + 1;
    if (value === mask) {
      let shift = 0;
      while (pos < bytes.length) {
        const b = bytes[pos++];
        value += (b & 0x7f) * (2 ** shift);
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 28) throw new Error("QPACK integer is too large");
      }
    }
    return { value, length: pos - offset };
  }

  function readQpackString(bytes, offset) {
    if (offset >= bytes.length) throw new Error("QPACK string is truncated");
    const huffman = !!(bytes[offset] & 0x80);
    const first = readQpackInt(bytes, offset, 7);
    const start = offset + first.length;
    if (start + first.value > bytes.length) throw new Error("QPACK string runs past the field section");
    const raw = bytes.subarray(start, start + first.value);
    if (huffman) return { value: "<Huffman: " + PH.bytesToHex(raw) + ">", raw, huffman: true, next: start + first.value };
    return { value: new TextDecoder().decode(raw), raw, huffman: false, next: start + first.value };
  }

  function readQpackName(bytes, offset) {
    const huffman = !!(bytes[offset] & 0x08);
    const first = readQpackInt(bytes, offset, 3);
    const start = offset + first.length;
    if (start + first.value > bytes.length) throw new Error("QPACK name runs past the field section");
    const raw = bytes.subarray(start, start + first.value);
    return {
      value: huffman ? "<Huffman: " + PH.bytesToHex(raw) + ">" : new TextDecoder().decode(raw),
      huffman, next: start + first.value
    };
  }

  /* Static-table indexed fields and plain literals. Dynamic and post-base
     references are reported, never guessed, because they need connection state. */
  function decodeQpackFieldSection(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const fields = [];
    const warnings = [];
    let pos = 0;
    while (pos < bytes.length) {
      const b = bytes[pos];
      try {
        if (b & 0x80) {
          const index = readQpackInt(bytes, pos, 6);
          const table = (b & 0x40) ? "dynamic" : "static";
          pos += index.length;
          if (table === "dynamic") {
            fields.push({ name: "<dynamic " + index.value + ">", value: "", index: index.value, table, warning: true });
            warnings.push("Dynamic-table index " + index.value + " cannot be resolved without the connection's QPACK state");
          } else {
            const entry = STATIC_TABLE[index.value];
            if (!entry) throw new Error("Static index " + index.value + " does not exist");
            fields.push({ name: entry[0], value: entry[1], index: index.value, table });
          }
        } else if ((b & 0xc0) === 0x40) {
          const never = !!(b & 0x20);
          const table = (b & 0x10) ? "dynamic" : "static";
          const index = readQpackInt(bytes, pos, 4);
          pos += index.length;
          let name;
          if (table === "static") {
            if (!STATIC_TABLE[index.value]) throw new Error("Static name index " + index.value + " does not exist");
            name = STATIC_TABLE[index.value][0];
          } else {
            name = "<dynamic name " + index.value + ">";
            warnings.push("Dynamic name index " + index.value + " cannot be resolved without QPACK state");
          }
          const value = readQpackString(bytes, pos);
          pos = value.next;
          fields.push({ name, value: value.value, index: index.value, table, never, huffman: value.huffman });
        } else if ((b & 0xe0) === 0x20) {
          const never = !!(b & 0x10);
          const name = readQpackName(bytes, pos);
          pos = name.next;
          const value = readQpackString(bytes, pos);
          pos = value.next;
          fields.push({ name: name.value, value: value.value, never, huffman: name.huffman || value.huffman });
        } else if ((b & 0xf0) === 0x10) {
          const index = readQpackInt(bytes, pos, 4);
          pos += index.length;
          const value = readQpackString(bytes, pos);
          pos = value.next;
          fields.push({ name: "<post-base " + index.value + ">", value: value.value, table: "post-base", warning: true });
          warnings.push("Post-base index " + index.value + " cannot be resolved without the encoder stream");
        } else if ((b & 0xf0) === 0x00) {
          const never = !!(b & 0x08);
          const index = readQpackInt(bytes, pos, 3);
          pos += index.length;
          const value = readQpackString(bytes, pos);
          pos = value.next;
          fields.push({ name: "<post-base name " + index.value + ">", value: value.value, table: "post-base", warning: true, never });
          warnings.push("Post-base name index " + index.value + " cannot be resolved without the encoder stream");
        } else {
          warnings.push("Unknown QPACK representation 0x" + PH.hex(b, 2) + " at +" + pos);
          break;
        }
      } catch (err) {
        warnings.push("QPACK at +" + pos + ": " + err.message);
        break;
      }
    }
    return { fields, warnings };
  }

  function decodeFrames(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const options = opts || {};
    const frames = [];
    const warnings = [];
    let pos = 0;
    while (pos < bytes.length) {
      let type, length;
      try {
        type = readVarint(bytes, pos); pos += type.length;
        length = readVarint(bytes, pos); pos += length.length;
      } catch (err) {
        warnings.push(err.message);
        break;
      }
      const typeNumber = Number(type.value);
      const payloadLength = Number(length.value);
      if (!Number.isFinite(payloadLength) || payloadLength < 0) { warnings.push("Frame length is too large"); break; }
      if (pos + payloadLength > bytes.length) {
        warnings.push("Frame " + frameTypeName(typeNumber) + " declares " + payloadLength + " B but only " + (bytes.length - pos) + " B remain");
        break;
      }
      const payload = bytes.subarray(pos, pos + payloadLength);
      const frame = { type: typeNumber, typeName: frameTypeName(typeNumber), length: payloadLength, offset: pos - type.length - length.length, payload, warnings: [] };
      try {
        if (typeNumber === 0x00) {
          frame.data = payload;
        } else if (typeNumber === 0x01) {
          const qpack = decodeQpackFieldSection(payload);
          frame.fields = qpack.fields;
          frame.qpackWarnings = qpack.warnings;
        } else if (typeNumber === 0x03 || typeNumber === 0x07 || typeNumber === 0x0d || typeNumber === 0x0e) {
          const value = readVarint(payload, 0);
          frame.value = value.value;
          if (typeNumber === 0x07 && payload.length > value.length) frame.debug = payload.subarray(value.length);
        } else if (typeNumber === 0x04) {
          const settings = decodeSettings(payload);
          frame.settings = settings.settings;
          frame.warnings.push.apply(frame.warnings, settings.warnings);
        } else if (typeNumber === 0x05) {
          const pushId = readVarint(payload, 0);
          frame.pushId = pushId.value;
          const qpack = decodeQpackFieldSection(payload.subarray(pushId.length));
          frame.fields = qpack.fields;
          frame.qpackWarnings = qpack.warnings;
        }
      } catch (err) {
        frame.warnings.push(err.message);
      }
      if (frame.typeName.indexOf("0x") === 0) frame.warnings.push("This frame type is not defined by HTTP/3 v1");
      warnings.push.apply(warnings, frame.warnings);
      frames.push(frame);
      pos += payloadLength;
    }
    return { frames, warnings, consumed: pos };
  }

  function buildFrame(input) {
    const type = toInt(input.type, "Frame type", 0, 0x3fffffff);
    const payload = toBytes(input.payload);
    const typeBytes = varint(type);
    const lengthBytes = varint(payload.length);
    return PH.concatBytes(typeBytes, lengthBytes, payload);
  }

  function buildSettings(settings) {
    const parts = [];
    (settings || []).forEach((setting) => {
      parts.push(varint(setting.id), varint(setting.value));
    });
    return buildFrame({ type: 0x04, payload: PH.concatBytes.apply(null, parts.length ? parts : [new Uint8Array(0)]) });
  }

  global.HTTP3Codec = {
    FRAME_TYPES, SETTINGS, STREAM_TYPES, ERROR_CODES, STATIC_TABLE,
    frameTypeName, settingName, streamTypeName, errorName,
    readVarint, varint, decodeSettings, decodeQpackFieldSection,
    decodeFrames, buildFrame, buildSettings
  };
})(typeof window !== "undefined" ? window : globalThis);
