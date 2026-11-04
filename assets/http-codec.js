/* HTTP/1.1 and HTTP/2 codec — shared by the HTTP page, the packet
   dissector and tests.

   HTTP/1.1 is parsed as text framing (start line, header fields, body,
   Content-Length or chunked transfer coding). HTTP/2 is parsed as binary
   frames, with HPACK header-block decoding including the RFC 7541 Huffman
   code. HTTP/3 is deliberately described rather than parsed: its frames sit
   inside QUIC streams and need QUIC stream reassembly. */
(function (global) {
  "use strict";

  const PH = global.PH;

  const H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

  const FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
    9: "CONTINUATION", 10: "ALTSVC", 11: "ORIGIN", 12: "PRIORITY_UPDATE"
  };

  const FRAME_FLAGS = {
    0: { 0x1: "END_STREAM", 0x8: "PADDED" },
    1: { 0x1: "END_STREAM", 0x4: "END_HEADERS", 0x8: "PADDED", 0x20: "PRIORITY" },
    2: {},
    3: {},
    4: { 0x1: "ACK" },
    5: { 0x4: "END_HEADERS", 0x8: "PADDED" },
    6: { 0x1: "ACK" },
    7: {},
    8: {},
    9: { 0x4: "END_HEADERS" },
    10: {},
    11: {},
    12: {}
  };

  const SETTINGS = {
    1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
    8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES"
  };

  const H2_ERRORS = {
    0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
    4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR",
    7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR",
    11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"
  };

  const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);

  const STATUS_TEXT = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
    206: "Partial Content", 301: "Moved Permanently", 302: "Found",
    303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 409: "Conflict", 410: "Gone",
    413: "Content Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
    418: "I'm a teapot", 421: "Misdirected Request", 422: "Unprocessable Content",
    429: "Too Many Requests", 431: "Request Header Fields Too Large",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported"
  };

  const STATIC_TABLE = [
    [":authority", ""], [":method", "GET"], [":method", "POST"], [":path", "/"],
    [":path", "/index.html"], [":scheme", "http"], [":scheme", "https"],
    [":status", "200"], [":status", "204"], [":status", "206"], [":status", "304"],
    [":status", "400"], [":status", "404"], [":status", "500"], ["accept-charset", ""],
    ["accept-encoding", "gzip, deflate"], ["accept-language", ""], ["accept-ranges", ""],
    ["accept", ""], ["access-control-allow-origin", ""], ["age", ""], ["allow", ""],
    ["authorization", ""], ["cache-control", ""], ["content-disposition", ""],
    ["content-encoding", ""], ["content-language", ""], ["content-length", ""],
    ["content-location", ""], ["content-range", ""], ["content-type", ""], ["cookie", ""],
    ["date", ""], ["etag", ""], ["expect", ""], ["expires", ""], ["from", ""], ["host", ""],
    ["if-match", ""], ["if-modified-since", ""], ["if-none-match", ""], ["if-range", ""],
    ["if-unmodified-since", ""], ["last-modified", ""], ["link", ""], ["location", ""],
    ["max-forwards", ""], ["proxy-authenticate", ""], ["proxy-authorization", ""],
    ["range", ""], ["referer", ""], ["refresh", ""], ["retry-after", ""], ["server", ""],
    ["set-cookie", ""], ["strict-transport-security", ""], ["transfer-encoding", ""],
    ["user-agent", ""], ["vary", ""], ["via", ""], ["www-authenticate", ""]
  ];

  /* ---------- byte helpers ---------- */

  function asciiBytes(text) {
    const s = String(text == null ? "" : text);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 255;
    return out;
  }

  function asciiString(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  }

  function latin1(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  }

  function utf8Length(text) {
    return asciiBytes(text).length;
  }

  function u24(bytes, off) {
    return ((bytes[off] << 16) | (bytes[off + 1] << 8) | bytes[off + 2]) >>> 0;
  }

  function putU24(arr, off, value) {
    arr[off] = (value >>> 16) & 255;
    arr[off + 1] = (value >>> 8) & 255;
    arr[off + 2] = value & 255;
  }

  function preview(bytes, max) {
    const n = max == null ? 16 : max;
    return bytes.length <= n ? PH.bytesToHex(bytes) : PH.bytesToHex(bytes.subarray(0, n)) + " …";
  }

  function field(name, value, note) {
    return { name, value: value == null ? "—" : String(value), note: note || "" };
  }

  function frameTypeName(type) {
    return FRAME_TYPES[type] || "frame 0x" + PH.hex(type, 2);
  }

  function errorName(code) {
    return H2_ERRORS[code] || "error 0x" + PH.hex(code, 8);
  }

  function settingName(id) {
    return SETTINGS[id] || "setting 0x" + PH.hex(id, 4);
  }

  function flagNames(type, flags) {
    const table = FRAME_FLAGS[type] || {};
    const out = [];
    Object.keys(table).forEach((bit) => {
      if (flags & Number(bit)) out.push(table[bit]);
    });
    return out;
  }

  /* ---------- HPACK ---------- */

  let huffmanTrie = null;

  function buildHuffmanTrie() {
    const root = { children: [null, null], sym: null, bit: 0 };
    HUFFMAN.forEach(([hexCode, bits], sym) => {
      let node = root;
      const code = parseInt(hexCode, 16);
      for (let i = bits - 1; i >= 0; i--) {
        const bit = (code >>> i) & 1;
        if (!node.children[bit]) node.children[bit] = { children: [null, null], sym: null, bit };
        node = node.children[bit];
      }
      node.sym = sym;
    });
    return root;
  }

  function decodeHuffman(bytes) {
    if (!huffmanTrie) huffmanTrie = buildHuffmanTrie();
    let value = "";
    let node = huffmanTrie;
    let tailOnes = true;
    let tailLength = 0;
    let warning = "";
    for (let i = 0; i < bytes.length && !warning; i++) {
      for (let bit = 7; bit >= 0; bit--) {
        const b = (bytes[i] >>> bit) & 1;
        node = node.children[b];
        tailLength += 1;
        tailOnes = tailOnes && b === 1;
        if (!node) {
          warning = "Huffman-coded string contains an invalid code near byte " + i;
          break;
        }
        if (node.sym != null) {
          if (node.sym === 256) {
            warning = "Huffman-coded string contains the EOS symbol";
            break;
          }
          value += String.fromCharCode(node.sym);
          node = huffmanTrie;
          tailOnes = true;
          tailLength = 0;
        }
      }
    }
    if (!warning && tailLength > 0) {
      if (!tailOnes || tailLength > 7) {
        warning = "Huffman-coded string has " + tailLength + " bit(s) of invalid padding";
      }
    }
    return { value, warning };
  }

  function decodeInteger(bytes, offset, prefixBits) {
    if (offset >= bytes.length) throw new Error("HPACK integer runs past the block");
    const max = (1 << prefixBits) - 1;
    let value = bytes[offset] & max;
    let pos = offset + 1;
    if (value < max) return { value, next: pos };
    let shift = 0;
    let guard = 0;
    while (pos < bytes.length) {
      if (guard++ > 8) throw new Error("HPACK integer is unreasonably long");
      const b = bytes[pos++];
      value += (b & 0x7f) * Math.pow(2, shift);
      if (!(b & 0x80)) return { value, next: pos };
      shift += 7;
    }
    throw new Error("HPACK integer ends mid-continuation");
  }

  function encodeInteger(value, prefixBits, highBits) {
    const max = (1 << prefixBits) - 1;
    if (value < max) return Uint8Array.from([highBits | value]);
    const out = [highBits | max];
    let n = value - max;
    while (n >= 128) {
      out.push((n & 0x7f) | 0x80);
      n = Math.floor(n / 128);
    }
    out.push(n);
    return Uint8Array.from(out);
  }

  function decodeString(bytes, offset) {
    if (offset >= bytes.length) throw new Error("HPACK string runs past the block");
    const huffman = (bytes[offset] & 0x80) !== 0;
    const parsed = decodeInteger(bytes, offset, 7);
    const start = parsed.next;
    if (start + parsed.value > bytes.length) throw new Error("HPACK string length exceeds the block");
    const raw = bytes.subarray(start, start + parsed.value);
    let value;
    let warning = "";
    if (huffman) {
      const decoded = decodeHuffman(raw);
      value = decoded.value;
      warning = decoded.warning;
    } else {
      value = latin1(raw);
    }
    return { value, huffman, raw, length: parsed.value, offset: start, next: start + parsed.value, warning };
  }

  function encodeString(text) {
    const bytes = asciiBytes(text);
    return PH.concatBytes(encodeInteger(bytes.length, 7, 0), bytes);
  }

  function createHpackContext() {
    return { dynamic: [], size: 0, maxSize: 4096, maxAllowed: 4096, updates: 0 };
  }

  function tableEntry(context, index) {
    if (!index) return null;
    if (index <= STATIC_TABLE.length) {
      const entry = STATIC_TABLE[index - 1];
      return { name: entry[0], value: entry[1], static: true, index };
    }
    const dynamic = context.dynamic[index - STATIC_TABLE.length - 1];
    return dynamic ? { name: dynamic.name, value: dynamic.value, static: false, index } : null;
  }

  function evictDynamic(context) {
    while (context.size > context.maxSize && context.dynamic.length) {
      const removed = context.dynamic.pop();
      context.size -= utf8Length(removed.name) + utf8Length(removed.value) + 32;
    }
    if (context.size < 0) context.size = 0;
  }

  function addDynamic(context, name, value) {
    const size = utf8Length(name) + utf8Length(value) + 32;
    if (size > context.maxSize) {
      context.dynamic = [];
      context.size = 0;
      return;
    }
    context.dynamic.unshift({ name, value });
    context.size += size;
    evictDynamic(context);
  }

  function setTableSize(context, size, warnings) {
    if (size > context.maxAllowed) {
      warnings.push("HPACK dynamic table size update " + size + " exceeds the peer's advertised limit " + context.maxAllowed);
    }
    context.maxSize = size;
    context.updates += 1;
    evictDynamic(context);
  }

  function decodeHpack(bytes, context, options) {
    const ctx = context || createHpackContext();
    const headers = [];
    const warnings = [];
    let pos = 0;
    let guard = 0;
    while (pos < bytes.length) {
      if (guard++ > 4096) { warnings.push("HPACK block has an unreasonable number of fields; stopping"); break; }
      const b = bytes[pos];
      try {
        if (b & 0x80) {
          const parsed = decodeInteger(bytes, pos, 7);
          pos = parsed.next;
          const entry = tableEntry(ctx, parsed.value);
          if (!entry) {
            warnings.push("HPACK indexed field " + parsed.value + " is not in the static or dynamic table");
            continue;
          }
          headers.push({ name: entry.name, value: entry.value, type: "indexed", index: parsed.value, sensitive: false, huffman: false });
          continue;
        }
        if ((b & 0x40) === 0x40) {
          const parsed = decodeInteger(bytes, pos, 6);
          pos = parsed.next;
          let name;
          let nameHuffman = false;
          if (parsed.value) {
            const entry = tableEntry(ctx, parsed.value);
            if (!entry) {
              warnings.push("HPACK literal field references missing name index " + parsed.value);
              name = "unknown";
            } else {
              name = entry.name;
            }
          } else {
            const decoded = decodeString(bytes, pos);
            name = decoded.value;
            nameHuffman = decoded.huffman;
            if (decoded.warning) warnings.push(decoded.warning);
            pos = decoded.next;
          }
          const value = decodeString(bytes, pos);
          if (value.warning) warnings.push(value.warning);
          pos = value.next;
          addDynamic(ctx, name, value.value);
          headers.push({ name, value: value.value, type: "incremental", index: parsed.value, sensitive: false, huffman: nameHuffman || value.huffman });
          continue;
        }
        if ((b & 0xe0) === 0x20) {
          const parsed = decodeInteger(bytes, pos, 5);
          pos = parsed.next;
          setTableSize(ctx, parsed.value, warnings);
          headers.push({ name: "dynamic table size update", value: parsed.value + " B", type: "size-update", sensitive: false, huffman: false });
          continue;
        }
        const never = (b & 0x10) !== 0;
        const parsed = decodeInteger(bytes, pos, 4);
        pos = parsed.next;
        let name;
        let nameHuffman = false;
        if (parsed.value) {
          const entry = tableEntry(ctx, parsed.value);
          if (!entry) {
            warnings.push("HPACK literal field references missing name index " + parsed.value);
            name = "unknown";
          } else {
            name = entry.name;
          }
        } else {
          const decoded = decodeString(bytes, pos);
          name = decoded.value;
          nameHuffman = decoded.huffman;
          if (decoded.warning) warnings.push(decoded.warning);
          pos = decoded.next;
        }
        const value = decodeString(bytes, pos);
        if (value.warning) warnings.push(value.warning);
        pos = value.next;
        headers.push({
          name, value: value.value, type: never ? "never-indexed" : "without-indexing",
          index: parsed.value, sensitive: never, huffman: nameHuffman || value.huffman
        });
      } catch (err) {
        warnings.push("HPACK decode stopped at byte " + pos + ": " + err.message);
        break;
      }
    }
    const forbidden = new Set(["connection", "keep-alive", "proxy-connection", "upgrade"]);
    let sawRegular = false;
    headers.forEach((header) => {
      if (header.type === "size-update") return;
      if (header.name !== header.name.toLowerCase()) {
        warnings.push("HTTP/2 header name \"" + header.name + "\" must be lowercase");
      }
      if (forbidden.has(header.name)) {
        warnings.push("HTTP/2 forbids the connection-specific header \"" + header.name + "\"");
      }
      if (header.name === "transfer-encoding") {
        warnings.push("HTTP/2 forbids Transfer-Encoding; use the END_STREAM flag");
      }
      if (header.name === "te" && header.value.trim().toLowerCase() !== "trailers") {
        warnings.push("HTTP/2 permits TE only with the value \"trailers\"");
      }
      if (header.name.startsWith(":")) {
        if (sawRegular) warnings.push("HTTP/2 pseudo-header \"" + header.name + "\" appears after a regular header");
      } else {
        sawRegular = true;
      }
    });
    return {
      headers, warnings, context: ctx, bytesUsed: pos,
      size: ctx.size, maxSize: ctx.maxSize, dynamicCount: ctx.dynamic.length
    };
  }

  function staticIndex(name, value) {
    for (let i = 0; i < STATIC_TABLE.length; i++) {
      if (STATIC_TABLE[i][0] === name && STATIC_TABLE[i][1] === value) return { index: i + 1, exact: true };
    }
    for (let i = 0; i < STATIC_TABLE.length; i++) {
      if (STATIC_TABLE[i][0] === name) return { index: i + 1, exact: false };
    }
    return { index: 0, exact: false };
  }

  function encodeHpack(headers) {
    const chunks = [];
    (headers || []).forEach((header) => {
      const name = String(header.name);
      const value = String(header.value == null ? "" : header.value);
      const found = staticIndex(name, value);
      if (found.exact && found.index < 62) {
        chunks.push(encodeInteger(found.index, 7, 0x80));
        return;
      }
      if (found.index) {
        chunks.push(encodeInteger(found.index, 4, 0x00));
      } else {
        chunks.push(Uint8Array.from([0x00]));
        chunks.push(encodeString(name));
      }
      chunks.push(encodeString(value));
    });
    return PH.concatBytes(...chunks);
  }

  /* RFC 7541 Appendix B: [code, bit length], indexed by symbol. 256 is EOS. */
const HUFFMAN = [
    ["1ff8",13],
    ["7fffd8",23],
    ["fffffe2",28],
    ["fffffe3",28],
    ["fffffe4",28],
    ["fffffe5",28],
    ["fffffe6",28],
    ["fffffe7",28],
    ["fffffe8",28],
    ["ffffea",24],
    ["3ffffffc",30],
    ["fffffe9",28],
    ["fffffea",28],
    ["3ffffffd",30],
    ["fffffeb",28],
    ["fffffec",28],
    ["fffffed",28],
    ["fffffee",28],
    ["fffffef",28],
    ["ffffff0",28],
    ["ffffff1",28],
    ["ffffff2",28],
    ["3ffffffe",30],
    ["ffffff3",28],
    ["ffffff4",28],
    ["ffffff5",28],
    ["ffffff6",28],
    ["ffffff7",28],
    ["ffffff8",28],
    ["ffffff9",28],
    ["ffffffa",28],
    ["ffffffb",28],
    ["14",6],
    ["3f8",10],
    ["3f9",10],
    ["ffa",12],
    ["1ff9",13],
    ["15",6],
    ["f8",8],
    ["7fa",11],
    ["3fa",10],
    ["3fb",10],
    ["f9",8],
    ["7fb",11],
    ["fa",8],
    ["16",6],
    ["17",6],
    ["18",6],
    ["0",5],
    ["1",5],
    ["2",5],
    ["19",6],
    ["1a",6],
    ["1b",6],
    ["1c",6],
    ["1d",6],
    ["1e",6],
    ["1f",6],
    ["5c",7],
    ["fb",8],
    ["7ffc",15],
    ["20",6],
    ["ffb",12],
    ["3fc",10],
    ["1ffa",13],
    ["21",6],
    ["5d",7],
    ["5e",7],
    ["5f",7],
    ["60",7],
    ["61",7],
    ["62",7],
    ["63",7],
    ["64",7],
    ["65",7],
    ["66",7],
    ["67",7],
    ["68",7],
    ["69",7],
    ["6a",7],
    ["6b",7],
    ["6c",7],
    ["6d",7],
    ["6e",7],
    ["6f",7],
    ["70",7],
    ["71",7],
    ["72",7],
    ["fc",8],
    ["73",7],
    ["fd",8],
    ["1ffb",13],
    ["7fff0",19],
    ["1ffc",13],
    ["3ffc",14],
    ["22",6],
    ["7ffd",15],
    ["3",5],
    ["23",6],
    ["4",5],
    ["24",6],
    ["5",5],
    ["25",6],
    ["26",6],
    ["27",6],
    ["6",5],
    ["74",7],
    ["75",7],
    ["28",6],
    ["29",6],
    ["2a",6],
    ["7",5],
    ["2b",6],
    ["76",7],
    ["2c",6],
    ["8",5],
    ["9",5],
    ["2d",6],
    ["77",7],
    ["78",7],
    ["79",7],
    ["7a",7],
    ["7b",7],
    ["7ffe",15],
    ["7fc",11],
    ["3ffd",14],
    ["1ffd",13],
    ["ffffffc",28],
    ["fffe6",20],
    ["3fffd2",22],
    ["fffe7",20],
    ["fffe8",20],
    ["3fffd3",22],
    ["3fffd4",22],
    ["3fffd5",22],
    ["7fffd9",23],
    ["3fffd6",22],
    ["7fffda",23],
    ["7fffdb",23],
    ["7fffdc",23],
    ["7fffdd",23],
    ["7fffde",23],
    ["ffffeb",24],
    ["7fffdf",23],
    ["ffffec",24],
    ["ffffed",24],
    ["3fffd7",22],
    ["7fffe0",23],
    ["ffffee",24],
    ["7fffe1",23],
    ["7fffe2",23],
    ["7fffe3",23],
    ["7fffe4",23],
    ["1fffdc",21],
    ["3fffd8",22],
    ["7fffe5",23],
    ["3fffd9",22],
    ["7fffe6",23],
    ["7fffe7",23],
    ["ffffef",24],
    ["3fffda",22],
    ["1fffdd",21],
    ["fffe9",20],
    ["3fffdb",22],
    ["3fffdc",22],
    ["7fffe8",23],
    ["7fffe9",23],
    ["1fffde",21],
    ["7fffea",23],
    ["3fffdd",22],
    ["3fffde",22],
    ["fffff0",24],
    ["1fffdf",21],
    ["3fffdf",22],
    ["7fffeb",23],
    ["7fffec",23],
    ["1fffe0",21],
    ["1fffe1",21],
    ["3fffe0",22],
    ["1fffe2",21],
    ["7fffed",23],
    ["3fffe1",22],
    ["7fffee",23],
    ["7fffef",23],
    ["fffea",20],
    ["3fffe2",22],
    ["3fffe3",22],
    ["3fffe4",22],
    ["7ffff0",23],
    ["3fffe5",22],
    ["3fffe6",22],
    ["7ffff1",23],
    ["3ffffe0",26],
    ["3ffffe1",26],
    ["fffeb",20],
    ["7fff1",19],
    ["3fffe7",22],
    ["7ffff2",23],
    ["3fffe8",22],
    ["1ffffec",25],
    ["3ffffe2",26],
    ["3ffffe3",26],
    ["3ffffe4",26],
    ["7ffffde",27],
    ["7ffffdf",27],
    ["3ffffe5",26],
    ["fffff1",24],
    ["1ffffed",25],
    ["7fff2",19],
    ["1fffe3",21],
    ["3ffffe6",26],
    ["7ffffe0",27],
    ["7ffffe1",27],
    ["3ffffe7",26],
    ["7ffffe2",27],
    ["fffff2",24],
    ["1fffe4",21],
    ["1fffe5",21],
    ["3ffffe8",26],
    ["3ffffe9",26],
    ["ffffffd",28],
    ["7ffffe3",27],
    ["7ffffe4",27],
    ["7ffffe5",27],
    ["fffec",20],
    ["fffff3",24],
    ["fffed",20],
    ["1fffe6",21],
    ["3fffe9",22],
    ["1fffe7",21],
    ["1fffe8",21],
    ["7ffff3",23],
    ["3fffea",22],
    ["3fffeb",22],
    ["1ffffee",25],
    ["1ffffef",25],
    ["fffff4",24],
    ["fffff5",24],
    ["3ffffea",26],
    ["7ffff4",23],
    ["3ffffeb",26],
    ["7ffffe6",27],
    ["3ffffec",26],
    ["3ffffed",26],
    ["7ffffe7",27],
    ["7ffffe8",27],
    ["7ffffe9",27],
    ["7ffffea",27],
    ["7ffffeb",27],
    ["ffffffe",28],
    ["7ffffec",27],
    ["7ffffed",27],
    ["7ffffee",27],
    ["7ffffef",27],
    ["7fffff0",27],
    ["3ffffee",26],
    ["3fffffff",30]
  ];

  /* ---------- HTTP/1.1 framing ---------- */

  function findCrlf(bytes, start) {
    for (let i = start; i + 1 < bytes.length; i++) {
      if (bytes[i] === 13 && bytes[i + 1] === 10) return i;
      if (bytes[i] === 10) return i;
    }
    return -1;
  }

  function findHeaderEnd(bytes) {
    for (let i = 0; i + 1 < bytes.length; i++) {
      if (bytes[i] === 13 && bytes[i + 1] === 10) {
        if (i + 3 < bytes.length && bytes[i + 2] === 13 && bytes[i + 3] === 10) return { index: i, length: 4 };
        if (i + 2 < bytes.length && bytes[i + 2] === 10) return { index: i, length: 3 };
      }
      if (bytes[i] === 10 && bytes[i + 1] === 10) return { index: i, length: 2 };
    }
    return { index: -1, length: 0 };
  }

  function firstLineEnd(bytes, start, end) {
    for (let i = start; i < end; i++) if (bytes[i] === 10) return i;
    return end;
  }

  function trimCr(line) {
    return line.endsWith("\r") ? line.slice(0, -1) : line;
  }

  function validToken(name) {
    return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name);
  }

  function parseStartLine(line) {
    let match = line.match(/^([!#$%&'*+\-.^_`|~0-9A-Za-z]+) (\S+) (HTTP\/\d(?:\.\d)?)$/);
    if (match) {
      return { kind: "request", method: match[1], target: match[2], version: match[3], startLine: line };
    }
    match = line.match(/^(HTTP\/\d(?:\.\d)?) (\d{3})(?: (.*))?$/);
    if (match) {
      const status = Number(match[2]);
      return {
        kind: "response", version: match[1], status,
        reason: match[3] == null ? (STATUS_TEXT[status] || "") : match[3],
        startLine: line
      };
    }
    return null;
  }

  function parseHeaderText(text, options) {
    const allowPseudo = !!(options && options.allowPseudo);
    const lines = String(text == null ? "" : text).split(/\r?\n/);
    const headers = [];
    lines.forEach((rawLine, index) => {
      const line = rawLine.trim();
      if (!line) return;
      let colon = line.indexOf(":");
      if (colon === 0) {
        if (!allowPseudo) throw new Error("Header line " + (index + 1) + " starts with a colon: " + line);
        colon = line.indexOf(":", 1);
      }
      if (colon < 1) throw new Error("Header line " + (index + 1) + " has no colon: " + line);
      const name = line.slice(0, colon).trim();
      const pseudo = allowPseudo && /^:[a-z0-9!#$%&'*+\-.^_`|~]+$/i.test(name);
      if (!pseudo && !validToken(name)) throw new Error("Header line " + (index + 1) + " has an invalid field name: " + name);
      headers.push({ name, lower: name.toLowerCase(), value: line.slice(colon + 1).trim() });
    });
    return headers;
  }

  function headerValues(headers, name) {
    return headers.filter((header) => header.lower === name).map((header) => header.value);
  }

  function parseChunks(bytes, start, warnings) {
    const chunks = [];
    const trailers = [];
    const parts = [];
    let pos = start;
    let complete = false;
    let guard = 0;
    while (pos < bytes.length) {
      if (guard++ > 10000) { warnings.push("Chunked body has an unreasonable number of chunks; stopping"); break; }
      const lineEnd = findCrlf(bytes, pos);
      if (lineEnd < 0) { warnings.push("Chunked body ended before a chunk-size line"); break; }
      const line = trimCr(asciiString(bytes.subarray(pos, lineEnd)));
      const sizeText = line.split(";")[0].trim();
      if (!/^[0-9a-fA-F]+$/.test(sizeText)) {
        warnings.push("Invalid chunk size \"" + sizeText + "\" at offset " + pos);
        break;
      }
      const size = parseInt(sizeText, 16);
      const dataStart = lineEnd + 1 + (bytes[lineEnd] === 13 ? 1 : 0);
      if (size === 0) {
        let trailerPos = dataStart;
        while (trailerPos < bytes.length) {
          const trailerEnd = findCrlf(bytes, trailerPos);
          if (trailerEnd < 0) { warnings.push("Chunked trailers ended before the blank line"); break; }
          const trailerLine = trimCr(asciiString(bytes.subarray(trailerPos, trailerEnd)));
          trailerPos = trailerEnd + 1 + (bytes[trailerEnd] === 13 ? 1 : 0);
          if (!trailerLine) { complete = true; break; }
          const colon = trailerLine.indexOf(":");
          if (colon < 1) {
            warnings.push("Invalid trailer line: " + trailerLine);
            continue;
          }
          const name = trailerLine.slice(0, colon).trim();
          trailers.push({ name, lower: name.toLowerCase(), value: trailerLine.slice(colon + 1).trim() });
        }
        pos = trailerPos;
        break;
      }
      if (dataStart + size > bytes.length) {
        warnings.push("Chunk declares " + size + " byte(s) but only " + (bytes.length - dataStart) + " remain");
        break;
      }
      chunks.push({ size, offset: dataStart, data: bytes.subarray(dataStart, dataStart + size) });
      parts.push(bytes.subarray(dataStart, dataStart + size));
      pos = dataStart + size;
      if (pos + 1 < bytes.length && bytes[pos] === 13 && bytes[pos + 1] === 10) pos += 2;
      else if (pos < bytes.length && bytes[pos] === 10) pos += 1;
      else warnings.push("Chunk data at offset " + dataStart + " is not followed by CRLF");
    }
    if (!complete) warnings.push("Chunked body has no terminating zero-length chunk in the capture");
    return { chunks, trailers, decodedBody: PH.concatBytes(...parts), end: pos, complete };
  }

  function decodeHttp1(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const warnings = [];
    if (!bytes.length) throw new Error("HTTP/1.1 input is empty");
    const end = findHeaderEnd(bytes);
    if (end.index < 0) warnings.push("No blank line found; the capture may end inside the header block");
    const headerEnd = end.index >= 0 ? end.index : bytes.length;
    const lineEnd = firstLineEnd(bytes, 0, headerEnd);
    const startLine = trimCr(asciiString(bytes.subarray(0, lineEnd)));
    const parsed = parseStartLine(startLine);
    if (!parsed) {
      throw new Error("Not an HTTP/1.x start line: \"" + startLine.slice(0, 80) + "\"");
    }
    const headers = [];
    let pos = Math.min(headerEnd, lineEnd + 1);
    while (pos < headerEnd) {
      const next = firstLineEnd(bytes, pos, headerEnd);
      const line = trimCr(asciiString(bytes.subarray(pos, next)));
      pos = next + 1;
      if (!line) continue;
      if (line.startsWith(" ") || line.startsWith("\t")) {
        warnings.push("Obsolete line folding at header line " + (headers.length + 1));
        if (headers.length) headers[headers.length - 1].value += " " + line.trim();
        continue;
      }
      const colon = line.indexOf(":");
      if (colon < 1) {
        warnings.push("Header line without a colon: " + line);
        continue;
      }
      const name = line.slice(0, colon).trim();
      if (!validToken(name)) warnings.push("Invalid header field name: " + name);
      headers.push({ name, lower: name.toLowerCase(), value: line.slice(colon + 1).trim() });
    }
    const bodyStart = end.index >= 0 ? end.index + end.length : bytes.length;
    const remaining = bytes.length - bodyStart;
    const transfer = headerValues(headers, "transfer-encoding").join(",").toLowerCase();
    const chunked = transfer.split(",").map((value) => value.trim()).includes("chunked");
    const lengths = headerValues(headers, "content-length");
    let contentLength = null;
    if (lengths.length) {
      const unique = Array.from(new Set(lengths.map((value) => value.trim())));
      if (unique.length > 1) warnings.push("Conflicting Content-Length values: " + unique.join(", "));
      const value = Number(unique[0]);
      if (!Number.isInteger(value) || value < 0) warnings.push("Content-Length is not a non-negative integer: " + unique[0]);
      else contentLength = value;
    }
    if (chunked && contentLength != null) {
      warnings.push("Message has both Transfer-Encoding: chunked and Content-Length; chunked framing takes precedence");
    }
    let body = new Uint8Array(0);
    let bodyOffset = bodyStart;
    let bodyEnd = bodyStart;
    let framing = "none";
    let chunks = [];
    let trailers = [];
    if (parsed.kind === "response" && (parsed.status < 200 || parsed.status === 204 || parsed.status === 304)) {
      framing = "body forbidden";
      if (remaining > 0) warnings.push("Status " + parsed.status + " must not carry a body but " + remaining + " byte(s) follow");
      bodyOffset = bodyEnd = bodyStart;
    } else if (chunked) {
      const parsedChunks = parseChunks(bytes, bodyStart, warnings);
      chunks = parsedChunks.chunks;
      trailers = parsedChunks.trailers;
      body = parsedChunks.decodedBody;
      bodyOffset = bodyStart;
      bodyEnd = parsedChunks.end;
      framing = "chunked";
    } else if (contentLength != null) {
      if (remaining < contentLength) {
        warnings.push("Content-Length is " + contentLength + " but only " + remaining + " byte(s) are captured");
      }
      body = bytes.subarray(bodyStart, Math.min(bytes.length, bodyStart + contentLength));
      bodyOffset = bodyStart;
      bodyEnd = bodyStart + body.length;
      framing = "content-length";
      if (remaining > contentLength) warnings.push((remaining - contentLength) + " byte(s) follow the declared Content-Length (pipelined message or capture padding)");
    } else if (parsed.kind === "request") {
      framing = "none";
      if (remaining > 0) warnings.push("Request has no Content-Length or Transfer-Encoding but " + remaining + " byte(s) follow");
      bodyOffset = bodyEnd = bodyStart;
    } else {
      body = bytes.subarray(bodyStart);
      bodyOffset = bodyStart;
      bodyEnd = bytes.length;
      framing = "close-delimited";
      if (body.length) warnings.push("Response has no Content-Length or Transfer-Encoding; body is close-delimited and may be incomplete");
    }
    const fields = [
      field("Start line", parsed.startLine),
      field("Version", parsed.version),
      field("Framing", framing)
    ];
    if (parsed.kind === "request") {
      fields.unshift(field("Method", parsed.method));
      fields.splice(2, 0, field("Target", parsed.target));
    } else {
      fields.unshift(field("Status", parsed.status + " · " + parsed.reason));
    }
    fields.push(field("Header fields", headers.length));
    fields.push(field("Body", body.length + " B" + (chunked ? " · " + chunks.length + " chunk(s)" : "")));
    const summary = parsed.kind === "request"
      ? parsed.method + " " + parsed.target + " · " + parsed.version + " · " + headers.length + " header(s) · " +
        (chunked ? chunks.length + " chunk(s)" : body.length + " B body")
      : parsed.version + " " + parsed.status + " " + parsed.reason + " · " + headers.length + " header(s) · " +
        (chunked ? chunks.length + " chunk(s)" : body.length + " B body");
    return {
      kind: "h1", messageKind: parsed.kind, bytes,
      startLine, method: parsed.method, target: parsed.target,
      version: parsed.version, status: parsed.status, reason: parsed.reason,
      headers, chunks, trailers, body,
      headerLength: bodyStart, bodyOffset, bodyEnd,
      framing, contentLength, chunked, warnings,
      messageLength: bodyEnd,
      summary
    };
  }

  function buildHttp1(spec) {
    const input = spec || {};
    const response = input.kind === "response" || (input.kind !== "request" && input.status != null);
    const version = input.version || "HTTP/1.1";
    const warnings = [];
    let headers;
    if (typeof input.headers === "string") headers = parseHeaderText(input.headers);
    else if (Array.isArray(input.headers)) {
      headers = input.headers.map((header) => {
        const name = String(header.name || "").trim();
        if (!validToken(name)) throw new Error("Invalid header field name: " + name);
        return { name, lower: name.toLowerCase(), value: String(header.value == null ? "" : header.value).trim() };
      });
    } else headers = [];
    let body;
    if (input.body instanceof Uint8Array) body = input.body;
    else if (Array.isArray(input.body)) body = Uint8Array.from(input.body);
    else if (input.body == null) body = new Uint8Array(0);
    else if ((input.bodyEncoding || "ascii") === "hex") body = PH.parseHex(String(input.body));
    else body = asciiBytes(String(input.body));
    const chunked = !!input.chunked;
    if (!response && !headerValues(headers, "host").length && version !== "HTTP/1.0") {
      if (input.host) headers.unshift({ name: "Host", lower: "host", value: String(input.host) });
      else warnings.push("HTTP/1.1 requests should carry a Host header");
    }
    headers = headers.filter((header) => header.lower !== "content-length" && header.lower !== "transfer-encoding");
    if (chunked) {
      headers.push({ name: "Transfer-Encoding", lower: "transfer-encoding", value: "chunked" });
    } else if (body.length > 0 || input.forceContentLength) {
      headers.push({ name: "Content-Length", lower: "content-length", value: String(body.length) });
    }
    let startLine;
    if (response) {
      const status = Number(input.status == null ? 200 : input.status);
      if (!Number.isInteger(status) || status < 100 || status > 599) throw new Error("Status must be 100–599");
      const reason = input.reason == null ? (STATUS_TEXT[status] || "Unknown") : String(input.reason);
      startLine = (version + " " + status + " " + reason).trimEnd();
    } else {
      const method = String(input.method || "GET").toUpperCase();
      if (!METHODS.has(method)) throw new Error("Unknown HTTP method " + method);
      const target = String(input.target || "/").trim() || "/";
      if (/\s/.test(target)) throw new Error("Request target must not contain whitespace");
      startLine = method + " " + target + " " + version;
    }
    const headerBlock = startLine + "\r\n" + headers.map((header) => header.name + ": " + header.value + "\r\n").join("") + "\r\n";
    let bodyBytes;
    if (chunked) {
      const size = input.chunkSize == null ? Math.max(1, body.length) : Number(input.chunkSize);
      if (!Number.isInteger(size) || size < 1) throw new Error("Chunk size must be a positive integer");
      const parts = [];
      for (let offset = 0; offset < body.length; offset += size) {
        const slice = body.subarray(offset, Math.min(body.length, offset + size));
        parts.push(asciiBytes(slice.length.toString(16) + "\r\n"), slice, asciiBytes("\r\n"));
      }
      parts.push(asciiBytes("0\r\n\r\n"));
      bodyBytes = PH.concatBytes(...parts);
    } else {
      bodyBytes = body;
    }
    const bytes = PH.concatBytes(asciiBytes(headerBlock), bodyBytes);
    return {
      kind: "h1", bytes, startLine, headers, body, bodyBytes,
      response, method: response ? null : String(input.method || "GET").toUpperCase(),
      target: response ? null : String(input.target || "/"),
      status: response ? Number(input.status == null ? 200 : input.status) : null,
      reason: response ? (input.reason == null ? (STATUS_TEXT[Number(input.status == null ? 200 : input.status)] || "Unknown") : String(input.reason)) : null,
      chunked, warnings,
      summary: startLine + " · " + headers.length + " header(s) · " + (chunked ? "chunked " + body.length + " B" : body.length + " B body")
    };
  }

  /* ---------- HTTP/2 frames ---------- */

  function parsePriority(payload, start, end) {
    if (start + 5 > end) return null;
    const raw = PH.u32be(payload, start);
    return {
      exclusive: (raw & 0x80000000) !== 0,
      dependency: raw & 0x7fffffff,
      weight: payload[start + 4] + 1
    };
  }

  function decodeHeaderBlock(frame, fragment, context, warnings, label) {
    const decoded = decodeHpack(fragment, context.hpack);
    decoded.warnings.forEach((warning) => {
      warnings.push((label || "HPACK") + ": " + warning);
      frame.warnings.push(warning);
    });
    frame.headers = decoded.headers;
    frame.hpack = {
      headers: decoded.headers, warnings: decoded.warnings,
      size: decoded.size, maxSize: decoded.maxSize,
      dynamicCount: decoded.dynamicCount, bytesUsed: decoded.bytesUsed
    };
    const named = decoded.headers.filter((header) => header.type !== "size-update");
    frame.fields.push(field("Header block", fragment.length + " B · " + named.length + " field(s)"));
    named.slice(0, 6).forEach((header, index) => {
      frame.fields.push(field("Header " + (index + 1), header.name + ": " + header.value,
        header.type + (header.huffman ? " · Huffman" : "")));
    });
    if (named.length > 6) frame.fields.push(field("More headers", (named.length - 6) + " not shown"));
    frame.summary += " · " + named.length + " header(s)";
  }

  function decodeHttp2(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const warnings = [];
    let pos = 0;
    let preface = false;
    if (bytes.length >= H2_PREFACE.length && asciiString(bytes.subarray(0, H2_PREFACE.length)) === H2_PREFACE) {
      preface = true;
      pos = H2_PREFACE.length;
    }
    const context = { hpack: createHpackContext(), settings: {}, pending: {} };
    const frames = [];
    let guard = 0;
    while (pos + 9 <= bytes.length) {
      if (guard++ > 8192) { warnings.push("Stream contains an unreasonable number of frames; stopping"); break; }
      const length = u24(bytes, pos);
      const type = bytes[pos + 3];
      const flags = bytes[pos + 4];
      const streamId = PH.u32be(bytes, pos + 5) & 0x7fffffff;
      const payloadStart = pos + 9;
      if (payloadStart + length > bytes.length) {
        warnings.push("Frame " + (frames.length + 1) + " declares " + length + " byte(s) but only " +
          (bytes.length - payloadStart) + " are captured");
      }
      const payload = bytes.subarray(payloadStart, Math.min(bytes.length, payloadStart + length));
      const frame = {
        index: frames.length, offset: pos, length, type, typeName: frameTypeName(type),
        flags, flagNames: flagNames(type, flags), streamId,
        headerLength: 9, payload, fields: [], warnings: [], summary: frameTypeName(type) + " · stream " + streamId
      };
      frame.fields.push(field("Type", type + " · " + frame.typeName));
      frame.fields.push(field("Stream ID", streamId === 0 ? "0 · connection" : String(streamId)));
      frame.fields.push(field("Length", length + " B"));
      frame.fields.push(field("Flags", "0x" + PH.hex(flags, 2) + (frame.flagNames.length ? " · " + frame.flagNames.join(" ") : "")));
      parseHttp2Frame(frame, context, warnings, frames);
      frames.push(frame);
      pos = payloadStart + length;
      if (pos > bytes.length) break;
    }
    if (pos < bytes.length && frames.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the last frame");
    Object.keys(context.pending).forEach((key) => {
      warnings.push("Header block on " + key + " has no END_HEADERS in this capture");
    });
    if (!frames.length && preface) warnings.push("HTTP/2 preface is present but no complete frame follows");
    const counts = {};
    frames.forEach((frame) => { counts[frame.typeName] = (counts[frame.typeName] || 0) + 1; });
    const countsText = Object.keys(counts).map((key) => key + (counts[key] > 1 ? " ×" + counts[key] : "")).join(", ");
    const headerCount = frames.reduce((sum, frame) => sum + (frame.headers ? frame.headers.length : 0), 0);
    return {
      kind: "h2", bytes, preface, frames, hpack: context.hpack,
      settings: context.settings, warnings,
      length: Math.min(pos, bytes.length),
      headerCount,
      summary: "HTTP/2 · " + (preface ? "preface · " : "") + frames.length + " frame(s)" +
        (countsText ? " · " + countsText : "") + (headerCount ? " · " + headerCount + " header field(s)" : "")
    };
  }

  function parseHttp2Frame(frame, context, warnings, frames) {
    const payload = frame.payload;
    const end = payload.length;
    switch (frame.type) {
      case 0: {
        let start = 0;
        let dataEnd = end;
        let padding = 0;
        if (frame.flags & 0x8) {
          if (end < 1) { warnings.push("Padded DATA frame has no pad length"); break; }
          padding = payload[0];
          start = 1;
          dataEnd = end - padding;
          if (dataEnd < start) { warnings.push("DATA padding exceeds the payload"); dataEnd = start; }
        }
        const data = payload.subarray(start, dataEnd);
        frame.data = data;
        frame.padding = padding;
        frame.fields.push(field("Data", data.length + " B" + (padding ? " · " + padding + " padding" : "")));
        frame.summary += " · " + data.length + " B data" + (frame.flags & 0x1 ? " · END_STREAM" : "");
        break;
      }
      case 1: {
        let start = 0;
        let headerEnd = end;
        let padding = 0;
        if (frame.flags & 0x8) {
          if (end < 1) { warnings.push("Padded HEADERS frame has no pad length"); break; }
          padding = payload[0];
          start = 1;
          headerEnd = end - padding;
          if (headerEnd < start) { warnings.push("HEADERS padding exceeds the payload"); headerEnd = start; }
        }
        if (frame.flags & 0x20) {
          const priority = parsePriority(payload, start, headerEnd);
          if (!priority) warnings.push("HEADERS has PRIORITY but not enough bytes for the priority fields");
          else {
            frame.priority = priority;
            start += 5;
            frame.fields.push(field("Priority", "dependency " + priority.dependency +
              " · weight " + priority.weight + (priority.exclusive ? " · exclusive" : "")));
          }
        }
        const fragment = payload.subarray(start, headerEnd);
        frame.headerBlock = fragment;
        frame.padding = padding;
        if (frame.flags & 0x4) {
          decodeHeaderBlock(frame, fragment, context, warnings, "HEADERS stream " + frame.streamId);
        } else {
          context.pending["stream " + frame.streamId] = { parts: [fragment], frames: [frame.index] };
          frame.fields.push(field("Header block", fragment.length + " B · END_HEADERS not set"));
          frame.summary += " · header block continues";
        }
        break;
      }
      case 9: {
        const key = "stream " + frame.streamId;
        if (!context.pending[key]) {
          warnings.push("CONTINUATION on stream " + frame.streamId + " has no preceding HEADERS");
          frame.fields.push(field("Fragment", payload.length + " B · orphaned"));
          break;
        }
        context.pending[key].parts.push(payload);
        context.pending[key].frames.push(frame.index);
        frame.fields.push(field("Fragment", payload.length + " B"));
        if (frame.flags & 0x4) {
          const combined = PH.concatBytes(...context.pending[key].parts);
          const blockFrames = context.pending[key].frames;
          delete context.pending[key];
          blockFrames.forEach((index) => {
            if (frames[index]) frames[index].summary += " · continued";
          });
          decodeHeaderBlock(frame, combined, context, warnings, "HEADERS stream " + frame.streamId);
          frame.fields.push(field("Combined block", combined.length + " B from " + blockFrames.length + " frame(s)"));
        } else {
          frame.summary += " · header block continues";
        }
        break;
      }
      case 4: {
        if (frame.flags & 0x1) {
          if (end !== 0) warnings.push("SETTINGS ACK must have an empty payload");
          frame.fields.push(field("ACK", "1 · no settings"));
          frame.summary += " · ACK";
          break;
        }
        if (end % 6 !== 0) warnings.push("SETTINGS payload length " + end + " is not a multiple of 6");
        const values = [];
        for (let offset = 0; offset + 6 <= end; offset += 6) {
          const id = PH.u16be(payload, offset);
          const value = PH.u32be(payload, offset + 2);
          const name = settingName(id);
          values.push({ id, name, value });
          context.settings[id] = value;
          frame.fields.push(field("Setting", name + " = " + value, "id " + id));
        }
        frame.settings = values;
        frame.summary += " · " + values.length + " setting(s)";
        break;
      }
      case 6: {
        if (end !== 8) warnings.push("PING payload should be 8 bytes, found " + end);
        frame.opaque = payload.subarray(0, 8);
        frame.fields.push(field("Opaque data", preview(frame.opaque, 8)));
        frame.summary += (frame.flags & 0x1 ? " · ACK" : "") + " · 8 B opaque";
        break;
      }
      case 7: {
        if (end < 8) { warnings.push("GOAWAY is shorter than last-stream-id + error-code"); break; }
        const lastStreamId = PH.u32be(payload, 0) & 0x7fffffff;
        const error = PH.u32be(payload, 4);
        const debug = payload.subarray(8);
        frame.lastStreamId = lastStreamId;
        frame.errorCode = error;
        frame.debugData = debug;
        frame.fields.push(field("Last stream ID", lastStreamId));
        frame.fields.push(field("Error code", error + " · " + errorName(error)));
        if (debug.length) frame.fields.push(field("Debug data", preview(debug, 32)));
        frame.summary += " · last stream " + lastStreamId + " · " + errorName(error);
        break;
      }
      case 8: {
        if (end !== 4) warnings.push("WINDOW_UPDATE payload should be 4 bytes, found " + end);
        const increment = end >= 4 ? (PH.u32be(payload, 0) & 0x7fffffff) : null;
        if (increment === 0) warnings.push("WINDOW_UPDATE increment must not be zero");
        frame.increment = increment;
        frame.fields.push(field("Window increment", increment == null ? "truncated" : increment + " B"));
        frame.summary += " · +" + increment + " B";
        break;
      }
      case 3: {
        if (end !== 4) warnings.push("RST_STREAM payload should be 4 bytes, found " + end);
        const error = end >= 4 ? PH.u32be(payload, 0) : null;
        frame.errorCode = error;
        frame.fields.push(field("Error code", error == null ? "truncated" : error + " · " + errorName(error)));
        frame.summary += " · " + (error == null ? "truncated" : errorName(error));
        break;
      }
      case 2: {
        if (end !== 5) warnings.push("PRIORITY payload should be 5 bytes, found " + end);
        const priority = parsePriority(payload, 0, end);
        if (priority) {
          frame.priority = priority;
          frame.fields.push(field("Dependency", priority.dependency));
          frame.fields.push(field("Weight", priority.weight));
          frame.fields.push(field("Exclusive", priority.exclusive ? "yes" : "no"));
          frame.summary += " · dependency " + priority.dependency + " · weight " + priority.weight;
        }
        break;
      }
      case 5: {
        let start = 0;
        let headerEnd = end;
        if (frame.flags & 0x8) {
          if (end < 1) { warnings.push("Padded PUSH_PROMISE has no pad length"); break; }
          start = 1;
          headerEnd = end - payload[0];
          if (headerEnd < start) headerEnd = start;
        }
        if (start + 4 > headerEnd) { warnings.push("PUSH_PROMISE is too short for a promised stream ID"); break; }
        const promised = PH.u32be(payload, start) & 0x7fffffff;
        start += 4;
        const fragment = payload.subarray(start, headerEnd);
        frame.promisedStreamId = promised;
        frame.fields.push(field("Promised stream", promised));
        if (frame.flags & 0x4) decodeHeaderBlock(frame, fragment, context, warnings, "PUSH_PROMISE");
        else {
          context.pending["push stream " + promised] = { parts: [fragment], frames: [frame.index] };
          frame.fields.push(field("Header block", fragment.length + " B · END_HEADERS not set"));
        }
        frame.summary += " · promised stream " + promised;
        break;
      }
      default:
        frame.fields.push(field("Payload", preview(payload, 32)));
        frame.summary += " · " + payload.length + " B";
        break;
    }
    if (frame.errors && frame.errors.length) frame.warnings.push(...frame.errors);
  }

  function buildFrame(type, flags, streamId, payload) {
    const body = payload instanceof Uint8Array ? payload : Uint8Array.from(payload || []);
    const out = new Uint8Array(9 + body.length);
    putU24(out, 0, body.length);
    out[3] = type & 255;
    out[4] = flags & 255;
    PH.put32be(out, 5, (streamId || 0) & 0x7fffffff);
    out.set(body, 9);
    return out;
  }

  function buildHttp2Example() {
    const parts = [asciiBytes(H2_PREFACE)];
    const settings = new Uint8Array(12);
    PH.put16be(settings, 0, 3);
    PH.put32be(settings, 2, 100);
    PH.put16be(settings, 6, 4);
    PH.put32be(settings, 8, 65535);
    parts.push(buildFrame(4, 0, 0, settings));
    parts.push(buildFrame(1, 0x5, 1, encodeHpack([
      { name: ":method", value: "GET" },
      { name: ":scheme", value: "https" },
      { name: ":authority", value: "example.com" },
      { name: ":path", value: "/index.html" },
      { name: "user-agent", value: "packet-headers/1.0" },
      { name: "accept", value: "text/html" }
    ])));
    parts.push(buildFrame(0, 0x1, 1, asciiBytes("<html><body>hello</body></html>\n")));
    return PH.concatBytes(...parts);
  }

  /* ---------- auto-detection ---------- */

  function looksLikeHttp1(bytes) {
    if (!bytes || !bytes.length) return false;
    const previewText = asciiString(bytes.subarray(0, Math.min(160, bytes.length))).split(/\r?\n/)[0];
    return !!parseStartLine(previewText);
  }

  function looksLikeHttp2(bytes) {
    if (!bytes || bytes.length < 9) return false;
    if (bytes.length >= H2_PREFACE.length && asciiString(bytes.subarray(0, H2_PREFACE.length)) === H2_PREFACE) return true;
    const length = u24(bytes, 0);
    const type = bytes[3];
    return length <= 16384 && type <= 12 && length <= bytes.length - 9;
  }

  function decodeHttpMessage(bytes, opts) {
    const options = opts || {};
    if (options.kind === "h1") return decodeHttp1(bytes, options);
    if (options.kind === "h2") return decodeHttp2(bytes, options);
    if (options.kind === "hpack") {
      const context = createHpackContext();
      const decoded = decodeHpack(bytes, context);
      return {
        kind: "hpack", bytes, headers: decoded.headers, warnings: decoded.warnings,
        hpack: decoded, length: decoded.bytesUsed,
        summary: "HPACK · " + decoded.headers.filter((header) => header.type !== "size-update").length +
          " header field(s) · " + decoded.bytesUsed + " B consumed"
      };
    }
    if (bytes.length >= H2_PREFACE.length && asciiString(bytes.subarray(0, H2_PREFACE.length)) === H2_PREFACE) {
      return decodeHttp2(bytes, options);
    }
    if (looksLikeHttp1(bytes)) return decodeHttp1(bytes, options);
    if (looksLikeHttp2(bytes)) return decodeHttp2(bytes, options);
    try {
      return decodeHttp1(bytes, options);
    } catch (err) {
      throw new Error("Not an HTTP/1.x message or HTTP/2 frame stream: " + err.message);
    }
  }

  /* ---------- examples ---------- */

  function examples() {
    const request = buildHttp1({
      kind: "request", method: "GET", target: "/index.html", host: "example.com",
      headers: [
        { name: "User-Agent", value: "packet-headers/1.0" },
        { name: "Accept", value: "text/html,application/xhtml+xml" },
        { name: "Accept-Encoding", value: "gzip, br" }
      ]
    });
    const response = buildHttp1({
      kind: "response", status: 200,
      headers: [
        { name: "Content-Type", value: "application/json" },
        { name: "Cache-Control", value: "max-age=60" },
        { name: "Server", value: "example" }
      ],
      body: "{\"ok\":true,\"items\":[1,2,3]}\n"
    });
    const chunked = buildHttp1({
      kind: "response", status: 200,
      headers: [{ name: "Content-Type", value: "text/plain; charset=utf-8" }],
      body: "chunked transfer coding splits the body so the sender never needs a Content-Length\n",
      chunked: true, chunkSize: 24
    });
    const post = buildHttp1({
      kind: "request", method: "POST", target: "/api/items", host: "example.com",
      headers: [{ name: "Content-Type", value: "application/json" }],
      body: "{\"name\":\"widget\"}\n"
    });
    return {
      request: { label: "HTTP/1.1 GET request", bytes: request.bytes, description: "Request line, Host and request headers, no body." },
      response: { label: "HTTP/1.1 200 response", bytes: response.bytes, description: "Content-Length framing and a JSON body." },
      chunked: { label: "HTTP/1.1 chunked response", bytes: chunked.bytes, description: "Transfer-Encoding: chunked with several chunks." },
      post: { label: "HTTP/1.1 POST", bytes: post.bytes, description: "Content-Length request framing." },
      h2: { label: "HTTP/2 frame stream", bytes: buildHttp2Example(), description: "Preface, SETTINGS, HPACK HEADERS and DATA on stream 1." }
    };
  }

  global.HTTPCodec = {
    H2_PREFACE, FRAME_TYPES, FRAME_FLAGS, SETTINGS, H2_ERRORS, METHODS, STATUS_TEXT, STATIC_TABLE,
    frameTypeName, flagNames, errorName, settingName,
    decodeHuffman, decodeInteger, encodeInteger, decodeString, encodeString,
    createHpackContext, decodeHpack, encodeHpack,
    decodeHttp1, buildHttp1, decodeHttp2, buildFrame, buildHttp2Example,
    decodeHttpMessage, looksLikeHttp1, looksLikeHttp2, examples, parseHeaderText,
    asciiBytes, asciiString, u24
  };
})(window);
