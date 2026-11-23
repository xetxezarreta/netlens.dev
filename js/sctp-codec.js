/* SCTP (RFC 9260) common header, chunks and CRC32c.
   This is a structural codec: it does not implement the association state
   machine, retransmission, path management or authentication. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const CHUNK_TYPES = {
    0: "DATA", 1: "INIT", 2: "INIT ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT ACK",
    6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN ACK", 9: "ERROR", 10: "COOKIE ECHO",
    11: "COOKIE ACK", 14: "SHUTDOWN COMPLETE", 15: "AUTH", 64: "I-DATA",
    128: "ASCONF ACK", 192: "FORWARD TSN", 193: "ASCONF"
  };
  const PARAM_TYPES = {
    1: "Heartbeat Info", 5: "IPv4 Address", 6: "IPv6 Address", 7: "State Cookie",
    8: "Unrecognized Parameters", 9: "Cookie Preservative", 11: "Supported Address Types",
    12: "Outgoing SSN Reset Request", 13: "Incoming SSN Reset Request",
    14: "SSN/TSN Reset Request", 15: "Reconfiguration Response",
    0x8008: "Supported Extensions", 0x8009: "Forward TSN Supported",
    0x800a: "ECN Capable", 0x800b: "Random", 0x800c: "Chunk Type",
    0x800d: "Padding", 0x800e: "Forward TSN Supported (old)"
  };
  const CAUSES = {
    1: "Invalid Stream Identifier", 2: "Missing Mandatory Parameter", 3: "Stale Cookie Error",
    4: "Out of Resource", 5: "Unresolvable Address", 6: "Unrecognized Chunk Type",
    7: "Invalid Mandatory Parameter", 8: "Unrecognized Parameters",
    9: "No User Data", 10: "Cookie Received While Shutting Down",
    11: "Restart of an Association with New Addresses", 12: "User Initiated Abort",
    13: "Protocol Violation"
  };

  function chunkName(type) { return CHUNK_TYPES[type] || "Chunk type " + type; }
  function paramName(type) { return PARAM_TYPES[type] || "Parameter 0x" + PH.hex(type, 4); }
  function causeName(type) { return CAUSES[type] || "Cause " + type; }

  const CRC_TABLE = (function () {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0x82f63b78 ^ (c >>> 1)) : (c >>> 1);
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32c(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) crc = (CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
    return (crc ^ 0xffffffff) >>> 0;
  }

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

  function decodeParams(bytes, offset) {
    const params = [];
    let pos = offset;
    const warnings = [];
    while (pos + 4 <= bytes.length) {
      const type = PH.u16be(bytes, pos);
      const length = PH.u16be(bytes, pos + 2);
      if (length < 4) { warnings.push("Parameter 0x" + PH.hex(type, 4) + " has length " + length + " (< 4)"); break; }
      const end = pos + length;
      if (end > bytes.length) { warnings.push("Parameter 0x" + PH.hex(type, 4) + " runs past the chunk"); break; }
      const value = bytes.subarray(pos + 4, end);
      const item = { type, name: paramName(type), length, value, offset: pos };
      if ((type === 5 && value.length === 4) || (type === 6 && value.length === 16)) {
        item.address = type === 5 ? PH.ipv4String(value, 0) : formatV6(value);
      }
      params.push(item);
      pos = (end + 3) & ~3;
    }
    return { params, warnings };
  }

  function formatV6(bytes) {
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    return codec ? codec.formatIPv6(bytes) : PH.bytesToHex(bytes);
  }

  function decodeCauses(bytes) {
    const causes = [];
    let pos = 0;
    const warnings = [];
    while (pos + 4 <= bytes.length) {
      const code = PH.u16be(bytes, pos);
      const length = PH.u16be(bytes, pos + 2);
      if (length < 4) { warnings.push("Error cause " + code + " has length " + length); break; }
      const end = pos + length;
      if (end > bytes.length) { warnings.push("Error cause " + code + " runs past the chunk"); break; }
      causes.push({ code, name: causeName(code), length, value: bytes.subarray(pos + 4, end), offset: pos });
      pos = (end + 3) & ~3;
    }
    return { causes, warnings };
  }

  function decodeData(bytes, value) {
    if (value.length < 12) return { warnings: ["DATA chunk is shorter than its 12-byte fixed fields"] };
    const flags = value[0];
    const out = {
      flags: { I: !!(flags & 0x08), U: !!(flags & 0x04), B: !!(flags & 0x02), E: !!(flags & 0x01) },
      tsn: PH.u32be(value, 0),
      streamId: PH.u16be(value, 4),
      streamSequence: PH.u16be(value, 6),
      ppid: PH.u32be(value, 8),
      payload: value.subarray(12)
    };
    return out;
  }

  function decodeInit(value) {
    if (value.length < 16) return { warnings: ["INIT chunk is shorter than its 16-byte fixed fields"] };
    const parsed = decodeParams(value, 16);
    return {
      initiateTag: PH.u32be(value, 0), aRwnd: PH.u32be(value, 4),
      outboundStreams: PH.u16be(value, 8), inboundStreams: PH.u16be(value, 10),
      initialTsn: PH.u32be(value, 12), params: parsed.params, warnings: parsed.warnings
    };
  }

  function decodeSack(value) {
    if (value.length < 12) return { warnings: ["SACK chunk is shorter than its 12-byte fixed fields"] };
    const out = {
      cumulativeTsn: PH.u32be(value, 0), aRwnd: PH.u32be(value, 4),
      gapBlocks: [], duplicateTsns: [], warnings: []
    };
    const gaps = PH.u16be(value, 8);
    const dups = PH.u16be(value, 10);
    let pos = 12;
    for (let i = 0; i < gaps && pos + 4 <= value.length; i++) {
      out.gapBlocks.push({ start: PH.u16be(value, pos), end: PH.u16be(value, pos + 2) });
      pos += 4;
    }
    for (let i = 0; i < dups && pos + 4 <= value.length; i++) {
      out.duplicateTsns.push(PH.u32be(value, pos));
      pos += 4;
    }
    if (gaps * 4 + dups * 4 + 12 > value.length) out.warnings.push("SACK gap/duplicate counts exceed the chunk length");
    return out;
  }

  function decodeChunk(bytes, offset) {
    if (offset + 4 > bytes.length) throw new Error("Chunk header runs past the packet");
    const type = bytes[offset];
    const flags = bytes[offset + 1];
    const length = PH.u16be(bytes, offset + 2);
    const warnings = [];
    if (length < 4) warnings.push("Chunk length " + length + " is smaller than its 4-byte header");
    if (length % 4) warnings.push("Chunk length " + length + " is not a multiple of four");
    const end = Math.min(bytes.length, offset + (length || 4));
    const value = bytes.subarray(offset + 4, end);
    const chunk = { type, name: chunkName(type), flags, length, offset, value, warnings, fields: [] };
    if (type === 0) Object.assign(chunk, decodeData(bytes, value));
    else if (type === 1 || type === 2) Object.assign(chunk, decodeInit(value));
    else if (type === 3) Object.assign(chunk, decodeSack(value));
    else if (type === 6 || type === 9) Object.assign(chunk, decodeCauses(value));
    else if (type === 7) {
      if (value.length >= 4) chunk.cumulativeTsn = PH.u32be(value, 0);
    } else if (type === 10) {
      chunk.cookie = value;
    } else if (type === 15) {
      chunk.auth = value;
    }
    if (chunk.warnings && chunk.warnings.length) warnings.push.apply(warnings, chunk.warnings);
    if (length > bytes.length - offset) warnings.push("Chunk declares " + length + " B but only " + (bytes.length - offset) + " B remain");
    return chunk;
  }

  function decodeSctp(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 12) throw new Error("SCTP needs a 12-byte common header");
    const srcPort = PH.u16be(bytes, 0);
    const dstPort = PH.u16be(bytes, 2);
    const verificationTag = PH.u32be(bytes, 4);
    const checksum = PH.u32be(bytes, 8);
    const warnings = [];
    const copy = bytes.slice();
    copy[8] = copy[9] = copy[10] = copy[11] = 0;
    const expected = crc32c(copy);
    const checksumState = checksum === 0 ? "not-set" : (expected === checksum ? "valid" : "invalid");
    if (checksumState === "invalid") warnings.push("SCTP CRC32c is invalid (expected 0x" + PH.hex(expected, 8) + ")");
    const chunks = [];
    let pos = 12;
    while (pos + 4 <= bytes.length) {
      let chunk;
      try { chunk = decodeChunk(bytes, pos); }
      catch (err) { warnings.push("Chunk at +" + pos + ": " + err.message); break; }
      chunks.push(chunk);
      warnings.push.apply(warnings, chunk.warnings);
      if (chunk.length < 4) break;
      pos = (pos + chunk.length + 3) & ~3;
    }
    if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the last chunk");
    return {
      bytes, srcPort, dstPort, verificationTag, checksum, expectedChecksum: expected,
      checksumState, chunks, warnings, headerLength: 12
    };
  }

  function pad4(bytes) {
    const padded = (bytes.length + 3) & ~3;
    if (padded === bytes.length) return bytes;
    const out = new Uint8Array(padded);
    out.set(bytes, 0);
    return out;
  }

  function buildParam(param) {
    const value = toBytes(param.value);
    const bytes = new Uint8Array(4 + value.length);
    PH.put16be(bytes, 0, toInt(param.type, "Parameter type", 0, 65535, 5));
    PH.put16be(bytes, 2, bytes.length);
    bytes.set(value, 4);
    return pad4(bytes);
  }

  function buildChunk(chunk) {
    const type = toInt(chunk.type, "Chunk type", 0, 255, 0);
    let value;
    if (chunk.value != null) value = toBytes(chunk.value);
    else if (type === 0) {
      const payload = toBytes(chunk.payload);
      value = new Uint8Array(12 + payload.length);
      value[0] = (chunk.I ? 0x08 : 0) | (chunk.U ? 0x04 : 0) | (chunk.B ? 0x02 : 0) | (chunk.E ? 0x01 : 0);
      PH.put32be(value, 0, toInt(chunk.tsn, "TSN", 0, 4294967295, 1));
      PH.put16be(value, 4, toInt(chunk.streamId, "Stream ID", 0, 65535, 0));
      PH.put16be(value, 6, toInt(chunk.streamSequence, "Stream sequence", 0, 65535, 0));
      PH.put32be(value, 8, toInt(chunk.ppid, "PPID", 0, 4294967295, 0));
      value.set(payload, 12);
    } else if (type === 1 || type === 2) {
      const params = (chunk.params || []).map(buildParam);
      const paramBytes = params.reduce((n, p) => n + p.length, 0);
      value = new Uint8Array(16 + paramBytes);
      PH.put32be(value, 0, toInt(chunk.initiateTag, "Initiate tag", 0, 4294967295, 1));
      PH.put32be(value, 4, toInt(chunk.aRwnd, "Advertised receiver window", 0, 4294967295, 65535));
      PH.put16be(value, 8, toInt(chunk.outboundStreams, "Outbound streams", 0, 65535, 10));
      PH.put16be(value, 10, toInt(chunk.inboundStreams, "Inbound streams", 0, 65535, 10));
      PH.put32be(value, 12, toInt(chunk.initialTsn, "Initial TSN", 0, 4294967295, 1));
      let pos = 16;
      params.forEach((p) => { value.set(p, pos); pos += p.length; });
    } else if (type === 3) {
      const gaps = chunk.gapBlocks || [];
      const dups = chunk.duplicateTsns || [];
      value = new Uint8Array(12 + gaps.length * 4 + dups.length * 4);
      PH.put32be(value, 0, toInt(chunk.cumulativeTsn, "Cumulative TSN", 0, 4294967295, 0));
      PH.put32be(value, 4, toInt(chunk.aRwnd, "Advertised receiver window", 0, 4294967295, 65535));
      PH.put16be(value, 8, gaps.length);
      PH.put16be(value, 10, dups.length);
      let pos = 12;
      gaps.forEach((g) => { PH.put16be(value, pos, g.start); PH.put16be(value, pos + 2, g.end); pos += 4; });
      dups.forEach((d) => { PH.put32be(value, pos, d); pos += 4; });
    } else {
      value = new Uint8Array(0);
    }
    const padded = pad4(value);
    const bytes = new Uint8Array(4 + padded.length);
    bytes[0] = type;
    bytes[1] = toInt(chunk.flags, "Flags", 0, 255, 0);
    PH.put16be(bytes, 2, bytes.length);
    bytes.set(padded, 4);
    return bytes;
  }

  function buildSctp(input) {
    const chunks = (input.chunks || []).map(buildChunk);
    const total = 12 + chunks.reduce((n, c) => n + c.length, 0);
    const bytes = new Uint8Array(total);
    PH.put16be(bytes, 0, toInt(input.srcPort, "Source port", 0, 65535, 0));
    PH.put16be(bytes, 2, toInt(input.dstPort, "Destination port", 0, 65535, 0));
    PH.put32be(bytes, 4, toInt(input.verificationTag, "Verification tag", 0, 4294967295, 0));
    let pos = 12;
    chunks.forEach((c) => { bytes.set(c, pos); pos += c.length; });
    const value = crc32c(bytes);
    PH.put32be(bytes, 8, value);
    return {
      bytes, srcPort: input.srcPort, dstPort: input.dstPort,
      verificationTag: input.verificationTag, checksum: value, checksumState: "built",
      chunks: chunks.length, chunkBytes: chunks
    };
  }

  global.SCTPCodec = {
    CHUNK_TYPES, PARAM_TYPES, CAUSES, chunkName, paramName, causeName,
    crc32c, decodeChunk, decodeSctp, buildChunk, buildSctp
  };
})(typeof window !== "undefined" ? window : globalThis);
