/* WireGuard message framing (protocol whitepaper, 2019).
   The codec describes the wire layout only. It never derives keys, checks
   MAC1/MAC2, decrypts transport data or claims that a handshake is authentic. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const TYPES = {
    1: "Handshake Initiation", 2: "Handshake Response", 3: "Cookie Reply", 4: "Transport Data"
  };
  const SIZES = { 1: 148, 2: 92, 3: 64, 4: 32 };

  function typeName(type) { return TYPES[type] || "Message type " + type; }

  function toInt(value, name, min, max, fallback) {
    if (value == null || value === "") {
      if (fallback != null) return fallback;
      throw new Error(name + " is required");
    }
    const n = Number(value);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(name + " must be " + min + "–" + max);
    return n;
  }

  function toBytes(value, length, name) {
    if (value instanceof Uint8Array) {
      if (length != null && value.length !== length) throw new Error(name + " must be " + length + " bytes");
      return value;
    }
    if (Array.isArray(value)) {
      if (length != null && value.length !== length) throw new Error(name + " must be " + length + " bytes");
      return Uint8Array.from(value);
    }
    if (value == null || String(value).trim() === "") {
      return new Uint8Array(length == null ? 0 : length);
    }
    const bytes = PH.parseHex(value);
    if (length != null && bytes.length !== length) throw new Error(name + " must be " + length + " bytes (got " + bytes.length + ")");
    return bytes;
  }

  function u64le(bytes, off) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i]);
    return v;
  }

  function put64le(bytes, off, value) {
    let n = BigInt(value);
    if (n < 0n || n > 0xffffffffffffffffn) throw new Error("Counter must fit in 64 bits");
    for (let i = 0; i < 8; i++) { bytes[off + i] = Number(n & 255n); n >>= 8n; }
  }

  function hex(bytes) { return PH.bytesToHex(bytes); }

  function decodeWireguard(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 4) throw new Error("WireGuard needs at least the 4-byte message type");
    const type = bytes[0];
    const reserved = bytes[1] | (bytes[2] << 8) | (bytes[3] << 16);
    const warnings = [];
    if (type < 1 || type > 4) warnings.push("Message type " + type + " is not defined by the WireGuard protocol");
    if (reserved !== 0) warnings.push("The three reserved bytes after the message type are non-zero");
    const out = {
      bytes, type, typeName: typeName(type), reserved, warnings,
      expectedLength: SIZES[type] || null,
      senderIndex: null, receiverIndex: null, counter: null
    };
    if (bytes.length < 8) { warnings.push("Message is shorter than the common index fields"); return out; }

    if (type === 1) {
      if (bytes.length !== 148) warnings.push("Handshake Initiation is " + bytes.length + " B; the protocol fixes it at 148 B");
      out.senderIndex = PH.u32le(bytes, 4);
      out.ephemeral = bytes.subarray(8, 40);
      out.encryptedStatic = bytes.subarray(40, 88);
      out.encryptedTimestamp = bytes.subarray(88, 116);
      out.mac1 = bytes.subarray(116, 132);
      out.mac2 = bytes.subarray(132, 148);
      out.fields = [
        ["Sender index", out.senderIndex],
        ["Ephemeral public key", hex(out.ephemeral)],
        ["Encrypted static", out.encryptedStatic.length + " B"],
        ["Encrypted timestamp", out.encryptedTimestamp.length + " B"],
        ["MAC1", hex(out.mac1) || "—"],
        ["MAC2", hex(out.mac2) || "—"]
      ];
    } else if (type === 2) {
      if (bytes.length !== 92) warnings.push("Handshake Response is " + bytes.length + " B; the protocol fixes it at 92 B");
      out.senderIndex = PH.u32le(bytes, 4);
      out.receiverIndex = PH.u32le(bytes, 8);
      out.ephemeral = bytes.subarray(12, 44);
      out.encryptedEmpty = bytes.subarray(44, 60);
      out.mac1 = bytes.subarray(60, 76);
      out.mac2 = bytes.subarray(76, 92);
      out.fields = [
        ["Sender index", out.senderIndex],
        ["Receiver index", out.receiverIndex],
        ["Ephemeral public key", hex(out.ephemeral)],
        ["Encrypted empty", out.encryptedEmpty.length + " B"],
        ["MAC1", hex(out.mac1) || "—"],
        ["MAC2", hex(out.mac2) || "—"]
      ];
    } else if (type === 3) {
      if (bytes.length !== 64) warnings.push("Cookie Reply is " + bytes.length + " B; the protocol fixes it at 64 B");
      out.receiverIndex = PH.u32le(bytes, 4);
      out.nonce = bytes.subarray(8, 32);
      out.encryptedCookie = bytes.subarray(32, 64);
      out.fields = [
        ["Receiver index", out.receiverIndex],
        ["Nonce", hex(out.nonce)],
        ["Encrypted cookie", out.encryptedCookie.length + " B"]
      ];
    } else if (type === 4) {
      if (bytes.length < 32) warnings.push("Transport Data is " + bytes.length + " B; at least 32 B (16 B header + 16 B tag) is required");
      out.receiverIndex = PH.u32le(bytes, 4);
      out.counter = bytes.length >= 16 ? u64le(bytes, 8) : null;
      out.encryptedPayload = bytes.subarray(16);
      out.fields = [
        ["Receiver index", out.receiverIndex],
        ["Counter", out.counter == null ? "—" : out.counter.toString()],
        ["Encrypted payload", out.encryptedPayload.length + " B (includes 16 B AEAD tag)"]
      ];
    }
    return out;
  }

  function base(type, length) {
    const bytes = new Uint8Array(length);
    bytes[0] = type;
    return bytes;
  }

  function buildWireguard(input) {
    const type = toInt(input.type, "Message type", 0, 255, 4);
    let bytes;
    let out;
    if (type === 1) {
      bytes = base(1, 148);
      PH.put32le(bytes, 4, toInt(input.senderIndex, "Sender index", 0, 4294967295, 0));
      bytes.set(toBytes(input.ephemeral, 32, "Ephemeral public key"), 8);
      bytes.set(toBytes(input.encryptedStatic, 48, "Encrypted static"), 40);
      bytes.set(toBytes(input.encryptedTimestamp, 28, "Encrypted timestamp"), 88);
      bytes.set(toBytes(input.mac1, 16, "MAC1"), 116);
      bytes.set(toBytes(input.mac2, 16, "MAC2"), 132);
    } else if (type === 2) {
      bytes = base(2, 92);
      PH.put32le(bytes, 4, toInt(input.senderIndex, "Sender index", 0, 4294967295, 0));
      PH.put32le(bytes, 8, toInt(input.receiverIndex, "Receiver index", 0, 4294967295, 0));
      bytes.set(toBytes(input.ephemeral, 32, "Ephemeral public key"), 12);
      bytes.set(toBytes(input.encryptedEmpty, 16, "Encrypted empty"), 44);
      bytes.set(toBytes(input.mac1, 16, "MAC1"), 60);
      bytes.set(toBytes(input.mac2, 16, "MAC2"), 76);
    } else if (type === 3) {
      bytes = base(3, 64);
      PH.put32le(bytes, 4, toInt(input.receiverIndex, "Receiver index", 0, 4294967295, 0));
      bytes.set(toBytes(input.nonce, 24, "Nonce"), 8);
      bytes.set(toBytes(input.encryptedCookie, 32, "Encrypted cookie"), 32);
    } else if (type === 4) {
      const payload = toBytes(input.payload);
      if (payload.length < 16) throw new Error("Transport Data payload must include the 16-byte AEAD tag");
      bytes = base(4, 16 + payload.length);
      PH.put32le(bytes, 4, toInt(input.receiverIndex, "Receiver index", 0, 4294967295, 0));
      put64le(bytes, 8, toBigInt(input.counter));
      bytes.set(payload, 16);
    } else {
      throw new Error("Message type must be 1–4");
    }
    out = {
      bytes, type, typeName: typeName(type),
      senderIndex: input.senderIndex == null ? null : Number(input.senderIndex),
      receiverIndex: input.receiverIndex == null ? null : Number(input.receiverIndex),
      counter: input.counter == null ? null : toBigInt(input.counter),
      note: "Structural build only: keys, MACs and AEAD tags are not computed."
    };
    return out;
  }

  function toBigInt(value) {
    if (value == null || value === "") return 0n;
    if (typeof value === "bigint") return value;
    const text = String(value).trim();
    if (/^0x/i.test(text)) return BigInt(text);
    if (/^\d+$/.test(text)) return BigInt(text);
    throw new Error("Counter must be a decimal or 0x-prefixed integer");
  }

  global.WireGuardCodec = { TYPES, SIZES, typeName, decodeWireguard, buildWireguard };
})(typeof window !== "undefined" ? window : globalThis);
