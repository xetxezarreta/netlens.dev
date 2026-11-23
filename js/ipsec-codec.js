/* IPsec AH (RFC 4302), ESP (RFC 4303) and the IKEv2 header (RFC 7296).
   ESP payloads and integrity check values are opaque without keys and the
   negotiated algorithms, so this codec never pretends to authenticate them. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const AH_NEXT = {
    1: "ICMP", 4: "IPv4", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"
  };
  const IKE_EXCHANGE = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
    43: "IKE_SESSION_RESUME"
  };
  const IKE_PAYLOAD = {
    0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Ni", 41: "Nr", 42: "N", 43: "D", 44: "V", 45: "TSi", 46: "TSr",
    47: "EAP", 48: "SK", 49: "CP"
  };

  function ahNextName(n) { return AH_NEXT[n] || "next header " + n; }
  function exchangeName(n) { return IKE_EXCHANGE[n] || "exchange " + n; }
  function payloadName(n) { return IKE_PAYLOAD[n] || "payload " + n; }

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

  function decodeAh(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 12) throw new Error("AH needs at least 12 bytes before its ICV");
    const nextHeader = bytes[0];
    const payloadLength = bytes[1];
    const total = (payloadLength + 2) * 4;
    const warnings = [];
    if (total < 12) warnings.push("AH Payload Length " + payloadLength + " implies a header shorter than 12 bytes");
    if (total > bytes.length) warnings.push("AH header length " + total + " exceeds the " + bytes.length + " captured bytes");
    const icvLength = Math.max(0, Math.min(total, bytes.length) - 12);
    return {
      bytes, nextHeader, nextHeaderName: ahNextName(nextHeader), payloadLength,
      totalLength: total, reserved: PH.u16be(bytes, 2), spi: PH.u32be(bytes, 4),
      sequence: PH.u32be(bytes, 8), icv: bytes.subarray(12, 12 + icvLength),
      icvLength, payload: bytes.subarray(Math.min(total, bytes.length)), warnings,
      note: "The ICV is algorithm-specific and is not verified without the SA keys."
    };
  }

  function buildAh(input) {
    const nextHeader = toInt(input.nextHeader, "Next header", 0, 255, 6);
    const icv = toBytes(input.icv);
    if (icv.length % 4) throw new Error("AH ICV must be a multiple of four bytes");
    const payloadLength = 1 + icv.length / 4;
    const bytes = new Uint8Array(12 + icv.length);
    bytes[0] = nextHeader;
    bytes[1] = payloadLength;
    PH.put16be(bytes, 2, 0);
    PH.put32be(bytes, 4, toInt(input.spi, "SPI", 0, 4294967295, 0));
    PH.put32be(bytes, 8, toInt(input.sequence, "Sequence", 0, 4294967295, 1));
    bytes.set(icv, 12);
    return { bytes, nextHeader, totalLength: bytes.length, spi: input.spi, sequence: input.sequence, icvLength: icv.length };
  }

  function decodeEsp(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 8) throw new Error("ESP needs at least its 8-byte header");
    const warnings = ["ESP payload, padding, next header and ICV are encrypted or algorithm-specific; they are not parsed without keys"];
    return {
      bytes, spi: PH.u32be(bytes, 0), sequence: PH.u32be(bytes, 4),
      ciphertext: bytes.subarray(8), ciphertextLength: bytes.length - 8,
      trailer: null, icv: null, warnings,
      note: "The receiver decrypts first; only then do Pad Length, Next Header and the ICV boundary become visible."
    };
  }

  function buildEsp(input) {
    const payload = toBytes(input.payload);
    const icv = toBytes(input.icv);
    const padLength = toInt(input.padLength, "Pad length", 0, 255, 0);
    let nextHeader = toInt(input.nextHeader, "Next header", 0, 255, 4);
    if (nextHeader === 50) throw new Error("ESP next header 50 is recursive; choose the inner protocol");
    const plaintext = PH.concatBytes(payload, new Uint8Array(padLength), Uint8Array.from([padLength, nextHeader]));
    /* Structural only: the caller supplies already-encrypted bytes in `ciphertext`. */
    const ciphertext = input.ciphertext != null ? toBytes(input.ciphertext) : plaintext;
    const bytes = new Uint8Array(8 + ciphertext.length + icv.length);
    PH.put32be(bytes, 0, toInt(input.spi, "SPI", 0, 4294967295, 0));
    PH.put32be(bytes, 4, toInt(input.sequence, "Sequence", 0, 4294967295, 1));
    bytes.set(ciphertext, 8);
    bytes.set(icv, 8 + ciphertext.length);
    return {
      bytes, spi: input.spi, sequence: input.sequence, ciphertext, icv,
      note: input.ciphertext != null
        ? "The supplied ciphertext is copied verbatim; no encryption is performed."
        : "Illustrative layout: the plaintext is shown where ciphertext belongs. Do not put this on a wire as encrypted traffic."
    };
  }

  function decodeIkev2(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 28) throw new Error("IKEv2 needs at least its 28-byte header");
    const initiatorSpi = bytes.subarray(0, 8);
    const responderSpi = bytes.subarray(8, 16);
    const nextPayload = bytes[16];
    const version = bytes[17];
    const exchangeType = bytes[18];
    const flags = bytes[19];
    const messageId = PH.u32be(bytes, 20);
    const length = PH.u32be(bytes, 24);
    const warnings = [];
    if (version !== 0x20) warnings.push("IKEv2 version byte is 0x" + PH.hex(version, 2) + ", expected 0x20");
    if (length < 28) warnings.push("IKEv2 Length " + length + " is smaller than the header");
    if (length > bytes.length) warnings.push("IKEv2 Length " + length + " exceeds the " + bytes.length + " captured bytes");
    const effective = Math.min(bytes.length, length || bytes.length);
    const payloads = [];
    let pos = 28;
    let type = nextPayload;
    let guard = 0;
    while (type !== 0 && pos + 4 <= effective && guard++ < 256) {
      const next = bytes[pos];
      const critical = !!(bytes[pos + 1] & 0x80);
      const payloadLength = PH.u16be(bytes, pos + 2);
      if (payloadLength < 4 || pos + payloadLength > effective) {
        warnings.push("IKEv2 payload " + payloadName(type) + " has an invalid length " + payloadLength);
        break;
      }
      payloads.push({
        type, name: payloadName(type), offset: pos, length: payloadLength,
        next, critical, value: bytes.subarray(pos + 4, pos + payloadLength)
      });
      pos += payloadLength;
      type = next;
    }
    if (pos < effective) warnings.push((effective - pos) + " trailing byte(s) after the payload chain");
    return {
      bytes, initiatorSpi, responderSpi,
      initiatorSpiText: PH.bytesToHex(initiatorSpi).replace(/ /g, ""),
      responderSpiText: PH.bytesToHex(responderSpi).replace(/ /g, ""),
      nextPayload, nextPayloadName: payloadName(nextPayload),
      version, exchangeType, exchangeName: exchangeName(exchangeType), flags,
      initiator: !!(flags & 0x08), versionFlag: !!(flags & 0x10), response: !!(flags & 0x20),
      messageId, length, payloads, warnings
    };
  }

  function buildIkev2(input) {
    const source = input.payloads || [];
    const payloads = source.map((p, index) => {
      const value = toBytes(p.value);
      const bytes = new Uint8Array(4 + value.length);
      bytes[0] = index + 1 < source.length ? toInt(source[index + 1].type, "Next payload", 0, 255, 0) : 0;
      bytes[1] = p.critical ? 0x80 : 0;
      PH.put16be(bytes, 2, bytes.length);
      bytes.set(value, 4);
      return bytes;
    });
    const total = 28 + payloads.reduce((n, p) => n + p.length, 0);
    const bytes = new Uint8Array(total);
    const ispi = toBytes(input.initiatorSpi || "00".repeat(8));
    const rspi = toBytes(input.responderSpi || "00".repeat(8));
    if (ispi.length !== 8 || rspi.length !== 8) throw new Error("IKEv2 SPIs must be eight bytes each");
    bytes.set(ispi, 0);
    bytes.set(rspi, 8);
    bytes[16] = payloads.length ? toInt(source[0].type, "Next payload", 0, 255, 0) : 0;
    bytes[17] = 0x20;
    bytes[18] = toInt(input.exchangeType, "Exchange type", 0, 255, 34);
    bytes[19] = (input.initiator ? 0x08 : 0) | (input.response ? 0x20 : 0) | (input.versionFlag ? 0x10 : 0);
    PH.put32be(bytes, 20, toInt(input.messageId, "Message ID", 0, 4294967295, 0));
    PH.put32be(bytes, 24, total);
    let pos = 28;
    payloads.forEach((p) => {
      bytes.set(p, pos);
      pos += p.length;
    });
    return { bytes, length: total, exchangeType: input.exchangeType, payloads: payloads.length };
  }

  global.IPsecCodec = {
    AH_NEXT, IKE_EXCHANGE, IKE_PAYLOAD, ahNextName, exchangeName, payloadName,
    decodeAh, buildAh, decodeEsp, buildEsp, decodeIkev2, buildIkev2
  };
})(typeof window !== "undefined" ? window : globalThis);
