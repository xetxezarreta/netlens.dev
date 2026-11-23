/* GRE (RFC 2784) and GRE with extensions (RFC 2890). PPTP GRE (RFC 2637)
   is recognised but its optional fields are reported rather than guessed. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const PROTOCOLS = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6", 0x6558: "Transparent Ethernet Bridging",
    0x8847: "MPLS unicast", 0x8848: "MPLS multicast", 0x880b: "PPP", 0x883e: "LLDP",
    0x88be: "ERSPAN Type II", 0x22eb: "ERSPAN Type III", 0x8100: "802.1Q VLAN", 0x8809: "Slow Protocols"
  };

  function protocolName(type) { return PROTOCOLS[type] || "EtherType 0x" + PH.hex(type, 4); }

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

  function decodeGre(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 4) throw new Error("GRE needs at least its 4-byte base header");
    const flags = bytes[0];
    const flags2 = bytes[1];
    const checksumPresent = !!(flags & 0x80);
    const routingPresent = !!(flags & 0x40);
    const keyPresent = !!(flags & 0x20);
    const sequencePresent = !!(flags & 0x10);
    const strictSourceRoute = !!(flags & 0x08);
    const recursion = (flags & 0x07);
    const version = flags2 & 0x07;
    const protocol = PH.u16be(bytes, 2);
    const warnings = [];
    if (version !== 0 && version !== 1) warnings.push("GRE version " + version + " is not 0 (GRE) or 1 (PPTP)");
    if (recursion !== 0) warnings.push("Recursion control is " + recursion + "; GRE recursion is not supported by most stacks");
    if (strictSourceRoute) warnings.push("Strict source route bit is set; source routing is obsolete");

    let offset = 4;
    const out = {
      bytes, flags, flags2, checksumPresent, routingPresent, keyPresent, sequencePresent,
      strictSourceRoute, recursion, version, protocol, protocolName: protocolName(protocol),
      headerLength: 0, checksum: null, reserved: null, key: null, sequence: null,
      routing: null, warnings, payload: new Uint8Array(0), checksumState: "absent"
    };

    if (version === 1) {
      /* PPTP variant: Payload Length, Call ID, optional Sequence and Ack. */
      if (bytes.length < 8) throw new Error("PPTP GRE needs at least 8 bytes");
      out.pptp = {
        payloadLength: PH.u16be(bytes, 4),
        callId: PH.u16be(bytes, 6)
      };
      offset = 8;
      if (sequencePresent) {
        if (bytes.length < 12) throw new Error("PPTP GRE sequence field is truncated");
        out.sequence = PH.u32be(bytes, 8);
        offset = 12;
      }
      if (checksumPresent) {
        if (bytes.length < offset + 4) throw new Error("PPTP GRE acknowledgment field is truncated");
        out.ack = PH.u32be(bytes, offset);
        offset += 4;
      }
      out.headerLength = offset;
      out.payload = bytes.subarray(offset);
      return out;
    }

    if (checksumPresent || routingPresent) {
      if (bytes.length < offset + 4) throw new Error("GRE checksum/reserved field is truncated");
      out.checksum = PH.u16be(bytes, offset);
      out.reserved = PH.u16be(bytes, offset + 2);
      if (out.reserved !== 0) warnings.push("GRE reserved1 field is non-zero (" + out.reserved + ")");
      offset += 4;
    }
    if (keyPresent) {
      if (bytes.length < offset + 4) throw new Error("GRE key field is truncated");
      out.key = PH.u32be(bytes, offset);
      offset += 4;
    }
    if (sequencePresent) {
      if (bytes.length < offset + 4) throw new Error("GRE sequence field is truncated");
      out.sequence = PH.u32be(bytes, offset);
      offset += 4;
    }
    if (routingPresent) {
      if (bytes.length < offset + 4) throw new Error("GRE routing field is truncated");
      out.routing = {
        addressFamily: PH.u16be(bytes, offset),
        sreOffset: bytes[offset + 2],
        sreLength: bytes[offset + 3]
      };
      warnings.push("GRE routing information is present; its SRE length is not self-describing, so the payload offset is approximate");
      offset += 4 + out.routing.sreOffset;
    }
    out.headerLength = offset;
    out.payload = bytes.subarray(offset);
    out.payloadLength = out.payload.length;
    if (checksumPresent) {
      const copy = bytes.slice();
      copy[4] = 0;
      copy[5] = 0;
      const expected = PH.checksum16(copy);
      out.expectedChecksum = expected;
      out.checksumState = expected === out.checksum ? "valid" : "invalid";
      if (out.checksumState === "invalid") warnings.push("GRE checksum is invalid (expected 0x" + PH.hex(expected, 4) + ")");
    }
    return out;
  }

  function buildGre(input) {
    const version = toInt(input.version, "Version", 0, 1, 0);
    const protocol = toInt(input.protocol, "Protocol type", 0, 65535, 0x0800);
    const payload = toBytes(input.payload);
    if (version === 1) {
      const keyPresent = input.key != null && input.key !== "";
      const sequencePresent = input.sequence != null && input.sequence !== "";
      const ackPresent = input.ack != null && input.ack !== "";
      const bytes = new Uint8Array(8 + (sequencePresent ? 4 : 0) + (ackPresent ? 4 : 0) + payload.length);
      bytes[0] = 0x20 | (sequencePresent ? 0x10 : 0) | (input.checksum ? 0x80 : 0);
      bytes[1] = 0x01;
      PH.put16be(bytes, 2, protocol);
      PH.put16be(bytes, 4, toInt(input.payloadLength, "Payload length", 0, 65535, payload.length));
      PH.put16be(bytes, 6, toInt(input.callId, "Call ID", 0, 65535, 0));
      let off = 8;
      if (sequencePresent) { PH.put32be(bytes, off, toInt(input.sequence, "Sequence", 0, 4294967295, 0)); off += 4; }
      if (ackPresent) { PH.put32be(bytes, off, toInt(input.ack, "Acknowledgment", 0, 4294967295, 0)); off += 4; }
      bytes.set(payload, off);
      return { bytes, headerLength: off, payload, version, protocol, protocolName: protocolName(protocol), checksumState: "not-used" };
    }
    const checksumPresent = !!input.checksum;
    const keyPresent = input.key != null && input.key !== "";
    const sequencePresent = input.sequence != null && input.sequence !== "";
    const routingPresent = !!input.routing;
    const head = 4 + ((checksumPresent || routingPresent) ? 4 : 0) + (keyPresent ? 4 : 0) + (sequencePresent ? 4 : 0) + (routingPresent ? 4 : 0);
    const bytes = new Uint8Array(head + payload.length);
    bytes[0] = (checksumPresent ? 0x80 : 0) | (routingPresent ? 0x40 : 0) | (keyPresent ? 0x20 : 0) | (sequencePresent ? 0x10 : 0);
    bytes[1] = version;
    PH.put16be(bytes, 2, protocol);
    let off = 4;
    if (checksumPresent || routingPresent) {
      PH.put16be(bytes, off, 0);
      off += 4;
    }
    if (keyPresent) { PH.put32be(bytes, off, toInt(input.key, "Key", 0, 4294967295, 0)); off += 4; }
    if (sequencePresent) { PH.put32be(bytes, off, toInt(input.sequence, "Sequence", 0, 4294967295, 0)); off += 4; }
    if (routingPresent) {
      PH.put16be(bytes, off, toInt(input.addressFamily, "Address family", 0, 65535, 0x0800));
      bytes[off + 2] = 4;
      bytes[off + 3] = 0;
      off += 4;
    }
    bytes.set(payload, off);
    let checksumValue = null;
    if (checksumPresent) {
      checksumValue = PH.checksum16(bytes);
      PH.put16be(bytes, 4, checksumValue);
    }
    return {
      bytes, headerLength: off, payload, payloadLength: payload.length,
      version, protocol, protocolName: protocolName(protocol), checksum: checksumValue,
      checksumState: checksumPresent ? "built" : "absent", key: keyPresent ? input.key : null,
      sequence: sequencePresent ? input.sequence : null
    };
  }

  global.GRECodec = { PROTOCOLS, protocolName, decodeGre, buildGre };
})(typeof window !== "undefined" ? window : globalThis);
