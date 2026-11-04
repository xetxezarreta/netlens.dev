/* ICMPv4 (RFC 792) codec — shared by the ICMP page and tests. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const TYPES = {
    0: { name: "Echo Reply", kind: "echo", rfc: "RFC 792", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    3: { name: "Destination Unreachable", kind: "error", rfc: "RFC 792 · RFC 1191 · RFC 4884", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    4: { name: "Source Quench", kind: "source-quench", rfc: "RFC 792 · deprecated by RFC 6633", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792", deprecated: "RFC 6633" },
    5: { name: "Redirect", kind: "redirect", rfc: "RFC 792", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    6: { name: "Alternate Host Address", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    8: { name: "Echo Request", kind: "echo", rfc: "RFC 792", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    9: { name: "Router Advertisement", kind: "router-advert", rfc: "RFC 1256", rfcUrl: "https://www.rfc-editor.org/rfc/rfc1256" },
    10: { name: "Router Solicitation", kind: "router-solicit", rfc: "RFC 1256", rfcUrl: "https://www.rfc-editor.org/rfc/rfc1256" },
    11: { name: "Time Exceeded", kind: "error", rfc: "RFC 792 · RFC 4884", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    12: { name: "Parameter Problem", kind: "parameter", rfc: "RFC 792 · RFC 4884", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    13: { name: "Timestamp Request", kind: "timestamp", rfc: "RFC 792", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    14: { name: "Timestamp Reply", kind: "timestamp", rfc: "RFC 792", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792" },
    15: { name: "Information Request", kind: "information", rfc: "RFC 792 · deprecated by RFC 6918", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792", deprecated: "RFC 6918" },
    16: { name: "Information Reply", kind: "information", rfc: "RFC 792 · deprecated by RFC 6918", rfcUrl: "https://www.rfc-editor.org/rfc/rfc792", deprecated: "RFC 6918" },
    17: { name: "Address Mask Request", kind: "address-mask", rfc: "RFC 950 · deprecated by RFC 6918", rfcUrl: "https://www.rfc-editor.org/rfc/rfc950", deprecated: "RFC 6918" },
    18: { name: "Address Mask Reply", kind: "address-mask", rfc: "RFC 950 · deprecated by RFC 6918", rfcUrl: "https://www.rfc-editor.org/rfc/rfc950", deprecated: "RFC 6918" },
    30: { name: "Traceroute", kind: "traceroute", rfc: "RFC 1393 · deprecated by RFC 6918", rfcUrl: "https://www.rfc-editor.org/rfc/rfc1393", deprecated: "RFC 6918" },
    31: { name: "Datagram Conversion Error", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    32: { name: "Mobile Host Redirect", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    33: { name: "IPv6 Where-Are-You", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    34: { name: "IPv6 I-Am-Here", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    35: { name: "Mobile Registration Request", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    36: { name: "Mobile Registration Reply", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    37: { name: "Domain Name Request", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    38: { name: "Domain Name Reply", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    39: { name: "SKIP", kind: "generic", rfc: "RFC 6918 · deprecated", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6918", deprecated: "RFC 6918" },
    40: { name: "Photuris", kind: "generic", rfc: "RFC 2521", rfcUrl: "https://www.rfc-editor.org/rfc/rfc2521" },
    41: { name: "Experimental Mobility", kind: "generic", rfc: "RFC 4065", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4065" },
    42: { name: "Extended Echo Request", kind: "extended-echo-request", rfc: "RFC 8335", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8335" },
    43: { name: "Extended Echo Reply", kind: "extended-echo-reply", rfc: "RFC 8335", rfcUrl: "https://www.rfc-editor.org/rfc/rfc8335" }
  };

  const CODES = {
    3: {
      0: "Network Unreachable",
      1: "Host Unreachable",
      2: "Protocol Unreachable",
      3: "Port Unreachable",
      4: "Fragmentation Needed and DF Set",
      5: "Source Route Failed",
      6: "Destination Network Unknown",
      7: "Destination Host Unknown",
      8: "Source Host Isolated",
      9: "Network Administratively Prohibited",
      10: "Host Administratively Prohibited",
      11: "Network Unreachable for TOS",
      12: "Host Unreachable for TOS",
      13: "Communication Administratively Prohibited",
      14: "Host Precedence Violation",
      15: "Precedence Cutoff in Effect"
    },
    5: {
      0: "Redirect for Network",
      1: "Redirect for Host",
      2: "Redirect for TOS and Network",
      3: "Redirect for TOS and Host"
    },
    11: {
      0: "TTL Exceeded in Transit",
      1: "Fragment Reassembly Time Exceeded"
    },
    12: {
      0: "Pointer Indicates Error",
      1: "Missing Required Option",
      2: "Bad Length"
    },
    42: { 0: "No Error" },
    43: {
      0: "No Error",
      1: "Malformed Query",
      2: "No Such Interface",
      3: "No Such Table Entry",
      4: "Multiple Interfaces Satisfy Query"
    }
  };

  const EXT_CLASSES = {
    0: "Reserved",
    1: "MPLS",
    2: "Experimental",
    3: "Interface Identification"
  };

  const IP_PROTOCOLS = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 43: "IPv6-Route",
    44: "IPv6-Frag", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 88: "EIGRP", 89: "OSPF", 94: "IPIP", 103: "PIM", 112: "VRRP",
    115: "L2TP", 132: "SCTP", 137: "MPLS-in-IP", 143: "Ethernet-in-IP"
  };

  function typeInfo(type) {
    const t = Number(type);
    return TYPES[t] || { name: "Type " + t, kind: "generic", rfc: "IANA ICMP parameters", rfcUrl: "https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml" };
  }

  function kindOf(type) { return typeInfo(type).kind; }

  function codeName(type, code) {
    const map = CODES[Number(type)];
    if (map && map[Number(code)] != null) return map[Number(code)];
    if (Number(code) === 0) return "No code";
    return "Unassigned code " + Number(code);
  }

  function protocolName(number) { return IP_PROTOCOLS[Number(number)] || "protocol " + Number(number); }

  function restDescription(type) {
    const kind = kindOf(type);
    if (kind === "echo" || kind === "timestamp" || kind === "information" || kind === "address-mask") {
      return "Identifier (16) + Sequence Number (16)";
    }
    if (kind === "error") {
      return Number(type) === 3
        ? "Unused (8) + Length (8) + Next-Hop MTU or unused (16)"
        : "Unused (8) + Length (8) + unused (16)";
    }
    if (kind === "source-quench") return "Unused (32)";
    if (kind === "redirect") return "Gateway IPv4 address (32)";
    if (kind === "parameter") return "Pointer (8) + Length (8) + unused (16)";
    if (kind === "router-advert") return "Num Addrs (8) + Addr Entry Size (8) + Lifetime (16)";
    if (kind === "router-solicit") return "Reserved (32)";
    if (kind === "extended-echo-request") return "Identifier (16) + Sequence (8) + Reserved (7) + L (1)";
    if (kind === "extended-echo-reply") return "Identifier (16) + Sequence (8) + State (3) + Res (2) + A (1) + 4 (1) + 6 (1)";
    if (kind === "traceroute") return "ID (16) + hop counts or type-specific use (16)";
    return "Type-specific / unused (32)";
  }

  function bodyDescription(type) {
    const kind = kindOf(type);
    if (kind === "echo") return "Echo payload (arbitrary length)";
    if (kind === "error" || kind === "source-quench" || kind === "redirect" || kind === "parameter") {
      return "Original IPv4 header + at least 8 bytes of the invoking datagram";
    }
    if (kind === "timestamp") return "Originate, receive and transmit timestamps (12 bytes)";
    if (kind === "address-mask") return "4-byte subnet mask";
    if (kind === "router-advert") return "Router address / preference entries";
    if (kind === "router-solicit") return "No body";
    if (kind === "extended-echo-request" || kind === "extended-echo-reply") return "ICMP extension structure (RFC 4884)";
    return "Type-specific body / data";
  }

  function timestampText(ms) {
    const value = Number(ms) >>> 0;
    const day = 86400000;
    if (value >= day) return value + " ms (outside a 24-hour day)";
    const h = Math.floor(value / 3600000);
    const m = Math.floor((value % 3600000) / 60000);
    const s = Math.floor((value % 60000) / 1000);
    const milli = value % 1000;
    return String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":" +
      String(s).padStart(2, "0") + "." + String(milli).padStart(3, "0") + " UTC";
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

  function macString(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(":");
  }

  function parseRest(type, code, rest, warnings) {
    const kind = kindOf(type);
    const out = {};
    if (kind === "echo" || kind === "timestamp" || kind === "information" || kind === "address-mask") {
      out.identifier = PH.u16be(rest, 0);
      out.sequence = PH.u16be(rest, 2);
    } else if (kind === "error") {
      out.unused = rest[0];
      out.lengthWords = rest[1];
      if (Number(type) === 3 && Number(code) === 4) out.nextHopMtu = PH.u16be(rest, 2);
      else out.unused16 = PH.u16be(rest, 2);
    } else if (kind === "source-quench") {
      out.unused = PH.u32be(rest, 0);
    } else if (kind === "redirect") {
      out.gateway = PH.ipv4String(rest, 0);
    } else if (kind === "parameter") {
      out.pointer = rest[0];
      out.lengthWords = rest[1];
      out.unused16 = PH.u16be(rest, 2);
    } else if (kind === "router-advert") {
      out.numAddrs = rest[0];
      out.entrySize = rest[1];
      out.lifetime = PH.u16be(rest, 2);
    } else if (kind === "router-solicit") {
      out.reserved = PH.u32be(rest, 0);
    } else if (kind === "extended-echo-request") {
      out.identifier = PH.u16be(rest, 0);
      out.sequence = rest[2];
      out.reserved7 = (rest[3] >> 1) & 0x7f;
      out.local = rest[3] & 1;
    } else if (kind === "extended-echo-reply") {
      out.identifier = PH.u16be(rest, 0);
      out.sequence = rest[2];
      out.state = (rest[3] >> 5) & 7;
      out.reserved2 = (rest[3] >> 3) & 3;
      out.active = (rest[3] >> 2) & 1;
      out.ipv4 = (rest[3] >> 1) & 1;
      out.ipv6 = rest[3] & 1;
    } else if (kind === "traceroute") {
      out.id = PH.u16be(rest, 0);
      out.outboundHops = PH.u16be(rest, 2);
    } else {
      out.unused = PH.u32be(rest, 0);
    }
    return out;
  }

  function parseRestSummary(info) {
    const parts = [];
    if (info.identifier != null) parts.push("id 0x" + PH.hex(info.identifier, 4));
    if (info.sequence != null) parts.push("seq " + info.sequence);
    if (info.id != null) parts.push("id 0x" + PH.hex(info.id, 4));
    if (info.outboundHops != null) parts.push("out " + info.outboundHops);
    if (info.lengthWords != null) parts.push("len " + info.lengthWords + " word" + (info.lengthWords === 1 ? "" : "s"));
    if (info.nextHopMtu != null) parts.push("MTU " + info.nextHopMtu);
    if (info.pointer != null) parts.push("ptr " + info.pointer);
    if (info.gateway) parts.push("gateway " + info.gateway);
    if (info.numAddrs != null) parts.push(info.numAddrs + " addr");
    if (info.entrySize != null) parts.push("entry " + info.entrySize * 4 + " B");
    if (info.lifetime != null) parts.push("lifetime " + info.lifetime);
    if (info.local != null) parts.push("L=" + info.local);
    if (info.state != null) parts.push("state " + info.state);
    if (info.active != null) parts.push("A=" + info.active + " 4=" + info.ipv4 + " 6=" + info.ipv6);
    if (info.reserved != null && !parts.length) parts.push("reserved 0x" + PH.hex(info.reserved, 8));
    if (info.unused != null && !parts.length) parts.push("unused 0x" + PH.hex(info.unused, 8));
    return parts.length ? parts.join(" · ") : "unused";
  }

  function buildIcmp(input) {
    const type = toInt(input.type, "Type", 0, 255);
    const code = toInt(input.code, "Code", 0, 255, 0);
    const data = toBytes(input.data);
    const kind = kindOf(type);
    const rest = new Uint8Array(4);
    const lengthWords = input.lengthWords == null ? 0 : toInt(input.lengthWords, "Length", 0, 255);

    if (kind === "echo" || kind === "timestamp" || kind === "information" || kind === "address-mask") {
      PH.put16be(rest, 0, toInt(input.identifier, "Identifier", 0, 65535, 0));
      PH.put16be(rest, 2, toInt(input.sequence, "Sequence Number", 0, 65535, 0));
    } else if (kind === "error") {
      if (Number(type) === 3) {
        rest[0] = 0;
        rest[1] = lengthWords;
        if (Number(code) === 4) PH.put16be(rest, 2, toInt(input.nextHopMtu, "Next-Hop MTU", 0, 65535, 1500));
      } else {
        rest[0] = 0;
        rest[1] = lengthWords;
      }
    } else if (kind === "redirect") {
      rest.set(PH.parseIPv4(input.gateway || "0.0.0.0"), 0);
    } else if (kind === "parameter") {
      rest[0] = toInt(input.pointer, "Pointer", 0, 255, 0);
      rest[1] = lengthWords;
    } else if (kind === "router-advert") {
      rest[0] = toInt(input.numAddrs, "Number of Addresses", 0, 255, 0);
      rest[1] = toInt(input.entrySize, "Address Entry Size", 0, 255, 2);
      PH.put16be(rest, 2, toInt(input.lifetime, "Lifetime", 0, 65535, 1800));
    } else if (kind === "extended-echo-request") {
      PH.put16be(rest, 0, toInt(input.identifier, "Identifier", 0, 65535, 0));
      rest[2] = toInt(input.sequence, "Sequence Number", 0, 255, 0);
      rest[3] = ((toInt(input.reserved, "Reserved", 0, 127, 0) & 0x7f) << 1) | (input.local ? 1 : 0);
    } else if (kind === "extended-echo-reply") {
      PH.put16be(rest, 0, toInt(input.identifier, "Identifier", 0, 65535, 0));
      rest[2] = toInt(input.sequence, "Sequence Number", 0, 255, 0);
      rest[3] = ((toInt(input.state, "State", 0, 7, 0) & 7) << 5) |
        ((toInt(input.reserved, "Reserved", 0, 3, 0) & 3) << 3) |
        (input.active ? 4 : 0) | (input.ipv4 ? 2 : 0) | (input.ipv6 ? 1 : 0);
    } else if (kind === "traceroute") {
      PH.put16be(rest, 0, toInt(input.identifier, "ID Number", 0, 65535, 0));
      PH.put16be(rest, 2, toInt(input.sequence, "Outbound Hop Count", 0, 65535, 0));
    } else if (input.rest != null) {
      const custom = toBytes(input.rest);
      if (custom.length !== 4) throw new Error("Rest of header must be exactly 4 bytes");
      rest.set(custom);
    }

    const header = new Uint8Array(8);
    header[0] = type;
    header[1] = code;
    header.set(rest, 4);
    const bytes = PH.concatBytes(header, data);
    const checksum = PH.checksum16(bytes);
    PH.put16be(bytes, 2, checksum);
    const info = typeInfo(type);
    return {
      bytes, type, code, typeName: info.name, codeName: codeName(type, code), kind,
      checksum, headerBytes: bytes.slice(0, 8), restBytes: rest, dataBytes: data,
      dataLength: data.length, messageLength: bytes.length
    };
  }

  function decodeInnerIpv4(bytes, warnings) {
    const warn = warnings || [];
    if (bytes.length < 20) throw new Error("embedded datagram is shorter than an IPv4 header");
    const version = bytes[0] >> 4;
    const ihl = bytes[0] & 15;
    if (version !== 4) throw new Error("embedded datagram does not start with an IPv4 version nibble");
    if (ihl < 5) throw new Error("embedded IPv4 IHL is " + ihl + "; minimum is 5");
    const headerLen = ihl * 4;
    if (headerLen > 60) throw new Error("embedded IPv4 header exceeds 60 bytes");
    if (bytes.length < headerLen) throw new Error("embedded IPv4 header is truncated");
    const totalLength = PH.u16be(bytes, 2);
    const protocol = bytes[9];
    const ttl = bytes[8];
    const id = PH.u16be(bytes, 4);
    const flagsWord = PH.u16be(bytes, 6);
    const declared = totalLength || bytes.length;
    if (totalLength === 0) warn.push("Embedded IPv4 Total Length is zero; using the captured length");
    else if (totalLength < headerLen) warn.push("Embedded IPv4 Total Length " + totalLength + " is smaller than its " + headerLen + "-byte header");
    else if (totalLength > bytes.length) warn.push("Embedded IPv4 datagram is truncated: Total Length " + totalLength + ", captured " + bytes.length);
    const payloadEnd = totalLength >= headerLen ? Math.min(bytes.length, totalLength) : bytes.length;
    const payload = bytes.subarray(headerLen, payloadEnd);
    const header = bytes.subarray(0, headerLen);
    const checksumOk = PH.checksumValid(header);
    if (!checksumOk) warn.push("Embedded IPv4 header checksum is invalid");
    let ports = null;
    if ((protocol === 6 || protocol === 17) && payload.length >= 4) {
      ports = { source: PH.u16be(payload, 0), destination: PH.u16be(payload, 2) };
      if (protocol === 17 && payload.length >= 6) ports.udpLength = PH.u16be(payload, 4);
    }
    return {
      version, ihl, headerLen, totalLength, declaredTotal: declared, ttl, id, flagsWord,
      protocol, protocolName: protocolName(protocol), src: PH.ipv4String(bytes, 12), dst: PH.ipv4String(bytes, 16),
      checksum: PH.u16be(header, 10), checksumOk, header, payload, payloadLength: payload.length,
      capturedLength: bytes.length, truncated: totalLength > bytes.length, ports,
      headerOnly: payloadEnd <= headerLen
    };
  }

  function parseExtensions(bytes, warnings) {
    const warn = warnings || [];
    if (!bytes || bytes.length < 4) {
      warn.push("ICMP extension structure is shorter than its 4-byte header");
      return null;
    }
    const version = bytes[0] >> 4;
    const reserved = ((bytes[0] & 15) << 8) | bytes[1];
    const checksum = PH.u16be(bytes, 2);
    if (version !== 2) {
      warn.push("ICMP extension version is " + version + ", not 2");
      return null;
    }
    const copy = bytes.slice();
    copy[2] = 0;
    copy[3] = 0;
    const expected = PH.checksum16(copy);
    const checksumOk = checksum === 0 || checksum === expected || PH.checksumValid(bytes);
    if (checksum !== 0 && !checksumOk) warn.push("ICMP extension checksum is invalid");
    const objects = [];
    let offset = 4;
    while (offset + 4 <= bytes.length) {
      const length = PH.u16be(bytes, offset);
      const classNum = bytes[offset + 2];
      const cType = bytes[offset + 3];
      if (length < 4 || offset + length > bytes.length) {
        warn.push("ICMP extension object at offset " + offset + " has invalid length " + length);
        break;
      }
      objects.push({
        offset, length, classNum, cType,
        className: EXT_CLASSES[classNum] || (classNum >= 0xf7 ? "Private Use" : "Class " + classNum),
        data: bytes.slice(offset + 4, offset + length)
      });
      offset += length;
    }
    if (offset < bytes.length) warn.push((bytes.length - offset) + " trailing byte(s) after the last ICMP extension object");
    return { version, reserved, checksum, checksumOk, objects, length: bytes.length, bytes };
  }

  function parseEmbedded(data, rest, warnings) {
    const warn = warnings;
    let originalLength = null;
    if (rest && rest.lengthWords > 0) {
      originalLength = Math.min(data.length, rest.lengthWords * 4);
      if (rest.lengthWords * 4 > data.length) warn.push("RFC 4884 Length says " + rest.lengthWords * 4 + " original-datagram bytes but only " + data.length + " are captured");
    }
    let inner = null;
    try {
      inner = decodeInnerIpv4(originalLength == null ? data : data.subarray(0, originalLength), warn);
    } catch (err) {
      warn.push("Original datagram: " + err.message);
    }
    if (originalLength == null) {
      if (inner) {
        const end = inner.declaredTotal >= inner.headerLen ? Math.min(data.length, inner.declaredTotal) : data.length;
        originalLength = end;
      } else {
        originalLength = data.length;
      }
    }
    let extensions = null;
    const tail = data.subarray(originalLength);
    if (tail.length) {
      if ((tail[0] >> 4) === 2) extensions = parseExtensions(tail, warn);
      else if (!tail.every((b) => b === 0)) warn.push(tail.length + " trailing byte(s) after the original datagram are neither zero padding nor an RFC 4884 extension");
    }
    return { inner, extensions, originalLength };
  }

  function decodeIcmp(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 8) throw new Error("ICMP needs at least 8 bytes for its common header");
    const type = bytes[0];
    const code = bytes[1];
    const checksum = PH.u16be(bytes, 2);
    const restBytes = bytes.slice(4, 8);
    const data = bytes.slice(8);
    const info = typeInfo(type);
    const warnings = [];
    const checksumOk = PH.checksumValid(bytes);
    const copy = bytes.slice();
    copy[2] = 0;
    copy[3] = 0;
    const expectedChecksum = PH.checksum16(copy);
    if (!checksumOk) warnings.push("ICMP checksum is invalid (expected 0x" + PH.hex(expectedChecksum, 4) + ")");
    if (!TYPES[type]) warnings.push("ICMP type " + type + " is unassigned or unknown to this reference");
    if (TYPES[type] && TYPES[type].deprecated) warnings.push("ICMP type " + type + " is deprecated by " + TYPES[type].deprecated);
    if (TYPES[type] && CODES[type] && CODES[type][code] == null && code !== 0) warnings.push("Code " + code + " is unassigned for type " + type);
    if (info.kind === "echo" && code !== 0) warnings.push("Echo messages normally use code 0");

    const rest = parseRest(type, code, restBytes, warnings);
    if (rest.nextHopMtu === 0) warnings.push("Fragmentation Needed carries a zero Next-Hop MTU");
    else if (rest.nextHopMtu != null && rest.nextHopMtu < 68) warnings.push("Next-Hop MTU " + rest.nextHopMtu + " is below the IPv4 minimum of 68 bytes");

    let timestamp = null;
    let mask = null;
    let router = null;
    let embedded = null;

    if (info.kind === "timestamp") {
      if (data.length < 12) warnings.push("Timestamp message needs 12 timestamp bytes; only " + data.length + " captured");
      if (data.length >= 12) {
        timestamp = {
          originate: PH.u32be(data, 0), receive: PH.u32be(data, 4), transmit: PH.u32be(data, 8),
          originateText: timestampText(PH.u32be(data, 0)),
          receiveText: timestampText(PH.u32be(data, 4)),
          transmitText: timestampText(PH.u32be(data, 8))
        };
      }
      if (data.length > 12) warnings.push((data.length - 12) + " trailing byte(s) after the timestamp fields");
    } else if (info.kind === "address-mask") {
      if (data.length < 4) warnings.push("Address Mask message needs a 4-byte subnet mask; only " + data.length + " captured");
      if (data.length >= 4) mask = PH.ipv4String(data, 0);
      if (data.length > 4) warnings.push((data.length - 4) + " trailing byte(s) after the subnet mask");
    } else if (info.kind === "router-advert") {
      const entries = [];
      const entryBytes = Math.max(8, (rest.entrySize || 2) * 4);
      for (let i = 0; i < (rest.numAddrs || 0); i++) {
        const offset = i * entryBytes;
        if (offset + 8 > data.length) {
          warnings.push("Router Advertisement declares " + rest.numAddrs + " address(es) but only " + Math.floor(data.length / entryBytes) + " fit in the captured body");
          break;
        }
        entries.push({ address: PH.ipv4String(data, offset), preference: PH.u32be(data, offset + 4) });
      }
      router = { entries, entryBytes };
      if (data.length % 4) warnings.push("Router Advertisement body is not 32-bit aligned");
    } else if (info.kind === "error" || info.kind === "source-quench" || info.kind === "redirect" || info.kind === "parameter") {
      embedded = parseEmbedded(data, rest, warnings);
      if (!embedded.inner && data.length) warnings.push("Error message does not contain a parseable original IPv4 datagram");
      else if (embedded.inner && embedded.originalLength < 28) warnings.push("Original datagram is shorter than the RFC 792 minimum of 28 bytes (IPv4 header + 8 data bytes)");
    }

    const restSummary = parseRestSummary(rest);
    return {
      bytes, type, code, typeName: info.name, codeName: codeName(type, code), kind: info.kind,
      rfc: info.rfc, rfcUrl: info.rfcUrl, deprecated: info.deprecated || null,
      checksum, expectedChecksum, checksumOk, headerBytes: bytes.slice(0, 8), restBytes, data,
      dataLength: data.length, messageLength: bytes.length, rest, restSummary,
      identifier: rest.identifier, sequence: rest.sequence, nextHopMtu: rest.nextHopMtu,
      gateway: rest.gateway, pointer: rest.pointer, lengthWords: rest.lengthWords,
      timestamp, mask, router, embedded: embedded ? embedded.inner : null,
      embeddedLength: embedded ? embedded.originalLength : 0, extensions: embedded ? embedded.extensions : null,
      warnings
    };
  }

  function parseEthernet(bytes) {
    if (bytes.length < 34) return null;
    let offset = 12;
    let type = PH.u16be(bytes, offset);
    const vlanTags = [];
    while ((type === 0x8100 || type === 0x88a8) && bytes.length >= offset + 6) {
      const tci = PH.u16be(bytes, offset + 2);
      vlanTags.push({ tpid: type, pcp: (tci >>> 13) & 7, dei: (tci >>> 12) & 1, vid: tci & 0xfff, tci });
      offset += 4;
      type = PH.u16be(bytes, offset);
    }
    if (type !== 0x0800) return null;
    const ipStart = offset + 2;
    if (bytes.length < ipStart + 20 || (bytes[ipStart] >> 4) !== 4) return null;
    return {
      dstMac: macString(bytes.subarray(0, 6)), srcMac: macString(bytes.subarray(6, 12)),
      etherType: type, vlanTags, headerLen: ipStart, ipStart
    };
  }

  function decodeIpv4At(bytes, offset) {
    if (bytes.length < offset + 20) throw new Error("Need at least 20 bytes of IPv4 header");
    const h = bytes.subarray(offset);
    const version = h[0] >> 4;
    if (version !== 4) throw new Error("IPv4 version nibble is " + version);
    const ihl = h[0] & 15;
    if (ihl < 5) throw new Error("IPv4 IHL is " + ihl + "; minimum is 5");
    const headerLen = ihl * 4;
    if (headerLen > 60) throw new Error("IPv4 header exceeds 60 bytes");
    if (h.length < headerLen) throw new Error("IPv4 header is truncated");
    const totalLength = PH.u16be(h, 2);
    const protocol = h[9];
    const header = h.subarray(0, headerLen);
    const checksumOk = PH.checksumValid(header);
    const warnings = [];
    if (!checksumOk) warnings.push("IPv4 header checksum is invalid");
    if (totalLength === 0) warnings.push("IPv4 Total Length is zero (possible TSO/GSO capture)");
    else if (totalLength < headerLen) warnings.push("IPv4 Total Length " + totalLength + " is smaller than its " + headerLen + "-byte header");
    else if (totalLength > h.length) warnings.push("IPv4 Total Length " + totalLength + " exceeds the " + h.length + " captured bytes");
    const payloadEnd = totalLength >= headerLen ? Math.min(h.length, totalLength) : h.length;
    const payload = h.subarray(headerLen, payloadEnd);
    const flagsWord = PH.u16be(h, 6);
    return {
      offset, headerLen, totalLength, protocol, protocolName: protocolName(protocol),
      ttl: h[8], id: PH.u16be(h, 4), flagsWord, df: (flagsWord >> 14) & 1,
      mf: (flagsWord >> 13) & 1, fragmentOffset: flagsWord & 0x1fff,
      checksum: PH.u16be(h, 10), checksumOk, src: PH.ipv4String(h, 12), dst: PH.ipv4String(h, 16),
      header, payload, payloadLength: payload.length, warnings
    };
  }

  function decodePacket(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const ethernet = parseEthernet(bytes);
    let ip = null;
    let icmpOffset = 0;

    if (ethernet) {
      ip = decodeIpv4At(bytes, ethernet.ipStart);
      icmpOffset = ethernet.ipStart + ip.headerLen;
    } else if (bytes.length >= 20 && (bytes[0] >> 4) === 4) {
      ip = decodeIpv4At(bytes, 0);
      icmpOffset = ip.headerLen;
    } else {
      if (bytes.length >= 40 && (bytes[0] >> 4) === 6) {
        throw new Error("IPv6 packet detected. ICMPv6 is a different protocol (IPv6 next header 58, RFC 4443) and is not parsed here.");
      }
      if (bytes.length < 8) throw new Error("Need at least 8 bytes of ICMP message");
      return {
        bytes, icmp: decodeIcmp(bytes), ip: null, ethernet: null,
        icmpOffset: 0, icmpLength: bytes.length, detectedAs: "raw ICMP message"
      };
    }

    if (ip.protocol !== 1) throw new Error("IPv4 Protocol is " + ip.protocol + " (" + ip.protocolName + "), not 1 (ICMP)");
    if (ip.fragmentOffset !== 0) throw new Error("ICMP must be in the first IPv4 fragment; fragment offset is " + ip.fragmentOffset * 8 + " bytes");
    const warnings = ip.warnings.slice();
    if (ip.mf) warnings.push("IPv4 packet has MF set; this is only the first fragment and the ICMP message may be truncated");
    if (!ip.payload.length) throw new Error("IPv4 packet has no ICMP payload");
    const icmp = decodeIcmp(ip.payload);
    icmp.warnings.unshift(...warnings);
    return {
      bytes, icmp, ip, ethernet,
      icmpOffset, icmpLength: ip.payload.length,
      detectedAs: ethernet ? "Ethernet frame with IPv4/ICMP" : "IPv4 packet with ICMP"
    };
  }

  function wrapIPv4(icmpBytes, input) {
    const opts = input || {};
    const payload = icmpBytes instanceof Uint8Array ? icmpBytes : Uint8Array.from(icmpBytes);
    if (!payload.length) throw new Error("ICMP payload is empty");
    if (payload.length > 65515) throw new Error("ICMP message exceeds the IPv4 maximum payload of 65515 bytes");
    const src = typeof opts.src === "string" ? PH.parseIPv4(opts.src) : opts.src;
    const dst = typeof opts.dst === "string" ? PH.parseIPv4(opts.dst) : opts.dst;
    if (!src || src.length !== 4 || !dst || dst.length !== 4) throw new Error("Source and destination must be IPv4 addresses");
    const ttl = toInt(opts.ttl, "TTL", 0, 255, 64);
    const id = toInt(opts.id, "Identification", 0, 65535, 0);
    const dscp = toInt(opts.dscp, "DSCP", 0, 63, 0);
    const ecn = toInt(opts.ecn, "ECN", 0, 3, 0);
    const frag = toInt(opts.fragmentOffset, "Fragment Offset", 0, 8191, 0);
    const totalLength = 20 + payload.length;
    const bytes = new Uint8Array(totalLength);
    bytes[0] = 0x45;
    bytes[1] = ((dscp & 0x3f) << 2) | (ecn & 3);
    PH.put16be(bytes, 2, totalLength);
    PH.put16be(bytes, 4, id);
    PH.put16be(bytes, 6, ((opts.df === false ? 0 : 1) << 14) | ((opts.mf ? 1 : 0) << 13) | frag);
    bytes[8] = ttl;
    bytes[9] = 1;
    PH.put16be(bytes, 10, 0);
    bytes.set(src, 12);
    bytes.set(dst, 16);
    bytes.set(payload, 20);
    const checksum = PH.checksum16(bytes.subarray(0, 20));
    PH.put16be(bytes, 10, checksum);
    return {
      bytes, header: bytes.slice(0, 20), checksum, headerLen: 20, totalLength,
      src: PH.ipv4String(src), dst: PH.ipv4String(dst), ttl, id
    };
  }

  global.ICMPCodec = {
    TYPES, CODES, EXT_CLASSES, IP_PROTOCOLS, typeInfo, kindOf, codeName, protocolName,
    restDescription, bodyDescription, restSummary: parseRestSummary, timestampText,
    buildIcmp, decodeIcmp, decodePacket, decodeInnerIpv4, decodeIpv4At, parseExtensions,
    wrapIPv4, parseEthernet
  };
})(window);
