/* IPv6 (RFC 8200) base header, extension chain and address codec. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const NEXT_HEADERS = {
    0: "Hop-by-Hop Options", 1: "ICMPv4", 2: "IGMPv4", 4: "IP-in-IP",
    6: "TCP", 17: "UDP", 41: "IPv6 encapsulation", 43: "Routing", 44: "Fragment",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "No Next Header",
    60: "Destination Options", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
    135: "Mobility", 136: "UDPLite", 137: "MPLS-in-IP", 139: "HIP", 140: "Shim6",
    143: "Ethernet-in-IP", 253: "Experimental", 254: "Experimental", 255: "Reserved"
  };
  const EXTENSION_HEADERS = new Set([0, 43, 44, 51, 60]);
  const OPTION_NAMES = {
    0: "Pad1", 1: "PadN", 4: "Tunnel Encapsulation Limit", 5: "Router Alert",
    194: "Jumbo Payload", 201: "Home Address"
  };
  const ROUTING_TYPES = {
    0: "Source Route (deprecated)", 2: "Mobile IPv6", 4: "Segment Routing Header"
  };
  const MCAST_SCOPES = {
    0: "reserved", 1: "interface-local", 2: "link-local", 3: "realm-local",
    4: "admin-local", 5: "site-local", 8: "organization-local", 14: "global", 15: "reserved"
  };
  const ICMPV6_TYPES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
    133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation",
    136: "Neighbor Advertisement", 137: "Redirect", 138: "Router Renumbering",
    139: "Node Information Query", 140: "Node Information Reply"
  };

  function nextHeaderName(n) { return NEXT_HEADERS[Number(n)] || "Next Header " + Number(n); }
  function protocolName(n) { return nextHeaderName(n); }

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

  function parseDotted(text) {
    const parts = String(text).trim().split(".");
    if (parts.length !== 4) throw new Error("IPv4 tail needs four octets");
    return parts.map((part) => {
      if (!/^\d{1,3}$/.test(part)) throw new Error("Invalid IPv4 octet: " + part);
      const n = Number(part);
      if (n > 255) throw new Error("IPv4 octet out of range: " + part);
      return n;
    });
  }

  function parseIPv6Info(text) {
    let s = String(text == null ? "" : text).trim();
    if (!s) throw new Error("IPv6 address is empty");
    let prefix = null;
    const slash = s.indexOf("/");
    if (slash !== -1) {
      if (s.indexOf("/", slash + 1) !== -1) throw new Error("IPv6 address has more than one prefix length");
      const p = s.slice(slash + 1);
      if (!/^\d{1,3}$/.test(p)) throw new Error("Prefix length must be 0–128");
      prefix = Number(p);
      if (prefix < 0 || prefix > 128) throw new Error("Prefix length must be 0–128");
      s = s.slice(0, slash);
    }
    let zone = null;
    const pct = s.indexOf("%");
    if (pct !== -1) {
      zone = s.slice(pct + 1);
      if (!zone) throw new Error("Zone identifier is empty");
      s = s.slice(0, pct);
    }
    if (s.indexOf("%") !== -1) throw new Error("IPv6 address has more than one zone identifier");
    if (s.indexOf(".") !== -1) {
      const lastColon = s.lastIndexOf(":");
      if (lastColon < 0) throw new Error("IPv4 tail must follow an IPv6 colon");
      const v4 = parseDotted(s.slice(lastColon + 1));
      const hi = ((v4[0] << 8) | v4[1]).toString(16);
      const lo = ((v4[2] << 8) | v4[3]).toString(16);
      s = s.slice(0, lastColon) + ":" + hi + ":" + lo;
    }
    let groups;
    if (s.includes("::")) {
      if (s.indexOf("::") !== s.lastIndexOf("::")) throw new Error("IPv6 address has more than one ::");
      const pieces = s.split("::");
      const left = pieces[0] ? pieces[0].split(":") : [];
      const right = pieces[1] ? pieces[1].split(":") : [];
      if (left.some((g) => g === "") || right.some((g) => g === "")) throw new Error("IPv6 address has an empty group");
      if (left.length + right.length > 7) throw new Error(":: must stand for at least one 16-bit group");
      const missing = 8 - left.length - right.length;
      groups = left.concat(new Array(missing).fill("0"), right);
    } else {
      groups = s.split(":");
      if (groups.length !== 8) throw new Error("IPv6 address needs eight 16-bit groups (or use ::)");
    }
    if (groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) throw new Error("Invalid IPv6 hex group");
    const bytes = new Uint8Array(16);
    groups.forEach((g, i) => {
      const value = parseInt(g, 16);
      bytes[i * 2] = value >>> 8;
      bytes[i * 2 + 1] = value & 255;
    });
    return { bytes, zone, prefix: prefix == null ? 128 : prefix };
  }

  function parseIPv6(text) { return parseIPv6Info(text).bytes; }

  function formatIPv6Full(bytes) {
    if (!bytes || bytes.length !== 16) throw new Error("IPv6 address must be 16 bytes");
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16).padStart(4, "0"));
    return groups.join(":");
  }

  function dottedTail(bytes, offset) {
    return bytes[offset] + "." + bytes[offset + 1] + "." + bytes[offset + 2] + "." + bytes[offset + 3];
  }

  function formatIPv6(bytes) {
    if (!bytes || bytes.length !== 16) throw new Error("IPv6 address must be 16 bytes");
    const b = Array.from(bytes);
    if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) {
      return "::ffff:" + dottedTail(bytes, 12);
    }
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    let bestStart = -1;
    let bestLen = 0;
    for (let i = 0; i < 8; i++) {
      if (groups[i] !== "0") continue;
      let j = i;
      while (j < 8 && groups[j] === "0") j++;
      if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
      i = j - 1;
    }
    if (bestLen < 2) return groups.join(":");
    const left = groups.slice(0, bestStart).join(":");
    const right = groups.slice(bestStart + bestLen).join(":");
    if (!left && !right) return "::";
    if (!left) return "::" + right;
    if (!right) return left + "::";
    return left + "::" + right;
  }

  function prefixNetwork(bytes, prefix) {
    const bits = toInt(prefix, "Prefix length", 0, 128, 128);
    const out = Uint8Array.from(bytes);
    for (let i = 0; i < 16; i++) {
      const keep = Math.max(0, Math.min(8, bits - i * 8));
      if (keep === 0) out[i] = 0;
      else if (keep < 8) out[i] &= (0xff << (8 - keep)) & 255;
    }
    return out;
  }

  function addressInfo(bytes, prefix, zone) {
    if (!bytes || bytes.length !== 16) throw new Error("IPv6 address must be 16 bytes");
    const b = Array.from(bytes);
    const p = toInt(prefix, "Prefix length", 0, 128, 128);
    const isUnspecified = b.every((x) => x === 0);
    const isLoopback = b.slice(0, 15).every((x) => x === 0) && b[15] === 1;
    const isMapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
    const isMulticast = b[0] === 0xff;
    const isLinkLocal = b[0] === 0xfe && (b[1] & 0xc0) === 0x80;
    const isUniqueLocal = (b[0] & 0xfe) === 0xfc;
    const isDocumentation = b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8;
    const is6to4 = b[0] === 0x20 && b[1] === 0x02;
    const isTeredo = b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0;
    const isGlobalUnicast = (b[0] & 0xe0) === 0x20;
    const isSolicitedNode = isMulticast && b[1] === 0x02 && b.slice(2, 11).every((x) => x === 0) && b[11] === 1 && b[12] === 0xff;
    let scope = "other";
    if (isUnspecified) scope = "unspecified";
    else if (isLoopback) scope = "loopback";
    else if (isMapped) scope = "IPv4-mapped";
    else if (isMulticast) scope = "multicast · " + (MCAST_SCOPES[b[1] & 15] || "scope " + (b[1] & 15));
    else if (isLinkLocal) scope = "link-local";
    else if (isUniqueLocal) scope = "unique local";
    else if (isDocumentation) scope = "documentation";
    else if (is6to4) scope = "6to4";
    else if (isTeredo) scope = "Teredo";
    else if (isGlobalUnicast) scope = "global unicast";
    return {
      bytes, canonical: formatIPv6(bytes), expanded: formatIPv6Full(bytes),
      hex: PH.bytesToHex(bytes), prefix: p, zone: zone || null,
      network: formatIPv6(prefixNetwork(bytes, p)) + "/" + p,
      scope, isUnspecified, isLoopback, isMapped, isMulticast, isLinkLocal,
      isUniqueLocal, isDocumentation, is6to4, isTeredo, isGlobalUnicast, isSolicitedNode,
      multicastScope: isMulticast ? (MCAST_SCOPES[b[1] & 15] || "scope " + (b[1] & 15)) : null,
      multicastFlags: isMulticast ? (b[1] >> 4) : null
    };
  }

  function buildHeader(input) {
    const version = toInt(input.version, "Version", 0, 15, 6);
    const dscp = toInt(input.dscp, "DSCP", 0, 63, 0);
    const ecn = toInt(input.ecn, "ECN", 0, 3, 0);
    const trafficClass = input.trafficClass == null ? ((dscp << 2) | ecn) : toInt(input.trafficClass, "Traffic Class", 0, 255);
    const flowLabel = toInt(input.flowLabel, "Flow Label", 0, 0xfffff, 0);
    const nextHeader = toInt(input.nextHeader, "Next Header", 0, 255, 59);
    const hopLimit = toInt(input.hopLimit, "Hop Limit", 0, 255, 64);
    const payload = toBytes(input.payload);
    if (payload.length > 65535) throw new Error("Payload exceeds 65535 bytes; IPv6 jumbograms require the Jumbo Payload option");
    const src = typeof input.src === "string" ? parseIPv6(input.src) : input.src;
    const dst = typeof input.dst === "string" ? parseIPv6(input.dst) : input.dst;
    if (!src || src.length !== 16 || !dst || dst.length !== 16) throw new Error("Source and destination must be IPv6 addresses");
    const bytes = new Uint8Array(40 + payload.length);
    bytes[0] = ((version & 15) << 4) | ((trafficClass >> 4) & 15);
    bytes[1] = ((trafficClass & 15) << 4) | ((flowLabel >> 16) & 15);
    bytes[2] = (flowLabel >> 8) & 255;
    bytes[3] = flowLabel & 255;
    PH.put16be(bytes, 4, payload.length);
    bytes[6] = nextHeader;
    bytes[7] = hopLimit;
    bytes.set(src, 8);
    bytes.set(dst, 24);
    bytes.set(payload, 40);
    return {
      bytes, header: bytes.slice(0, 40), payload, version, trafficClass, dscp, ecn,
      flowLabel, payloadLength: payload.length, nextHeader, nextHeaderName: nextHeaderName(nextHeader),
      hopLimit, src: formatIPv6(src), dst: formatIPv6(dst), srcBytes: src, dstBytes: dst
    };
  }

  function parseOptions(bytes) {
    const options = [];
    const warnings = [];
    let jumboPayloadLength = null;
    let offset = 0;
    while (offset < bytes.length) {
      const start = offset;
      const type = bytes[offset];
      if (type === 0) {
        options.push({ type, name: "Pad1", length: 1, offset: start, action: 0, change: 0, number: 0, data: new Uint8Array(0), detail: "one-byte padding" });
        offset += 1;
        continue;
      }
      if (offset + 1 >= bytes.length) {
        warnings.push("Option at offset " + start + " is truncated before its length byte");
        break;
      }
      const len = bytes[offset + 1];
      if (offset + 2 + len > bytes.length) {
        warnings.push("Option at offset " + start + " claims " + len + " data bytes but only " + (bytes.length - offset - 2) + " remain");
        break;
      }
      const data = bytes.slice(offset + 2, offset + 2 + len);
      const option = {
        type, name: OPTION_NAMES[type] || "Option " + type, length: len + 2, offset: start,
        action: (type >> 6) & 3, change: (type >> 5) & 1, number: type & 31, data, detail: ""
      };
      if (type === 1) {
        option.detail = "padding";
        if (data.some((x) => x !== 0)) warnings.push("PadN option at offset " + start + " contains non-zero bytes");
      } else if (type === 4) {
        option.detail = data.length ? "encapsulation limit " + data[0] : "truncated";
      } else if (type === 5) {
        const value = data.length >= 2 ? PH.u16be(data, 0) : null;
        const alert = { 0: "MLD", 1: "RSVP", 2: "Active Networks", 3: "NSIS" }[value] || "value " + value;
        option.detail = value == null ? "truncated" : "value " + value + " · " + alert;
        option.parsed = { value };
      } else if (type === 194) {
        const value = data.length >= 4 ? PH.u32be(data, 0) : null;
        option.detail = value == null ? "truncated" : "jumbogram payload " + value + " B";
        option.parsed = { value };
        if (value != null) jumboPayloadLength = value;
      } else if (type === 201) {
        option.detail = data.length === 16 ? formatIPv6(data) : "truncated home address";
        if (data.length === 16) option.parsed = { address: formatIPv6(data) };
      } else {
        option.detail = data.length ? data.length + " data byte(s)" : "no data";
      }
      options.push(option);
      offset += 2 + len;
    }
    if (offset < bytes.length) warnings.push((bytes.length - offset) + " trailing byte(s) after the parsed options");
    return { options, warnings, jumboPayloadLength };
  }

  function parseExtension(payload, offset, type, warnings) {
    if (payload.length - offset < 2) throw new Error("extension header is truncated before Next Header");
    const next = payload[offset];
    const header = { type, name: nextHeaderName(type), nextHeader: next, nextHeaderName: nextHeaderName(next) };
    if (type === 44) {
      if (payload.length - offset < 8) throw new Error("fragment header needs 8 bytes");
      const word = PH.u16be(payload, offset + 2);
      header.length = 8;
      header.reserved = payload[offset + 1];
      header.fragmentOffset = word >>> 3;
      header.reservedBits = (word >>> 1) & 3;
      header.moreFragments = word & 1;
      header.identification = PH.u32be(payload, offset + 4);
      header.detail = "offset " + header.fragmentOffset * 8 + " B · " + (header.moreFragments ? "more fragments" : "last fragment") + " · id 0x" + PH.hex(header.identification, 8);
      return header;
    }
    if (type === 51) {
      const payloadLen = payload[offset + 1];
      const length = (payloadLen + 2) * 4;
      if (length < 12) warnings.push("AH Payload Len " + payloadLen + " gives a " + length + "-byte header; AH has at least 12 bytes");
      if (offset + length > payload.length) throw new Error("AH header claims " + length + " bytes but only " + (payload.length - offset) + " remain");
      header.length = length;
      header.reserved = length >= 4 ? PH.u16be(payload, offset + 2) : null;
      header.spi = length >= 8 ? PH.u32be(payload, offset + 4) : null;
      header.sequence = length >= 12 ? PH.u32be(payload, offset + 8) : null;
      header.icv = length > 12 ? payload.slice(offset + 12, offset + length) : new Uint8Array(0);
      header.detail = header.spi == null
        ? "truncated AH (" + length + " B)"
        : "SPI 0x" + PH.hex(header.spi, 8) + " · seq " + header.sequence + " · ICV " + header.icv.length + " B";
      return header;
    }
    const hdrExtLen = payload[offset + 1];
    const length = (hdrExtLen + 1) * 8;
    if (length < 8) throw new Error("extension header length is less than 8 bytes");
    if (offset + length > payload.length) throw new Error("extension header claims " + length + " bytes but only " + (payload.length - offset) + " remain");
    header.length = length;
    header.hdrExtLen = hdrExtLen;
    if (type === 0 || type === 60) {
      const parsed = parseOptions(payload.subarray(offset + 2, offset + length));
      header.options = parsed.options;
      header.optionWarnings = parsed.warnings;
      header.jumboPayloadLength = parsed.jumboPayloadLength;
      header.detail = parsed.options.length + " option(s)";
    } else if (type === 43) {
      header.routingType = payload[offset + 2];
      header.routingTypeName = ROUTING_TYPES[header.routingType] || "type " + header.routingType;
      header.segmentsLeft = payload[offset + 3];
      header.detail = header.routingTypeName + " · " + header.segmentsLeft + " segment(s) left";
      if (header.routingType === 4 && length >= 8) {
        header.lastEntry = payload[offset + 4];
        header.flags = payload[offset + 5];
        header.tag = PH.u16be(payload, offset + 6);
        header.segments = [];
        for (let pos = offset + 8; pos + 16 <= offset + length; pos += 16) header.segments.push(formatIPv6(payload.subarray(pos, pos + 16)));
        header.detail += " · " + header.segments.length + " segment(s)";
      }
    } else {
      header.detail = (length - 2) + " B of type-specific data";
    }
    return header;
  }

  function transportHint(next, bytes) {
    if (next === 6 && bytes.length >= 20) {
      const dataOffset = (bytes[12] >> 4) * 4;
      return {
        kind: "TCP", source: PH.u16be(bytes, 0), destination: PH.u16be(bytes, 2),
        sequence: PH.u32be(bytes, 4), acknowledgment: PH.u32be(bytes, 8),
        dataOffset, flags: bytes[13], window: PH.u16be(bytes, 14)
      };
    }
    if (next === 17 && bytes.length >= 8) {
      return { kind: "UDP", source: PH.u16be(bytes, 0), destination: PH.u16be(bytes, 2), length: PH.u16be(bytes, 4), checksum: PH.u16be(bytes, 6) };
    }
    if (next === 58 && bytes.length >= 4) {
      return { kind: "ICMPv6", type: bytes[0], code: bytes[1], typeName: ICMPV6_TYPES[bytes[0]] || "type " + bytes[0] };
    }
    if (next === 132 && bytes.length >= 12) {
      return { kind: "SCTP", source: PH.u16be(bytes, 0), destination: PH.u16be(bytes, 2), verificationTag: PH.u32be(bytes, 4) };
    }
    if (next === 50) return { kind: "ESP", encrypted: true };
    if (next === 41) return { kind: "IPv6-in-IPv6", tunneled: true };
    return null;
  }

  function walkChain(payload, firstNextHeader, baseOffset) {
    let next = firstNextHeader;
    let position = 0;
    let guard = 0;
    let jumboPayloadLength = null;
    const headers = [];
    const warnings = [];
    while (EXTENSION_HEADERS.has(next)) {
      if (guard++ > 32) { warnings.push("Extension chain exceeds 32 headers; stopping to avoid a loop"); break; }
      let header;
      try {
        header = parseExtension(payload, position, next, warnings);
      } catch (err) {
        warnings.push("Extension header " + nextHeaderName(next) + " at byte " + ((baseOffset || 0) + position) + ": " + err.message);
        break;
      }
      header.offset = (baseOffset || 0) + position;
      if (header.optionWarnings) warnings.push(...header.optionWarnings);
      if (header.jumboPayloadLength != null) jumboPayloadLength = header.jumboPayloadLength;
      headers.push(header);
      position += header.length;
      next = header.nextHeader;
    }
    const terminal = {
      nextHeader: next, name: nextHeaderName(next), offset: (baseOffset || 0) + position,
      bytes: payload.subarray(position), length: payload.length - position
    };
    terminal.transport = transportHint(next, terminal.bytes);
    if (next === 59 && terminal.bytes.length) warnings.push("No Next Header (59) is followed by " + terminal.bytes.length + " byte(s)");
    return { headers, terminal, jumboPayloadLength, warnings, payloadLength: payload.length };
  }

  function parseEthernet(bytes) {
    if (bytes.length < 14) return null;
    let offset = 12;
    let type = PH.u16be(bytes, offset);
    const vlanTags = [];
    while ((type === 0x8100 || type === 0x88a8) && bytes.length >= offset + 6) {
      const tci = PH.u16be(bytes, offset + 2);
      vlanTags.push({ tpid: type, pcp: (tci >>> 13) & 7, dei: (tci >>> 12) & 1, vid: tci & 0xfff, tci });
      offset += 4;
      type = PH.u16be(bytes, offset);
    }
    if (type !== 0x86dd) return null;
    const ipStart = offset + 2;
    if (bytes.length < ipStart + 40 || (bytes[ipStart] >> 4) !== 6) return null;
    return {
      dstMac: macString(bytes.subarray(0, 6)), srcMac: macString(bytes.subarray(6, 12)),
      etherType: type, vlanTags, headerLen: ipStart, ipStart
    };
  }

  function decodeHeader(bytes, offset) {
    const start = offset || 0;
    if (bytes.length < start + 40) throw new Error("Need at least 40 bytes of IPv6 header");
    const h = bytes.subarray(start);
    const version = h[0] >> 4;
    if (version !== 6) throw new Error("IPv6 version nibble is " + version + ", not 6");
    const trafficClass = ((h[0] & 15) << 4) | (h[1] >> 4);
    const flowLabel = ((h[1] & 15) << 16) | (h[2] << 8) | h[3];
    const payloadLength = PH.u16be(h, 4);
    const nextHeader = h[6];
    const hopLimit = h[7];
    const srcBytes = h.slice(8, 24);
    const dstBytes = h.slice(24, 40);
    const warnings = [];
    let payloadEnd;
    if (payloadLength === 0) payloadEnd = bytes.length;
    else {
      payloadEnd = Math.min(bytes.length, start + 40 + payloadLength);
      if (start + 40 + payloadLength > bytes.length) warnings.push("Payload Length " + payloadLength + " exceeds the captured bytes after the IPv6 header");
      if (start + 40 + payloadLength < bytes.length) warnings.push((bytes.length - start - 40 - payloadLength) + " trailing byte(s) beyond Payload Length (Ethernet padding or FCS?)");
    }
    return {
      offset: start, version, trafficClass, dscp: trafficClass >> 2, ecn: trafficClass & 3,
      flowLabel, payloadLength, payloadLengthZero: payloadLength === 0, nextHeader,
      nextHeaderName: nextHeaderName(nextHeader), hopLimit, srcBytes, dstBytes,
      src: formatIPv6(srcBytes), dst: formatIPv6(dstBytes),
      srcInfo: addressInfo(srcBytes), dstInfo: addressInfo(dstBytes),
      header: h.slice(0, 40), payload: bytes.subarray(start + 40, payloadEnd),
      capturedPayloadLength: Math.max(0, payloadEnd - start - 40), warnings
    };
  }

  function decodePacket(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const ethernet = parseEthernet(bytes);
    const ipStart = ethernet ? ethernet.ipStart : 0;
    if (bytes.length < ipStart + 40) throw new Error("Need at least 40 bytes of IPv6 header");
    const version = bytes[ipStart] >> 4;
    if (version === 4) throw new Error("IPv4 packet detected; use the IPv4 explorer instead");
    if (version !== 6) throw new Error("Version nibble is " + version + ", not 6");
    const ip = decodeHeader(bytes, ipStart);
    const chain = walkChain(ip.payload, ip.nextHeader, ipStart + 40);
    ip.warnings.unshift(...chain.warnings);
    if (chain.jumboPayloadLength != null) {
      ip.jumboPayloadLength = chain.jumboPayloadLength;
      if (!ip.payloadLengthZero) ip.warnings.push("Jumbo Payload option appears while Payload Length is non-zero");
      if (chain.jumboPayloadLength > ip.capturedPayloadLength) ip.warnings.push("Jumbo Payload length " + chain.jumboPayloadLength + " exceeds the " + ip.capturedPayloadLength + " captured payload bytes");
    } else if (ip.payloadLengthZero && ip.capturedPayloadLength > 0) {
      ip.warnings.push("Payload Length is 0; this is only valid for an empty packet or an RFC 2675 jumbogram");
    }
    return {
      bytes, ip, chain, ethernet, ipOffset: ipStart,
      detectedAs: ethernet ? "Ethernet frame with IPv6" : "IPv6 packet"
    };
  }

  function transportChecksum(src, dst, nextHeader, payload) {
    const source = src instanceof Uint8Array ? src : parseIPv6(src);
    const dest = dst instanceof Uint8Array ? dst : parseIPv6(dst);
    const body = payload instanceof Uint8Array ? payload : Uint8Array.from(payload);
    const pseudo = new Uint8Array(40);
    pseudo.set(source, 0);
    pseudo.set(dest, 16);
    PH.put32be(pseudo, 32, body.length);
    pseudo[39] = nextHeader & 255;
    return PH.checksum16(PH.concatBytes(pseudo, body));
  }

  function buildHopByHop(nextHeader, options) {
    const raw = toBytes(options);
    const total = 2 + raw.length;
    const target = Math.max(8, Math.ceil(total / 8) * 8);
    const pad = target - total;
    let padding;
    if (pad === 0) padding = new Uint8Array(0);
    else if (pad === 1) padding = new Uint8Array([0]);
    else { padding = new Uint8Array(pad); padding[0] = 1; padding[1] = pad - 2; }
    const bytes = new Uint8Array(target);
    bytes[0] = nextHeader & 255;
    bytes[1] = target / 8 - 1;
    bytes.set(raw, 2);
    bytes.set(padding, 2 + raw.length);
    return bytes;
  }

  function buildDestinationOptions(nextHeader, options) { return buildHopByHop(nextHeader, options); }

  function buildRouterAlert(nextHeader, value) {
    return buildHopByHop(nextHeader, new Uint8Array([5, 2, (Number(value || 0) >> 8) & 255, Number(value || 0) & 255]));
  }

  function buildFragment(nextHeader, offset, moreFragments, identification) {
    const fragOffset = toInt(offset, "Fragment Offset", 0, 8191, 0);
    const id = toInt(identification, "Identification", 0, 0xffffffff, 0);
    const bytes = new Uint8Array(8);
    bytes[0] = nextHeader & 255;
    PH.put16be(bytes, 2, (fragOffset << 3) | (moreFragments ? 1 : 0));
    PH.put32be(bytes, 4, id);
    return bytes;
  }

  global.IPv6Codec = {
    NEXT_HEADERS, EXTENSION_HEADERS, OPTION_NAMES, ROUTING_TYPES, MCAST_SCOPES, ICMPV6_TYPES,
    nextHeaderName, protocolName, parseIPv6Info, parseIPv6, formatIPv6, formatIPv6Full,
    prefixNetwork, addressInfo, buildHeader, decodeHeader, decodePacket, parseOptions,
    parseExtension, walkChain, transportHint, parseEthernet, transportChecksum, buildHopByHop,
    buildDestinationOptions, buildRouterAlert, buildFragment
  };

})(window);
