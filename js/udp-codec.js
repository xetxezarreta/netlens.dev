/* UDP (RFC 768) datagram codec — shared by the UDP page and tests. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const SERVICES = {
    7: "echo", 9: "discard", 19: "chargen", 37: "time", 53: "DNS", 67: "DHCP server",
    68: "DHCP client", 69: "TFTP", 111: "rpcbind", 123: "NTP", 137: "NetBIOS name",
    138: "NetBIOS datagram", 161: "SNMP", 162: "SNMP trap", 500: "IKE / ISAKMP",
    514: "syslog", 520: "RIP", 546: "DHCPv6 client", 547: "DHCPv6 server", 631: "IPP",
    1900: "SSDP", 2049: "NFS", 2152: "GTP", 33434: "traceroute", 3784: "BFD control",
    3785: "BFD echo", 4500: "IPsec NAT-T", 4789: "VXLAN",
    5353: "mDNS", 5355: "LLMNR", 6081: "Geneve"
  };

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

  function portInfo(port) {
    const p = Number(port);
    if (p === 0) return { port: 0, service: null, range: "reserved", name: "reserved" };
    let range = "dynamic / private";
    if (p <= 1023) range = "system / well-known";
    else if (p <= 49151) range = "user / registered";
    return { port: p, service: SERVICES[p] || null, range, name: SERVICES[p] ? SERVICES[p] : range };
  }

  function portLabel(port) {
    const info = portInfo(port);
    return info.service ? info.port + " · " + info.service : info.port + " · " + info.range;
  }

  function parseAddress(version, address) {
    if (version === 4) return PH.parseIPv4(address);
    if (version === 6) {
      const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
      if (codec) return codec.parseIPv6(address);
      throw new Error("IPv6 address support is not loaded");
    }
    throw new Error("IP version must be 4 or 6");
  }

  function pseudoHeader(version, src, dst, udpLength) {
    if (version === 4) {
      const source = src instanceof Uint8Array ? src : parseAddress(4, src);
      const dest = dst instanceof Uint8Array ? dst : parseAddress(4, dst);
      if (source.length !== 4 || dest.length !== 4) throw new Error("IPv4 pseudo-header needs 4-byte addresses");
      const bytes = new Uint8Array(12);
      bytes.set(source, 0);
      bytes.set(dest, 4);
      bytes[8] = 0;
      bytes[9] = 17;
      PH.put16be(bytes, 10, udpLength);
      return bytes;
    }
    if (version === 6) {
      const source = src instanceof Uint8Array ? src : parseAddress(6, src);
      const dest = dst instanceof Uint8Array ? dst : parseAddress(6, dst);
      if (source.length !== 16 || dest.length !== 16) throw new Error("IPv6 pseudo-header needs 16-byte addresses");
      const bytes = new Uint8Array(40);
      bytes.set(source, 0);
      bytes.set(dest, 16);
      PH.put32be(bytes, 32, udpLength);
      bytes[36] = 0;
      bytes[37] = 0;
      bytes[38] = 0;
      bytes[39] = 17;
      return bytes;
    }
    throw new Error("IP version must be 4 or 6");
  }

  function checksum(udpBytes, context) {
    const bytes = udpBytes instanceof Uint8Array ? udpBytes.slice() : Uint8Array.from(udpBytes);
    if (bytes.length < 8) throw new Error("UDP datagram needs at least 8 bytes");
    if (context.ipVersion == null) throw new Error("IP context is required for the UDP checksum");
    bytes[6] = 0;
    bytes[7] = 0;
    const pseudo = pseudoHeader(context.ipVersion, context.srcIp, context.dstIp, bytes.length);
    return PH.checksum16(PH.concatBytes(pseudo, bytes));
  }

  function buildUdp(input) {
    const srcPort = toInt(input.srcPort, "Source Port", 0, 65535, 0);
    const dstPort = toInt(input.dstPort, "Destination Port", 0, 65535, 0);
    const payload = toBytes(input.payload);
    const length = 8 + payload.length;
    if (length > 65535) throw new Error("UDP Length exceeds 65535; UDP has no jumbogram");
    const version = input.ipVersion == null ? null : Number(input.ipVersion);
    if (version != null && version !== 4 && version !== 6) throw new Error("IP version must be 4 or 6");
    const bytes = new Uint8Array(length);
    PH.put16be(bytes, 0, srcPort);
    PH.put16be(bytes, 2, dstPort);
    PH.put16be(bytes, 4, length);
    PH.put16be(bytes, 6, 0);
    bytes.set(payload, 8);

    let checksumValue = 0;
    let checksumState = "absent";
    if (version != null) {
      if (version === 4 && input.zeroChecksum) {
        checksumState = "zero-ipv4";
      } else {
        checksumValue = checksum(bytes, { ipVersion: version, srcIp: input.srcIp, dstIp: input.dstIp });
        if (checksumValue === 0) checksumValue = 0xffff;
        checksumState = "built";
        PH.put16be(bytes, 6, checksumValue);
      }
    }
    return {
      bytes, srcPort, dstPort, length, checksum: checksumValue, checksumState,
      payload, payloadLength: payload.length, ipVersion: version || null,
      src: portInfo(srcPort), dst: portInfo(dstPort), messageLength: bytes.length
    };
  }

  function decodeUdp(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 8) throw new Error("UDP needs at least 8 bytes for its header");
    const options = opts || {};
    const srcPort = PH.u16be(bytes, 0);
    const dstPort = PH.u16be(bytes, 2);
    const length = PH.u16be(bytes, 4);
    const checksumValue = PH.u16be(bytes, 6);
    const warnings = [];
    if (length < 8) warnings.push("UDP Length " + length + " is smaller than the 8-byte header");
    const payloadEnd = Math.min(bytes.length, Math.max(8, length || 8));
    const payload = bytes.subarray(8, payloadEnd);
    if (length > bytes.length) warnings.push("UDP Length " + length + " exceeds the " + bytes.length + " captured bytes; payload is truncated");
    else if (length && length < bytes.length) warnings.push((bytes.length - length) + " trailing byte(s) beyond UDP Length");

    let expectedChecksum = null;
    let checksumState = "unknown";
    const version = options.ipVersion == null ? null : Number(options.ipVersion);
    if (version != null && options.srcIp && options.dstIp) {
      if (checksumValue === 0) {
        if (version === 4) checksumState = "absent";
        else { checksumState = "invalid"; warnings.push("IPv6 requires a non-zero UDP checksum"); }
      } else if (length >= 8 && length <= bytes.length) {
        expectedChecksum = checksum(bytes.subarray(0, length), { ipVersion: version, srcIp: options.srcIp, dstIp: options.dstIp });
        if (expectedChecksum === 0) expectedChecksum = 0xffff;
        checksumState = expectedChecksum === checksumValue ? "valid" : "invalid";
        if (checksumState === "invalid") warnings.push("UDP checksum is invalid (expected 0x" + PH.hex(expectedChecksum, 4) + ")");
      } else {
        checksumState = "not-checked";
        warnings.push("UDP checksum could not be checked because the UDP Length is inconsistent");
      }
    }

    return {
      bytes, srcPort, dstPort, length, checksum: checksumValue, expectedChecksum,
      checksumState, checksumOk: checksumState === "valid" || (version === 4 && checksumState === "absent"),
      payload, payloadLength: payload.length, ipVersion: version || null,
      src: portInfo(srcPort), dst: portInfo(dstPort), messageLength: bytes.length,
      warnings
    };
  }

  global.UDPCodec = {
    SERVICES, portInfo, portLabel, pseudoHeader, checksum, buildUdp, decodeUdp
  };
})(window);
