/* IPv4 and IPv6 prefix arithmetic for the subnet calculator.
   IPv4 uses unsigned 32-bit numbers; IPv6 uses BigInt so /0 and /128
   are both exact. No address is ever silently normalised in display output. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);
  const MAX_SPLIT = 4096;

  function ipv4ToLong(text) {
    const parts = String(text == null ? "" : text).trim().split(".");
    if (parts.length !== 4) throw new Error("IPv4 address needs four octets");
    let value = 0;
    parts.forEach((part) => {
      if (!/^\d{1,3}$/.test(part)) throw new Error("Invalid IPv4 octet: " + part);
      const n = Number(part);
      if (n > 255) throw new Error("IPv4 octet out of range: " + part);
      value = value * 256 + n;
    });
    return value >>> 0;
  }

  function longToIpv4(value) {
    const n = Number(value) >>> 0;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }

  function prefixToMask(prefix) {
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error("IPv4 prefix must be 0–32");
    return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  }

  function maskToPrefix(mask) {
    const n = Number(mask) >>> 0;
    let seenZero = false;
    let prefix = 0;
    for (let i = 31; i >= 0; i--) {
      const bit = (n >>> i) & 1;
      if (bit === 1) {
        if (seenZero) throw new Error("IPv4 mask is not contiguous");
        prefix += 1;
      } else seenZero = true;
    }
    return prefix;
  }

  function ipv4Type(value) {
    const n = Number(value) >>> 0;
    const inRange = (base, prefix) => {
      const mask = prefixToMask(prefix);
      return (n & mask) >>> 0 === (base & mask) >>> 0;
    };
    if (inRange(ipv4ToLong("0.0.0.0"), 8)) return "this network";
    if (inRange(ipv4ToLong("10.0.0.0"), 8)) return "private (RFC 1918)";
    if (inRange(ipv4ToLong("100.64.0.0"), 10)) return "carrier-grade NAT (RFC 6598)";
    if (inRange(ipv4ToLong("127.0.0.0"), 8)) return "loopback";
    if (inRange(ipv4ToLong("169.254.0.0"), 16)) return "link-local";
    if (inRange(ipv4ToLong("172.16.0.0"), 12)) return "private (RFC 1918)";
    if (inRange(ipv4ToLong("192.0.0.0"), 24)) return "IETF protocol assignments";
    if (inRange(ipv4ToLong("192.0.2.0"), 24)) return "documentation (TEST-NET-1)";
    if (inRange(ipv4ToLong("192.168.0.0"), 16)) return "private (RFC 1918)";
    if (inRange(ipv4ToLong("198.18.0.0"), 15)) return "benchmarking (RFC 2544)";
    if (inRange(ipv4ToLong("198.51.100.0"), 24)) return "documentation (TEST-NET-2)";
    if (inRange(ipv4ToLong("203.0.113.0"), 24)) return "documentation (TEST-NET-3)";
    if (inRange(ipv4ToLong("224.0.0.0"), 4)) return "multicast";
    if (inRange(ipv4ToLong("240.0.0.0"), 4)) return n === 0xffffffff ? "limited broadcast" : "reserved (RFC 1112)";
    return "public unicast";
  }

  function ipv4Class(value) {
    const first = (Number(value) >>> 24) & 255;
    if (first < 128) return "A";
    if (first < 192) return "B";
    if (first < 224) return "C";
    if (first < 240) return "D (multicast)";
    return "E (reserved)";
  }

  function parseIpv4Cidr(text) {
    const raw = String(text == null ? "" : text).trim();
    if (!raw) throw new Error("Enter an IPv4 address or CIDR prefix");
    let addressText = raw;
    let prefix = null;
    const slash = raw.indexOf("/");
    if (slash !== -1) {
      addressText = raw.slice(0, slash).trim();
      const tail = raw.slice(slash + 1).trim();
      if (!tail) throw new Error("Prefix length is empty");
      if (tail.indexOf(".") !== -1) prefix = maskToPrefix(ipv4ToLong(tail));
      else {
        if (!/^\d{1,2}$/.test(tail)) throw new Error("Prefix length must be 0–32");
        prefix = Number(tail);
        if (prefix > 32) throw new Error("IPv4 prefix must be 0–32");
      }
    } else {
      const parts = raw.split(/\s+/);
      if (parts.length === 2) {
        addressText = parts[0];
        prefix = parts[1].indexOf(".") !== -1 ? maskToPrefix(ipv4ToLong(parts[1])) : Number(parts[1]);
      }
    }
    if (prefix == null) prefix = 32;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error("IPv4 prefix must be 0–32");
    const address = ipv4ToLong(addressText);
    const mask = prefixToMask(prefix);
    const wildcard = (~mask) >>> 0;
    const network = (address & mask) >>> 0;
    const broadcast = (network | wildcard) >>> 0;
    const hostBits = 32 - prefix;
    const total = 2 ** hostBits;
    let usable;
    if (prefix === 32) usable = 1;
    else if (prefix === 31) usable = 2; /* RFC 3021 point-to-point links */
    else usable = Math.max(0, total - 2);
    return {
      version: 4, input: raw, address, addressText: longToIpv4(address), prefix,
      mask, maskText: longToIpv4(mask), wildcardText: longToIpv4(wildcard),
      network, networkText: longToIpv4(network), broadcast, broadcastText: longToIpv4(broadcast),
      firstText: prefix >= 31 ? longToIpv4(network) : longToIpv4((network + 1) >>> 0),
      lastText: prefix >= 31 ? longToIpv4(broadcast) : longToIpv4((broadcast - 1) >>> 0),
      totalHosts: total, usableHosts: usable, hostBits,
      type: ipv4Type(address), networkType: ipv4Type(network), class: ipv4Class(address),
      binary: binary32(address), networkBinary: binary32(network),
      cidr: longToIpv4(network) + "/" + prefix
    };
  }

  function binary32(value) {
    const n = Number(value) >>> 0;
    let out = "";
    for (let i = 31; i >= 0; i--) {
      out += ((n >>> i) & 1);
      if (i % 8 === 0 && i > 0) out += ".";
    }
    return out;
  }

  function ipv6ToBigInt(bytes) {
    let n = 0n;
    for (let i = 0; i < 16; i++) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  }

  function bigIntToIpv6(value) {
    let n = BigInt(value);
    const bytes = new Uint8Array(16);
    for (let i = 15; i >= 0; i--) { bytes[i] = Number(n & 255n); n >>= 8n; }
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    return codec ? codec.formatIPv6(bytes) : PH.bytesToHex(bytes);
  }

  function parseIpv6Cidr(text) {
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    if (!codec) throw new Error("IPv6 codec is not loaded");
    const raw = String(text == null ? "" : text).trim();
    if (!raw) throw new Error("Enter an IPv6 address or CIDR prefix");
    const info = codec.parseIPv6Info(raw);
    const prefix = info.prefix == null ? 128 : info.prefix;
    const address = ipv6ToBigInt(info.bytes);
    const networkBytes = codec.prefixNetwork(info.bytes, prefix);
    const network = ipv6ToBigInt(networkBytes);
    const hostBits = 128 - prefix;
    const total = 1n << BigInt(hostBits);
    const last = hostBits === 0 ? network : network + total - 1n;
    const addressInfo = codec.addressInfo(info.bytes, prefix, info.zone);
    const networkInfo = codec.addressInfo(networkBytes, prefix, null);
    return {
      version: 6, input: raw, address, addressText: codec.formatIPv6(info.bytes),
      prefix, network, networkText: codec.formatIPv6(networkBytes), last, lastText: bigIntToIpv6(last),
      firstText: codec.formatIPv6(networkBytes), totalHosts: total, usableHosts: total,
      hostBits, cidr: codec.formatIPv6(networkBytes) + "/" + prefix,
      type: addressInfo.scope || "unknown", networkType: networkInfo.scope || "unknown",
      zone: info.zone || null, expanded: addressInfo.expanded,
      networkExpanded: networkInfo.expanded,
      binary: ipv6Binary(info.bytes), networkBinary: ipv6Binary(networkBytes)
    };
  }

  function ipv6Binary(bytes) {
    let out = "";
    for (let i = 0; i < 16; i++) {
      out += bytes[i].toString(2).padStart(8, "0");
      if (i % 2 === 1 && i < 15) out += ":";
    }
    return out;
  }

  function parseCidr(text) {
    const raw = String(text == null ? "" : text).trim();
    if (raw.indexOf(":") !== -1) return parseIpv6Cidr(raw);
    return parseIpv4Cidr(raw);
  }

  function splitCidr(text, newPrefix) {
    const base = parseCidr(text);
    const target = Number(newPrefix);
    if (!Number.isInteger(target) || target < base.prefix) throw new Error("New prefix must be between " + base.prefix + " and 32 or 128");
    if (base.version === 4 && target > 32) throw new Error("IPv4 prefix must be 0–32");
    if (base.version === 6 && target > 128) throw new Error("IPv6 prefix must be 0–128");
    if (target === base.prefix) {
      return [{ cidr: base.cidr, networkText: base.networkText, firstText: base.firstText, lastText: base.lastText, totalHosts: base.totalHosts, usableHosts: base.usableHosts }];
    }
    const count = 2 ** (target - base.prefix);
    if (count > MAX_SPLIT) throw new Error("That split creates " + count + " prefixes; the tool caps at " + MAX_SPLIT);
    const out = [];
    if (base.version === 4) {
      const step = 2 ** (32 - target);
      for (let i = 0; i < count; i++) {
        const network = (base.network + i * step) >>> 0;
        const broadcast = (network + step - 1) >>> 0;
        out.push({
          cidr: longToIpv4(network) + "/" + target,
          networkText: longToIpv4(network), firstText: target >= 31 ? longToIpv4(network) : longToIpv4((network + 1) >>> 0),
          lastText: target >= 31 ? longToIpv4(broadcast) : longToIpv4((broadcast - 1) >>> 0),
          broadcastText: longToIpv4(broadcast),
          totalHosts: 2 ** (32 - target),
          usableHosts: target === 32 ? 1 : target === 31 ? 2 : 2 ** (32 - target) - 2
        });
      }
    } else {
      const step = 1n << BigInt(128 - target);
      for (let i = 0n; i < BigInt(count); i++) {
        const network = base.network + i * step;
        out.push({
          cidr: bigIntToIpv6(network) + "/" + target,
          networkText: bigIntToIpv6(network), firstText: bigIntToIpv6(network),
          lastText: bigIntToIpv6(network + step - 1n),
          totalHosts: 1n << BigInt(128 - target), usableHosts: 1n << BigInt(128 - target)
        });
      }
    }
    return out;
  }

  /* Greedy VLSM planner: largest requirement first, then the next aligned block. */
  function vlsmPlan(text, requirements) {
    const base = parseIpv4Cidr(text);
    const list = (requirements || []).map((r, index) => ({ name: r.name || "subnet " + (index + 1), hosts: Math.max(0, Number(r.hosts) || 0) }))
      .sort((a, b) => b.hosts - a.hosts);
    let cursor = base.network;
    const out = [];
    const warnings = [];
    list.forEach((item) => {
      const needed = item.hosts;
      let prefix;
      if (needed <= 0) prefix = 32;
      else if (needed <= 2) prefix = 31;
      else {
        prefix = 30;
        while (prefix > 0 && (2 ** (32 - prefix) - 2) < needed) prefix -= 1;
        if ((2 ** (32 - prefix) - 2) < needed) throw new Error("Requirement is too large: " + item.hosts);
      }
      const step = 2 ** (32 - prefix);
      const aligned = Math.ceil(cursor / step) * step;
      const end = aligned + step - 1;
      if (aligned + step - 1 > base.broadcast) {
        warnings.push(item.name + " does not fit in " + base.cidr);
        return;
      }
      out.push({
        name: item.name, hosts: item.hosts, prefix,
        cidr: longToIpv4(aligned) + "/" + prefix,
        networkText: longToIpv4(aligned),
        firstText: prefix >= 31 ? longToIpv4(aligned) : longToIpv4(aligned + 1),
        lastText: prefix >= 31 ? longToIpv4(end) : longToIpv4(end - 1),
        broadcastText: longToIpv4(end),
        usableHosts: prefix === 32 ? 1 : prefix === 31 ? 2 : step - 2
      });
      cursor = aligned + step;
    });
    return { base, plan: out, warnings, free: Math.max(0, base.broadcast - cursor + 1) };
  }

  global.SubnetCodec = {
    MAX_SPLIT, ipv4ToLong, longToIpv4, prefixToMask, maskToPrefix, ipv4Type, ipv4Class,
    parseIpv4Cidr, parseIpv6Cidr, parseCidr, splitCidr, vlsmPlan,
    ipv6ToBigInt, bigIntToIpv6, binary32, ipv6Binary
  };
})(typeof window !== "undefined" ? window : globalThis);
