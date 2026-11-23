/* DHCPv6 (RFC 8415) message, relay and option codec.
   DHCPv6 is a different protocol from DHCPv4: 4-byte message header,
   16-bit option codes, DUIDs, IA_NA/IA_PD and UDP 546/547. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const MESSAGE_TYPES = {
    1: "SOLICIT", 2: "ADVERTISE", 3: "REQUEST", 4: "CONFIRM", 5: "RENEW",
    6: "REBIND", 7: "REPLY", 8: "RELEASE", 9: "DECLINE", 10: "RECONFIGURE",
    11: "INFORMATION-REQUEST", 12: "RELAY-FORW", 13: "RELAY-REPL"
  };
  const OPTION_NAMES = {
    1: "Client Identifier", 2: "Server Identifier", 3: "IA_NA", 4: "IA_TA",
    5: "IA Address", 6: "Option Request", 7: "Preference", 8: "Elapsed Time",
    9: "Relay Message", 11: "Authentication", 12: "Server Unicast", 13: "Status Code",
    14: "Rapid Commit", 15: "User Class", 16: "Vendor Class", 17: "Vendor-specific",
    18: "Interface ID", 19: "Reconfigure Message", 20: "Reconfigure Accept",
    23: "DNS Servers", 24: "Domain Search List", 25: "IA_PD", 26: "IA Prefix",
    39: "Client FQDN", 59: "Bootfile URL", 82: "SOL_MAX_RT", 83: "INF_MAX_RT",
    143: "IPv6 Address (deprecated)"
  };
  const DUID_TYPES = { 1: "DUID-LLT", 2: "DUID-EN", 3: "DUID-LL", 4: "DUID-UUID" };
  const STATUS = { 0: "Success", 1: "UnspecFail", 2: "NoAddrsAvail", 3: "NoBinding", 4: "NotOnLink", 5: "UseMulticast", 6: "NoPrefixAvail" };

  function messageName(type) { return MESSAGE_TYPES[type] || "Message type " + type; }
  function optionName(code) { return OPTION_NAMES[code] || "Option " + code; }
  function duidName(type) { return DUID_TYPES[type] || "DUID type " + type; }

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

  function ipv6(codec, value, name) {
    if (value instanceof Uint8Array) {
      if (value.length !== 16) throw new Error(name + " must be 16 bytes");
      return value;
    }
    if (!codec) throw new Error("IPv6 codec is not loaded");
    return codec.parseIPv6(value);
  }

  function addr(codec, bytes) {
    if (!bytes || bytes.length !== 16) return "?";
    return codec ? codec.formatIPv6(bytes) : PH.bytesToHex(bytes);
  }

  function macString(bytes) {
    return Array.from(bytes, (b) => PH.hex(b).toLowerCase()).join(":");
  }

  function decodeDuid(bytes) {
    if (bytes.length < 2) return { type: null, name: "truncated", warnings: ["DUID needs at least 2 bytes"] };
    const type = PH.u16be(bytes, 0);
    const out = { type, name: duidName(type), bytes };
    if (type === 1 && bytes.length >= 8) {
      out.hardwareType = PH.u16be(bytes, 2);
      out.time = PH.u32be(bytes, 4);
      out.linkLayerAddress = macString(bytes.subarray(8));
    } else if (type === 2 && bytes.length >= 6) {
      out.enterpriseNumber = PH.u32be(bytes, 2);
      out.identifier = bytes.subarray(6);
    } else if (type === 3 && bytes.length >= 4) {
      out.hardwareType = PH.u16be(bytes, 2);
      out.linkLayerAddress = macString(bytes.subarray(4));
    } else if (type === 4 && bytes.length >= 18) {
      out.uuid = PH.bytesToHex(bytes.subarray(2, 18));
    }
    return out;
  }

  function dnsName(bytes, offset) {
    const labels = [];
    let pos = offset;
    let guard = 0;
    while (pos < bytes.length && guard++ < 128) {
      const length = bytes[pos];
      if (length === 0) { pos += 1; return { name: labels.join("."), next: pos }; }
      if (length > 63 || pos + 1 + length > bytes.length) return { name: null, next: pos, error: "invalid label" };
      labels.push(String.fromCharCode.apply(null, Array.from(bytes.subarray(pos + 1, pos + 1 + length))));
      pos += 1 + length;
    }
    return { name: null, next: pos, error: "unterminated name" };
  }

  function decodeOptions(bytes, offset, depth, codec) {
    const options = [];
    const warnings = [];
    let pos = offset;
    while (pos + 4 <= bytes.length) {
      const code = PH.u16be(bytes, pos);
      const length = PH.u16be(bytes, pos + 2);
      if (pos + 4 + length > bytes.length) {
        warnings.push("Option " + code + " declares " + length + " B but only " + (bytes.length - pos - 4) + " B remain");
        break;
      }
      const data = bytes.subarray(pos + 4, pos + 4 + length);
      options.push(decodeOption(code, data, depth, codec, pos));
      pos += 4 + length;
    }
    if (pos < bytes.length && bytes.length - pos < 4) warnings.push((bytes.length - pos) + " trailing byte(s) after the last option");
    return { options, warnings };
  }

  function decodeOption(code, data, depth, codec, offset) {
    const option = { code, name: optionName(code), offset, length: data.length, data, fields: [], warnings: [] };
    try {
      if (code === 1 || code === 2) {
        option.duid = decodeDuid(data);
      } else if (code === 3 || code === 25) {
        if (data.length < 12) throw new Error("IA option is shorter than 12 bytes");
        option.iaid = PH.u32be(data, 0);
        option.t1 = PH.u32be(data, 4);
        option.t2 = PH.u32be(data, 8);
        option.iaType = code === 3 ? "IA_NA" : "IA_PD";
        if (depth < 2) {
          const nested = decodeOptions(data, 12, depth + 1, codec);
          option.options = nested.options;
          option.warnings.push.apply(option.warnings, nested.warnings);
        }
      } else if (code === 4) {
        if (data.length < 4) throw new Error("IA_TA is shorter than 4 bytes");
        option.iaid = PH.u32be(data, 0);
        if (depth < 2) {
          const nested = decodeOptions(data, 4, depth + 1, codec);
          option.options = nested.options;
          option.warnings.push.apply(option.warnings, nested.warnings);
        }
      } else if (code === 5) {
        if (data.length < 24) throw new Error("IA Address is shorter than 24 bytes");
        option.address = addr(codec, data.subarray(0, 16));
        option.preferred = PH.u32be(data, 16);
        option.valid = PH.u32be(data, 20);
        if (depth < 2) {
          const nested = decodeOptions(data, 24, depth + 1, codec);
          option.options = nested.options;
        }
      } else if (code === 26) {
        if (data.length < 25) throw new Error("IA Prefix is shorter than 25 bytes");
        option.preferred = PH.u32be(data, 0);
        option.valid = PH.u32be(data, 4);
        option.prefixLength = data[8];
        option.prefix = addr(codec, data.subarray(9, 25));
        if (depth < 2) {
          const nested = decodeOptions(data, 25, depth + 1, codec);
          option.options = nested.options;
        }
      } else if (code === 6) {
        option.requested = [];
        for (let p = 0; p + 2 <= data.length; p += 2) option.requested.push({ code: PH.u16be(data, p), name: optionName(PH.u16be(data, p)) });
      } else if (code === 7) {
        option.preference = data.length ? data[0] : null;
      } else if (code === 8) {
        option.elapsed = data.length >= 2 ? PH.u16be(data, 0) : null;
        option.elapsedSeconds = option.elapsed == null ? null : option.elapsed / 100;
      } else if (code === 9) {
        option.nested = decodeDhcpv6(data, { depth: depth + 1 });
      } else if (code === 12) {
        option.address = addr(codec, data);
      } else if (code === 13) {
        option.status = data.length >= 2 ? PH.u16be(data, 0) : null;
        option.statusName = STATUS[option.status] || "status " + option.status;
        option.message = data.length > 2 ? new TextDecoder().decode(data.subarray(2)) : "";
      } else if (code === 18) {
        option.interfaceId = PH.bytesToHex(data);
      } else if (code === 19) {
        option.reconfigureMessage = data.length ? data[0] : null;
      } else if (code === 23) {
        option.servers = [];
        for (let p = 0; p + 16 <= data.length; p += 16) option.servers.push(addr(codec, data.subarray(p, p + 16)));
      } else if (code === 24) {
        option.domains = [];
        let p = 0;
        while (p < data.length) {
          const parsed = dnsName(data, p);
          if (parsed.name) option.domains.push(parsed.name);
          if (parsed.error || parsed.next <= p) break;
          p = parsed.next;
        }
      } else if (code === 39) {
        option.flags = data.length ? data[0] : null;
        const parsed = data.length > 1 ? dnsName(data, 1) : { name: null };
        option.fqdn = parsed.name;
      } else if (code === 59) {
        option.url = new TextDecoder().decode(data);
      } else if (code === 82 || code === 83) {
        option.seconds = data.length >= 4 ? PH.u32be(data, 0) : null;
      } else if (code === 15 || code === 16) {
        option.classes = [];
        let p = 0;
        while (p + 2 <= data.length) {
          const len = PH.u16be(data, p);
          if (p + 2 + len > data.length) break;
          option.classes.push(new TextDecoder().decode(data.subarray(p + 2, p + 2 + len)));
          p += 2 + len;
        }
        if (code === 16 && data.length >= 4) option.enterpriseNumber = PH.u32be(data, 0);
      }
    } catch (err) {
      option.warnings.push(err.message);
    }
    return option;
  }

  function decodeDhcpv6(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 4) throw new Error("DHCPv6 needs at least its 4-byte message header");
    const options = opts || {};
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    const type = bytes[0];
    const transactionId = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    const warnings = [];
    const out = { bytes, type, typeName: messageName(type), transactionId, warnings, relay: null };
    if (type === 12 || type === 13) {
      if (bytes.length < 34) throw new Error("DHCPv6 relay message needs 34 bytes before its options");
      out.relay = {
        hopCount: bytes[1],
        linkAddress: addr(codec, bytes.subarray(2, 18)),
        peerAddress: addr(codec, bytes.subarray(18, 34))
      };
      const parsed = decodeOptions(bytes, 34, (options.depth || 0) + 1, codec);
      out.options = parsed.options;
      warnings.push.apply(warnings, parsed.warnings);
      const relay = out.options.find((o) => o.code === 9);
      if (relay && relay.nested) out.relay.message = relay.nested;
    } else {
      const parsed = decodeOptions(bytes, 4, (options.depth || 0) + 1, codec);
      out.options = parsed.options;
      warnings.push.apply(warnings, parsed.warnings);
    }
    const client = out.options && out.options.find((o) => o.code === 1);
    const server = out.options && out.options.find((o) => o.code === 2);
    out.clientId = client ? client.duid : null;
    out.serverId = server ? server.duid : null;
    const status = out.options && out.options.find((o) => o.code === 13);
    if (status) out.status = status;
    return out;
  }

  /* ---------- build ---------- */
  function buildDuid(duid) {
    if (duid instanceof Uint8Array) return duid;
    if (typeof duid === "string") return toBytes(duid);
    const type = toInt(duid.type, "DUID type", 1, 4, 3);
    if (type === 1) {
      const ll = toBytes(duid.linkLayerAddress || "02:00:00:00:00:01".replace(/:/g, " "));
      const bytes = new Uint8Array(8 + ll.length);
      PH.put16be(bytes, 0, 1);
      PH.put16be(bytes, 2, toInt(duid.hardwareType, "Hardware type", 0, 65535, 1));
      PH.put32be(bytes, 4, toInt(duid.time, "Time", 0, 4294967295, 0));
      bytes.set(ll, 8);
      return bytes;
    }
    if (type === 2) {
      const id = toBytes(duid.identifier);
      const bytes = new Uint8Array(6 + id.length);
      PH.put16be(bytes, 0, 2);
      PH.put32be(bytes, 2, toInt(duid.enterpriseNumber, "Enterprise number", 0, 4294967295, 0));
      bytes.set(id, 6);
      return bytes;
    }
    if (type === 3) {
      const ll = toBytes(duid.linkLayerAddress || "02:00:00:00:00:01".replace(/:/g, " "));
      const bytes = new Uint8Array(4 + ll.length);
      PH.put16be(bytes, 0, 3);
      PH.put16be(bytes, 2, toInt(duid.hardwareType, "Hardware type", 0, 65535, 1));
      bytes.set(ll, 4);
      return bytes;
    }
    const uuid = toBytes(duid.uuid);
    if (uuid.length !== 16) throw new Error("DUID-UUID needs a 16-byte UUID");
    const bytes = new Uint8Array(18);
    PH.put16be(bytes, 0, 4);
    bytes.set(uuid, 2);
    return bytes;
  }

  function buildOption(option) {
    const code = toInt(option.code, "Option code", 0, 65535);
    let data;
    if (option.value != null) data = toBytes(option.value);
    else if (code === 1 || code === 2) data = buildDuid(option.duid || option.value || { type: 3, hardwareType: 1, linkLayerAddress: "02:00:00:00:00:01" });
    else if (code === 3 || code === 25) {
      const nested = (option.options || []).map(buildOption);
      data = new Uint8Array(12 + nested.reduce((n, o) => n + o.length, 0));
      PH.put32be(data, 0, toInt(option.iaid, "IAID", 0, 4294967295, 0));
      PH.put32be(data, 4, toInt(option.t1, "T1", 0, 4294967295, 0));
      PH.put32be(data, 8, toInt(option.t2, "T2", 0, 4294967295, 0));
      let pos = 12; nested.forEach((o) => { data.set(o, pos); pos += o.length; });
    } else if (code === 4) {
      const nested = (option.options || []).map(buildOption);
      data = new Uint8Array(4 + nested.reduce((n, o) => n + o.length, 0));
      PH.put32be(data, 0, toInt(option.iaid, "IAID", 0, 4294967295, 0));
      let pos = 4; nested.forEach((o) => { data.set(o, pos); pos += o.length; });
    } else if (code === 5) {
      if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
      const address = ipv6(global.IPv6Codec, option.address, "Address");
      const nested = (option.options || []).map(buildOption);
      data = new Uint8Array(24 + nested.reduce((n, o) => n + o.length, 0));
      data.set(address, 0);
      PH.put32be(data, 16, toInt(option.preferred, "Preferred lifetime", 0, 4294967295, 0));
      PH.put32be(data, 20, toInt(option.valid, "Valid lifetime", 0, 4294967295, 0));
      let pos = 24; nested.forEach((o) => { data.set(o, pos); pos += o.length; });
    } else if (code === 26) {
      if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
      const prefix = ipv6(global.IPv6Codec, option.prefix, "Prefix");
      data = new Uint8Array(25);
      PH.put32be(data, 0, toInt(option.preferred, "Preferred lifetime", 0, 4294967295, 0));
      PH.put32be(data, 4, toInt(option.valid, "Valid lifetime", 0, 4294967295, 0));
      data[8] = toInt(option.prefixLength, "Prefix length", 0, 128, 64);
      data.set(prefix, 9);
    } else if (code === 6) {
      const codes = option.requested || option.codes || [];
      data = new Uint8Array(codes.length * 2);
      codes.forEach((c, i) => PH.put16be(data, i * 2, Number(c.code != null ? c.code : c)));
    } else if (code === 7) {
      data = Uint8Array.from([toInt(option.preference, "Preference", 0, 255, 0)]);
    } else if (code === 8) {
      data = new Uint8Array(2);
      PH.put16be(data, 0, toInt(option.elapsed, "Elapsed time", 0, 65535, 0));
    } else if (code === 9) {
      data = option.nestedBytes || buildDhcpv6(option.message || {}).bytes;
    } else if (code === 12) {
      if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
      data = ipv6(global.IPv6Codec, option.address, "Address");
    } else if (code === 13) {
      const message = new TextEncoder().encode(option.message || "");
      data = new Uint8Array(2 + message.length);
      PH.put16be(data, 0, toInt(option.status, "Status code", 0, 65535, 0));
      data.set(message, 2);
    } else if (code === 23) {
      if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
      const servers = option.servers || [];
      data = new Uint8Array(servers.length * 16);
      servers.forEach((s, i) => data.set(ipv6(global.IPv6Codec, s, "DNS server"), i * 16));
    } else if (code === 24) {
      const parts = [];
      (option.domains || []).forEach((name) => {
        const labels = String(name).split(".").filter(Boolean);
        const bytes = [];
        labels.forEach((label) => {
          if (label.length > 63) throw new Error("Domain label exceeds 63 bytes");
          bytes.push(label.length);
          for (let i = 0; i < label.length; i++) bytes.push(label.charCodeAt(i) & 255);
        });
        bytes.push(0);
        parts.push(Uint8Array.from(bytes));
      });
      data = PH.concatBytes.apply(null, parts.length ? parts : [new Uint8Array(0)]);
    } else if (code === 15 || code === 16) {
      const parts = [];
      if (code === 16) {
        const head = new Uint8Array(4);
        PH.put32be(head, 0, toInt(option.enterpriseNumber, "Enterprise number", 0, 4294967295, 0));
        parts.push(head);
      }
      (option.classes || []).forEach((cls) => {
        const value = new TextEncoder().encode(String(cls));
        const head = new Uint8Array(2);
        PH.put16be(head, 0, value.length);
        parts.push(head, value);
      });
      data = PH.concatBytes.apply(null, parts);
    } else if (code === 18) {
      data = toBytes(option.interfaceId);
    } else if (code === 39) {
      const fqdn = String(option.fqdn || "").split(".").filter(Boolean);
      const labels = [];
      fqdn.forEach((label) => { labels.push(label.length); for (let i = 0; i < label.length; i++) labels.push(label.charCodeAt(i) & 255); });
      labels.push(0);
      data = Uint8Array.from([toInt(option.flags, "Flags", 0, 255, 0)].concat(labels));
    } else if (code === 59) {
      data = new TextEncoder().encode(option.url || "");
    } else if (code === 82 || code === 83) {
      data = new Uint8Array(4);
      PH.put32be(data, 0, toInt(option.seconds, "Seconds", 0, 4294967295, 0));
    } else {
      data = new Uint8Array(0);
    }
    const bytes = new Uint8Array(4 + data.length);
    PH.put16be(bytes, 0, code);
    PH.put16be(bytes, 2, data.length);
    bytes.set(data, 4);
    return bytes;
  }

  function buildDhcpv6(input) {
    const type = toInt(input.type, "Message type", 1, 13, 1);
    const transactionId = toInt(input.transactionId, "Transaction ID", 0, 0xffffff, 0x123456);
    const options = (input.options || []).map(buildOption);
    const optionBytes = options.reduce((n, o) => n + o.length, 0);
    if (type === 12 || type === 13) {
      if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
      const bytes = new Uint8Array(34 + optionBytes);
      bytes[0] = type;
      bytes[1] = toInt(input.hopCount, "Hop count", 0, 255, 0);
      bytes.set(ipv6(global.IPv6Codec, input.linkAddress || "::", "Link address"), 2);
      bytes.set(ipv6(global.IPv6Codec, input.peerAddress || "::", "Peer address"), 18);
      let pos = 34; options.forEach((o) => { bytes.set(o, pos); pos += o.length; });
      return { bytes, type, typeName: messageName(type), transactionId: null, hopCount: bytes[1], options: options.length };
    }
    const bytes = new Uint8Array(4 + optionBytes);
    bytes[0] = type;
    bytes[1] = (transactionId >>> 16) & 255;
    bytes[2] = (transactionId >>> 8) & 255;
    bytes[3] = transactionId & 255;
    let pos = 4; options.forEach((o) => { bytes.set(o, pos); pos += o.length; });
    return { bytes, type, typeName: messageName(type), transactionId, options: options.length };
  }

  global.DHCPv6Codec = {
    MESSAGE_TYPES, OPTION_NAMES, DUID_TYPES, STATUS, messageName, optionName, duidName,
    decodeDuid, decodeOption, decodeDhcpv6, buildDuid, buildOption, buildDhcpv6
  };
})(typeof window !== "undefined" ? window : globalThis);
