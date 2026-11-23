/* ICMPv6 (RFC 4443), Neighbor Discovery (RFC 4861), SLAAC (RFC 4862)
   and MLD (RFC 3810) codec. Shared by icmpv6.html and the tests. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const TYPES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
    130: "MLD Query", 131: "MLD Report", 132: "MLD Done", 133: "Router Solicitation",
    134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
    137: "Redirect", 138: "Router Renumbering", 139: "Node Information Query",
    140: "Node Information Reply", 143: "MLDv2 Report", 151: "Multicast Router Advertisement",
    152: "Multicast Router Solicitation", 153: "Multicast Router Termination",
    155: "RPL Control", 156: "RPL Control"
  };

  const CODES = {
    1: { 0: "no route to destination", 1: "administratively prohibited", 2: "beyond scope of source address",
      3: "address unreachable", 4: "port unreachable", 5: "source address failed ingress/egress policy",
      6: "reject route to destination", 7: "error in source routing header" },
    2: { 0: "packet too big" },
    3: { 0: "hop limit exceeded in transit", 1: "fragment reassembly time exceeded" },
    4: { 0: "erroneous header field", 1: "unrecognized Next Header", 2: "unrecognized IPv6 option" },
    128: { 0: "echo request" }, 129: { 0: "echo reply" },
    133: { 0: "router solicitation" }, 134: { 0: "router advertisement" },
    135: { 0: "neighbor solicitation" }, 136: { 0: "neighbor advertisement" },
    137: { 0: "redirect" }
  };

  const ND_OPTIONS = {
    1: "Source Link-Layer Address", 2: "Target Link-Layer Address", 3: "Prefix Information",
    4: "Redirected Header", 5: "MTU", 24: "Route Information", 25: "Recursive DNS Server",
    31: "DNS Search List", 38: "PREF64", 253: "Experimental", 254: "Experimental"
  };

  const RA_FLAGS = { M: 0x80, O: 0x40, H: 0x20, Prf: 0x18, P: 0x08 };

  function typeName(type) { return TYPES[type] || "Type " + type; }
  function codeName(type, code) {
    const map = CODES[type];
    return map && map[code] != null ? map[code] : (code === 0 ? null : "code " + code);
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

  function ipv6(codec, text, name) {
    if (text instanceof Uint8Array) {
      if (text.length !== 16) throw new Error(name + " must be 16 bytes");
      return text;
    }
    if (!codec) throw new Error("IPv6 codec is not loaded");
    return codec.parseIPv6(text);
  }

  function addrString(codec, bytes) {
    if (!bytes || bytes.length !== 16) return "::";
    return codec ? codec.formatIPv6(bytes) : Array.from(bytes, (b) => PH.hex(b)).join(":");
  }

  function macString(bytes) {
    return Array.from(bytes, (b) => PH.hex(b).toLowerCase()).join(":");
  }

  function pseudoHeader(src, dst, length) {
    if (!src || !dst || src.length !== 16 || dst.length !== 16) {
      throw new Error("ICMPv6 checksum needs 16-byte IPv6 source and destination addresses");
    }
    const bytes = new Uint8Array(40);
    bytes.set(src, 0);
    bytes.set(dst, 16);
    PH.put32be(bytes, 32, length);
    bytes[39] = 58;
    return bytes;
  }

  function checksum(icmpBytes, context) {
    const bytes = icmpBytes instanceof Uint8Array ? icmpBytes.slice() : Uint8Array.from(icmpBytes);
    if (bytes.length < 4) throw new Error("ICMPv6 needs at least 4 bytes");
    const c = context || {};
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    const src = ipv6(codec, c.src, "Source address");
    const dst = ipv6(codec, c.dst, "Destination address");
    bytes[2] = 0;
    bytes[3] = 0;
    const pseudo = pseudoHeader(src, dst, bytes.length);
    let value = PH.checksum16(PH.concatBytes(pseudo, bytes));
    if (value === 0) value = 0xffff;
    return value;
  }

  /* ---------- Neighbor Discovery options ---------- */
  function parseOptions(bytes, offset, codec) {
    const options = [];
    let pos = offset;
    const warnings = [];
    while (pos + 2 <= bytes.length) {
      const type = bytes[pos];
      const length = bytes[pos + 1];
      if (length === 0) {
        warnings.push("ND option at +" + pos + " has length 0");
        break;
      }
      const end = pos + length * 8;
      if (end > bytes.length) {
        warnings.push("ND option type " + type + " runs past the message (" + (end - bytes.length) + " B short)");
        break;
      }
      const raw = bytes.subarray(pos + 2, end);
      const option = { type, name: ND_OPTIONS[type] || "Option " + type, length: length * 8, offset: pos, raw, fields: [] };
      if (type === 1 || type === 2) {
        if (raw.length >= 6 && raw.length <= 8) {
          option.address = macString(raw.subarray(0, 6));
          option.fields.push(["Link-layer address", option.address]);
        } else {
          option.address = PH.bytesToHex(raw);
          option.fields.push(["Address", option.address]);
        }
      } else if (type === 3 && raw.length >= 30) {
        option.prefixLength = raw[0];
        option.flags = { L: !!(raw[1] & 0x80), A: !!(raw[1] & 0x40), R: !!(raw[1] & 0x20) };
        option.validLifetime = PH.u32be(raw, 2);
        option.preferredLifetime = PH.u32be(raw, 6);
        option.prefix = addrString(codec, raw.subarray(14, 30));
        option.fields.push(["Prefix", option.prefix + "/" + option.prefixLength]);
        option.fields.push(["Flags", ["L", "A", "R"].filter((f) => option.flags[f]).join(" ") || "none"]);
        option.fields.push(["Valid lifetime", option.validLifetime + " s"]);
        option.fields.push(["Preferred lifetime", option.preferredLifetime + " s"]);
      } else if (type === 5 && raw.length >= 6) {
        option.mtu = PH.u32be(raw, 2);
        option.fields.push(["MTU", option.mtu]);
      } else if (type === 25 && raw.length >= 22) {
        option.lifetime = PH.u32be(raw, 2);
        option.addresses = [];
        for (let p = 6; p + 16 <= raw.length; p += 16) option.addresses.push(addrString(codec, raw.subarray(p, p + 16)));
        option.fields.push(["Lifetime", option.lifetime + " s"]);
        option.fields.push(["Servers", option.addresses.join(", ") || "none"]);
      } else if (type === 31) {
        option.lifetime = raw.length >= 6 ? PH.u32be(raw, 2) : null;
        option.fields.push(["Lifetime", option.lifetime == null ? "—" : option.lifetime + " s"]);
        option.fields.push(["Raw domain list", PH.bytesToHex(raw.subarray(6)) || "empty"]);
      } else if (type === 38 && raw.length >= 14) {
        option.scaledLifetime = PH.u16be(raw, 0);
        option.prefixLength = raw[2];
        option.prefix = addrString(codec, raw.subarray(6, 14)).replace(/::0$/, "::");
        option.fields.push(["Prefix", option.prefix + "/" + option.prefixLength]);
        option.fields.push(["Scaled lifetime", option.scaledLifetime]);
      } else {
        option.fields.push(["Raw", PH.bytesToHex(raw) || "empty"]);
      }
      options.push(option);
      pos = end;
    }
    if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the last ND option");
    return { options, warnings, consumed: pos - offset };
  }

  /* ---------- build ---------- */
  function buildOptions(input, codec) {
    const options = input.options || [];
    const parts = [];
    options.forEach((raw) => {
      if (raw instanceof Uint8Array) { parts.push(raw); return; }
      const kind = String(raw.kind || raw.type || "slla").toLowerCase();
      if (kind === "slla" || kind === "tlla" || kind === "lladdr") {
        const type = kind === "tlla" ? 2 : 1;
        const mac = raw.mac || "02:00:00:00:00:01";
        const macBytes = String(mac).split(":").map((x) => parseInt(x, 16));
        if (macBytes.length !== 6 || macBytes.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
          throw new Error("Link-layer address must be six hex octets");
        }
        const bytes = new Uint8Array(8);
        bytes[0] = type;
        bytes[1] = 1;
        bytes.set(macBytes, 2);
        parts.push(bytes);
      } else if (kind === "prefix") {
        const prefix = ipv6(codec, raw.prefix || "2001:db8::", "Prefix");
        const plen = toInt(raw.prefixLength, "Prefix length", 0, 128, 64);
        const bytes = new Uint8Array(32);
        bytes[0] = 3;
        bytes[1] = 4;
        bytes[2] = plen;
        bytes[3] = (raw.onLink === false ? 0 : 0x80) | (raw.autonomous === false ? 0 : 0x40);
        PH.put32be(bytes, 4, toInt(raw.validLifetime, "Valid lifetime", 0, 4294967295, 2592000));
        PH.put32be(bytes, 8, toInt(raw.preferredLifetime, "Preferred lifetime", 0, 4294967295, 604800));
        bytes.set(prefix, 16);
        parts.push(bytes);
      } else if (kind === "mtu") {
        const bytes = new Uint8Array(8);
        bytes[0] = 5;
        bytes[1] = 1;
        PH.put32be(bytes, 4, toInt(raw.mtu, "MTU", 1280, 4294967295, 1500));
        parts.push(bytes);
      } else {
        throw new Error("Unknown ND option kind: " + kind);
      }
    });
    return parts.length ? PH.concatBytes.apply(null, parts) : new Uint8Array(0);
  }

  function buildIcmpv6(input) {
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    const type = toInt(input.type, "Type", 0, 255);
    const code = toInt(input.code, "Code", 0, 255, 0);
    let body;
    if (type === 128 || type === 129) {
      const data = toBytes(input.data);
      body = new Uint8Array(4 + data.length);
      PH.put16be(body, 0, toInt(input.identifier, "Identifier", 0, 65535, 1));
      PH.put16be(body, 2, toInt(input.sequence, "Sequence", 0, 65535, 1));
      body.set(data, 4);
    } else if (type === 1 || type === 3) {
      const data = toBytes(input.data);
      body = new Uint8Array(4 + data.length);
      body.set(data, 4);
    } else if (type === 2) {
      const data = toBytes(input.data);
      body = new Uint8Array(4 + data.length);
      PH.put32be(body, 0, toInt(input.mtu, "MTU", 0, 4294967295, 1280));
      body.set(data, 4);
    } else if (type === 4) {
      const data = toBytes(input.data);
      body = new Uint8Array(4 + data.length);
      PH.put32be(body, 0, toInt(input.pointer, "Pointer", 0, 4294967295, 0));
      body.set(data, 4);
    } else if (type === 133) {
      const options = buildOptions(input, codec);
      body = new Uint8Array(4 + options.length);
      body.set(options, 4);
    } else if (type === 135) {
      const target = ipv6(codec, input.target, "Target address");
      const options = buildOptions(input, codec);
      body = new Uint8Array(20 + options.length);
      body.set(target, 4);
      body.set(options, 20);
    } else if (type === 136) {
      const target = ipv6(codec, input.target, "Target address");
      const options = buildOptions(input, codec);
      body = new Uint8Array(20 + options.length);
      body[0] = (input.router ? 0x80 : 0) | (input.solicited ? 0x40 : 0) | (input.override ? 0x20 : 0);
      body.set(target, 4);
      body.set(options, 20);
    } else if (type === 134) {
      const options = buildOptions(input, codec);
      body = new Uint8Array(12 + options.length);
      body[0] = toInt(input.curHopLimit, "Current hop limit", 0, 255, 64);
      body[1] = (input.managed ? 0x80 : 0) | (input.other ? 0x40 : 0);
      PH.put16be(body, 2, toInt(input.routerLifetime, "Router lifetime", 0, 65535, 1800));
      PH.put32be(body, 4, toInt(input.reachableTime, "Reachable time", 0, 4294967295, 0));
      PH.put32be(body, 8, toInt(input.retransTimer, "Retrans timer", 0, 4294967295, 0));
      body.set(options, 12);
    } else {
      body = toBytes(input.data);
    }
    const bytes = new Uint8Array(4 + body.length);
    bytes[0] = type;
    bytes[1] = code;
    bytes.set(body, 4);
    let checksumValue = 0;
    let checksumState = "unset";
    if (input.src && input.dst) {
      checksumValue = checksum(bytes, { src: input.src, dst: input.dst });
      PH.put16be(bytes, 2, checksumValue);
      checksumState = "built";
    }
    return {
      bytes, type, code, typeName: typeName(type), codeName: codeName(type, code),
      checksum: checksumValue, checksumState, body,
      messageLength: bytes.length
    };
  }

  /* ---------- decode ---------- */
  function decodeIcmpv6(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 4) throw new Error("ICMPv6 needs at least 4 bytes");
    const options = opts || {};
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    const type = bytes[0];
    const code = bytes[1];
    const checksumValue = PH.u16be(bytes, 2);
    const warnings = [];
    const fields = [];
    let details = {};

    let expectedChecksum = null;
    let checksumState = "unknown";
    if (options.src && options.dst) {
      try {
        expectedChecksum = checksum(bytes, options);
        checksumState = expectedChecksum === checksumValue ? "valid" : "invalid";
        if (checksumState === "invalid") warnings.push("ICMPv6 checksum is invalid (expected 0x" + PH.hex(expectedChecksum, 4) + ")");
      } catch (err) {
        checksumState = "not-checked";
        warnings.push("Checksum not checked: " + err.message);
      }
    }

    const payload = bytes.subarray(4);

    if (type === 128 || type === 129) {
      if (payload.length < 4) warnings.push("Echo message is shorter than its identifier and sequence");
      details = {
        identifier: payload.length >= 2 ? PH.u16be(payload, 0) : null,
        sequence: payload.length >= 4 ? PH.u16be(payload, 2) : null,
        data: payload.subarray(4)
      };
      fields.push(["Identifier", details.identifier], ["Sequence", details.sequence], ["Data", details.data.length + " B"]);
    } else if (type === 1 || type === 3 || type === 4) {
      const value = payload.length >= 4 ? PH.u32be(payload, 0) : null;
      details = { unused: value, quoted: payload.subarray(4) };
      if (type === 4) details.pointer = value;
      if (type === 4 && value != null) fields.push(["Pointer", value]);
      if (type === 1 || type === 3) fields.push(["Unused", value == null ? "—" : "0x" + PH.hex(value, 8)]);
      fields.push(["Quoted packet", details.quoted.length + " B"]);
    } else if (type === 2) {
      details = { mtu: payload.length >= 4 ? PH.u32be(payload, 0) : null, quoted: payload.subarray(4) };
      fields.push(["MTU", details.mtu], ["Quoted packet", details.quoted.length + " B"]);
    } else if (type === 133) {
      const parsed = parseOptions(bytes, 8, codec);
      details = { options: parsed.options, warnings: parsed.warnings };
      warnings.push.apply(warnings, parsed.warnings);
      fields.push(["Options", parsed.options.length + " (ND)"]);
    } else if (type === 134) {
      details = {
        curHopLimit: bytes.length > 4 ? bytes[4] : null,
        managed: bytes.length > 5 ? !!(bytes[5] & 0x80) : false,
        other: bytes.length > 5 ? !!(bytes[5] & 0x40) : false,
        routerLifetime: bytes.length >= 8 ? PH.u16be(bytes, 6) : null,
        reachableTime: bytes.length >= 12 ? PH.u32be(bytes, 8) : null,
        retransTimer: bytes.length >= 16 ? PH.u32be(bytes, 12) : null
      };
      const parsed = parseOptions(bytes, 16, codec);
      details.options = parsed.options;
      warnings.push.apply(warnings, parsed.warnings);
      fields.push(["Cur hop limit", details.curHopLimit]);
      fields.push(["Flags", [details.managed ? "M" : "", details.other ? "O" : ""].filter(Boolean).join(" ") || "none"]);
      fields.push(["Router lifetime", details.routerLifetime + " s"]);
      fields.push(["Reachable time", details.reachableTime + " ms"]);
      fields.push(["Retrans timer", details.retransTimer + " ms"]);
      fields.push(["Options", parsed.options.length + " (ND)"]);
    } else if (type === 135) {
      const target = bytes.length >= 20 ? bytes.subarray(8, 24) : null;
      const parsed = parseOptions(bytes, 24, codec);
      details = { target: target ? addrString(codec, target) : null, targetBytes: target, options: parsed.options };
      warnings.push.apply(warnings, parsed.warnings);
      fields.push(["Target", details.target || "—"]);
      fields.push(["Options", parsed.options.length + " (ND)"]);
    } else if (type === 136) {
      const flags = bytes.length > 4 ? bytes[4] : 0;
      const target = bytes.length >= 24 ? bytes.subarray(8, 24) : null;
      const parsed = parseOptions(bytes, 24, codec);
      details = {
        router: !!(flags & 0x80), solicited: !!(flags & 0x40), override: !!(flags & 0x20),
        target: target ? addrString(codec, target) : null, targetBytes: target, options: parsed.options
      };
      warnings.push.apply(warnings, parsed.warnings);
      fields.push(["Flags", [details.router ? "R" : "", details.solicited ? "S" : "", details.override ? "O" : ""].filter(Boolean).join(" ") || "none"]);
      fields.push(["Target", details.target || "—"]);
      fields.push(["Options", parsed.options.length + " (ND)"]);
    } else if (type === 137) {
      const target = bytes.length >= 24 ? bytes.subarray(8, 24) : null;
      const destination = bytes.length >= 40 ? bytes.subarray(24, 40) : null;
      const parsed = parseOptions(bytes, 40, codec);
      details = {
        target: target ? addrString(codec, target) : null,
        destination: destination ? addrString(codec, destination) : null,
        options: parsed.options
      };
      warnings.push.apply(warnings, parsed.warnings);
      fields.push(["Target", details.target || "—"], ["Destination", details.destination || "—"]);
    } else if (type === 130 || type === 131 || type === 132 || type === 143) {
      details = {
        maxResponseDelay: bytes.length >= 6 ? PH.u16be(bytes, 4) : null,
        multicastAddress: bytes.length >= 24 ? addrString(codec, bytes.subarray(8, 24)) : null,
        flags: bytes.length >= 8 ? bytes[4] : null
      };
      fields.push(["Multicast address", details.multicastAddress || "—"]);
      if (type === 130) fields.push(["Max response delay", details.maxResponseDelay + " (0.1 s units)"]);
    } else {
      details = { data: payload };
      fields.push(["Body", payload.length + " B"]);
    }

    const quoted = details.quoted || (details.data && details.data.length ? details.data : null);

    return {
      bytes, type, code, typeName: typeName(type), codeName: codeName(type, code),
      checksum: checksumValue, expectedChecksum, checksumState, checksumOk: checksumState === "valid",
      payload, details, fields, warnings, messageLength: bytes.length,
      quoted: quoted || new Uint8Array(0),
      nd: type >= 133 && type <= 137
    };
  }

  global.ICMPv6Codec = {
    TYPES, CODES, ND_OPTIONS, RA_FLAGS, typeName, codeName, parseOptions,
    pseudoHeader, checksum, buildIcmpv6, decodeIcmpv6
  };
})(typeof window !== "undefined" ? window : globalThis);
