/* DNS (RFC 1035, RFC 6891, RFC 3596) message codec — shared by the DNS page,
   the packet dissector and tests. */
(function (global) {
  "use strict";

  const PH = global.PH;

  const TYPES = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
    9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX",
    16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC",
    33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL",
    43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
    49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
    59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY",
    250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA"
  };

  const TYPE_VALUES = {};
  Object.keys(TYPES).forEach((code) => { TYPE_VALUES[TYPES[code]] = Number(code); });

  const CLASSES = { 1: "IN", 2: "CS", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY" };
  const CLASS_VALUES = { IN: 1, CS: 2, CH: 3, HS: 4, NONE: 254, ANY: 255 };

  const OPCODES = { 0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DSO" };
  const RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
    6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
    11: "DSOTYPENI", 16: "BADVERS / BADSIG", 17: "BADKEY", 18: "BADTIME",
    19: "BADMODE", 20: "BADNAME", 21: "BADALG", 22: "BADTRUNC", 23: "BADCOOKIE"
  };

  const EDNS_OPTIONS = {
    3: "NSID", 5: "DAU", 6: "DHU", 7: "N3U", 8: "ECS", 9: "EXPIRE", 10: "COOKIE",
    11: "TCP Keepalive", 12: "Padding", 13: "CHAIN", 14: "Key Tag", 15: "EDE",
    16: "Client Tag", 17: "Server Tag", 18: "Report Channel", 19: "Zoneversion"
  };

  const EDE_CODES = {
    0: "Other", 1: "Unsupported DNSKEY Algorithm", 2: "Unsupported DS Digest Type",
    3: "Stale Answer", 4: "Forged Answer", 5: "DNSSEC Indeterminate",
    6: "DNSSEC Bogus", 7: "Signature Expired", 8: "Signature Not Yet Valid",
    9: "DNSKEY Missing", 10: "RRSIGs Missing", 11: "No Zone Key Bit Set",
    12: "NSEC Missing", 13: "Cached Error", 14: "Not Ready", 15: "Blocked",
    16: "Censored", 17: "Filtered", 18: "Prohibited", 19: "Stale NXDOMAIN Answer",
    20: "Not Authoritative", 21: "Not Supported", 22: "No Reachable Authority",
    23: "Network Error", 24: "Invalid Data", 25: "Signature Expired before Valid",
    26: "Too Early", 27: "Unsupported NSEC3 Iterations Value"
  };

  const TYPE_DESCRIPTIONS = {
    A: "IPv4 address", NS: "Authoritative name server", CNAME: "Canonical name alias",
    SOA: "Start of authority", PTR: "Reverse lookup pointer", MX: "Mail exchange",
    TXT: "Text strings", AAAA: "IPv6 address", SRV: "Service location", OPT: "EDNS(0) pseudo-record",
    DS: "Delegation signer", RRSIG: "DNSSEC signature", NSEC: "DNSSEC denial of existence",
    DNSKEY: "DNSSEC public key", CAA: "Certificate authority authorization",
    SVCB: "Service binding", HTTPS: "HTTPS service binding", ANY: "Any type"
  };

  function typeName(code) { return TYPES[code] || "TYPE" + code; }
  function typeCode(value) {
    if (typeof value === "number") return value;
    if (value == null || value === "") return 1;
    const upper = String(value).trim().toUpperCase();
    if (TYPE_VALUES[upper] != null) return TYPE_VALUES[upper];
    if (/^TYPE\d+$/i.test(upper)) return Number(upper.slice(4));
    const n = Number(upper);
    if (Number.isInteger(n) && n >= 0 && n <= 65535) return n;
    throw new Error("Unknown DNS type " + value);
  }
  function className(code) { return CLASSES[code] || "CLASS" + code; }
  function classCode(value) {
    if (typeof value === "number") return value;
    const upper = String(value || "IN").trim().toUpperCase();
    if (CLASS_VALUES[upper] != null) return CLASS_VALUES[upper];
    if (/^CLASS\d+$/i.test(upper)) return Number(upper.slice(5));
    const n = Number(upper);
    if (Number.isInteger(n) && n >= 0 && n <= 65535) return n;
    throw new Error("Unknown DNS class " + value);
  }
  function opcodeName(code) { return OPCODES[code] || "opcode " + code; }
  function rcodeName(code) { return RCODES[code] || "rcode " + code; }

  function parseIPv6ForDisplay(bytes) {
    const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
    if (codec) return codec.formatIPv6(bytes);
    return bytes.length === 16 ? PH.bytesToHex(bytes) : "";
  }

  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (Array.isArray(value)) return Uint8Array.from(value);
    if (value == null) return new Uint8Array(0);
    return PH.parseHex(String(value));
  }

  function asciiBytes(text) {
    if (global.TextEncoder) return new TextEncoder().encode(text);
    const out = [];
    for (let i = 0; i < text.length; i++) out.push(text.charCodeAt(i) & 255);
    return Uint8Array.from(out);
  }

  function decodeName(bytes, start, context) {
    const warnings = context && context.warnings ? context.warnings : [];
    const labels = [];
    const pointers = [];
    let pos = start;
    let next = null;
    let jumps = 0;
    let ended = false;
    while (!ended) {
      if (pos >= bytes.length) {
        warnings.push("DNS name at offset " + start + " runs past the end of the message");
        break;
      }
      const length = bytes[pos];
      if ((length & 0xc0) === 0xc0) {
        if (pos + 1 >= bytes.length) {
          warnings.push("Truncated compression pointer at offset " + pos);
          break;
        }
        const pointer = ((length & 0x3f) << 8) | bytes[pos + 1];
        pointers.push(pointer);
        if (next == null) next = pos + 2;
        if (pointer >= bytes.length) {
          warnings.push("Compression pointer at offset " + pos + " targets " + pointer + ", beyond the " + bytes.length + "-byte message");
          break;
        }
        if (++jumps > 32 || pointers.length > 32) {
          warnings.push("Compression pointer chain at offset " + start + " loops or is unreasonably deep");
          break;
        }
        pos = pointer;
        continue;
      }
      if (length & 0xc0) {
        warnings.push("Unsupported label type 0x" + PH.hex(length, 2) + " at offset " + pos);
        break;
      }
      if (length === 0) {
        if (next == null) next = pos + 1;
        ended = true;
        break;
      }
      if (length > 63) {
        warnings.push("Label length " + length + " exceeds 63 at offset " + pos);
        break;
      }
      if (pos + 1 + length > bytes.length) {
        warnings.push("Label at offset " + pos + " declares " + length + " bytes but the message ends first");
        break;
      }
      labels.push(asciiToString(bytes.subarray(pos + 1, pos + 1 + length)));
      pos += 1 + length;
      if (labels.join(".").length > 253) {
        warnings.push("DNS name at offset " + start + " exceeds 253 characters");
        break;
      }
    }
    return {
      name: labels.length ? labels.join(".") + "." : ".",
      labels,
      next: next == null ? pos : next,
      pointers,
      compressed: pointers.length > 0,
      length: (next == null ? pos : next) - start,
      warnings
    };
  }

  function asciiToString(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0x5c || b === 0x2e) out += "\\" + String.fromCharCode(b);
      else if (b >= 32 && b < 127) out += String.fromCharCode(b);
      else out += "\\" + (b < 16 ? "0" : "") + b.toString(16);
    }
    return out;
  }

  function buildName(name, offset, dictionary, compress) {
    const text = String(name == null ? "" : name).trim();
    if (text === "" || text === ".") return new Uint8Array([0]);
    if (text.length > 253) throw new Error("DNS name exceeds 253 characters: " + text);
    const labels = text.replace(/\.$/, "").split(".");
    const chunks = [];
    let cursor = offset;
    for (let i = 0; i < labels.length; i++) {
      const label = labels[i];
      if (!label.length) throw new Error("DNS name has an empty label: " + text);
      const bytes = asciiBytes(label);
      if (bytes.length > 63) throw new Error("DNS label exceeds 63 bytes: " + label);
      const suffix = labels.slice(i).join(".");
      if (compress && dictionary && dictionary[suffix] != null) {
        const target = dictionary[suffix];
        if (target < 0x4000) {
          chunks.push(Uint8Array.from([0xc0 | (target >> 8), target & 255]));
          return PH.concatBytes.apply(PH, chunks);
        }
      }
      if (compress && dictionary && cursor < 0x4000 && dictionary[suffix] == null) {
        dictionary[suffix] = cursor;
      }
      const chunk = new Uint8Array(1 + bytes.length);
      chunk[0] = bytes.length;
      chunk.set(bytes, 1);
      chunks.push(chunk);
      cursor += chunk.length;
    }
    chunks.push(new Uint8Array([0]));
    return PH.concatBytes.apply(PH, chunks);
  }

  function readU16(bytes, offset) { return PH.u16be(bytes, offset); }
  function readU32(bytes, offset) { return PH.u32be(bytes, offset); }

  function parseCharacterStrings(bytes, start, end, warnings) {
    const strings = [];
    let pos = start;
    while (pos < end) {
      const length = bytes[pos];
      if (pos + 1 + length > end) {
        warnings.push("TXT character-string at offset " + pos + " overruns RDLENGTH");
        break;
      }
      const raw = bytes.subarray(pos + 1, pos + 1 + length);
      strings.push({ text: asciiToString(raw), bytes: raw, length });
      pos += 1 + length;
    }
    return strings;
  }

  function parseRdata(bytes, type, rdataStart, rdlength, context) {
    const end = rdataStart + rdlength;
    const region = bytes.subarray(rdataStart, end);
    const warnings = context.warnings;
    const result = { kind: typeName(type), bytes: region, fields: [] };
    if (rdlength === 0 && type !== 41) {
      warnings.push("RDLENGTH is 0 for " + typeName(type) + " at offset " + rdataStart);
      return result;
    }
    switch (type) {
      case 1:
        if (rdlength !== 4) warnings.push("A record RDLENGTH is " + rdlength + ", expected 4");
        result.value = rdlength >= 4 ? PH.ipv4String(bytes, rdataStart) : PH.bytesToHex(region);
        if (rdlength >= 4) result.fields = [{ name: "Address", value: result.value }];
        break;
      case 28:
        if (rdlength !== 16) warnings.push("AAAA record RDLENGTH is " + rdlength + ", expected 16");
        result.value = rdlength >= 16 ? parseIPv6ForDisplay(bytes.subarray(rdataStart, rdataStart + 16)) : PH.bytesToHex(region);
        if (rdlength >= 16) result.fields = [{ name: "Address", value: result.value }];
        break;
      case 2: case 5: case 12: case 39:
        {
          const name = decodeName(bytes, rdataStart, context);
          result.value = name.name;
          result.name = name;
          result.fields = [{ name: "Name", value: name.name }];
          if (name.next > end) warnings.push(typeName(type) + " name at offset " + rdataStart + " extends beyond RDLENGTH " + rdlength);
        }
        break;
      case 15:
        if (rdlength < 3) { warnings.push("MX record is too short for a preference and exchange name"); result.value = PH.bytesToHex(region); break; }
        {
          const preference = readU16(bytes, rdataStart);
          const name = decodeName(bytes, rdataStart + 2, context);
          result.value = preference + " " + name.name;
          result.fields = [{ name: "Preference", value: preference }, { name: "Exchange", value: name.name }];
          result.name = name;
          if (name.next > end) warnings.push("MX exchange name extends beyond RDLENGTH");
        }
        break;
      case 6:
        {
          const mname = decodeName(bytes, rdataStart, context);
          const rname = decodeName(bytes, mname.next, context);
          const numbersAt = rname.next;
          if (numbersAt + 20 > end) {
            warnings.push("SOA record is too short for its five 32-bit values");
            result.value = mname.name + " " + rname.name;
            break;
          }
          const serial = readU32(bytes, numbersAt);
          const refresh = readU32(bytes, numbersAt + 4);
          const retry = readU32(bytes, numbersAt + 8);
          const expire = readU32(bytes, numbersAt + 12);
          const minimum = readU32(bytes, numbersAt + 16);
          result.soa = { mname: mname.name, rname: rname.name, serial, refresh, retry, expire, minimum };
          result.value = mname.name + " " + rname.name + " · serial " + serial;
          result.fields = [
            { name: "Primary NS", value: mname.name }, { name: "Responsible", value: rname.name },
            { name: "Serial", value: serial }, { name: "Refresh", value: refresh + " s" },
            { name: "Retry", value: retry + " s" }, { name: "Expire", value: expire + " s" },
            { name: "Minimum TTL", value: minimum + " s" }
          ];
        }
        break;
      case 16: case 99:
        {
          const strings = parseCharacterStrings(bytes, rdataStart, end, warnings);
          result.strings = strings.map((s) => s.text);
          result.value = strings.map((s) => "\"" + s.text + "\"").join(" ");
          result.fields = strings.map((s, i) => ({ name: "String " + (i + 1), value: "\"" + s.text + "\"" }));
        }
        break;
      case 33:
        if (rdlength < 7) { warnings.push("SRV record is shorter than its six fixed bytes plus a target name"); result.value = PH.bytesToHex(region); break; }
        {
          const priority = readU16(bytes, rdataStart);
          const weight = readU16(bytes, rdataStart + 2);
          const port = readU16(bytes, rdataStart + 4);
          const target = decodeName(bytes, rdataStart + 6, context);
          result.srv = { priority, weight, port, target: target.name };
          result.value = priority + " " + weight + " " + port + " " + target.name;
          result.fields = [
            { name: "Priority", value: priority }, { name: "Weight", value: weight },
            { name: "Port", value: port }, { name: "Target", value: target.name }
          ];
        }
        break;
      case 257:
        if (rdlength < 2) { warnings.push("CAA record is too short"); result.value = PH.bytesToHex(region); break; }
        {
          const flags = bytes[rdataStart];
          const tagLength = bytes[rdataStart + 1];
          if (rdataStart + 2 + tagLength > end) { warnings.push("CAA tag overruns RDLENGTH"); result.value = PH.bytesToHex(region); break; }
          const tag = asciiToString(bytes.subarray(rdataStart + 2, rdataStart + 2 + tagLength));
          const value = asciiToString(bytes.subarray(rdataStart + 2 + tagLength, end));
          result.caa = { flags, tag, value };
          result.value = flags + " " + tag + " \"" + value + "\"";
          result.fields = [{ name: "Flags", value: flags }, { name: "Tag", value: tag }, { name: "Value", value: value }];
        }
        break;
      case 43:
        if (rdlength < 4) { warnings.push("DS record is shorter than its four fixed bytes"); result.value = PH.bytesToHex(region); break; }
        {
          const keyTag = readU16(bytes, rdataStart);
          const algorithm = bytes[rdataStart + 2];
          const digestType = bytes[rdataStart + 3];
          const digest = bytes.subarray(rdataStart + 4, end);
          result.value = keyTag + " alg " + algorithm + " digest " + digestType;
          result.fields = [
            { name: "Key Tag", value: keyTag }, { name: "Algorithm", value: algorithm },
            { name: "Digest Type", value: digestType }, { name: "Digest", value: PH.bytesToHex(digest) }
          ];
        }
        break;
      case 48:
        if (rdlength < 5) { warnings.push("DNSKEY record is shorter than its four fixed bytes"); result.value = PH.bytesToHex(region); break; }
        {
          const flags = readU16(bytes, rdataStart);
          const protocol = bytes[rdataStart + 2];
          const algorithm = bytes[rdataStart + 3];
          result.value = "flags " + flags + " alg " + algorithm;
          result.fields = [
            { name: "Flags", value: flags + ((flags & 0x0100) ? " · ZONE" : "") + ((flags & 0x0001) ? " · SEP" : "") },
            { name: "Protocol", value: protocol }, { name: "Algorithm", value: algorithm },
            { name: "Public Key", value: PH.bytesToHex(bytes.subarray(rdataStart + 4, end)) }
          ];
          if (protocol !== 3) warnings.push("DNSKEY Protocol is " + protocol + "; RFC 4034 requires 3");
        }
        break;
      case 41:
        {
          const options = [];
          let pos = rdataStart;
          while (pos + 4 <= end) {
            const code = readU16(bytes, pos);
            const length = readU16(bytes, pos + 2);
            if (pos + 4 + length > end) { warnings.push("EDNS option " + code + " overruns RDLENGTH"); break; }
            const data = bytes.subarray(pos + 4, pos + 4 + length);
            const option = { code, name: EDNS_OPTIONS[code] || "option " + code, length, bytes: data, value: PH.bytesToHex(data) };
            if (code === 8 && length >= 4) {
              const family = readU16(data, 0);
              const sourcePrefix = data[2];
              const scopePrefix = data[3];
              let address = PH.bytesToHex(data.subarray(4));
              if (family === 1 && data.length >= 8) address = PH.ipv4String(data, 4);
              else if (family === 2 && data.length >= 20) address = parseIPv6ForDisplay(data.subarray(4, 20));
              option.value = (family === 1 ? "IPv4" : family === 2 ? "IPv6" : "family " + family) +
                " " + address + "/" + sourcePrefix + " scope /" + scopePrefix;
            } else if (code === 10) {
              option.value = data.length >= 8 ? "client " + PH.bytesToHex(data.subarray(0, 8)) +
                (data.length >= 16 ? " · server " + PH.bytesToHex(data.subarray(8, 16)) : "") : PH.bytesToHex(data);
            } else if (code === 15 && length >= 2) {
              const infoCode = readU16(data, 0);
              option.value = infoCode + " · " + (EDE_CODES[infoCode] || "unknown") +
                (length > 2 ? " · " + asciiToString(data.subarray(2)) : "");
            } else if (code === 12) {
              option.value = length + " padding byte(s)";
            } else if (code === 3) {
              option.value = asciiToString(data);
            }
            options.push(option);
            pos += 4 + length;
          }
          if (pos !== end) warnings.push("EDNS option area has " + (end - pos) + " trailing byte(s)");
          result.options = options;
          result.value = options.length ? options.map((o) => o.name).join(", ") : "no options";
          result.fields = options.map((o) => ({ name: o.name, value: o.value }));
        }
        break;
      default:
        result.value = PH.bytesToHex(region);
        result.fields = [{ name: "RDATA", value: PH.bytesToHex(region) }];
        break;
    }
    return result;
  }

  function parseFlags(raw) {
    return {
      raw,
      qr: (raw >> 15) & 1,
      opcode: (raw >> 11) & 15,
      aa: (raw >> 10) & 1,
      tc: (raw >> 9) & 1,
      rd: (raw >> 8) & 1,
      ra: (raw >> 7) & 1,
      z: (raw >> 6) & 1,
      ad: (raw >> 5) & 1,
      cd: (raw >> 4) & 1,
      rcode: raw & 15
    };
  }

  function encodeFlags(flags) {
    const f = flags || {};
    return ((f.qr ? 1 : 0) << 15) |
      ((Number(f.opcode || 0) & 15) << 11) |
      ((f.aa ? 1 : 0) << 10) |
      ((f.tc ? 1 : 0) << 9) |
      ((f.rd ? 1 : 0) << 8) |
      ((f.ra ? 1 : 0) << 7) |
      ((f.z ? 1 : 0) << 6) |
      ((f.ad ? 1 : 0) << 5) |
      ((f.cd ? 1 : 0) << 4) |
      (Number(f.rcode || 0) & 15);
  }

  function serverFailure(message, offset, context) {
    const err = { error: message, offset };
    if (context && context.warnings) context.warnings.push(message);
    return err;
  }

  function parseQuestion(bytes, offset, context) {
    const name = decodeName(bytes, offset, context);
    const after = name.next;
    if (after + 4 > bytes.length) {
      return { question: { name: name.name, nameInfo: name }, next: bytes.length, truncated: true };
    }
    const type = readU16(bytes, after);
    const cls = readU16(bytes, after + 2);
    return {
      question: {
        name: name.name, nameInfo: name, type, typeName: typeName(type),
        class: cls, className: className(cls), offset, length: after + 4 - offset
      },
      next: after + 4
    };
  }

  function parseRecord(bytes, offset, context) {
    const name = decodeName(bytes, offset, context);
    const after = name.next;
    if (after + 10 > bytes.length) {
      return { record: { name: name.name, nameInfo: name, truncated: true }, next: bytes.length, truncated: true };
    }
    const type = readU16(bytes, after);
    const cls = readU16(bytes, after + 2);
    const ttl = readU32(bytes, after + 4);
    const rdlength = readU16(bytes, after + 8);
    const rdataStart = after + 10;
    if (rdataStart + rdlength > bytes.length) {
      context.warnings.push("Record " + name.name + " " + typeName(type) + " declares RDLENGTH " + rdlength +
        " but only " + (bytes.length - rdataStart) + " byte(s) remain");
    }
    if (type === 41) {
      const extRcode = (ttl >>> 24) & 255;
      const version = (ttl >>> 16) & 255;
      const flags = ttl & 0xffff;
      return {
        record: {
          name: name.name, nameInfo: name, type, typeName: typeName(type), class: cls,
          className: className(cls), udpPayloadSize: cls, extRcode, version, flags,
          do: (flags >> 15) & 1, ttl, rdlength, rdataStart, offset,
          length: Math.min(bytes.length, rdataStart + rdlength) - offset,
          rdata: parseRdata(bytes, type, rdataStart, Math.min(rdlength, bytes.length - rdataStart), context)
        },
        next: rdataStart + rdlength
      };
    }
    const record = {
      name: name.name, nameInfo: name, type, typeName: typeName(type), typeDescription: TYPE_DESCRIPTIONS[typeName(type)] || "",
      class: cls, className: className(cls), ttl, rdlength, rdataStart, offset,
      length: Math.min(bytes.length, rdataStart + rdlength) - offset,
      rdata: parseRdata(bytes, type, rdataStart, Math.min(rdlength, bytes.length - rdataStart), context)
    };
    if (ttl & 0x80000000) context.warnings.push("TTL " + ttl + " has the high bit set (RFC 2181 treats TTL as 31-bit)");
    return { record, next: rdataStart + rdlength };
  }

  function decodeMessage(bytes, opts) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const options = opts || {};
    if (bytes.length < 12) throw new Error("DNS needs at least 12 bytes for its header");
    const warnings = [];
    const id = PH.u16be(bytes, 0);
    const flagsRaw = PH.u16be(bytes, 2);
    const flags = parseFlags(flagsRaw);
    const counts = {
      questions: PH.u16be(bytes, 4),
      answers: PH.u16be(bytes, 6),
      authority: PH.u16be(bytes, 8),
      additional: PH.u16be(bytes, 10)
    };
    const context = { warnings };
    let pos = 12;
    const questions = [];
    for (let i = 0; i < counts.questions; i++) {
      if (pos >= bytes.length) { warnings.push("QDCOUNT says " + counts.questions + " question(s) but the message ended after " + questions.length); break; }
      const parsed = parseQuestion(bytes, pos, context);
      if (parsed.truncated) warnings.push("Question " + (i + 1) + " is truncated");
      questions.push(parsed.question);
      pos = parsed.next;
      if (parsed.truncated) break;
    }
    function parseSection(count, label) {
      const records = [];
      for (let i = 0; i < count; i++) {
        if (pos >= bytes.length) {
          warnings.push(label + " count says " + count + " record(s) but the message ended after " + records.length);
          break;
        }
        const parsed = parseRecord(bytes, pos, context);
        if (parsed.truncated) warnings.push(label + " record " + (i + 1) + " is truncated");
        records.push(parsed.record);
        pos = parsed.next;
        if (parsed.truncated) break;
        if (pos > bytes.length) { warnings.push(label + " record " + (i + 1) + " extends past the message"); break; }
      }
      return records;
    }
    const answers = parseSection(counts.answers, "Answer");
    const authority = parseSection(counts.authority, "Authority");
    const additional = parseSection(counts.additional, "Additional");

    if (counts.questions === 0 && flags.qr === 0) warnings.push("A query with QDCOUNT 0 has nothing to resolve");
    if (flags.qr === 0 && counts.answers + counts.authority > 0 && flags.opcode !== 5) warnings.push("A query carries answer or authority records; unusual except for UPDATE or NOTIFY");
    if (flags.z) warnings.push("The reserved Z bit (0x0040) is set");
    if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the last parsed record");
    if (bytes.length > 512 && !options.allowLarge && !additional.some((r) => r.type === 41)) {
      warnings.push("Message exceeds 512 bytes without an OPT record (classic UDP DNS limit)");
    }
    if (flags.tc) warnings.push("TC is set; the sender truncated the message and the client should retry over TCP");

    const optRecord = additional.find((r) => r.type === 41) || null;
    const effectiveRcode = optRecord ? ((optRecord.extRcode << 4) | flags.rcode) : flags.rcode;
    if (optRecord) {
      if (optRecord.version !== 0) warnings.push("EDNS version " + optRecord.version + " is not supported by most responders");
      const optCount = additional.filter((r) => r.type === 41).length;
      if (optCount > 1) warnings.push("More than one OPT record is present; RFC 6891 allows at most one");
      if (optRecord.name !== ".") warnings.push("OPT owner name must be the root (\".\")");
      if (optRecord.udpPayloadSize < 512) warnings.push("EDNS UDP payload size " + optRecord.udpPayloadSize + " is below 512");
    }

    const header = {
      id, flagsRaw, flags, counts,
      qr: flags.qr, opcode: flags.opcode, opcodeName: opcodeName(flags.opcode),
      aa: flags.aa, tc: flags.tc, rd: flags.rd, ra: flags.ra, ad: flags.ad, cd: flags.cd,
      rcode: flags.rcode, rcodeName: rcodeName(flags.rcode),
      effectiveRcode, effectiveRcodeName: rcodeName(effectiveRcode)
    };

    return {
      bytes, messageLength: bytes.length, id, flags, flagsRaw, counts, header,
      questions, answers, authority, additional, opt: optRecord,
      sections: [
        { key: "questions", label: "Question", items: questions },
        { key: "answers", label: "Answer", items: answers },
        { key: "authority", label: "Authority", items: authority },
        { key: "additional", label: "Additional", items: additional }
      ],
      warnings, parsedLength: pos,
      truncated: flags.tc === 1
    };
  }

  /* ---------- encoding ---------- */

  function buildQuestion(question, offset, dict, compress) {
    const type = typeCode(question.type == null ? 1 : question.type);
    const cls = classCode(question.class == null ? "IN" : question.class);
    const name = buildName(question.name, offset, dict, compress);
    const tail = new Uint8Array(4);
    PH.put16be(tail, 0, type);
    PH.put16be(tail, 2, cls);
    return PH.concatBytes(name, tail);
  }

  function buildRdata(record, offset, dict, warnings) {
    const type = typeCode(record.type);
    const data = record.data;
    const compress = record.compress !== false;
    switch (type) {
      case 1: {
        if (typeof data === "string" && /^\d+\.\d+\.\d+\.\d+$/.test(data.trim())) return PH.parseIPv4(data);
        const bytes = toBytes(data);
        if (bytes.length !== 4) throw new Error("A record needs a 4-byte address");
        return bytes;
      }
      case 28: {
        if (typeof data === "string") {
          if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
          return global.IPv6Codec.parseIPv6(data);
        }
        const bytes = toBytes(data);
        if (bytes.length !== 16) throw new Error("AAAA record needs a 16-byte address");
        return bytes;
      }
      case 2: case 5: case 12: case 39:
        return buildName(typeof data === "string" ? data : data.name, offset, dict, compress);
      case 15: {
        const preference = typeof data === "object" ? data.preference : Number(String(data).trim().split(/\s+/)[0]);
        const exchange = typeof data === "object" ? data.exchange : String(data).trim().split(/\s+/).slice(1).join(" ");
        if (!Number.isInteger(preference) || preference < 0 || preference > 65535) throw new Error("MX preference must be 0–65535");
        const fixed = new Uint8Array(2);
        PH.put16be(fixed, 0, preference);
        return PH.concatBytes(fixed, buildName(exchange, offset + 2, dict, compress));
      }
      case 16: case 99: {
        const strings = Array.isArray(data) ? data : [data == null ? "" : String(data)];
        const chunks = [];
        strings.forEach((text) => {
          let bytes = asciiBytes(String(text));
          if (bytes.length > 255) throw new Error("TXT string exceeds 255 bytes");
          const head = new Uint8Array([bytes.length]);
          chunks.push(head, bytes);
        });
        if (!chunks.length) chunks.push(new Uint8Array([0]));
        return PH.concatBytes.apply(PH, chunks);
      }
      case 6: {
        const soa = typeof data === "object" ? data : {};
        const mname = soa.mname || soa.primary || "ns.invalid.";
        const rname = soa.rname || soa.responsible || "hostmaster.invalid.";
        let part = buildName(mname, offset, dict, compress);
        part = PH.concatBytes(part, buildName(rname, offset + part.length, dict, compress));
        const numbers = new Uint8Array(20);
        ["serial", "refresh", "retry", "expire", "minimum"].forEach((key, i) => {
          const value = Number(soa[key] == null ? (key === "serial" ? 1 : key === "minimum" ? 300 : 3600) : soa[key]);
          if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error("SOA " + key + " must be an unsigned 32-bit value");
          PH.put32be(numbers, i * 4, value);
        });
        return PH.concatBytes(part, numbers);
      }
      case 33: {
        const srv = typeof data === "object" ? data : {};
        const priority = Number(srv.priority || 0);
        const weight = Number(srv.weight || 0);
        const port = Number(srv.port || 0);
        if ([priority, weight, port].some((n) => !Number.isInteger(n) || n < 0 || n > 65535)) throw new Error("SRV priority, weight and port must be 0–65535");
        const target = srv.target || ".";
        const fixed = new Uint8Array(6);
        PH.put16be(fixed, 0, priority);
        PH.put16be(fixed, 2, weight);
        PH.put16be(fixed, 4, port);
        return PH.concatBytes(fixed, buildName(target, offset + 6, dict, false));
      }
      case 257: {
        const caa = typeof data === "object" ? data : {};
        const flags = Number(caa.flags || 0);
        const tag = String(caa.tag || "issue");
        const value = String(caa.value || data || "");
        const tagBytes = asciiBytes(tag);
        if (tagBytes.length > 255) throw new Error("CAA tag exceeds 255 bytes");
        return PH.concatBytes(Uint8Array.from([flags & 255, tagBytes.length]), tagBytes, asciiBytes(value));
      }
      case 43: {
        const ds = typeof data === "object" ? data : {};
        const digest = toBytes(ds.digest || "");
        const bytes = new Uint8Array(4 + digest.length);
        PH.put16be(bytes, 0, Number(ds.keyTag || 0));
        bytes[2] = Number(ds.algorithm || 8);
        bytes[3] = Number(ds.digestType || 2);
        bytes.set(digest, 4);
        return bytes;
      }
      case 48: {
        const key = typeof data === "object" ? data : {};
        const publicKey = toBytes(key.publicKey || "");
        const bytes = new Uint8Array(4 + publicKey.length);
        PH.put16be(bytes, 0, Number(key.flags || 256));
        bytes[2] = 3;
        bytes[3] = Number(key.algorithm || 8);
        bytes.set(publicKey, 4);
        return bytes;
      }
      case 41: {
        const opt = typeof data === "object" ? data : {};
        const chunks = [];
        (opt.options || []).forEach((option) => {
          const payload = toBytes(option.data || "");
          const head = new Uint8Array(4);
          PH.put16be(head, 0, Number(option.code));
          PH.put16be(head, 2, payload.length);
          chunks.push(head, payload);
        });
        return PH.concatBytes.apply(PH, chunks);
      }
      case 255:
        throw new Error("ANY is a query-only QTYPE; it cannot carry RDATA");
      default: {
        const bytes = toBytes(data);
        if (warnings) warnings.push("Encoding " + typeName(type) + " as opaque RDATA (" + bytes.length + " bytes)");
        return bytes;
      }
    }
  }

  function buildRecord(record, offset, dict, warnings) {
    const type = typeCode(record.type);
    const cls = classCode(record.class == null ? (type === 41 ? 4096 : "IN") : record.class);
    const name = buildName(record.name == null ? "." : record.name, offset, dict, record.compress !== false);
    const rdataOffset = offset + name.length + 10;
    let rdata;
    if (type === 41) {
      const opt = typeof record.data === "object" ? record.data : {};
      const options = [];
      (opt.options || []).forEach((option) => {
        const payload = option.bytes ? toBytes(option.bytes) : toBytes(option.data || "");
        const head = new Uint8Array(4);
        PH.put16be(head, 0, Number(option.code));
        PH.put16be(head, 2, payload.length);
        options.push(head, payload);
      });
      rdata = PH.concatBytes.apply(PH, options);
    } else {
      rdata = buildRdata(record, rdataOffset, dict, warnings);
    }
    let ttl = Number(record.ttl == null ? 300 : record.ttl);
    if (type === 41) {
      const opt = typeof record.data === "object" ? record.data : {};
      ttl = ((Number(opt.extendedRcode || 0) & 255) << 24) |
        ((Number(opt.version || 0) & 255) << 16) |
        (Number(opt.flags || 0) & 0xffff);
    }
    if (!Number.isInteger(ttl) || ttl < 0 || ttl > 0xffffffff) throw new Error("TTL must be an unsigned 32-bit value");
    const head = new Uint8Array(10);
    PH.put16be(head, 0, type);
    PH.put16be(head, 2, cls);
    PH.put32be(head, 4, ttl);
    PH.put16be(head, 8, rdata.length);
    return PH.concatBytes(name, head, rdata);
  }

  function buildMessage(input) {
    const spec = input || {};
    const warnings = [];
    const flags = encodeFlags(spec);
    const questions = (spec.questions || []).filter(Boolean);
    const answers = (spec.answers || []).filter(Boolean);
    const authority = (spec.authority || []).filter(Boolean);
    const additional = (spec.additional || []).filter(Boolean);
    const header = new Uint8Array(12);
    PH.put16be(header, 0, Number(spec.id == null ? 0 : spec.id) & 0xffff);
    PH.put16be(header, 2, flags);
    PH.put16be(header, 4, questions.length);
    PH.put16be(header, 6, answers.length);
    PH.put16be(header, 8, authority.length);
    PH.put16be(header, 10, additional.length);
    const chunks = [header];
    let offset = 12;
    const dict = {};
    const compress = spec.compress !== false;
    questions.forEach((question) => {
      const bytes = buildQuestion(question, offset, dict, compress);
      chunks.push(bytes);
      offset += bytes.length;
    });
    [answers, authority, additional].forEach((section) => {
      section.forEach((record) => {
        const bytes = buildRecord(record, offset, dict, warnings);
        chunks.push(bytes);
        offset += bytes.length;
      });
    });
    const bytes = PH.concatBytes.apply(PH, chunks);
    const decoded = decodeMessage(bytes, { allowLarge: true });
    return {
      bytes, messageLength: bytes.length, id: Number(spec.id || 0) & 0xffff,
      flags, flagsObject: parseFlags(flags), counts: {
        questions: questions.length, answers: answers.length,
        authority: authority.length, additional: additional.length
      },
      decoded, warnings: decoded.warnings.concat(warnings)
    };
  }

  /* ---------- text helpers for the page and tests ---------- */

  function parseRecordLine(line) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) return null;
    const tokens = trimmed.split(/\s+/);
    if (tokens.length < 3) throw new Error("Record lines need: name [ttl] type data");
    const name = tokens.shift();
    let ttl = 300;
    if (/^\d+$/.test(tokens[0]) && tokens.length >= 3) ttl = Number(tokens.shift());
    const type = tokens.shift().toUpperCase();
    const rest = tokens.join(" ");
    const code = typeCode(type);
    const record = { name, type, ttl };
    switch (code) {
      case 1: record.data = rest; break;
      case 28: record.data = rest; break;
      case 2: case 5: case 12: case 39: record.data = rest; break;
      case 15: record.data = rest; break;
      case 16: case 99: {
        const strings = [];
        const re = /"([^"]*)"|(\S+)/g;
        let match;
        while ((match = re.exec(rest))) strings.push(match[1] != null ? match[1] : match[2]);
        record.data = strings.length ? strings : [""];
        break;
      }
      case 6: {
        const parts = rest.split(/\s+/);
        if (parts.length < 7) throw new Error("SOA needs: mname rname serial refresh retry expire minimum");
        record.data = {
          mname: parts[0], rname: parts[1], serial: Number(parts[2]), refresh: Number(parts[3]),
          retry: Number(parts[4]), expire: Number(parts[5]), minimum: Number(parts[6])
        };
        break;
      }
      case 33: {
        const parts = rest.split(/\s+/);
        if (parts.length < 4) throw new Error("SRV needs: priority weight port target");
        record.data = { priority: Number(parts[0]), weight: Number(parts[1]), port: Number(parts[2]), target: parts[3] };
        break;
      }
      case 257: {
        const parts = rest.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?$/);
        if (!parts) throw new Error("CAA needs: flags tag \"value\"");
        record.data = { flags: Number(parts[1]), tag: parts[2], value: parts[3] };
        break;
      }
      case 43: {
        const parts = rest.split(/\s+/);
        if (parts.length < 4) throw new Error("DS needs: keyTag algorithm digestType hexDigest");
        record.data = { keyTag: Number(parts[0]), algorithm: Number(parts[1]), digestType: Number(parts[2]), digest: parts.slice(3).join(" ") };
        break;
      }
      case 41: {
        record.data = { extendedRcode: 0, version: 0, flags: 0, options: [] };
        if (/^\d+$/.test(rest)) record.class = Number(rest);
        break;
      }
      case 48: {
        const parts = rest.split(/\s+/);
        if (parts.length < 4) throw new Error("DNSKEY needs: flags algorithm hexKey");
        record.data = { flags: Number(parts[0]), algorithm: Number(parts[1]), publicKey: parts.slice(2).join(" ") };
        break;
      }
      default:
        record.data = rest;
        break;
    }
    return record;
  }

  function parseRecordLines(text) {
    return String(text || "").split(/\r?\n/).map(parseRecordLine).filter(Boolean);
  }

  function examples() {
    return {
      queryA: {
        label: "A query", id: 0x1234, rd: true,
        questions: [{ name: "example.com.", type: "A", class: "IN" }]
      },
      responseA: {
        label: "A + AAAA response", id: 0x1234, qr: true, aa: true, rd: true, ra: true,
        questions: [{ name: "example.com.", type: "A", class: "IN" }],
        answers: [
          { name: "example.com.", type: "A", ttl: 300, data: "192.0.2.10" },
          { name: "example.com.", type: "AAAA", ttl: 300, data: "2001:db8::10" }
        ]
      },
      mx: {
        label: "MX response", id: 0x2222, qr: true, aa: true, rd: true, ra: true,
        questions: [{ name: "example.com.", type: "MX", class: "IN" }],
        answers: [
          { name: "example.com.", type: "MX", ttl: 3600, data: "10 mail1.example.com." },
          { name: "example.com.", type: "MX", ttl: 3600, data: "20 mail2.example.com." }
        ]
      },
      cname: {
        label: "CNAME + A", id: 0x3333, qr: true, aa: true, rd: true, ra: true,
        questions: [{ name: "www.example.com.", type: "A", class: "IN" }],
        answers: [
          { name: "www.example.com.", type: "CNAME", ttl: 300, data: "example.com." },
          { name: "example.com.", type: "A", ttl: 300, data: "192.0.2.10" }
        ]
      },
      txt: {
        label: "TXT + SPF", id: 0x4444, qr: true, aa: true, rd: true, ra: true,
        questions: [{ name: "example.com.", type: "TXT", class: "IN" }],
        answers: [
          { name: "example.com.", type: "TXT", ttl: 300, data: ["v=spf1 ip4:192.0.2.0/24 -all"] },
          { name: "example.com.", type: "TXT", ttl: 300, data: ["hello world", "second string"] }
        ]
      },
      srv: {
        label: "SRV", id: 0x5555, qr: true, aa: true, rd: true, ra: true,
        questions: [{ name: "_sip._tcp.example.com.", type: "SRV", class: "IN" }],
        answers: [
          { name: "_sip._tcp.example.com.", type: "SRV", ttl: 300, data: { priority: 10, weight: 60, port: 5060, target: "sip.example.com." } }
        ]
      },
      nxdomain: {
        label: "NXDOMAIN", id: 0x6666, qr: true, aa: true, rd: true, ra: true, rcode: 3,
        questions: [{ name: "missing.example.com.", type: "A", class: "IN" }],
        authority: [
          { name: "example.com.", type: "SOA", ttl: 300, data: { mname: "ns1.example.com.", rname: "hostmaster.example.com.", serial: 2026110401, refresh: 3600, retry: 600, expire: 86400, minimum: 300 } }
        ]
      },
      edns: {
        label: "EDNS(0) query", id: 0x7777, rd: true,
        questions: [{ name: "example.com.", type: "A", class: "IN" }],
        additional: [
          { name: ".", type: "OPT", class: 1232, ttl: 0, data: { extendedRcode: 0, version: 0, flags: 0x8000, options: [] } }
        ]
      }
    };
  }

  global.DNSCodec = {
    TYPES, TYPE_VALUES, CLASSES, CLASS_VALUES, OPCODES, RCODES, EDNS_OPTIONS, EDE_CODES,
    typeName, typeCode, className, classCode, opcodeName, rcodeName, parseFlags, encodeFlags,
    decodeName, buildName, decodeMessage, buildMessage, parseRecordLine, parseRecordLines, examples,
    asciiToString
  };
})(window);
