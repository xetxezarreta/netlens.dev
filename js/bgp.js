/* BGP-4 path attributes — pure codec + page wiring */
(function () {
  "use strict";

  const PH = window.PH;
  const BGP_RFC = "https://www.rfc-editor.org/rfc/rfc4271";

  const ATTR = {
    1: { name: "ORIGIN", flags: 0x40, kind: "well-known mandatory", hint: "0 = IGP · 1 = EGP · 2 = INCOMPLETE", def: "0", rfc: "4271 §5.1.1" },
    2: { name: "AS_PATH", flags: 0x40, kind: "well-known mandatory", hint: "space-separated ASNs; braces for AS_SET: 65001 65002 {65003,65004}", def: "65001 65002 65003", rfc: "4271 §5.1.2" },
    3: { name: "NEXT_HOP", flags: 0x40, kind: "well-known mandatory", hint: "IPv4 address", def: "192.0.2.1", rfc: "4271 §5.1.3" },
    4: { name: "MULTI_EXIT_DISC", flags: 0x80, kind: "optional non-transitive", hint: "32-bit integer", def: "50", rfc: "4271 §5.1.4" },
    5: { name: "LOCAL_PREF", flags: 0x40, kind: "well-known discretionary", hint: "32-bit integer", def: "100", rfc: "4271 §5.1.5" },
    6: { name: "ATOMIC_AGGREGATE", flags: 0x40, kind: "well-known discretionary", hint: "no value", def: "", rfc: "4271 §5.1.6" },
    7: { name: "AGGREGATOR", flags: 0xc0, kind: "optional transitive", hint: "ASN:IPv4, e.g. 65001:192.0.2.1", def: "65001:192.0.2.1", rfc: "4271 §5.1.7" },
    8: { name: "COMMUNITIES", flags: 0xc0, kind: "optional transitive", hint: "AS:value or no-export, no-advertise, no-peer; comma-separated", def: "65001:100, no-export", rfc: "RFC 1997" },
    9: { name: "ORIGINATOR_ID", flags: 0x80, kind: "optional non-transitive", hint: "IPv4 router ID", def: "192.0.2.1", rfc: "RFC 4456" },
    10: { name: "CLUSTER_LIST", flags: 0x80, kind: "optional non-transitive", hint: "comma-separated IPv4 cluster IDs", def: "192.0.2.1, 192.0.2.2", rfc: "RFC 4456" },
    14: { name: "MP_REACH_NLRI", flags: 0x80, kind: "optional non-transitive", hint: "raw hex: AFI, SAFI, next hop, NLRI", def: "", rfc: "RFC 4760" },
    15: { name: "MP_UNREACH_NLRI", flags: 0x80, kind: "optional non-transitive", hint: "raw hex: AFI, SAFI, withdrawn NLRI", def: "", rfc: "RFC 4760" },
    16: { name: "EXTENDED_COMMUNITIES", flags: 0xc0, kind: "optional transitive", hint: "raw hex, 8 bytes per community", def: "00 02 00 00 00 00 00 64", rfc: "RFC 4360" },
    17: { name: "AS4_PATH", flags: 0xc0, kind: "optional transitive", hint: "AS path with 4-byte ASNs", def: "65001 65002", rfc: "RFC 6793" },
    18: { name: "AS4_AGGREGATOR", flags: 0xc0, kind: "optional transitive", hint: "4-byte ASN:IPv4", def: "65001:192.0.2.1", rfc: "RFC 6793" },
    32: { name: "LARGE_COMMUNITIES", flags: 0xc0, kind: "optional transitive", hint: "global:local1:local2, comma-separated", def: "65001:1:2", rfc: "RFC 8092" }
  };

  const WELL_KNOWN_COMMUNITIES = {
    0xffffff01: "NO_EXPORT",
    0xffffff02: "NO_ADVERTISE",
    0xffffff03: "NO_EXPORT_SUBCONFED",
    0xffffff04: "NO_PEER"
  };
  const COMMUNITY_ALIASES = {
    "no-export": 0xffffff01,
    "no-advertise": 0xffffff02,
    "no-export-subconfed": 0xffffff03,
    "no-peer": 0xffffff04
  };

  function standardFlags(code) { return ATTR[code] ? ATTR[code].flags : 0x80; }
  function attrName(code) { return ATTR[code] ? ATTR[code].name : "UNKNOWN"; }
  function flagNames(flags) {
    const out = [];
    if (flags & 0x80) out.push("Optional");
    if (flags & 0x40) out.push("Transitive");
    if (flags & 0x20) out.push("Partial");
    if (flags & 0x10) out.push("Extended");
    return out;
  }
  function flagBadges(flags) { return flagNames(flags).join(" · ") || "none"; }
  function u32(value, label) {
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(label + " must be 0–4294967295");
    return n >>> 0;
  }
  function u16(value, label) {
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new Error(label + " must be 0–65535");
    return n;
  }
  function concat(parts) { return PH.concatBytes.apply(null, parts); }
  function be16(n) { const a = new Uint8Array(2); PH.put16be(a, 0, n); return a; }
  function be32(n) { const a = new Uint8Array(4); PH.put32be(a, 0, n); return a; }
  function beAs(n, width) {
    if (width === 2) return be16(n);
    return be32(n);
  }
  function parseIp(text) {
    try { return PH.parseIPv4(text); }
    catch (err) { throw new Error("invalid IPv4 address: " + text); }
  }
  function ipStr(bytes) { return Array.from(bytes).join("."); }

  function parseAsPath(text, width) {
    const tokens = String(text).match(/\{[^}]*\}|[^\s,{}]+/g) || [];
    if (!tokens.length) throw new Error("AS_PATH needs at least one AS number");
    const segments = [];
    let current = [];
    const max = width === 2 ? 65535 : 0xffffffff;
    function asn(token) {
      const raw = String(token).replace(/^AS/i, "");
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 0 || n > max) throw new Error("AS" + raw + " does not fit in " + width + " bytes");
      return n;
    }
    function flush() {
      if (!current.length) return;
      if (current.length > 255) throw new Error("AS_SEQUENCE exceeds 255 ASNs");
      segments.push({ type: 2, name: "AS_SEQUENCE", asns: current });
      current = [];
    }
    tokens.forEach((token) => {
      if (token.startsWith("{")) {
        flush();
        const inner = token.slice(1, -1).split(/[\s,]+/).filter(Boolean);
        if (!inner.length) return;
        if (inner.length > 255) throw new Error("AS_SET exceeds 255 ASNs");
        segments.push({ type: 1, name: "AS_SET", asns: inner.map(asn) });
      } else {
        current.push(asn(token));
      }
    });
    flush();
    if (!segments.length) throw new Error("AS_PATH produced no segments");
    const parts = [];
    segments.forEach((seg) => {
      parts.push(new Uint8Array([seg.type, seg.asns.length]));
      seg.asns.forEach((n) => parts.push(beAs(n, width)));
    });
    return { bytes: concat(parts), segments };
  }

  function parseAggregator(text, width) {
    const m = String(text).trim().match(/^(\d+)[:\s]+(\S+)$/);
    if (!m) throw new Error("AGGREGATOR expects ASN:IPv4");
    const asn = width === 2 ? u16(m[1], "ASN") : u32(m[1], "ASN");
    return concat([beAs(asn, width), parseIp(m[2])]);
  }

  function parseCommunities(text) {
    const tokens = String(text).split(",").map((s) => s.trim()).filter(Boolean);
    if (!tokens.length) throw new Error("COMMUNITIES needs at least one value");
    const out = [];
    tokens.forEach((token) => {
      const lower = token.toLowerCase();
      let value;
      if (COMMUNITY_ALIASES[lower] != null) value = COMMUNITY_ALIASES[lower];
      else if (/^0x[0-9a-f]{1,8}$/i.test(token)) value = Number.parseInt(token.slice(2), 16) >>> 0;
      else if (/^\d+:\d+$/.test(token)) {
        const [asn, local] = token.split(":").map(Number);
        if (asn > 65535 || local > 65535) throw new Error("2-byte community halves must be 0–65535");
        value = ((asn << 16) | local) >>> 0;
      } else throw new Error("community must be AS:value, 0xhex, or a well-known name: " + token);
      out.push(be32(value));
    });
    return concat(out);
  }

  function parseLargeCommunities(text) {
    const tokens = String(text).split(",").map((s) => s.trim()).filter(Boolean);
    if (!tokens.length) throw new Error("LARGE_COMMUNITIES needs at least one value");
    const parts = [];
    tokens.forEach((token) => {
      const fields = token.split(":").map((s) => s.trim());
      if (fields.length !== 3) throw new Error("large community must be global:local1:local2");
      const nums = fields.map((n) => u32(n, "large community field"));
      parts.push(be32(nums[0]), be32(nums[1]), be32(nums[2]));
    });
    return concat(parts);
  }

  function buildValue(code, value, asWidth) {
    const text = String(value == null ? "" : value).trim();
    switch (code) {
      case 1: {
        const map = { "0": 0, "igp": 0, "1": 1, "egp": 1, "2": 2, "incomplete": 2 };
        const v = map[text.toLowerCase()];
        if (v == null) throw new Error("ORIGIN must be 0 IGP, 1 EGP, or 2 INCOMPLETE");
        return new Uint8Array([v]);
      }
      case 2: return parseAsPath(text, asWidth).bytes;
      case 3: return parseIp(text);
      case 4:
      case 5: return be32(u32(text, "value"));
      case 6: return new Uint8Array(0);
      case 7: return parseAggregator(text, asWidth);
      case 8: return parseCommunities(text);
      case 9: return parseIp(text);
      case 10: {
        const ips = text.split(",").map((s) => s.trim()).filter(Boolean);
        if (!ips.length) throw new Error("CLUSTER_LIST needs at least one IPv4 address");
        return concat(ips.map(parseIp));
      }
      case 14:
      case 15: return PH.parseHex(text);
      case 16: {
        const bytes = PH.parseHex(text);
        if (bytes.length % 8) throw new Error("EXTENDED_COMMUNITIES length must be a multiple of 8");
        return bytes;
      }
      case 17: return parseAsPath(text, 4).bytes;
      case 18: return parseAggregator(text, 4);
      case 32: return parseLargeCommunities(text);
      default: return PH.parseHex(text);
    }
  }

  function buildAttribute(input) {
    const code = Number(input.type);
    if (!Number.isInteger(code) || code < 0 || code > 255) throw new Error("attribute type must be 0–255");
    const asWidth = Number(input.asWidth) === 4 ? 4 : 2;
    let flags = input.flags != null ? (Number(input.flags) & 0xff) : standardFlags(code);
    const value = buildValue(code, input.value, asWidth);
    if (value.length > 65535) throw new Error("attribute value exceeds 65535 bytes");
    if (value.length > 255) flags |= 0x10;
    const ext = Boolean(flags & 0x10);
    const header = [flags, code];
    if (ext) header.push((value.length >>> 8) & 255, value.length & 255);
    else header.push(value.length & 255);
    return {
      bytes: concat([new Uint8Array(header), value]),
      flags, code, ext, value, asWidth,
      name: attrName(code), length: value.length
    };
  }

  function buildUpdate(attrs, withdrawn, nlri) {
    const w = withdrawn || new Uint8Array(0);
    const a = attrs || new Uint8Array(0);
    const n = nlri || new Uint8Array(0);
    const body = concat([be16(w.length), w, be16(a.length), a, n]);
    return body;
  }
  function buildMessage(type, body) {
    const marker = new Uint8Array(16).fill(0xff);
    const len = 19 + body.length;
    if (len > 65535) throw new Error("BGP message exceeds 65535 bytes");
    return concat([marker, be16(len), new Uint8Array([type]), body]);
  }

  /* ---------- value decoders ---------- */
  function decodeAsPath(value, width) {
    const segments = [];
    const warnings = [];
    let off = 0;
    while (off < value.length) {
      if (off + 2 > value.length) { warnings.push("AS_PATH has a truncated segment header"); break; }
      const type = value[off++];
      const count = value[off++];
      const need = count * width;
      if (off + need > value.length) {
        warnings.push(`AS_PATH segment ${segments.length + 1} needs ${need} bytes, only ${value.length - off} remain`);
        break;
      }
      const asns = [];
      for (let i = 0; i < count; i++) {
        asns.push(width === 2 ? PH.u16be(value, off) : PH.u32be(value, off));
        off += width;
      }
      const names = { 1: "AS_SET", 2: "AS_SEQUENCE", 3: "AS_CONFED_SEQUENCE", 4: "AS_CONFED_SET" };
      segments.push({ type, name: names[type] || "UNKNOWN", asns });
      if (!names[type]) warnings.push("AS_PATH segment type " + type + " is unknown");
    }
    return { segments, warnings };
  }

  function decodeCommunities(value) {
    const list = [];
    for (let i = 0; i + 4 <= value.length; i += 4) {
      const raw = PH.u32be(value, i);
      const wellKnown = WELL_KNOWN_COMMUNITIES[raw];
      list.push({
        raw,
        hex: "0x" + PH.hex(raw, 8),
        text: wellKnown || `${raw >>> 16}:${raw & 0xffff}`,
        wellKnown: Boolean(wellKnown)
      });
    }
    return list;
  }

  function decodeLarge(value) {
    const list = [];
    for (let i = 0; i + 12 <= value.length; i += 12) {
      list.push({
        global: PH.u32be(value, i),
        local1: PH.u32be(value, i + 4),
        local2: PH.u32be(value, i + 8),
        text: `${PH.u32be(value, i)}:${PH.u32be(value, i + 4)}:${PH.u32be(value, i + 8)}`,
        hex: PH.bytesToHex(value.subarray(i, i + 12))
      });
    }
    return list;
  }

  function decodeExtended(value) {
    const list = [];
    const subtypeNames = { 2: "route target", 3: "route origin", 4: "link bandwidth", 5: "unknown", 6: "OSPF domain" };
    for (let i = 0; i + 8 <= value.length; i += 8) {
      const type = value[i];
      const subtype = value[i + 1];
      const data = value.subarray(i + 2, i + 8);
      let detail = "";
      if (type === 0x00) detail = `2-byte AS ${PH.u16be(data, 0)} · local 0x${PH.hex(PH.u32be(data, 2), 8)}`;
      else if (type === 0x01) detail = `IPv4 ${ipStr(data.subarray(0, 4))} · local ${PH.u16be(data, 4)}`;
      else if (type === 0x02) detail = `4-byte AS ${PH.u32be(data, 0)} · local ${PH.u16be(data, 4)}`;
      else if (type === 0x40) detail = `opaque 0x${PH.bytesToHex(data).replace(/ /g, "")}`;
      else detail = `0x${PH.bytesToHex(data).replace(/ /g, "")}`;
      list.push({
        type, subtype, hex: PH.bytesToHex(value.subarray(i, i + 8)),
        text: `${subtypeNames[subtype] || "subtype 0x" + PH.hex(subtype, 2)} · ${detail}`
      });
    }
    return list;
  }

  function formatIPv6(bytes) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(PH.u16be(bytes, i).toString(16));
    let out = groups.join(":");
    out = out.replace(/(^|:)0(:0)+(:|$)/, "::");
    return out;
  }

  function parseNlri(bytes, afi, safi) {
    const list = [];
    let off = 0;
    const maxBytes = afi === 2 ? 16 : 4;
    while (off < bytes.length) {
      const bits = bytes[off++];
      if (bits > maxBytes * 8) { list.push({ text: "invalid prefix length " + bits, bits }); break; }
      const n = Math.ceil(bits / 8);
      if (off + n > bytes.length) { list.push({ text: "truncated prefix", bits }); break; }
      const raw = bytes.slice(off, off + n);
      off += n;
      if (afi === 1 || afi === 2) {
        const padded = new Uint8Array(maxBytes);
        padded.set(raw.subarray(0, maxBytes));
        const addr = afi === 1 ? ipStr(padded) : formatIPv6(padded);
        list.push({ text: addr + "/" + bits, bits, hex: PH.bytesToHex(raw) });
      } else {
        list.push({ text: PH.bytesToHex(raw) + " (AFI " + afi + ")", bits, hex: PH.bytesToHex(raw) });
      }
    }
    return list;
  }

  function parseAttributeValue(code, value, asWidth) {
    const fields = [];
    const out = { fields };
    const warn = [];
    switch (code) {
      case 1: {
        if (value.length !== 1) warn.push("ORIGIN length is " + value.length + "; expected 1");
        const v = value[0];
        const label = ["IGP", "EGP", "INCOMPLETE"][v] || "reserved";
        fields.push({ name: "Origin", value: `${label} (${v})` });
        break;
      }
      case 2:
      case 17: {
        const width = code === 17 ? 4 : asWidth;
        const parsed = decodeAsPath(value, width);
        out.segments = parsed.segments;
        warn.push.apply(warn, parsed.warnings);
        fields.push({ name: "Segments", value: parsed.segments.length + " · " + width + "-byte ASNs" });
        break;
      }
      case 3:
        if (value.length !== 4) warn.push("NEXT_HOP length is " + value.length + "; expected 4");
        fields.push({ name: "Next Hop", value: value.length >= 4 ? ipStr(value.subarray(0, 4)) : "truncated" });
        break;
      case 4:
        if (value.length !== 4) warn.push("MULTI_EXIT_DISC length is " + value.length + "; expected 4");
        fields.push({ name: "MED", value: value.length >= 4 ? PH.u32be(value, 0).toString() : "truncated" });
        break;
      case 5:
        if (value.length !== 4) warn.push("LOCAL_PREF length is " + value.length + "; expected 4");
        fields.push({ name: "Local Preference", value: value.length >= 4 ? PH.u32be(value, 0).toString() : "truncated" });
        break;
      case 6:
        if (value.length !== 0) warn.push("ATOMIC_AGGREGATE must have zero-length value");
        fields.push({ name: "Value", value: "empty" });
        break;
      case 7:
      case 18: {
        const width = code === 18 ? 4 : asWidth;
        if (value.length !== width + 4) warn.push("AGGREGATOR length is " + value.length + "; expected " + (width + 4));
        const asn = value.length >= width ? (width === 2 ? PH.u16be(value, 0) : PH.u32be(value, 0)) : 0;
        const ip = value.length >= width + 4 ? ipStr(value.subarray(width, width + 4)) : "?";
        fields.push({ name: "AS", value: String(asn) });
        fields.push({ name: "Router ID", value: ip });
        break;
      }
      case 8: {
        if (value.length % 4) warn.push("COMMUNITIES length is not a multiple of 4");
        out.communities = decodeCommunities(value);
        fields.push({ name: "Communities", value: out.communities.length + " × 4 B" });
        break;
      }
      case 9:
        if (value.length !== 4) warn.push("ORIGINATOR_ID length is " + value.length + "; expected 4");
        fields.push({ name: "Router ID", value: value.length >= 4 ? ipStr(value.subarray(0, 4)) : "truncated" });
        break;
      case 10: {
        if (value.length % 4) warn.push("CLUSTER_LIST length is not a multiple of 4");
        const ids = [];
        for (let i = 0; i + 4 <= value.length; i += 4) ids.push(ipStr(value.subarray(i, i + 4)));
        out.clusterList = ids;
        fields.push({ name: "Cluster IDs", value: ids.join(", ") || "empty" });
        break;
      }
      case 14: {
        if (value.length < 5) { warn.push("MP_REACH_NLRI is too short"); break; }
        const afi = PH.u16be(value, 0);
        const safi = value[2];
        const nhLen = value[3];
        if (4 + nhLen >= value.length) { warn.push("MP_REACH_NLRI next-hop length overruns the attribute"); break; }
        const nh = value.subarray(4, 4 + nhLen);
        const reserved = value[4 + nhLen];
        const nlri = value.subarray(5 + nhLen);
        const afiName = afi === 1 ? "IPv4" : afi === 2 ? "IPv6" : afi === 25 ? "L2VPN" : "AFI " + afi;
        const safiName = safi === 1 ? "unicast" : safi === 2 ? "multicast" : safi === 70 ? "EVPN" : safi === 128 ? "VPN" : "SAFI " + safi;
        let nhText = PH.bytesToHex(nh);
        if (afi === 1 && nhLen === 4) nhText = ipStr(nh);
        else if (afi === 2 && nhLen === 16) nhText = formatIPv6(nh);
        fields.push({ name: "AFI", value: afi + " · " + afiName });
        fields.push({ name: "SAFI", value: safi + " · " + safiName });
        fields.push({ name: "Next Hop Length", value: String(nhLen) });
        fields.push({ name: "Next Hop", value: nhText });
        fields.push({ name: "Reserved", value: String(reserved) });
        out.nlri = parseNlri(nlri, afi, safi);
        fields.push({ name: "NLRI", value: out.nlri.map((n) => n.text).join(", ") || "none" });
        if (reserved !== 0) warn.push("MP_REACH_NLRI reserved byte is non-zero");
        break;
      }
      case 15: {
        if (value.length < 3) { warn.push("MP_UNREACH_NLRI is too short"); break; }
        const afi = PH.u16be(value, 0);
        const safi = value[2];
        const nlri = value.subarray(3);
        fields.push({ name: "AFI", value: String(afi) });
        fields.push({ name: "SAFI", value: String(safi) });
        out.nlri = parseNlri(nlri, afi, safi);
        fields.push({ name: "Withdrawn NLRI", value: out.nlri.map((n) => n.text).join(", ") || "none" });
        break;
      }
      case 16: {
        if (value.length % 8) warn.push("EXTENDED_COMMUNITIES length is not a multiple of 8");
        out.extended = decodeExtended(value);
        fields.push({ name: "Extended Communities", value: out.extended.length + " × 8 B" });
        break;
      }
      case 32: {
        if (value.length % 12) warn.push("LARGE_COMMUNITIES length is not a multiple of 12");
        out.large = decodeLarge(value);
        fields.push({ name: "Large Communities", value: out.large.length + " × 12 B" });
        break;
      }
      default:
        fields.push({ name: "Value", value: value.length ? PH.bytesToHex(value) : "empty" });
    }
    out.warnings = warn;
    out.raw = value;
    return out;
  }

  function parseAttributes(bytes, opts) {
    const asWidth = opts && Number(opts.asWidth) === 4 ? 4 : 2;
    const attrs = [];
    const warnings = [];
    let off = 0;
    while (off < bytes.length) {
      const start = off;
      if (off + 3 > bytes.length) { warnings.push(`Attribute at offset ${off} is truncated (need at least 3 bytes)`); break; }
      const flags = bytes[off++];
      const code = bytes[off++];
      let length;
      if (flags & 0x10) {
        if (off + 2 > bytes.length) { warnings.push("Extended length at offset " + start + " is truncated"); break; }
        length = PH.u16be(bytes, off); off += 2;
      } else {
        length = bytes[off++];
      }
      if (off + length > bytes.length) {
        warnings.push(`Attribute ${attrName(code)} at offset ${start} claims ${length} bytes but only ${bytes.length - off} remain`);
        break;
      }
      const value = bytes.slice(off, off + length);
      off += length;
      const info = ATTR[code] || null;
      const parsed = parseAttributeValue(code, value, asWidth);
      warnings.push.apply(warnings, parsed.warnings.map((w) => `${attrName(code)}: ${w}`));
      if (flags & 0x0f) warnings.push(`${attrName(code)}: lower reserved flag bits are 0x${PH.hex(flags & 0x0f, 1)}`);
      if (flags & 0x20 && (!(flags & 0x80) || !(flags & 0x40))) warnings.push(`${attrName(code)}: Partial is set but the attribute is not optional transitive`);
      if (info) {
        const std = info.flags;
        if ((flags & 0xc0) !== (std & 0xc0)) warnings.push(`${attrName(code)}: flags 0x${PH.hex(flags, 2)} differ from standard 0x${PH.hex(std, 2)}`);
      } else if (!(flags & 0x80)) {
        warnings.push(`Unknown attribute code ${code} is marked well-known; that is invalid`);
      }
      attrs.push({
        offset: start, flags, code, name: attrName(code), length, value,
        ext: Boolean(flags & 0x10), info, parsed, asWidth,
        optional: Boolean(flags & 0x80), transitive: Boolean(flags & 0x40),
        partial: Boolean(flags & 0x20)
      });
    }
    return { attrs, warnings, asWidth };
  }

  function parseInput(bytes, asWidth) {
    const result = { attrs: [], warnings: [], asWidth, envelope: null, inputType: "attributes" };
    if (bytes.length >= 19 && bytes.subarray(0, 16).every((b) => b === 0xff)) {
      const length = PH.u16be(bytes, 16);
      const type = bytes[18];
      const typeNames = { 1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH" };
      result.inputType = "message";
      result.envelope = {
        marker: PH.bytesToHex(bytes.subarray(0, 16)),
        length, type, typeName: typeNames[type] || "TYPE " + type,
        actualLength: bytes.length
      };
      if (length < 19) result.warnings.push("BGP Length is below the 19-byte minimum");
      if (length > bytes.length) result.warnings.push(`BGP Length says ${length} bytes but only ${bytes.length} captured`);
      if (length > 4096 && length <= 65535) result.warnings.push("BGP message length exceeds 4096; requires RFC 8654 extended message capability");
      if (type !== 2) {
        result.warnings.push("Message type is " + (typeNames[type] || type) + "; no path attributes to parse");
        return result;
      }
      const end = Math.min(length || bytes.length, bytes.length);
      const body = bytes.subarray(19, end);
      if (body.length < 4) { result.warnings.push("UPDATE body is shorter than its two length fields"); return result; }
      const wlen = PH.u16be(body, 0);
      if (2 + wlen + 2 > body.length) { result.warnings.push("Withdrawn Routes Length overruns the UPDATE body"); return result; }
      const withdrawn = body.subarray(2, 2 + wlen);
      const attrLenOff = 2 + wlen;
      const alen = PH.u16be(body, attrLenOff);
      if (attrLenOff + 2 + alen > body.length) { result.warnings.push("Total Path Attribute Length overruns the UPDATE body"); return result; }
      const attrBytes = body.subarray(attrLenOff + 2, attrLenOff + 2 + alen);
      const nlriBytes = body.subarray(attrLenOff + 2 + alen);
      result.envelope.update = {
        withdrawnLength: wlen,
        withdrawn: parseNlri(withdrawn, 1, 1),
        attrLength: alen,
        nlri: parseNlri(nlriBytes, 1, 1),
        attrBytes, nlriBytes, withdrawnBytes: withdrawn
      };
      const parsed = parseAttributes(attrBytes, { asWidth });
      result.attrs = parsed.attrs;
      result.warnings.push.apply(result.warnings, parsed.warnings);
      return result;
    }

    // UPDATE body heuristic: withdrawn length, withdrawn routes, attribute length.
    if (bytes.length >= 4) {
      const wlen = PH.u16be(bytes, 0);
      if (2 + wlen + 2 <= bytes.length) {
        const alen = PH.u16be(bytes, 2 + wlen);
        if (alen > 0 && 4 + wlen + alen <= bytes.length) {
          const attrBytes = bytes.subarray(4 + wlen, 4 + wlen + alen);
          const parsed = parseAttributes(attrBytes, { asWidth });
          if (parsed.attrs.length) {
            result.inputType = "update";
            result.envelope = {
              update: {
                withdrawnLength: wlen,
                withdrawn: parseNlri(bytes.subarray(2, 2 + wlen), 1, 1),
                attrLength: alen,
                nlri: parseNlri(bytes.subarray(4 + wlen + alen), 1, 1),
                attrBytes, nlriBytes: bytes.subarray(4 + wlen + alen),
                withdrawnBytes: bytes.subarray(2, 2 + wlen)
              }
            };
            result.attrs = parsed.attrs;
            result.warnings.push.apply(result.warnings, parsed.warnings);
            return result;
          }
        }
      }
    }

    const parsed = parseAttributes(bytes, { asWidth });
    result.attrs = parsed.attrs;
    result.warnings.push.apply(result.warnings, parsed.warnings);
    return result;
  }

  window.BGPCodec = {
    buildAttribute, buildUpdate, buildMessage, buildValue, parseAttributes, parseInput,
    parseAsPath, standardFlags, ATTR, attrName, flagNames
  };

  /* ---------- page wiring ---------- */
  let flagDiagram = null;
  let applyEditorFlags = null;

  const FLAG_FIELDS = [
    { id: "optional", name: "Optional", bits: 1, value: "0", range: "0/1", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "If set, a speaker that does not recognize the attribute may ignore it. Well-known attributes leave this clear." },
    { id: "transitive", name: "Transitive", bits: 1, value: "1", range: "0/1", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "If set, the attribute should be passed to other BGP speakers. Well-known attributes are always transitive." },
    { id: "partial", name: "Partial", bits: 1, value: "0", range: "0/1", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Set by a speaker that received an optional transitive attribute it did not fully understand. Only valid when both Optional and Transitive are set." },
    { id: "extended", name: "Extended Length", bits: 1, value: "0", range: "0/1", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "If set, the Attribute Length field is 16 bits instead of 8. It may be used even for short values, but senders normally minimize." },
    { id: "reserved", name: "Reserved", bits: 4, value: "0000", range: "0", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Four reserved bits. Transmitters set them to zero; receivers should ignore the attribute or treat it as malformed if they are not zero." }
  ];

  function checkFlagSet(flags, code) {
    const info = ATTR[code];
    const warnings = [];
    if (flags & 0x20 && (!(flags & 0x80) || !(flags & 0x40))) warnings.push("Partial needs Optional + Transitive");
    if (info && (flags & 0xc0) !== (info.flags & 0xc0)) warnings.push("Not the standard flag pattern for " + info.name);
    if (!info && !(flags & 0x80)) warnings.push("An unknown attribute must be optional");
    return warnings;
  }

  function initFlagEditor() {
    flagDiagram = PH.diagram("#bgp-flag-diagram", {
      title: "<b>Path attribute</b> · flag octet", badge: "RFC 4271 §4.3", bitsPerRow: 8,
      fields: FLAG_FIELDS, inspector: "#bgp-flag-inspector",
      note: "The attribute header then carries an 8-bit type code and an 8- or 16-bit length. The value follows."
    });

    const typeSelect = document.getElementById("bgp-flag-type");
    if (!typeSelect) return;
    typeSelect.innerHTML = Object.keys(ATTR).map((code) =>
      `<option value="${code}">${code} · ${ATTR[code].name}</option>`
    ).join("");
    typeSelect.value = "8";

    const optional = document.getElementById("bgp-flag-optional");
    const transitive = document.getElementById("bgp-flag-transitive");
    const partial = document.getElementById("bgp-flag-partial");
    const extended = document.getElementById("bgp-flag-extended");
    const byteOut = document.getElementById("bgp-flag-byte");
    const standardOut = document.getElementById("bgp-flag-standard");
    const validOut = document.getElementById("bgp-flag-valid");

    function readFlags() {
      return ((optional.checked ? 1 : 0) << 7) | ((transitive.checked ? 1 : 0) << 6) |
        ((partial.checked ? 1 : 0) << 5) | ((extended.checked ? 1 : 0) << 4);
    }
    function setFlags(flags) {
      optional.checked = Boolean(flags & 0x80);
      transitive.checked = Boolean(flags & 0x40);
      partial.checked = Boolean(flags & 0x20);
      extended.checked = Boolean(flags & 0x10);
    }
    function update() {
      const flags = readFlags();
      const code = Number(typeSelect.value);
      const std = standardFlags(code);
      byteOut.textContent = "0x" + PH.hex(flags, 2) + " · " + PH.bin(flags, 8);
      standardOut.textContent = "0x" + PH.hex(std, 2);
      const problems = checkFlagSet(flags, code);
      const known = ATTR[code];
      if (problems.length) {
        validOut.textContent = problems.join(" · ");
        validOut.className = "warn-text";
      } else {
        validOut.textContent = known ? ("consistent with " + known.kind) : "optional unknown attribute";
        validOut.className = "good-text";
      }
      if (flagDiagram) flagDiagram.setValues({
        optional: optional.checked ? "1" : "0",
        transitive: transitive.checked ? "1" : "0",
        partial: partial.checked ? "1" : "0",
        extended: extended.checked ? "1" : "0",
        reserved: "0000"
      });
    }

    typeSelect.addEventListener("change", () => {
      setFlags(standardFlags(Number(typeSelect.value)));
      update();
    });
    [optional, transitive, partial, extended].forEach((el) => el.addEventListener("change", update));
    applyEditorFlags = (code, flags) => {
      if (!ATTR[code]) return;
      typeSelect.value = String(code);
      setFlags(flags);
      update();
    };
    document.querySelectorAll("[data-bgp-type]").forEach((row) => {
      row.style.cursor = "pointer";
      row.addEventListener("click", () => {
        const code = Number(row.getAttribute("data-bgp-type"));
        if (!ATTR[code]) return;
        typeSelect.value = String(code);
        setFlags(standardFlags(code));
        update();
        document.getElementById("attribute").scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
    setFlags(standardFlags(8));
    update();
  }

  function initStructures() {
    PH.byteLane("#bgp-msg-lane", {
      title: "<b>BGP message</b> · header", badge: "RFC 4271 §4.1", fields: [
        { name: "Marker", bytes: 16, range: "16 B · all 0xff", rfc: "RFC 4271 §4.1", rfcUrl: BGP_RFC + "#section-4.1", desc: "Must be all ones in BGP-4. It provides a coarse frame boundary inside the TCP stream; the Length field does the real work." },
        { name: "Length", bytes: 2, range: "19–4096 B", rfc: "RFC 4271 §4.1", rfcUrl: BGP_RFC + "#section-4.1", desc: "Total message length including the 19-byte header. RFC 8654 extends the maximum with capability negotiation." },
        { name: "Type", bytes: 1, range: "1–5", rfc: "RFC 4271 §4.1", rfcUrl: BGP_RFC + "#section-4.1", desc: "1 OPEN, 2 UPDATE, 3 NOTIFICATION, 4 KEEPALIVE, 5 ROUTE-REFRESH." }
      ], inspector: "#bgp-structure-inspector", note: "The marker and length are visible inside the TCP stream. BGP has no separate length framing beyond this header."
    });
    PH.byteLane("#bgp-update-lane", {
      title: "<b>UPDATE</b> · body", badge: "RFC 4271 §4.3", fields: [
        { name: "Withdrawn Routes Length", bytes: 2, range: "0–65535", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Length in bytes of the Withdrawn Routes field." },
        { name: "Withdrawn Routes", bytes: "var", variable: true, range: "NLRI list", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Prefixes being withdrawn, encoded as length-prefixed NLRI." },
        { name: "Total Path Attribute Length", bytes: 2, range: "0–65535", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Length in bytes of the Path Attributes field." },
        { name: "Path Attributes", bytes: "var", variable: true, range: "attribute list", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "A sequence of path attributes, each a flags/type/length/value structure." },
        { name: "NLRI", bytes: "var", variable: true, range: "rest of message", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Reachable prefixes. Classic IPv4 NLRI uses 1-byte prefix lengths." }
      ], inspector: "#bgp-structure-inspector", note: "A minimal UPDATE can have zero withdrawn routes, zero attributes and no NLRI. MP_REACH_NLRI moves non-IPv4 reachability into an attribute."
    });
    PH.byteLane("#bgp-attr-normal", {
      title: "<b>Path attribute</b> · 8-bit length", badge: "flags 0x10 = 0", fields: [
        { name: "Flags", bytes: 1, range: "0x00–0xff", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Optional, Transitive, Partial, Extended Length, then four reserved bits." },
        { name: "Type Code", bytes: 1, range: "0–255", rfc: "IANA", rfcUrl: "https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml", desc: "Attribute code: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 8 COMMUNITIES, 14 MP_REACH_NLRI, 32 LARGE_COMMUNITIES." },
        { name: "Length", bytes: 1, range: "0–255", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Value length in bytes when Extended Length is clear." },
        { name: "Value", bytes: "var", variable: true, range: "Length bytes", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Type-specific payload. The length must agree with the value format." }
      ], inspector: "#bgp-attribute-inspector", note: "A normal-length attribute header is three bytes. The value may be empty for ATOMIC_AGGREGATE."
    });
    PH.byteLane("#bgp-attr-extended", {
      title: "<b>Path attribute</b> · 16-bit length", badge: "flags 0x10 = 1", fields: [
        { name: "Flags", bytes: 1, range: "0x10 bit set", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Extended Length bit is set; the low four bits remain reserved." },
        { name: "Type Code", bytes: 1, range: "0–255", rfc: "IANA", rfcUrl: "https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml", desc: "Attribute code." },
        { name: "Length", bytes: 2, range: "0–65535", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Value length in bytes. The Extended Length bit changes only the width, not the maximum BGP message size." },
        { name: "Value", bytes: "var", variable: true, range: "Length bytes", rfc: "RFC 4271 §4.3", rfcUrl: BGP_RFC + "#section-4.3", desc: "Type-specific payload." }
      ], inspector: "#bgp-attribute-inspector", note: "The bit can be set even when the value is shorter than 256 bytes; that is legal but not the usual encoding."
    });
    PH.byteLane("#bgp-aspath-lane", {
      title: "<b>AS_PATH</b> · segment", badge: "RFC 4271 §5.1.2", fields: [
        { name: "Segment Type", bytes: 1, range: "1–4", rfc: "RFC 4271 §5.1.2", rfcUrl: BGP_RFC + "#section-5.1.2", desc: "1 AS_SET, 2 AS_SEQUENCE, 3 AS_CONFED_SEQUENCE, 4 AS_CONFED_SET." },
        { name: "Segment Length", bytes: 1, range: "0–255", rfc: "RFC 4271 §5.1.2", rfcUrl: BGP_RFC + "#section-5.1.2", desc: "Number of AS numbers in this segment, not bytes. Multiply by the AS width for the byte length." },
        { name: "AS Numbers", bytes: "var", variable: true, range: "2 or 4 bytes each", rfc: "RFC 4271 · RFC 6793", rfcUrl: "https://www.rfc-editor.org/rfc/rfc6793", desc: "ASNs in network byte order. The width is negotiated by capability; AS4_PATH always uses 4-byte ASNs." }
      ], inspector: "#bgp-attribute-inspector", note: "An AS_SEQUENCE is ordered path history; an AS_SET is unordered and normally appears only in aggregation scenarios."
    });

    PH.diagram("#bgp-community-diagram", {
      title: "<b>COMMUNITIES</b> · one 32-bit value", badge: "RFC 1997", bitsPerRow: 32,
      fields: [
        { name: "AS", bits: 16, range: "0–65535", rfc: "RFC 1997 §2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc1997#section-2", desc: "High 16 bits. Well-known communities use AS 65535 (0xffff)." },
        { name: "Local Value", bits: 16, range: "0–65535", rfc: "RFC 1997 §2", rfcUrl: "https://www.rfc-editor.org/rfc/rfc1997#section-2", desc: "Low 16 bits. Values 0xff01–0xff04 are the well-known NO_EXPORT, NO_ADVERTISE, NO_EXPORT_SUBCONFED and NO_PEER communities." }
      ],
      inspector: "#bgp-community-inspector",
      note: "AS:value notation writes the two 16-bit halves in decimal. The raw value is a single 32-bit big-endian word."
    });
  }

  function initEncoder() {
    const select = document.getElementById("bgp-build-type");
    if (!select) return;
    select.innerHTML = Object.keys(ATTR).map((code) =>
      `<option value="${code}">${code} · ${ATTR[code].name}</option>`
    ).join("");
    select.value = "1";
    const optional = document.getElementById("bgp-build-optional");
    const transitive = document.getElementById("bgp-build-transitive");
    const partial = document.getElementById("bgp-build-partial");
    const extended = document.getElementById("bgp-build-extended");
    const value = document.getElementById("bgp-build-value");
    const hint = document.getElementById("bgp-build-hint");
    const asWidth = document.getElementById("bgp-build-aswidth");
    const note = document.getElementById("bgp-build-note");

    function setStandard() {
      const code = Number(select.value);
      const info = ATTR[code];
      if (!info) return;
      optional.checked = Boolean(info.flags & 0x80);
      transitive.checked = Boolean(info.flags & 0x40);
      partial.checked = false;
      extended.checked = false;
      if (code === 17 || code === 18) asWidth.value = "4";
    }
    function syncType() {
      const code = Number(select.value);
      const info = ATTR[code];
      if (!info) return;
      setStandard();
      value.value = info.def;
      hint.textContent = info.hint;
      note.textContent = info.kind + " · standard flags 0x" + PH.hex(info.flags, 2) + " · " + info.rfc;
    }
    select.addEventListener("change", syncType);
    document.getElementById("bgp-build-standard").addEventListener("click", () => {
      setStandard();
      PH.setStatus(document.getElementById("bgp-build-status"), "flags reset to the standard pattern", "ok");
    });
    document.getElementById("bgp-build").addEventListener("click", () => buildFromForm());
    document.getElementById("bgp-build-example").addEventListener("click", () => {
      select.value = "8";
      syncType();
      value.value = "65001:100, no-export";
      buildFromForm();
    });
    syncType();

    function buildFromForm() {
      const status = document.getElementById("bgp-build-status");
      const out = document.getElementById("bgp-build-out");
      const summary = document.getElementById("bgp-build-summary");
      const tag = document.getElementById("bgp-build-tag");
      const flags = ((optional.checked ? 1 : 0) << 7) | ((transitive.checked ? 1 : 0) << 6) |
        ((partial.checked ? 1 : 0) << 5) | ((extended.checked ? 1 : 0) << 4);
      let r;
      try {
        r = buildAttribute({ type: Number(select.value), value: value.value, asWidth: Number(asWidth.value), flags });
      } catch (err) {
        PH.setStatus(status, "error: " + err.message, "bad");
        tag.textContent = "error";
        return null;
      }
      extended.checked = r.ext;
      out.textContent = PH.bytesToHex(r.bytes);
      out.classList.remove("placeholder");
      summary.innerHTML = [
        `<span class="pill">${PH.esc(r.name)}</span>`,
        `<span class="pill">code <b>${r.code}</b></span>`,
        `<span class="pill">flags <b>0x${PH.hex(r.flags, 2)}</b></span>`,
        `<span class="pill">length <b>${r.length} B</b>${r.ext ? " (extended)" : ""}</span>`,
        `<span class="pill">total <b>${r.bytes.length} B</b></span>`
      ].join("");
      tag.textContent = r.bytes.length + " bytes";
      const problems = checkFlagSet(r.flags, r.code);
      PH.setStatus(status, "built " + r.name + " · " + r.bytes.length + " byte(s)" + (problems.length ? " · " + problems.join(" · ") : ""), problems.length ? "warn" : "ok");
      return r;
    }
    buildFromForm();
  }

  function renderDecoded(result, bytes) {
    const host = document.getElementById("bgp-decode-result");
    if (!result) { host.innerHTML = ""; return; }
    const envelope = result.envelope;
    let envHtml = "";
    if (result.inputType === "message" && envelope) {
      envHtml = '<div class="callout"><div class="callout__title">BGP message envelope</div><p>' +
        `type <b>${PH.esc(envelope.typeName)}</b> (${envelope.type}) · declared length <b>${envelope.length}</b> · captured <b>${envelope.actualLength}</b> B · marker ${envelope.marker.slice(0, 11)}…` +
        (envelope.update ? ` · withdrawn <b>${envelope.update.withdrawnLength} B</b> · attributes <b>${envelope.update.attrLength} B</b> · NLRI ${envelope.update.nlri.length ? PH.esc(envelope.update.nlri.map((n) => n.text).join(", ")) : "none"}` : "") +
        "</p></div>";
    } else if (result.inputType === "update" && envelope && envelope.update) {
      envHtml = '<div class="callout"><div class="callout__title">UPDATE body</div><p>' +
        `withdrawn <b>${envelope.update.withdrawnLength} B</b> · attributes <b>${envelope.update.attrLength} B</b> · NLRI ${envelope.update.nlri.length ? PH.esc(envelope.update.nlri.map((n) => n.text).join(", ")) : "none"}` +
        "</p></div>";
    } else {
      envHtml = '<div class="callout"><div class="callout__title">raw attribute stream</div><p>No BGP message marker or UPDATE envelope detected. Each attribute is parsed from the stream using its own length field.</p></div>';
    }

    const cards = result.attrs.map((a) => {
      const badges = [
        a.optional ? "Optional" : "Well-known",
        a.transitive ? "Transitive" : "Non-transitive",
        a.partial ? "Partial" : null,
        a.ext ? "Extended length" : null
      ].filter(Boolean);
      const fields = a.parsed.fields.map((f) =>
        `<tr><td><b>${PH.esc(f.name)}</b></td><td><code>${PH.esc(f.value)}</code></td></tr>`
      ).join("");
      let detailTables = "";
      if (a.parsed.segments && a.parsed.segments.length) {
        detailTables += '<div class="table-wrap" style="margin-top:8px"><table class="data-table"><thead><tr><th>AS_PATH segment</th><th class="num">ASNs</th><th>Values</th></tr></thead><tbody>' +
          a.parsed.segments.map((s) => `<tr><td><b>${PH.esc(s.name)}</b> (${s.type})</td><td class="num">${s.asns.length}</td><td><code>${PH.esc(s.asns.join(" "))}</code></td></tr>`).join("") +
          "</tbody></table></div>";
      }
      if (a.parsed.communities && a.parsed.communities.length) {
        detailTables += '<div class="table-wrap" style="margin-top:8px"><table class="data-table"><thead><tr><th>Community</th><th>Raw</th><th>Type</th></tr></thead><tbody>' +
          a.parsed.communities.map((c) => `<tr><td><code>${PH.esc(c.text)}</code></td><td><code>${PH.esc(c.hex)}</code></td><td>${c.wellKnown ? "well-known" : "AS:value"}</td></tr>`).join("") +
          "</tbody></table></div>";
      }
      if (a.parsed.extended && a.parsed.extended.length) {
        detailTables += '<div class="table-wrap" style="margin-top:8px"><table class="data-table"><thead><tr><th>Type</th><th>Subtype</th><th>Decoded</th><th>Raw</th></tr></thead><tbody>' +
          a.parsed.extended.map((c) => `<tr><td><code>0x${PH.hex(c.type, 2)}</code></td><td><code>0x${PH.hex(c.subtype, 2)}</code></td><td>${PH.esc(c.text)}</td><td><code>${PH.esc(c.hex)}</code></td></tr>`).join("") +
          "</tbody></table></div>";
      }
      if (a.parsed.large && a.parsed.large.length) {
        detailTables += '<div class="table-wrap" style="margin-top:8px"><table class="data-table"><thead><tr><th>Large community</th><th>Raw</th></tr></thead><tbody>' +
          a.parsed.large.map((c) => `<tr><td><code>${PH.esc(c.text)}</code></td><td><code>${PH.esc(c.hex)}</code></td></tr>`).join("") +
          "</tbody></table></div>";
      }
      if (a.parsed.nlri && a.parsed.nlri.length) {
        detailTables += '<div class="table-wrap" style="margin-top:8px"><table class="data-table"><thead><tr><th>NLRI</th><th class="num">Prefix bits</th><th>Bytes</th></tr></thead><tbody>' +
          a.parsed.nlri.map((n) => `<tr><td><code>${PH.esc(n.text)}</code></td><td class="num">${n.bits != null ? n.bits : "—"}</td><td><code>${PH.esc(n.hex || "—")}</code></td></tr>`).join("") +
          "</tbody></table></div>";
      }
      return `<div class="frame-card">` +
        `<div class="frame-card__head"><div><span class="frame-card__type">${PH.esc(a.name)}</span> <code>${a.code}</code></div><div class="dim">${a.length} B · offset ${a.offset} · flags 0x${PH.hex(a.flags, 2)}</div></div>` +
        `<div class="frame-card__note">${badges.join(" · ")} · ${a.ext ? "16-bit length" : "8-bit length"}${a.info ? " · " + PH.esc(a.info.rfc) : " · unknown code"}</div>` +
        `<div class="table-wrap" style="margin:0"><table class="data-table"><tbody>${fields}</tbody></table></div>` +
        detailTables +
        `<div class="frame-card__note">value <code>${a.value.length ? PH.esc(PH.bytesToHex(a.value)) : "empty"}</code></div>` +
        `</div>`;
    }).join("");

    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean parse</div><p>Attribute lengths, value shapes and flag patterns are consistent with the selected AS width.</p></div>';

    host.innerHTML =
      `<div class="decode-summary"><span class="pill">${result.attrs.length} attribute(s)</span><span class="pill">${result.asWidth}-byte AS_PATH</span><span class="pill">${result.inputType}</span><span class="pill">${bytes.length} B input</span></div>` +
      envHtml +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>bytes on the wire</span><span>${bytes.length} B</span></div>${PH.hexdump(bytes)}</div>` +
      `<div class="frame-list">${cards || '<p class="dim">No attributes parsed.</p>'}</div>` +
      warnings;
  }

  function initDecoder() {
    const input = document.getElementById("bgp-decode-input");
    const status = document.getElementById("bgp-decode-status");
    const host = document.getElementById("bgp-decode-result");
    const asWidthSel = document.getElementById("bgp-decode-aswidth");
    if (!input) return;

    function run(showErrors = true) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      const asWidth = Number(asWidthSel.value) === 4 ? 4 : 2;
      const result = parseInput(bytes, asWidth);
      renderDecoded(result, bytes);
      PH.setStatus(status,
        `${result.attrs.length} attribute(s) · ${result.inputType}${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""} · AS_PATH width ${asWidth}`,
        result.warnings.length ? "warn" : "ok");
      if (result.attrs.length && applyEditorFlags) applyEditorFlags(result.attrs[0].code, result.attrs[0].flags);
    }

    document.getElementById("bgp-decode").addEventListener("click", () => run());
    document.getElementById("bgp-decode-example").addEventListener("click", () => {
      const attrs = [
        buildAttribute({ type: 1, value: "0", flags: 0x40 }),
        buildAttribute({ type: 2, value: "65001 65002 65003", flags: 0x40 }),
        buildAttribute({ type: 3, value: "192.0.2.1", flags: 0x40 }),
        buildAttribute({ type: 4, value: "50", flags: 0x80 }),
        buildAttribute({ type: 5, value: "200", flags: 0x40 }),
        buildAttribute({ type: 8, value: "65001:100, no-export", flags: 0xc0 }),
        buildAttribute({ type: 32, value: "65001:1:2, 65001:3:4", flags: 0xc0 })
      ];
      const attrBytes = PH.concatBytes.apply(null, attrs.map((a) => a.bytes));
      const update = buildUpdate(attrBytes, new Uint8Array(0), PH.parseHex("08 0a"));
      const message = buildMessage(2, update);
      input.value = PH.bytesToHex(message);
      run();
    });
    document.getElementById("bgp-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No input decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
  }

  function init() {
    if (!document.getElementById("bgp-flag-diagram")) return;
    initFlagEditor();
    initStructures();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
