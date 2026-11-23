/* VXLAN (RFC 7348) and Geneve (RFC 8926) overlay headers.
   Both carry an inner Ethernet frame in this field guide. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const INNER = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6", 0x8100: "802.1Q VLAN",
    0x88a8: "802.1ad", 0x8847: "MPLS unicast", 0x8848: "MPLS multicast",
    0x6558: "Transparent Ethernet Bridging", 0x880b: "PPP", 0x88cc: "LLDP"
  };

  function innerName(type) { return INNER[type] || "EtherType 0x" + PH.hex(type, 4); }

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

  function decodeVxlan(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 8) throw new Error("VXLAN needs an 8-byte header");
    const flags = bytes[0];
    const warnings = [];
    if (!(flags & 0x08)) warnings.push("VXLAN I bit is not set; the VNI is not marked valid");
    if (bytes[1] || bytes[2] || bytes[3]) warnings.push("VXLAN reserved bytes 1–3 are non-zero");
    if (bytes[7]) warnings.push("VXLAN reserved byte 7 is non-zero");
    const vni = (bytes[4] << 16) | (bytes[5] << 8) | bytes[6];
    const inner = bytes.subarray(8);
    let innerType = null;
    if (inner.length >= 14) innerType = PH.u16be(inner, 12);
    return {
      bytes, flags, vni, reserved: bytes[7], headerLength: 8, inner,
      innerType, innerTypeName: innerType == null ? null : innerName(innerType),
      warnings, payloadLength: inner.length
    };
  }

  function buildVxlan(input) {
    const vni = toInt(input.vni, "VNI", 0, 0xffffff, 42);
    const inner = toBytes(input.inner);
    const bytes = new Uint8Array(8 + inner.length);
    bytes[0] = 0x08;
    bytes[4] = (vni >>> 16) & 255;
    bytes[5] = (vni >>> 8) & 255;
    bytes[6] = vni & 255;
    bytes.set(inner, 8);
    return { bytes, vni, headerLength: 8, inner, innerType: inner.length >= 14 ? PH.u16be(inner, 12) : null };
  }

  function peer(inner) {
    if (!inner || inner.length < 14) return null;
    const mac = (start) => Array.from(inner.subarray(start, start + 6), (b) => PH.hex(b).toLowerCase()).join(":");
    return { dst: mac(0), src: mac(6), type: innerName(PH.u16be(inner, 12)) };
  }

  function decodeGeneve(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 8) throw new Error("Geneve needs an 8-byte base header");
    const version = bytes[0] >> 6;
    const optionLength = bytes[0] & 0x3f;
    const oam = !!(bytes[1] & 0x80);
    const critical = !!(bytes[1] & 0x40);
    const warnings = [];
    if (version !== 0) warnings.push("Geneve version " + version + " is not 0");
    if (bytes[1] & 0x3f) warnings.push("Geneve reserved bits in byte 1 are set");
    if (bytes[7]) warnings.push("Geneve reserved byte 7 is non-zero");
    const protocol = PH.u16be(bytes, 2);
    const vni = (bytes[4] << 16) | (bytes[5] << 8) | bytes[6];
    const optionBytes = optionLength * 4;
    if (8 + optionBytes > bytes.length) throw new Error("Geneve options (" + optionBytes + " B) run past the packet");
    const options = [];
    let pos = 8;
    while (pos + 4 <= 8 + optionBytes) {
      const cls = PH.u16be(bytes, pos);
      const type = bytes[pos + 2];
      const length = bytes[pos + 3] * 4;
      if (pos + 4 + length > 8 + optionBytes) {
        warnings.push("Geneve option class 0x" + PH.hex(cls, 4) + " type " + type + " runs past the option area");
        break;
      }
      options.push({
        class: cls, type, length, offset: pos,
        value: bytes.subarray(pos + 4, pos + 4 + length),
        critical: !!(type & 0x80)
      });
      pos += 4 + length;
    }
    const inner = bytes.subarray(8 + optionBytes);
    let innerType = inner.length >= 14 ? PH.u16be(inner, 12) : null;
    return {
      bytes, version, optionLength, oam, critical, protocol, protocolName: innerName(protocol),
      vni, options, headerLength: 8 + optionBytes, inner, innerType,
      innerTypeName: innerType == null ? null : innerName(innerType), warnings,
      payloadLength: inner.length
    };
  }

  function buildGeneve(input) {
    const protocol = toInt(input.protocol, "Protocol type", 0, 65535, 0x6558);
    const vni = toInt(input.vni, "VNI", 0, 0xffffff, 42);
    const inner = toBytes(input.inner);
    const rawOptions = input.options || [];
    const parts = [];
    rawOptions.forEach((raw) => {
      const value = raw.value instanceof Uint8Array ? raw.value : toBytes(raw.value);
      const padded = (value.length + 3) & ~3;
      const bytes = new Uint8Array(4 + padded);
      PH.put16be(bytes, 0, toInt(raw.class, "Option class", 0, 65535, 0x0108));
      bytes[2] = toInt(raw.type, "Option type", 0, 255, (raw.critical ? 0x80 : 0));
      bytes[3] = padded / 4;
      bytes.set(value, 4);
      parts.push(bytes);
    });
    const optionBytes = parts.reduce((n, p) => n + p.length, 0);
    if (optionBytes / 4 > 63) throw new Error("Geneve options exceed the 6-bit option length field (252 B)");
    const bytes = new Uint8Array(8 + optionBytes + inner.length);
    bytes[0] = (toInt(input.version, "Version", 0, 3, 0) << 6) | (optionBytes / 4);
    bytes[1] = (input.oam ? 0x80 : 0) | (input.critical ? 0x40 : 0);
    PH.put16be(bytes, 2, protocol);
    bytes[4] = (vni >>> 16) & 255;
    bytes[5] = (vni >>> 8) & 255;
    bytes[6] = vni & 255;
    let optPos = 8;
    parts.forEach((part) => { bytes.set(part, optPos); optPos += part.length; });
    bytes.set(inner, 8 + optionBytes);
    return { bytes, protocol, protocolName: innerName(protocol), vni, optionLength: optionBytes / 4, headerLength: 8 + optionBytes, inner };
  }

  global.VXLANCodec = { INNER, innerName, decodeVxlan, buildVxlan, decodeGeneve, buildGeneve, peer };
})(typeof window !== "undefined" ? window : globalThis);
