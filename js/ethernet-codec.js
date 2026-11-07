/* Ethernet II / 802.1Q / FCS codec — shared by the Ethernet and ARP pages. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
    0x86dd: "IPv6",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x888e: "EAPOL",
    0x88a8: "802.1ad QinQ",
    0x88cc: "LLDP",
    0x88f7: "PTP",
    0x8906: "FCoE",
    0x8915: "RoCE"
  };

  const MAC_SPECIAL = {
    "ff:ff:ff:ff:ff:ff": "broadcast",
    "01:00:5e:00:00:01": "IPv4 all-hosts multicast",
    "33:33:00:00:00:01": "IPv6 all-nodes multicast",
    "00:00:00:00:00:00": "null / unset"
  };

  function etherTypeName(type) {
    if (type <= 1500) return "IEEE 802.3 length";
    if (type < 1536) return "reserved / undefined";
    return ETHER_TYPES[type] || "unknown EtherType";
  }

  function parseMac(text) {
    const s = String(text == null ? "" : text).trim().replace(/[^0-9a-fA-F]/g, "");
    if (s.length !== 12) throw new Error("MAC address needs 12 hex digits");
    const out = new Uint8Array(6);
    for (let i = 0; i < 6; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function macString(bytes, off) {
    if (!bytes || bytes.length < (off || 0) + 6) return "?";
    const o = off || 0;
    return Array.from(bytes.subarray(o, o + 6), (b) => b.toString(16).padStart(2, "0")).join(":");
  }

  function macFlags(bytes, off) {
    const o = off || 0;
    const broadcast = [0, 1, 2, 3, 4, 5].every((i) => bytes[o + i] === 0xff);
    const multicast = (bytes[o] & 0x01) === 1;
    const local = (bytes[o] & 0x02) === 2;
    return {
      broadcast,
      multicast,
      local,
      label: broadcast ? "broadcast" : multicast ? "multicast" : "unicast",
      admin: local ? "locally administered" : "globally administered"
    };
  }

  function macDescription(text) {
    const mac = macString(parseMac(text));
    const special = MAC_SPECIAL[mac];
    return special ? mac + " · " + special : mac;
  }

  function concat(parts) {
    const bytes = [];
    function add(part) {
      if (part == null) return;
      if (part instanceof Uint8Array) {
        for (let i = 0; i < part.length; i++) bytes.push(part[i]);
      } else if (Array.isArray(part)) {
        part.forEach(add);
      } else {
        bytes.push(Number(part) & 255);
      }
    }
    parts.forEach(add);
    return new Uint8Array(bytes);
  }
  function be16(n) { return new Uint8Array([(n >>> 8) & 255, n & 255]); }
  function be32(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }
  function le32(n) { return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]); }

  /* Reflected CRC-32 (IEEE 802.3 3.2.9). The FCS field is this value on the wire, LSB first. */
  function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      crc ^= bytes[i];
      for (let bit = 0; bit < 8; bit++) {
        crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
      }
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function fcsBytes(bytes) {
    return le32(crc32(bytes));
  }

  function fcsCheck(bytes) {
    // CRC over a frame including its valid FCS is the residue 0x2144df1c.
    return crc32(bytes) === 0x2144df1c;
  }

  function buildFrame(input) {
    const dst = typeof input.dst === "string" ? parseMac(input.dst) : input.dst;
    const src = typeof input.src === "string" ? parseMac(input.src) : input.src;
    if (!dst || dst.length !== 6) throw new Error("destination MAC must be 6 bytes");
    if (!src || src.length !== 6) throw new Error("source MAC must be 6 bytes");
    if (input.etherType == null || input.etherType === "") throw new Error("EtherType is required");
    const etherType = Number(input.etherType);
    if (!Number.isInteger(etherType) || etherType < 0 || etherType > 65535) throw new Error("EtherType must be 0–65535");
    const payload = input.payload instanceof Uint8Array
      ? input.payload
      : (input.payload == null || String(input.payload).trim() === "" ? new Uint8Array(0) : PH.parseHex(input.payload));
    const vlan = input.vlan || null;
    const header = [dst, src];
    if (vlan) {
      const pcp = Number(vlan.pcp || 0);
      const dei = vlan.dei ? 1 : 0;
      const vid = Number(vlan.vid || 0);
      const tpid = Number(vlan.tpid || 0x8100);
      if (!Number.isInteger(pcp) || pcp < 0 || pcp > 7) throw new Error("VLAN PCP must be 0–7");
      if (!Number.isInteger(vid) || vid < 0 || vid > 4095) throw new Error("VLAN ID must be 0–4095");
      if (![0x8100, 0x88a8].includes(tpid)) throw new Error("TPID must be 0x8100 or 0x88a8");
      header.push(be16(tpid), be16(((pcp & 7) << 13) | ((dei & 1) << 12) | (vid & 0xfff)));
    }
    header.push(be16(etherType));
    const headerLen = vlan ? 18 : 14;
    const minPayload = vlan ? 42 : 46;
    let padding = new Uint8Array(0);
    if (input.pad !== false && payload.length < minPayload) padding = new Uint8Array(minPayload - payload.length);
    const withoutFcs = concat([header, payload, padding]);
    let fcs = null;
    let bytes = withoutFcs;
    if (input.fcs !== false) {
      fcs = fcsBytes(withoutFcs);
      bytes = concat([withoutFcs, fcs]);
    }
    return {
      bytes, header: concat(header), headerLen, payload, payloadLength: payload.length,
      padding, paddingLength: padding.length, fcs, etherType, vlan, dst, src,
      frameLength: bytes.length, withoutFcs
    };
  }

  function decodeFrame(bytes, opts) {
    const options = opts || {};
    let offset = 0;
    let preamble = false;
    if (bytes.length >= 8 && [0, 1, 2, 3, 4, 5, 6].every((i) => bytes[i] === 0x55) && bytes[7] === 0xd5) {
      preamble = true;
      offset = 8;
    }
    const frame = bytes.subarray(offset);
    if (frame.length < 14) throw new Error("Need at least 14 bytes of Ethernet header");
    const dst = frame.subarray(0, 6);
    const src = frame.subarray(6, 12);
    let cursor = 12;
    let etherType = PH.u16be(frame, cursor);
    const vlanTags = [];
    while ((etherType === 0x8100 || etherType === 0x88a8) && frame.length >= cursor + 6) {
      const tpid = etherType;
      const tci = PH.u16be(frame, cursor + 2);
      vlanTags.push({
        tpid,
        pcp: (tci >>> 13) & 7,
        dei: (tci >>> 12) & 1,
        vid: tci & 0xfff,
        tci
      });
      cursor += 4;
      etherType = PH.u16be(frame, cursor);
    }
    const headerLen = cursor + 2;
    if (frame.length < headerLen) throw new Error("VLAN tag or EtherType overruns the frame");
    const after = frame.subarray(headerLen);
    let payload = after;
    let fcs = null;
    let fcsOk = false;
    let fcsPresent = false;
    const fcsMode = options.fcs || "auto";
    if (fcsMode !== "absent" && after.length >= 4) {
      const candidate = after.subarray(after.length - 4);
      const expected = crc32(frame.subarray(0, frame.length - 4));
      const candidateValue = (candidate[0] | (candidate[1] << 8) | (candidate[2] << 16) | (candidate[3] << 24)) >>> 0;
      fcsOk = candidateValue === expected;
      if (fcsMode === "present" || (fcsMode === "auto" && fcsOk)) {
        fcsPresent = true;
        fcs = candidate.slice();
        payload = after.subarray(0, after.length - 4);
      }
    }
    const trailingZeros = (() => {
      let n = 0;
      for (let i = payload.length - 1; i >= 0 && payload[i] === 0; i--) n++;
      return n;
    })();
    const warnings = [];
    if (preamble) warnings.push("Preamble/SFD detected and skipped; it is a physical-layer field, not part of the captured MAC frame");
    if (fcsMode === "absent") warnings.push("FCS excluded by the selected mode");
    else if (!fcsPresent) warnings.push("No valid FCS detected; captures often strip it at the NIC");
    else if (!fcsOk) warnings.push("FCS field detected but the CRC is invalid");
    const wireLength = frame.length + (!fcsPresent ? 4 : 0);
    if (wireLength < 64) warnings.push(`Frame is ${wireLength} bytes including the expected FCS; the Ethernet minimum is 64 (a runt frame)`);
    const max = vlanTags.length ? 1522 : 1518;
    if (frame.length > max) warnings.push(`Frame is ${frame.length} bytes; ${max} is the standard maximum without jumbo-frame support`);
    if (etherType <= 1500) warnings.push("The Length/Type field is ≤ 1500, so this is an IEEE 802.3 length field, not an Ethernet II EtherType");
    else if (etherType < 1536) warnings.push("Length/Type value is in the reserved 1501–1535 range");
    if (etherType === 0x8100 || etherType === 0x88a8) warnings.push("A VLAN TPID remains in the final EtherType position; the tag chain may be malformed");
    return {
      bytes, frame, preamble, offset, dst, src, dstMac: macString(dst), srcMac: macString(src),
      dstFlags: macFlags(dst), srcFlags: macFlags(src), vlanTags, headerLen, etherType,
      etherTypeName: etherTypeName(etherType), typeKind: etherType <= 1500 ? "length" : etherType < 1536 ? "reserved" : "ethertype",
      payload, payloadLength: payload.length, fcs, fcsOk, fcsPresent, wireLength,
      frameLength: frame.length, trailingZeros, warnings
    };
  }

  global.EthernetCodec = {
    ETHER_TYPES, etherTypeName, parseMac, macString, macFlags, macDescription,
    crc32, fcsBytes, fcsCheck, buildFrame, decodeFrame
  };
})(window);
