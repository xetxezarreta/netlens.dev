/* LLDP (IEEE 802.1AB) TLV codec. LLDP is a link-local, one-way neighbour
   advertisement carried in an Ethernet frame with EtherType 0x88CC. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const TLV_NAMES = {
    0: "End of LLDPDU", 1: "Chassis ID", 2: "Port ID", 3: "Time To Live",
    4: "Port Description", 5: "System Name", 6: "System Description",
    7: "System Capabilities", 8: "Management Address", 127: "Organizationally Specific"
  };
  const CHASSIS_SUBTYPES = {
    1: "Chassis component", 2: "Interface alias", 3: "Port component", 4: "MAC address",
    5: "Network address", 6: "Interface name", 7: "Locally assigned"
  };
  const PORT_SUBTYPES = {
    1: "Interface alias", 2: "Port component", 3: "MAC address", 4: "Network address",
    5: "Interface name", 6: "Agent circuit ID", 7: "Locally assigned"
  };
  const CAPABILITIES = {
    0x0001: "Other", 0x0002: "Repeater", 0x0004: "Bridge", 0x0008: "WLAN access point",
    0x0010: "Router", 0x0020: "Telephone", 0x0040: "DOCSIS cable device",
    0x0080: "Station only", 0x0100: "C-VLAN component", 0x0200: "S-VLAN component",
    0x0400: "Two-port MAC relay"
  };
  const OUIS = {
    "00120f": "IEEE 802.3", "0080c2": "IEEE 802.1", "0012bb": "LLDP-MED",
    "001b21": "IEEE 802.3 (historic)", "00-12-0f": "IEEE 802.3"
  };

  function tlvName(type) { return TLV_NAMES[type] || "TLV " + type; }
  function subtypeName(type, subtype) {
    if (type === 1) return CHASSIS_SUBTYPES[subtype] || "subtype " + subtype;
    if (type === 2) return PORT_SUBTYPES[subtype] || "subtype " + subtype;
    return null;
  }

  function capabilityNames(mask) {
    const names = [];
    Object.keys(CAPABILITIES).forEach((bit) => {
      if (mask & Number(bit)) names.push(CAPABILITIES[bit]);
    });
    return names;
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

  function textBytes(value) {
    return new TextEncoder().encode(String(value == null ? "" : value));
  }

  function decodeTlv(bytes, offset) {
    if (offset + 2 > bytes.length) throw new Error("LLDP TLV header is truncated");
    const header = PH.u16be(bytes, offset);
    const type = header >> 9;
    const length = header & 0x1ff;
    if (offset + 2 + length > bytes.length) throw new Error("LLDP TLV " + type + " declares " + length + " B and runs past the frame");
    const value = bytes.subarray(offset + 2, offset + 2 + length);
    const tlv = { type, name: tlvName(type), length, offset, value, fields: [], warnings: [] };
    if (type === 1 || type === 2) {
      if (value.length < 1) tlv.warnings.push("TLV has no subtype byte");
      else {
        tlv.subtype = value[0];
        tlv.subtypeName = subtypeName(type, tlv.subtype);
        const id = value.subarray(1);
        const isMac = (type === 1 && tlv.subtype === 4) || (type === 2 && tlv.subtype === 3);
        const isNetwork = (type === 1 && tlv.subtype === 5) || (type === 2 && tlv.subtype === 4);
        if (isMac && id.length === 6) tlv.address = Array.from(id, (b) => PH.hex(b).toLowerCase()).join(":");
        else if (isNetwork && id.length >= 1) {
          const addrSubtype = id[0];
          tlv.addressSubtype = addrSubtype;
          tlv.address = addrSubtype === 1 && id.length === 5 ? PH.ipv4String(id, 1) : PH.bytesToHex(id.subarray(1));
        } else tlv.address = new TextDecoder().decode(id).replace(/\0+$/, "");
      }
    } else if (type === 3) {
      tlv.ttl = value.length >= 2 ? PH.u16be(value, 0) : null;
    } else if (type === 4 || type === 5 || type === 6) {
      tlv.text = new TextDecoder().decode(value);
    } else if (type === 7) {
      tlv.capabilities = value.length >= 4 ? PH.u16be(value, 0) : null;
      tlv.enabled = value.length >= 4 ? PH.u16be(value, 2) : null;
      tlv.capabilityNames = capabilityNames(tlv.capabilities || 0);
      tlv.enabledNames = capabilityNames(tlv.enabled || 0);
    } else if (type === 8) {
      if (value.length >= 2) {
        tlv.addressLength = value[0];
        tlv.addressSubtype = value[1];
        if (tlv.addressLength >= 1 && 2 + (tlv.addressLength - 1) <= value.length) {
          const addr = value.subarray(2, 2 + tlv.addressLength - 1);
          tlv.address = tlv.addressSubtype === 1 && addr.length === 4 ? PH.ipv4String(addr, 0)
            : tlv.addressSubtype === 2 && addr.length === 16 ? PH.bytesToHex(addr) : PH.bytesToHex(addr);
        }
        let pos = 1 + tlv.addressLength;
        if (pos + 5 <= value.length) {
          tlv.interfaceSubtype = value[pos];
          tlv.interfaceNumber = PH.u32be(value, pos + 1);
          pos += 5;
          if (pos < value.length && value[pos] > 0) tlv.oid = PH.bytesToHex(value.subarray(pos + 1, pos + 1 + value[pos]));
        }
      }
    } else if (type === 127) {
      if (value.length >= 4) {
        tlv.oui = PH.bytesToHex(value.subarray(0, 3)).replace(/ /g, "").toLowerCase();
        tlv.ouiName = OUIS[tlv.oui] || OUIS[tlv.oui.match(/../g).join("-")] || null;
        tlv.subtype = value[3];
        tlv.value = value.subarray(4);
        if (tlv.oui === "0080c2" && tlv.subtype === 1 && tlv.value.length >= 2) {
          tlv.vlanId = PH.u16be(tlv.value, 0) & 0x0fff;
        }
      } else tlv.warnings.push("Organizationally Specific TLV is shorter than its OUI and subtype");
    }
    return tlv;
  }

  function decodeLldp(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    const warnings = [];
    const tlvs = [];
    let pos = 0;
    let ended = false;
    while (pos + 2 <= bytes.length) {
      let tlv;
      try { tlv = decodeTlv(bytes, pos); }
      catch (err) { warnings.push(err.message); break; }
      tlvs.push(tlv);
      warnings.push.apply(warnings, tlv.warnings);
      pos += 2 + tlv.length;
      if (tlv.type === 0) { ended = true; break; }
    }
    if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the End TLV");
    const mandatory = [1, 2, 3];
    mandatory.forEach((type) => {
      if (!tlvs.some((t) => t.type === type)) warnings.push("Mandatory TLV " + tlvName(type) + " is missing");
    });
    const ttl = tlvs.find((t) => t.type === 3);
    const chassis = tlvs.find((t) => t.type === 1);
    const port = tlvs.find((t) => t.type === 2);
    return {
      bytes, tlvs, warnings, ended, ttl: ttl ? ttl.ttl : null,
      shutdown: !!(ttl && ttl.ttl === 0),
      chassis: chassis || null, port: port || null,
      systemName: (tlvs.find((t) => t.type === 5) || {}).text || null,
      systemDescription: (tlvs.find((t) => t.type === 6) || {}).text || null,
      capabilities: (tlvs.find((t) => t.type === 7) || null)
    };
  }

  function header(type, length) {
    if (type < 0 || type > 127) throw new Error("LLDP TLV type must be 0–127");
    if (length < 0 || length > 511) throw new Error("LLDP TLV length must be 0–511");
    const out = new Uint8Array(2);
    PH.put16be(out, 0, (type << 9) | length);
    return out;
  }

  function buildTlv(tlv) {
    const type = toInt(tlv.type, "TLV type", 0, 127, 0);
    let value;
    if (type === 0) value = new Uint8Array(0);
    else if (type === 1 || type === 2) {
      const subtype = toInt(tlv.subtype, "Subtype", 0, 255, type === 1 ? 4 : 3);
      let id;
      const mac = (type === 1 && subtype === 4) || (type === 2 && subtype === 3);
      if (mac) {
        id = toBytes((tlv.address || "02:00:00:00:00:01").replace(/:/g, " "));
        if (id.length !== 6) throw new Error("A MAC address ID must be six bytes");
      } else id = textBytes(tlv.address || tlv.id || "id");
      value = PH.concatBytes(Uint8Array.from([subtype]), id);
    } else if (type === 3) {
      value = new Uint8Array(2);
      PH.put16be(value, 0, toInt(tlv.ttl, "TTL", 0, 65535, 120));
    } else if (type === 4 || type === 5 || type === 6) {
      value = textBytes(tlv.text);
    } else if (type === 7) {
      value = new Uint8Array(4);
      PH.put16be(value, 0, toInt(tlv.capabilities, "Capabilities", 0, 65535, 0));
      PH.put16be(value, 2, toInt(tlv.enabled, "Enabled capabilities", 0, 65535, 0));
    } else if (type === 127) {
      const oui = toBytes((tlv.oui || "00 80 c2").replace(/[:-]/g, " "));
      if (oui.length !== 3) throw new Error("OUI must be three bytes");
      value = PH.concatBytes(oui, Uint8Array.from([toInt(tlv.subtype, "Subtype", 0, 255, 1)]), toBytes(tlv.value || ""));
    } else {
      value = toBytes(tlv.value);
    }
    if (value.length > 511) throw new Error("LLDP TLV value exceeds 511 bytes");
    return PH.concatBytes(header(type, value.length), value);
  }

  function buildChassisTlv() {
    const bytes = new Uint8Array(7);
    bytes[0] = 4;
    bytes.set([2, 0, 0, 0, 0, 1], 1);
    return PH.concatBytes(header(1, bytes.length), bytes);
  }

  function buildLldp(input) {
    const tlvs = [];
    tlvs.push(buildTlv({ type: 1, subtype: (input.chassis && input.chassis.subtype) || 4, address: (input.chassis && input.chassis.address) || "02:00:00:00:00:01" }));
    tlvs.push(buildTlv({ type: 2, subtype: (input.port && input.port.subtype) || 3, address: (input.port && input.port.address) || "02:00:00:00:00:01" }));
    tlvs.push(buildTlv({ type: 3, ttl: input.ttl == null ? 120 : input.ttl }));
    if (input.portDescription) tlvs.push(buildTlv({ type: 4, text: input.portDescription }));
    if (input.systemName) tlvs.push(buildTlv({ type: 5, text: input.systemName }));
    if (input.systemDescription) tlvs.push(buildTlv({ type: 6, text: input.systemDescription }));
    if (input.capabilities != null) tlvs.push(buildTlv({ type: 7, capabilities: input.capabilities, enabled: input.enabled == null ? input.capabilities : input.enabled }));
    if (input.managementAddress) {
      let addr;
      if (typeof input.managementAddress === "string" && input.managementAddress.indexOf(".") !== -1) {
        addr = PH.parseIPv4(input.managementAddress);
      } else if (typeof input.managementAddress === "string" && input.managementAddress.indexOf(":") !== -1) {
        const codec = global.IPv6Codec || (global.window && global.window.IPv6Codec);
        if (!codec) throw new Error("IPv6 codec is not loaded");
        addr = codec.parseIPv6(input.managementAddress);
      } else {
        addr = toBytes(input.managementAddress);
      }
      const value = new Uint8Array(2 + addr.length + 5);
      value[0] = addr.length + 1;
      value[1] = addr.length === 4 ? 1 : 2;
      value.set(addr, 2);
      value[2 + addr.length] = 2;
      PH.put32be(value, 3 + addr.length, 0);
      tlvs.push(buildTlv({ type: 8, value }));
    }
    (input.orgSpecific || []).forEach((org) => tlvs.push(buildTlv({ type: 127, oui: org.oui || "00 80 c2", subtype: org.subtype || 1, value: org.value || "" })));
    tlvs.push(buildTlv({ type: 0 }));
    return { bytes: PH.concatBytes.apply(null, tlvs), tlvs: tlvs.length };
  }

  global.LLDPCodec = {
    TLV_NAMES, CHASSIS_SUBTYPES, PORT_SUBTYPES, CAPABILITIES, OUIS,
    tlvName, subtypeName, capabilityNames, decodeTlv, decodeLldp, buildTlv, buildLldp
  };
})(typeof window !== "undefined" ? window : globalThis);
