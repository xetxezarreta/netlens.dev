/* OSPFv2 (RFC 2328) packet, Hello, database description and LSA codec.
   OSPFv3 differs in layout (no authentication field, 16-byte router IDs
   are still 32-bit, and LSAs are redesigned); this codec is OSPFv2 only. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const TYPES = { 1: "Hello", 2: "Database Description", 3: "Link State Request", 4: "Link State Update", 5: "Link State Ack" };
  const LSA_TYPES = {
    1: "Router", 2: "Network", 3: "Summary Network", 4: "Summary ASBR", 5: "AS External",
    6: "Group Membership", 7: "NSSA External", 8: "External Attributes",
    9: "Link Opaque", 10: "Area Opaque", 11: "AS Opaque"
  };
  const AUTH_TYPES = { 0: "Null", 1: "Simple password", 2: "Cryptographic" };
  const OPTIONS = { 0x01: "T", 0x02: "E", 0x04: "MC", 0x08: "NP", 0x10: "EA", 0x20: "DC", 0x40: "O", 0x80: "DN" };

  function typeName(type) { return TYPES[type] || "Type " + type; }
  function lsaTypeName(type) { return LSA_TYPES[type] || "LSA type " + type; }
  function authName(type) { return AUTH_TYPES[type] || "auth " + type; }

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

  function routerId(value, name) {
    if (value instanceof Uint8Array) {
      if (value.length !== 4) throw new Error(name + " must be four bytes");
      return value;
    }
    const text = String(value == null ? "" : value).trim();
    if (!text) throw new Error(name + " is required");
    let numeric = null;
    if (typeof value === "number") numeric = value;
    else if (/^0x[0-9a-f]+$/i.test(text)) numeric = parseInt(text.slice(2), 16);
    else if (/^\d+$/.test(text)) numeric = Number(text);
    if (numeric != null) {
      if (!Number.isInteger(numeric) || numeric < 0 || numeric > 0xffffffff) throw new Error(name + " must fit in 32 bits");
      const bytes = new Uint8Array(4);
      bytes[0] = (numeric >>> 24) & 255;
      bytes[1] = (numeric >>> 16) & 255;
      bytes[2] = (numeric >>> 8) & 255;
      bytes[3] = numeric & 255;
      return bytes;
    }
    return PH.parseIPv4(text);
  }

  function ridString(bytes) {
    return bytes && bytes.length >= 4 ? PH.ipv4String(bytes, 0) : "?";
  }

  function optionNames(value) {
    const names = [];
    Object.keys(OPTIONS).forEach((mask) => {
      if (Number(mask) && (value & Number(mask))) names.push(OPTIONS[mask]);
    });
    return names;
  }

  function checksum(bytes) {
    const copy = bytes.slice();
    if (copy.length < 24) throw new Error("OSPF packet needs at least 24 bytes");
    copy[12] = 0;
    copy[13] = 0;
    for (let i = 16; i < 24; i++) copy[i] = 0;
    return PH.checksum16(copy);
  }

  /* ---------- LSAs ---------- */
  function decodeLsaHeader(bytes, offset) {
    if (offset + 20 > bytes.length) throw new Error("LSA header runs past the packet");
    const type = bytes[offset + 3];
    return {
      offset,
      age: PH.u16be(bytes, offset),
      options: bytes[offset + 2],
      optionNames: optionNames(bytes[offset + 2]),
      type,
      typeName: lsaTypeName(type),
      linkStateId: PH.u32be(bytes, offset + 4),
      linkStateIdText: PH.ipv4String(bytes, offset + 4),
      advertisingRouter: PH.u32be(bytes, offset + 8),
      advertisingRouterText: PH.ipv4String(bytes, offset + 8),
      sequence: PH.u32be(bytes, offset + 12),
      checksum: PH.u16be(bytes, offset + 16),
      length: PH.u16be(bytes, offset + 18),
      headerLength: 20
    };
  }

  function decodeLsaBody(lsa, bytes, offset, length) {
    const body = bytes.subarray(offset + 20, offset + length);
    const out = { bodyLength: body.length, warnings: [] };
    if (lsa.type === 1) {
      if (body.length < 4) { out.warnings.push("Router LSA body is shorter than its flags and link count"); return out; }
      out.flags = { virtual: !!(body[1] & 0x04), asbr: !!(body[1] & 0x02), abr: !!(body[1] & 0x01), external: !!(body[1] & 0x08) };
      out.links = [];
      let count = Math.min(PH.u16be(body, 2), 256);
      let pos = 4;
      while (count-- > 0 && pos + 12 <= body.length) {
        const link = {
          linkId: PH.ipv4String(body, pos), linkIdRaw: PH.u32be(body, pos),
          linkData: PH.ipv4String(body, pos + 4), linkDataRaw: PH.u32be(body, pos + 4),
          type: body[pos + 8], metric: PH.u16be(body, pos + 10)
        };
        link.typeName = ["Point-to-point", "Transit network", "Stub network", "Virtual link"][link.type] || "type " + link.type;
        out.links.push(link);
        pos += 12 + body[pos + 9] * 4;
      }
      out.linkCount = out.links.length;
    } else if (lsa.type === 2) {
      if (body.length >= 4) {
        out.networkMask = PH.ipv4String(body, 0);
        out.attachedRouters = [];
        for (let pos = 4; pos + 4 <= body.length; pos += 4) out.attachedRouters.push(PH.ipv4String(body, pos));
      }
    } else if (lsa.type === 3 || lsa.type === 4) {
      if (body.length >= 8) {
        out.networkMask = PH.ipv4String(body, 0);
        out.metric = PH.u32be(body, 4) & 0x00ffffff;
      }
    } else if (lsa.type === 5 || lsa.type === 7) {
      if (body.length >= 16) {
        out.networkMask = PH.ipv4String(body, 0);
        out.forwardingAddress = PH.ipv4String(body, 4);
        out.externalTag = PH.u32be(body, 8);
        out.metric = PH.u32be(body, 12) & 0x00ffffff;
        out.externalType = (PH.u32be(body, 12) & 0x80000000) ? 2 : 1;
      }
    } else {
      out.raw = PH.bytesToHex(body);
    }
    return out;
  }

  function decodeLsa(bytes, offset) {
    const header = decodeLsaHeader(bytes, offset);
    if (header.length < 20) header.warnings = ["LSA length " + header.length + " is smaller than the 20-byte header"];
    else if (offset + header.length > bytes.length) header.warnings = ["LSA length " + header.length + " runs past the packet"];
    header.body = decodeLsaBody(header, bytes, offset, Math.min(header.length, bytes.length - offset));
    return header;
  }

  function encodeLsaHeader(lsa) {
    const bytes = new Uint8Array(20);
    PH.put16be(bytes, 0, toInt(lsa.age, "LS age", 0, 3600, 0));
    bytes[2] = toInt(lsa.options, "Options", 0, 255, 0x02);
    bytes[3] = toInt(lsa.type, "LSA type", 0, 255, 1);
    bytes.set(routerId(lsa.linkStateId, "Link State ID"), 4);
    bytes.set(routerId(lsa.advertisingRouter, "Advertising router"), 8);
    PH.put32be(bytes, 12, typeof lsa.sequence === "number" ? lsa.sequence : 0x80000001);
    PH.put16be(bytes, 16, 0);
    PH.put16be(bytes, 18, 20 + (lsa.body ? lsa.body.length : 0));
    return bytes;
  }

  /* ---------- packet bodies ---------- */
  function decodeHello(bytes) {
    if (bytes.length < 44) throw new Error("OSPF Hello needs at least 44 bytes");
    const out = {
      networkMask: PH.ipv4String(bytes, 24),
      helloInterval: PH.u16be(bytes, 28),
      options: bytes[30],
      optionNames: optionNames(bytes[30]),
      priority: bytes[31],
      deadInterval: PH.u32be(bytes, 32),
      designatedRouter: PH.ipv4String(bytes, 36),
      backupRouter: PH.ipv4String(bytes, 40),
      neighbors: []
    };
    for (let pos = 44; pos + 4 <= bytes.length; pos += 4) out.neighbors.push(PH.ipv4String(bytes, pos));
    return out;
  }

  function decodeDatabaseDescription(bytes) {
    if (bytes.length < 32) throw new Error("OSPF Database Description needs at least 32 bytes");
    const flags = bytes[27];
    const out = {
      interfaceMtu: PH.u16be(bytes, 24),
      options: bytes[26],
      optionNames: optionNames(bytes[26]),
      flags,
      master: !!(flags & 0x01),
      more: !!(flags & 0x02),
      init: !!(flags & 0x04),
      sequence: PH.u32be(bytes, 28),
      lsas: []
    };
    for (let pos = 32; pos + 20 <= bytes.length; pos += 20) out.lsas.push(decodeLsaHeader(bytes, pos));
    return out;
  }

  function decodeLsRequest(bytes) {
    const requests = [];
    for (let pos = 24; pos + 12 <= bytes.length; pos += 12) {
      requests.push({
        type: PH.u32be(bytes, pos), typeName: lsaTypeName(PH.u32be(bytes, pos)),
        linkStateId: PH.ipv4String(bytes, pos + 4), advertisingRouter: PH.ipv4String(bytes, pos + 8)
      });
    }
    return { requests };
  }

  function decodeLsUpdate(bytes) {
    if (bytes.length < 28) throw new Error("OSPF Link State Update needs at least 28 bytes");
    const count = PH.u32be(bytes, 24);
    const lsas = [];
    let pos = 28;
    const warnings = [];
    for (let i = 0; i < Math.min(count, 1024) && pos + 20 <= bytes.length; i++) {
      let lsa;
      try { lsa = decodeLsa(bytes, pos); }
      catch (err) { warnings.push("LSA " + (i + 1) + ": " + err.message); break; }
      lsas.push(lsa);
      if (lsa.length < 20) { warnings.push("LSA " + (i + 1) + " has an invalid length"); break; }
      pos += lsa.length;
    }
    if (count > lsas.length) warnings.push("Header says " + count + " LSA(s) but " + lsas.length + " parses");
    return { count, lsas, warnings };
  }

  function decodeLsAck(bytes) {
    const lsas = [];
    for (let pos = 24; pos + 20 <= bytes.length; pos += 20) lsas.push(decodeLsaHeader(bytes, pos));
    return { lsas };
  }

  function decodeOspf(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 24) throw new Error("OSPF needs at least the 24-byte header");
    const version = bytes[0];
    const type = bytes[1];
    const length = PH.u16be(bytes, 2);
    const warnings = [];
    if (version !== 2) warnings.push("Version " + version + " is not OSPFv2 (2)");
    if (length < 24) warnings.push("Packet length " + length + " is smaller than the header");
    if (length > bytes.length) warnings.push("Packet length " + length + " exceeds the " + bytes.length + " captured bytes");
    const effective = Math.min(bytes.length, length || bytes.length);
    const copy = bytes.subarray(0, effective);
    const expected = checksum(copy);
    const transmitted = PH.u16be(bytes, 12);
    const checksumState = transmitted === 0 ? "unset" : (expected === transmitted ? "valid" : "invalid");
    if (checksumState === "invalid") warnings.push("OSPF checksum is invalid (expected 0x" + PH.hex(expected, 4) + ")");
    const packet = {
      bytes, version, type, typeName: typeName(type), length,
      routerId: PH.ipv4String(bytes, 4), areaId: PH.ipv4String(bytes, 8),
      checksum: transmitted, expectedChecksum: expected, checksumState,
      authType: PH.u16be(bytes, 14), authTypeName: authName(PH.u16be(bytes, 14)),
      auth: bytes.subarray(16, 24), warnings, bodyLength: Math.max(0, effective - 24)
    };
    try {
      if (type === 1) packet.hello = decodeHello(bytes.subarray(0, effective));
      else if (type === 2) packet.dd = decodeDatabaseDescription(bytes.subarray(0, effective));
      else if (type === 3) packet.requests = decodeLsRequest(bytes.subarray(0, effective)).requests;
      else if (type === 4) packet.update = decodeLsUpdate(bytes.subarray(0, effective));
      else if (type === 5) packet.acks = decodeLsAck(bytes.subarray(0, effective)).lsas;
      if (packet.update && packet.update.warnings.length) warnings.push.apply(warnings, packet.update.warnings);
    } catch (err) {
      warnings.push("Body decode failed: " + err.message);
    }
    return packet;
  }

  /* ---------- build ---------- */
  function buildOspf(input) {
    const version = 2;
    const type = toInt(input.type, "Type", 1, 5, 1);
    let body;
    if (type === 1) {
      const neighbors = (input.neighbors || []).map((n) => routerId(n, "Neighbor router ID"));
      body = new Uint8Array(20 + neighbors.length * 4);
      body.set(PH.parseIPv4(input.networkMask || "255.255.255.0"), 0);
      PH.put16be(body, 4, toInt(input.helloInterval, "Hello interval", 1, 65535, 10));
      body[6] = toInt(input.options, "Options", 0, 255, 0x02);
      body[7] = toInt(input.priority, "Router priority", 0, 255, 1);
      PH.put32be(body, 8, toInt(input.deadInterval, "Dead interval", 1, 4294967295, 40));
      body.set(routerId(input.designatedRouter || "0.0.0.0", "Designated router"), 12);
      body.set(routerId(input.backupRouter || "0.0.0.0", "Backup router"), 16);
      neighbors.forEach((n, i) => body.set(n, 20 + i * 4));
    } else if (type === 2) {
      const lsas = (input.lsas || []).map(encodeLsaHeader);
      body = new Uint8Array(8 + lsas.length * 20);
      PH.put16be(body, 0, toInt(input.interfaceMtu, "Interface MTU", 0, 65535, 1500));
      body[2] = toInt(input.options, "Options", 0, 255, 0x02);
      body[3] = (input.master ? 0x01 : 0) | (input.more ? 0x02 : 0) | (input.init ? 0x04 : 0);
      PH.put32be(body, 4, toInt(input.sequence, "DD sequence", 0, 4294967295, 1));
      lsas.forEach((lsa, i) => body.set(lsa, 8 + i * 20));
    } else if (type === 3) {
      const requests = input.requests || [];
      body = new Uint8Array(requests.length * 12);
      requests.forEach((r, i) => {
        PH.put32be(body, i * 12, toInt(r.type, "LSA type", 0, 4294967295, 1));
        body.set(PH.parseIPv4(r.linkStateId || "0.0.0.0"), i * 12 + 4);
        body.set(routerId(r.advertisingRouter || "0.0.0.0", "Advertising router"), i * 12 + 8);
      });
    } else if (type === 4) {
      const lsas = (input.lsas || []).map((lsa) => {
        const header = encodeLsaHeader(lsa);
        const lsaBody = toBytes(lsa.body);
        const out = new Uint8Array(20 + lsaBody.length);
        out.set(header, 0);
        out.set(lsaBody, 20);
        PH.put16be(out, 18, out.length);
        return out;
      });
      body = new Uint8Array(4 + lsas.reduce((n, l) => n + l.length, 0));
      PH.put32be(body, 0, lsas.length);
      let pos = 4;
      lsas.forEach((lsa) => { body.set(lsa, pos); pos += lsa.length; });
    } else {
      const lsas = (input.lsas || []).map(encodeLsaHeader);
      body = new Uint8Array(lsas.length * 20);
      lsas.forEach((lsa, i) => body.set(lsa, i * 20));
    }

    const bytes = new Uint8Array(24 + body.length);
    bytes[0] = version;
    bytes[1] = type;
    PH.put16be(bytes, 2, bytes.length);
    bytes.set(routerId(input.routerId || "192.0.2.1", "Router ID"), 4);
    bytes.set(routerId(input.areaId || "0.0.0.0", "Area ID"), 8);
    const authType = toInt(input.authType, "Authentication type", 0, 2, 0);
    PH.put16be(bytes, 14, authType);
    if (authType === 1) {
      const password = String(input.password || "").slice(0, 8);
      for (let i = 0; i < 8 && i < password.length; i++) bytes[16 + i] = password.charCodeAt(i) & 255;
    } else if (authType === 2) {
      const auth = toBytes(input.auth);
      bytes.set(auth.subarray(0, 8), 16);
    }
    bytes.set(body, 24);
    const value = checksum(bytes);
    PH.put16be(bytes, 12, value);
    return {
      bytes, version, type, typeName: typeName(type), length: bytes.length,
      routerId: PH.ipv4String(bytes, 4), areaId: PH.ipv4String(bytes, 8),
      checksum: value, checksumState: "built", authType, authTypeName: authName(authType),
      body, bodyLength: body.length
    };
  }

  global.OSPFCodec = {
    TYPES, LSA_TYPES, AUTH_TYPES, OPTIONS, typeName, lsaTypeName, authName,
    checksum, encodeLsaHeader, decodeLsaHeader, decodeLsa, decodeOspf, buildOspf
  };
})(typeof window !== "undefined" ? window : globalThis);
