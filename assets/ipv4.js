/* IPv4 header explorer — pure codec + page wiring */
(function () {
  "use strict";

  const PH = window.PH;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc791",
    dscp: "https://www.rfc-editor.org/rfc/rfc2474",
    ecn: "https://www.rfc-editor.org/rfc/rfc3168",
    id: "https://www.rfc-editor.org/rfc/rfc6864",
    checksum: "https://www.rfc-editor.org/rfc/rfc1071",
    alert: "https://www.rfc-editor.org/rfc/rfc2113"
  };

  const PROTOCOLS = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 43: "IPv6-Route",
    44: "IPv6-Frag", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 88: "EIGRP", 89: "OSPF", 94: "IPIP", 103: "PIM", 112: "VRRP",
    115: "L2TP", 132: "SCTP", 137: "MPLS-in-IP", 143: "Ethernet-in-IP"
  };

  const DSCP = {
    0: "CS0 / default", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13",
    16: "CS2", 18: "AF21", 20: "AF22", 22: "AF23", 24: "CS3", 26: "AF31",
    28: "AF32", 30: "AF33", 32: "CS4", 34: "AF41", 36: "AF42", 38: "AF43",
    40: "CS5", 46: "EF / expedited forwarding", 48: "CS6", 56: "CS7"
  };

  const OPTION_NAMES = {
    0: "EOL", 1: "NOP", 7: "RR", 68: "Timestamp", 82: "Traceroute", 130: "Security",
    131: "LSRR", 136: "Stream ID", 137: "SSRR", 148: "Router Alert"
  };
  const CLASS_NAMES = { 0: "control", 1: "reserved", 2: "debug", 3: "reserved" };

  function dscpName(n) { return DSCP[n] || "class selector " + Math.floor(n / 8); }
  function protocolName(n) { return PROTOCOLS[n] || "unknown"; }
  function optionName(type) {
    if (OPTION_NAMES[type]) return OPTION_NAMES[type];
    const copied = (type >> 7) & 1;
    const cls = (type >> 5) & 3;
    const num = type & 31;
    return `${copied ? "C" : "-"}${CLASS_NAMES[cls]}:${num}`;
  }
  function flagsText(reserved, df, mf) {
    const out = [];
    if (reserved) out.push("R");
    if (df) out.push("DF");
    if (mf) out.push("MF");
    return out.length ? out.join("+") : "none";
  }
  function ecnName(n) {
    return ["Not-ECT", "ECT(1)", "ECT(0)", "CE"][n] || "?";
  }

  function parseIp(text) {
    const parts = String(text).trim().split(".");
    if (parts.length !== 4) throw new Error("IPv4 address needs four octets");
    const out = new Uint8Array(4);
    parts.forEach((part, i) => {
      if (!/^\d{1,3}$/.test(part)) throw new Error("Invalid IPv4 octet: " + part);
      const n = Number(part);
      if (n > 255) throw new Error("IPv4 octet > 255: " + part);
      out[i] = n;
    });
    return out;
  }

  function ipString(bytes) { return Array.from(bytes).join("."); }

  function buildHeader(input) {
    const options = input.options ? PH.parseHex(input.options) : new Uint8Array(0);
    if (options.length > 40) throw new Error("Options exceed 40 bytes (IHL would exceed 15)");
    let optionsPadded = options;
    if (options.length % 4) {
      optionsPadded = new Uint8Array(options.length + (4 - (options.length % 4)));
      optionsPadded.set(options);
    }
    const headerLen = 20 + optionsPadded.length;
    const ihl = headerLen / 4;
    if (ihl > 15) throw new Error("Header exceeds 60 bytes (IHL > 15)");
    const payloadLen = Number(input.payloadLength) || 0;
    if (payloadLen < 0 || payloadLen > 65535) throw new Error("Payload length out of range");
    const total = headerLen + payloadLen;
    if (total > 65535) throw new Error("Total Length exceeds 65535; IPv4 has no jumbogram");
    const version = Number(input.version);
    if (!Number.isInteger(version) || version < 0 || version > 15) throw new Error("Version must be 0–15");
    const dscp = Number(input.dscp);
    if (!Number.isInteger(dscp) || dscp < 0 || dscp > 63) throw new Error("DSCP must be 0–63");
    const ecn = Number(input.ecn);
    if (!Number.isInteger(ecn) || ecn < 0 || ecn > 3) throw new Error("ECN must be 0–3");
    const id = Number(input.id);
    if (!Number.isInteger(id) || id < 0 || id > 65535) throw new Error("Identification must be 0–65535");
    const ttl = Number(input.ttl);
    if (!Number.isInteger(ttl) || ttl < 0 || ttl > 255) throw new Error("TTL must be 0–255");
    const proto = Number(input.protocol);
    if (!Number.isInteger(proto) || proto < 0 || proto > 255) throw new Error("Protocol must be 0–255");
    const frag = Number(input.fragmentOffset) || 0;
    if (!Number.isInteger(frag) || frag < 0 || frag > 8191) throw new Error("Fragment offset must be 0–8191");
    const src = typeof input.src === "string" ? parseIp(input.src) : input.src;
    const dst = typeof input.dst === "string" ? parseIp(input.dst) : input.dst;
    if (!src || src.length !== 4 || !dst || dst.length !== 4) throw new Error("Source and destination must be IPv4 addresses");

    const bytes = new Uint8Array(headerLen);
    bytes[0] = ((version & 0x0f) << 4) | (ihl & 0x0f);
    bytes[1] = ((dscp & 0x3f) << 2) | (ecn & 0x03);
    PH.put16be(bytes, 2, total);
    PH.put16be(bytes, 4, id);
    const flagsWord = ((input.reserved ? 1 : 0) << 15) | ((input.df ? 1 : 0) << 14) | ((input.mf ? 1 : 0) << 13) | (frag & 0x1fff);
    PH.put16be(bytes, 6, flagsWord);
    bytes[8] = ttl;
    bytes[9] = proto;
    PH.put16be(bytes, 10, 0);
    bytes.set(src, 12);
    bytes.set(dst, 16);
    bytes.set(optionsPadded, 20);
    const checksum = PH.checksum16(bytes);
    PH.put16be(bytes, 10, checksum);
    return {
      bytes, checksum, headerLen, payloadLen, totalLength: total, ihl,
      optionsBytes: options.length, optionsPadded: optionsPadded.length,
      flagsWord, src, dst
    };
  }

  function parseOptions(bytes) {
    const options = [];
    const warnings = [];
    let i = 0;
    while (i < bytes.length) {
      const type = bytes[i];
      const start = i;
      const copied = (type >> 7) & 1;
      const cls = (type >> 5) & 3;
      const num = type & 31;
      if (type === 0) {
        options.push({ type, name: "EOL", length: 1, offset: start, copied, cls, num, data: new Uint8Array(0), detail: "end of option list" });
        if (bytes.length - (i + 1) > 0) {
          const padding = bytes.length - (i + 1);
          if (bytes.slice(i + 1).some((b) => b !== 0)) warnings.push(`EOL at options offset ${start}; ${padding} trailing byte(s) after EOL are not all zero`);
          else warnings.push(`EOL at options offset ${start}; ${padding} byte(s) of padding`);
        }
        break;
      }
      if (type === 1) {
        options.push({ type, name: "NOP", length: 1, offset: start, copied, cls, num, data: new Uint8Array(0), detail: "alignment padding" });
        i += 1;
        continue;
      }
      if (i + 1 >= bytes.length) {
        warnings.push(`Option at offset ${start} (${optionName(type)}) is truncated before its length byte`);
        break;
      }
      const len = bytes[i + 1];
      if (len < 2) {
        warnings.push(`Option at offset ${start} (${optionName(type)}) has invalid length ${len}`);
        break;
      }
      if (i + len > bytes.length) {
        warnings.push(`Option at offset ${start} (${optionName(type)}) claims ${len} bytes but only ${bytes.length - i} remain`);
        break;
      }
      const data = bytes.slice(i + 2, i + len);
      const option = { type, name: optionName(type), length: len, offset: start, copied, cls, num, data, detail: "" };
      if (num === 7 || num === 131 || num === 137) {
        const pointer = data[0] || 0;
        const addresses = [];
        for (let j = 1; j + 4 <= data.length; j += 4) addresses.push(Array.from(data.slice(j, j + 4)).join("."));
        option.detail = `pointer ${pointer} (1-based) · ${addresses.length} address(es)`;
        option.parsed = { pointer, addresses };
      } else if (num === 68 && type === 0x44) {
        const pointer = data[0] || 0;
        const overflow = (data[1] >> 4) & 15;
        const flag = data[1] & 15;
        option.detail = `pointer ${pointer} · overflow ${overflow} · flag ${flag} (${flag === 0 ? "timestamps" : flag === 1 ? "address+timestamp" : flag === 3 ? "prespecified" : "reserved"})`;
        option.parsed = { pointer, overflow, flag };
      } else if (type === 0x94) {
        const value = data.length >= 2 ? PH.u16be(data, 0) : null;
        const alert = { 0: "router shall examine", 1: "IGMP", 2: "RSVP", 3: "active networks", 5: "MLD", 6: "NSIS", 7: "NSC" }[value] || "unassigned";
        option.detail = value == null ? "truncated value" : `value ${value} · ${alert}`;
        option.parsed = { value };
      } else if (type === 0x88 && data.length >= 2) {
        option.detail = `stream id ${PH.u16be(data, 0)}`;
      } else {
        option.detail = data.length ? `${data.length} data byte(s)` : "no data";
      }
      options.push(option);
      i += len;
    }
    return { options, warnings };
  }

  function decode(bytes) {
    let base = 0;
    let ethernet = false;
    let vlan = false;
    if (bytes.length >= 14 && (bytes[0] >> 4) !== 4) {
      const ethertype = PH.u16be(bytes, 12);
      if (ethertype === 0x0800) { base = 14; ethernet = true; }
      else if (ethertype === 0x8100 && bytes.length >= 18 && PH.u16be(bytes, 16) === 0x0800) {
        base = 18; ethernet = true; vlan = true;
      }
    }
    if (bytes.length < base + 20) throw new Error("Need at least 20 bytes of IPv4 header");
    const h = bytes.subarray(base);
    const version = h[0] >> 4;
    const ihl = h[0] & 15;
    if (version !== 4) throw new Error(`Version nibble is ${version}, not 4`);
    if (ihl < 5) throw new Error(`IHL is ${ihl}; minimum is 5 (20 bytes)`);
    const headerLen = ihl * 4;
    if (h.length < headerLen) throw new Error(`IHL says ${headerLen} bytes but only ${h.length} are available`);
    if (headerLen > 60) throw new Error(`Header length ${headerLen} exceeds 60 bytes`);
    const totalLength = PH.u16be(h, 2);
    const dscp = h[1] >> 2;
    const ecn = h[1] & 3;
    const id = PH.u16be(h, 4);
    const flagsWord = PH.u16be(h, 6);
    const reserved = (flagsWord >> 15) & 1;
    const df = (flagsWord >> 14) & 1;
    const mf = (flagsWord >> 13) & 1;
    const fragmentOffset = flagsWord & 0x1fff;
    const ttl = h[8];
    const protocol = h[9];
    const checksum = PH.u16be(h, 10);
    const checksumHeader = h.slice(0, headerLen);
    checksumHeader[10] = 0;
    checksumHeader[11] = 0;
    const expected = PH.checksum16(checksumHeader);
    const checksumOk = PH.checksumValid(h.subarray(0, headerLen));
    const src = ipString(h.subarray(12, 16));
    const dst = ipString(h.subarray(16, 20));
    const optionsBytes = h.subarray(20, headerLen);
    const parsedOptions = parseOptions(optionsBytes);
    const warnings = parsedOptions.warnings.slice();
    let payloadEnd = Math.min(h.length, totalLength || h.length);
    if (totalLength === 0) warnings.push("Total Length is 0 (possible TSO/GSO capture)");
    else if (totalLength < headerLen) warnings.push(`Total Length ${totalLength} is smaller than the ${headerLen}-byte header`);
    else if (totalLength > h.length) warnings.push(`Total Length ${totalLength} exceeds the ${h.length} captured bytes; payload is truncated`);
    if (totalLength && totalLength < h.length) warnings.push(`${h.length - totalLength} trailing byte(s) beyond Total Length (Ethernet padding?)`);
    if (fragmentOffset > 0 && mf === 1 && fragmentOffset * 8 === 0) warnings.push("MF is set with offset 0; check fragment reassembly");
    if (reserved) warnings.push("Reserved flag bit is set; compliant receivers should ignore it");
    if (df && mf) warnings.push("DF and MF are both set — contradictory fragmentation flags");
    if (!checksumOk) warnings.push("Header checksum is invalid (or checksum offload is in play)");
    return {
      ok: true, base, ethernet, vlan, version, ihl, headerLen, dscp, ecn, ecnLabel: ecnName(ecn),
      dscpLabel: dscpName(dscp), totalLength, id, flagsWord, reserved, df, mf, fragmentOffset,
      ttl, protocol, protocolLabel: protocolName(protocol), checksum, expectedChecksum: expected,
      checksumOk, src, dst, options: parsedOptions.options, optionsBytes: optionsBytes.length,
      warnings, headerBytes: h.subarray(0, headerLen), payloadBytes: h.subarray(headerLen, payloadEnd),
      capturedHeader: bytes.subarray(0, base + headerLen), totalCaptured: bytes.length
    };
  }

  window.IPv4Codec = { buildHeader, decode, parseOptions, optionName, protocolName, dscpName, ecnName, flagsText };

  /* ---------- field data ---------- */
  const fields = [
    {
      id: "version", name: "Version", bits: 4, range: "4 (IPv4)", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "IP version. For IPv4 this nibble is <code>4</code>; a value of <code>6</code> here means the parser should hand off to IPv6. It sits in the high nibble of the first octet."
    },
    {
      id: "ihl", name: "IHL", bits: 4, range: "5–15 words", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "Internet Header Length in 32-bit words. <code>5</code> means the 20-byte minimum; each extra word holds options. Multiply by four for the byte length of the header."
    },
    {
      id: "dscp", name: "DSCP", bits: 6, range: "0–63", rfc: "RFC 2474 §3", rfcUrl: RFC.dscp + "#section-3",
      desc: "Differentiated Services Code Point, the top six bits of the former ToS octet. Common values: <code>0</code> default, <code>46</code> EF, <code>10/12/14</code> AF11/12/13."
    },
    {
      id: "ecn", name: "ECN", bits: 2, range: "00–11", rfc: "RFC 3168 §5", rfcUrl: RFC.ecn + "#section-5",
      desc: "Explicit Congestion Notification: <code>00</code> Not-ECT, <code>01</code> ECT(1), <code>10</code> ECT(0), <code>11</code> Congestion Experienced. The last two bits of the second octet."
    },
    {
      id: "total", name: "Total Length", bits: 16, range: "20–65535 B", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "Length of the entire datagram in bytes: header plus payload. A 20-byte header with 100 bytes of data carries <code>120</code>. Values below the header length are malformed."
    },
    {
      id: "id", name: "Identification", bits: 16, range: "0–65535", rfc: "RFC 791 · RFC 6864", rfcUrl: RFC.id,
      desc: "Fragment identification. Fragments of one original datagram share this value. Modern semantics are constrained by RFC 6864: atomic datagrams should use zero."
    },
    {
      id: "flags", name: "Flags", bits: 3, range: "R, DF, MF", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "Three bits: reserved (must be zero), <strong>DF</strong> (don't fragment) and <strong>MF</strong> (more fragments follow). The next 13 bits are the fragment offset."
    },
    {
      id: "frag", name: "Fragment Offset", bits: 13, range: "0–8191 × 8 B", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "Position of this fragment in the original datagram, in units of eight bytes. Multiply by eight to get the byte offset. The final fragment has MF=0."
    },
    {
      id: "ttl", name: "TTL", bits: 8, range: "0–255", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "Time To Live, decremented by every router. Reaching zero produces ICMP Time Exceeded. Common initial values are 64, 128 and 255; no value is mandated."
    },
    {
      id: "proto", name: "Protocol", bits: 8, range: "0–255", rfc: "IANA protocol numbers", rfcUrl: "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml",
      desc: "Upper-layer protocol: <code>1</code> ICMP, <code>6</code> TCP, <code>17</code> UDP, <code>41</code> IPv6, <code>47</code> GRE, <code>50</code> ESP, <code>51</code> AH, <code>58</code> ICMPv6, <code>89</code> OSPF."
    },
    {
      id: "sum", name: "Header Checksum", bits: 16, range: "0–65535", rfc: "RFC 1071 · RFC 791", rfcUrl: RFC.checksum,
      desc: "One's-complement sum of the header (including options) with this field zeroed. It does <em>not</em> cover the payload; TCP and UDP carry their own checksums."
    },
    {
      id: "src", name: "Source Address", bits: 32, range: "IPv4 address", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "The sending interface's IPv4 address. It is not authenticated by the header; source-address spoofing is a packet-filtering and ingress-filtering problem."
    },
    {
      id: "dst", name: "Destination Address", bits: 32, range: "IPv4 address", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "The final destination address. Routers forward based on this value; multicast destinations use 224.0.0.0/4 and limited broadcast is 255.255.255.255."
    },
    {
      id: "options", name: "Options", bits: "var", varWidth: 32, range: "0–40 B", rfc: "RFC 791 §3.1", rfcUrl: RFC.base + "#section-3.1",
      desc: "Optional TLVs: EOL, NOP, Record Route, Timestamp, source routing and Router Alert. Padded to 4 bytes. The diagram draws a nominal 32-bit slot; real options may be 0–40 bytes.",
      tone: "j"
    }
  ];

  let diagramController = null;

  function initDiagram() {
    diagramController = PH.diagram("#ipv4-diagram", {
      title: "<b>IPv4 header</b> · 20–60 bytes",
      badge: "RFC 791",
      fields,
      inspector: "#ipv4-inspector",
      table: "#ipv4-fields",
      note: "Total length includes the header. The optional field is drawn at a nominal 32 bits; the actual option list can be 0–40 bytes and is padded to a multiple of four."
    });
    PH.fieldTable("#ipv4-fields", diagramController, {
      columns: ["field", "bits", "offset", "range/values", "rfc"]
    });
  }

  function updateDiagram(result) {
    if (!diagramController) return;
    diagramController.setValues({
      version: String(result.version),
      ihl: String(result.ihl),
      dscp: String(result.dscp),
      ecn: result.ecnLabel,
      total: String(result.totalLength),
      id: "0x" + PH.hex(result.id, 4),
      flags: IPV4_FLAGS(result),
      frag: String(result.fragmentOffset),
      ttl: String(result.ttl),
      proto: result.protocol + " " + result.protocolLabel,
      sum: "0x" + PH.hex(result.checksum, 4) + (result.checksumOk ? " ✓" : " ✗"),
      src: result.src,
      dst: result.dst,
      options: result.optionsBytes + " B"
    });
  }
  function IPV4_FLAGS(r) { return flagsText(r.reserved, r.df, r.mf); }

  /* ---------- flag explorer ---------- */
  function initFlags() {
    const reserved = document.getElementById("frag-reserved");
    const df = document.getElementById("frag-df");
    const mf = document.getElementById("frag-mf");
    const offset = document.getElementById("frag-offset");
    const payload = document.getElementById("frag-payload");
    const word = document.getElementById("frag-word");
    const flagsEl = document.getElementById("frag-flags");
    const bytesEl = document.getElementById("frag-bytes");
    const rangeEl = document.getElementById("frag-range");
    const validEl = document.getElementById("frag-valid");
    if (!reserved) return;

    function update() {
      const o = Math.max(0, Math.min(8191, Number(offset.value) || 0));
      const p = Math.max(0, Number(payload.value) || 0);
      offset.value = o;
      const fieldsWord = ((reserved.checked ? 1 : 0) << 15) | ((df.checked ? 1 : 0) << 14) | ((mf.checked ? 1 : 0) << 13) | o;
      word.textContent = "0x" + PH.hex(fieldsWord, 4) + " · " + PH.bin(fieldsWord, 16);
      flagsEl.textContent = flagsText(reserved.checked, df.checked, mf.checked);
      bytesEl.textContent = String(o * 8);
      rangeEl.textContent = p > 0 ? `${o * 8}–${o * 8 + p - 1}` : `${o * 8} (empty)`;
      if (reserved.checked) {
        validEl.textContent = "reserved bit set — should be zero";
        validEl.className = "warn-text";
      } else if (df.checked && mf.checked) {
        validEl.textContent = "DF + MF — contradictory";
        validEl.className = "bad-text";
      } else {
        validEl.textContent = "consistent";
        validEl.className = "good-text";
      }
      if (diagramController) diagramController.setValues({
        flags: flagsText(reserved.checked, df.checked, mf.checked),
        frag: String(o)
      });
    }
    [reserved, df, mf].forEach((el) => el.addEventListener("change", update));
    [offset, payload].forEach((el) => el.addEventListener("input", update));
    update();
  }

  /* ---------- option type factory ---------- */
  function initOptionFactory() {
    const copied = document.getElementById("opt-copied");
    const cls = document.getElementById("opt-class");
    const num = document.getElementById("opt-number");
    const out = document.getElementById("opt-type-out");
    if (!copied) return;
    function update() {
      const n = Math.max(0, Math.min(31, Number(num.value) || 0));
      num.value = n;
      const type = (copied.checked ? 0x80 : 0) | ((Number(cls.value) & 3) << 5) | n;
      out.textContent = `0x${PH.hex(type, 2)} · ${optionName(type)}`;
    }
    [copied, cls, num].forEach((el) => { el.addEventListener("input", update); el.addEventListener("change", update); });
    update();
  }

  /* ---------- encoder ---------- */
  function readEncoder() {
    const id = PH.parseNumber(document.getElementById("enc-id").value);
    if (id == null) throw new Error("Identification is not a number");
    const payloadLength = PH.parseNumber(document.getElementById("enc-payload-len").value);
    if (payloadLength == null) throw new Error("Payload length is not a number");
    return {
      version: Number(document.getElementById("enc-version").value),
      dscp: Number(document.getElementById("enc-dscp").value),
      ecn: Number(document.getElementById("enc-ecn").value),
      id,
      ttl: Number(document.getElementById("enc-ttl").value),
      protocol: Number(document.getElementById("enc-proto").value),
      fragmentOffset: Number(document.getElementById("enc-frag-offset").value) || 0,
      payloadLength,
      reserved: document.getElementById("enc-reserved").checked,
      df: document.getElementById("enc-df").checked,
      mf: document.getElementById("enc-mf").checked,
      src: document.getElementById("enc-src").value,
      dst: document.getElementById("enc-dst").value,
      options: document.getElementById("enc-options").value
    };
  }

  function buildFromForm(showErrors = true) {
    const status = document.getElementById("ipv4-encode-status");
    const output = document.getElementById("enc-output");
    const summary = document.getElementById("enc-summary");
    const tag = document.getElementById("enc-summary-tag");
    let result;
    try {
      result = buildHeader(readEncoder());
    } catch (err) {
      if (showErrors) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    const summaryHtml = [
      `<span class="pill pill--good">checksum <b>0x${PH.hex(result.checksum, 4)}</b></span>`,
      `<span class="pill">header <b>${result.headerLen} B</b></span>`,
      `<span class="pill">IHL <b>${result.ihl}</b></span>`,
      `<span class="pill">options <b>${result.optionsBytes} B</b>${result.optionsPadded !== result.optionsBytes ? " (padded)" : ""}</span>`,
      `<span class="pill">total <b>${result.totalLength} B</b></span>`
    ].join("");
    summary.innerHTML = summaryHtml;
    tag.textContent = `${result.headerLen} bytes`;
    PH.setStatus(status, `built ${result.headerLen}-byte header · checksum 0x${PH.hex(result.checksum, 4)} · ${result.optionsPadded > result.optionsBytes ? "options padded to 4-byte boundary" : "options aligned"}`, "ok");
    updateDiagram({
      version: Number(document.getElementById("enc-version").value),
      ihl: result.ihl,
      dscp: Number(document.getElementById("enc-dscp").value),
      ecnLabel: ecnName(Number(document.getElementById("enc-ecn").value)),
      totalLength: result.totalLength,
      id: PH.parseNumber(document.getElementById("enc-id").value),
      reserved: document.getElementById("enc-reserved").checked,
      df: document.getElementById("enc-df").checked,
      mf: document.getElementById("enc-mf").checked,
      fragmentOffset: Number(document.getElementById("enc-frag-offset").value) || 0,
      ttl: Number(document.getElementById("enc-ttl").value),
      protocol: Number(document.getElementById("enc-proto").value),
      protocolLabel: protocolName(Number(document.getElementById("enc-proto").value)),
      checksum: result.checksum,
      checksumOk: true,
      src: document.getElementById("enc-src").value,
      dst: document.getElementById("enc-dst").value,
      optionsBytes: result.optionsBytes
    });
    return result;
  }

  function initEncoder() {
    document.getElementById("ipv4-build").addEventListener("click", () => buildFromForm());
    document.querySelectorAll("[data-ipv4-opt]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("enc-options").value = btn.getAttribute("data-ipv4-opt");
        buildFromForm(false);
      });
    });
    document.getElementById("ipv4-load-example").addEventListener("click", () => {
      document.getElementById("enc-version").value = "4";
      document.getElementById("enc-dscp").value = "0";
      document.getElementById("enc-ecn").value = "0";
      document.getElementById("enc-id").value = "0x1c46";
      document.getElementById("enc-ttl").value = "64";
      document.getElementById("enc-proto").value = "6";
      document.getElementById("enc-frag-offset").value = "0";
      document.getElementById("enc-payload-len").value = "0";
      document.getElementById("enc-reserved").checked = false;
      document.getElementById("enc-df").checked = true;
      document.getElementById("enc-mf").checked = false;
      document.getElementById("enc-src").value = "192.0.2.10";
      document.getElementById("enc-dst").value = "198.51.100.20";
      document.getElementById("enc-options").value = "94 04 00 00";
      buildFromForm();
    });
    ["enc-version", "enc-dscp", "enc-ecn", "enc-id", "enc-ttl", "enc-proto", "enc-frag-offset", "enc-payload-len", "enc-reserved", "enc-df", "enc-mf", "enc-src", "enc-dst"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", () => buildFromForm(false));
    });
    buildFromForm(false);
  }

  /* ---------- decoder ---------- */
  function renderDecoded(result, bytes) {
    const host = document.getElementById("ipv4-decode-result");
    if (!result) { host.innerHTML = ""; return; }
    const warnings = result.warnings;
    const pills = [
      `<span class="pill">IPv4</span>`,
      `<span class="pill">header <b>${result.headerLen} B</b></span>`,
      `<span class="pill">payload <b>${result.payloadBytes.length} B</b></span>`,
      `<span class="pill">total <b>${result.totalLength || "?"} B</b></span>`,
      `<span class="pill">DSCP <b>${result.dscp} ${PH.esc(result.dscpLabel)}</b></span>`,
      `<span class="pill">ECN <b>${result.ecnLabel}</b></span>`,
      `<span class="pill ${result.checksumOk ? "pill--good" : "pill--bad"}">checksum ${result.checksumOk ? "valid" : "invalid"}</span>`,
      `<span class="pill">flags <b>${flagsText(result.reserved, result.df, result.mf)}</b></span>`,
      `<span class="pill">options <b>${result.optionsBytes} B</b></span>`
    ];
    if (result.ethernet) pills.push(`<span class="pill pill--good">Ethernet${result.vlan ? " + VLAN" : ""} frame</span>`);

    const rows = [
      ["Version", "4", "0–3", String(result.version), "must be 4"],
      ["IHL", "4", "4–7", `${result.ihl} (${result.headerLen} B)`, "units of 4 bytes"],
      ["DSCP", "6", "8–13", `${result.dscp} · ${result.dscpLabel}`, "ToS high bits"],
      ["ECN", "2", "14–15", `${result.ecn} · ${result.ecnLabel}`, ""],
      ["Total Length", "16", "16–31", `${result.totalLength} B`, result.totalLength >= result.headerLen ? "" : "less than header"],
      ["Identification", "16", "32–47", `0x${PH.hex(result.id, 4)}`, ""],
      ["Flags", "3", "48–50", flagsText(result.reserved, result.df, result.mf), `raw 0x${PH.hex(result.flagsWord >> 13, 1)}`],
      ["Fragment Offset", "13", "51–63", `${result.fragmentOffset} × 8 = ${result.fragmentOffset * 8} B`, ""],
      ["TTL", "8", "64–71", String(result.ttl), ""],
      ["Protocol", "8", "72–79", `${result.protocol} · ${result.protocolLabel}`, ""],
      ["Header Checksum", "16", "80–95", `0x${PH.hex(result.checksum, 4)} · ${result.checksumOk ? "valid" : "expected 0x" + PH.hex(result.expectedChecksum, 4)}`, result.checksumOk ? "" : "checksum invalid"],
      ["Source Address", "32", "96–127", result.src, ""],
      ["Destination Address", "32", "128–159", result.dst, ""],
      ["Options", `${result.optionsBytes * 8}`, result.optionsBytes ? `160–${159 + result.optionsBytes * 8}` : "—", `${result.optionsBytes} B`, result.optionsBytes ? "parsed below" : "none"]
    ];
    const table = rows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    let optionsHtml = "";
    if (result.options.length) {
      optionsHtml = '<div class="decoded-head"><h3>option TLVs</h3><span class="dim">offsets relative to the IPv4 header</span></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Offset</th><th>Type</th><th>Name</th><th class="num">Length</th><th>Data</th><th>Decoded</th></tr></thead><tbody>' +
        result.options.map((opt) =>
          `<tr><td class="num">${20 + opt.offset}</td><td><code>0x${PH.hex(opt.type, 2)}</code></td><td><b>${PH.esc(opt.name)}</b></td><td class="num">${opt.length}</td><td><code>${opt.data.length ? PH.bytesToHex(opt.data) : "—"}</code></td><td class="small">${PH.esc(opt.detail)}</td></tr>`
        ).join("") + "</tbody></table></div>";
    }

    const warningHtml = warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean parse</div><p>Header length, total length and checksum agree. Payload parsing is up to the next layer.</p></div>';

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>bytes on the wire</span><span>${bytes.length} B · ${result.headerLen} B header</span></div>${PH.hexdump(bytes, { highlight: [{ start: result.base, end: result.base + result.headerLen }] })}</div>` +
      `<div class="decoded-head"><h3>header fields</h3><span class="dim">offsets relative to the IPv4 header</span></div>` +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${table}</tbody></table></div>` +
      optionsHtml + warningHtml;
  }

  function initDecoder() {
    const input = document.getElementById("ipv4-decode-input");
    const status = document.getElementById("ipv4-decode-status");
    const resultHost = document.getElementById("ipv4-decode-result");
    if (!input) return;

    function run(showErrors = true) {
      let bytes;
      try {
        bytes = PH.parseHex(input.value);
      } catch (err) {
        if (showErrors) PH.setStatus(status, "hex error: " + err.message, "bad");
        resultHost.innerHTML = "";
        return;
      }
      let result;
      try {
        result = decode(bytes);
      } catch (err) {
        if (showErrors) PH.setStatus(status, "decode error: " + err.message, "bad");
        resultHost.innerHTML = "";
        return;
      }
      PH.setStatus(status,
        `decoded ${result.headerLen} B header${result.ethernet ? " inside an Ethernet frame" : ""} · ${result.payloadBytes.length} B payload · checksum ${result.checksumOk ? "valid" : "invalid"}${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
        result.checksumOk && !result.warnings.length ? "ok" : (result.checksumOk ? "warn" : "bad"));
      renderDecoded(result, bytes);
      updateDiagram(result);
    }

    document.getElementById("ipv4-decode").addEventListener("click", () => run());
    document.getElementById("ipv4-decode-example").addEventListener("click", () => {
      const example = buildHeader({
        version: 4, dscp: 0, ecn: 0, id: 0x1c46, ttl: 64, protocol: 6,
        fragmentOffset: 0, payloadLength: 20, reserved: false, df: true, mf: false,
        src: "192.0.2.10", dst: "198.51.100.20", options: "94 04 00 00"
      });
      const payload = PH.parseHex("de ad be ef 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
      input.value = PH.bytesToHex(PH.concatBytes(example.bytes, payload));
      run();
    });
    document.getElementById("ipv4-decode-clear").addEventListener("click", () => {
      input.value = "";
      resultHost.innerHTML = "";
      PH.setStatus(status, "No input decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
    // Do not run automatically on load; an empty panel is a better starting state.
  }

  function init() {
    if (!document.getElementById("ipv4-diagram")) return;
    initDiagram();
    initFlags();
    initOptionFactory();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
