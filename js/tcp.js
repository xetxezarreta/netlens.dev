/* TCP header / flags / options explorer — pure codec + page wiring */
(function () {
  "use strict";

  const PH = window.PH;
  const RFC = {
    tcp: "https://www.rfc-editor.org/rfc/rfc9293",
    ws: "https://www.rfc-editor.org/rfc/rfc7323",
    sack: "https://www.rfc-editor.org/rfc/rfc2018",
    ecn: "https://www.rfc-editor.org/rfc/rfc3168",
    tfo: "https://www.rfc-editor.org/rfc/rfc7413",
    ao: "https://www.rfc-editor.org/rfc/rfc5925"
  };

  const OPTION_NAMES = {
    0: "EOL", 1: "NOP", 2: "MSS", 3: "Window Scale", 4: "SACK permitted", 5: "SACK",
    8: "Timestamps", 19: "MD5 signature", 28: "User Timeout", 29: "TCP-AO",
    30: "MPTCP", 34: "Fast Open", 253: "Experimental", 254: "Experimental"
  };

  const FLAG_BITS = [
    { key: "cwr", mask: 0x80, bit: 104, letter: "W", name: "CWR" },
    { key: "ece", mask: 0x40, bit: 105, letter: "E", name: "ECE" },
    { key: "urg", mask: 0x20, bit: 106, letter: "U", name: "URG" },
    { key: "ack", mask: 0x10, bit: 107, letter: ".", name: "ACK" },
    { key: "psh", mask: 0x08, bit: 108, letter: "P", name: "PSH" },
    { key: "rst", mask: 0x04, bit: 109, letter: "R", name: "RST" },
    { key: "syn", mask: 0x02, bit: 110, letter: "S", name: "SYN" },
    { key: "fin", mask: 0x01, bit: 111, letter: "F", name: "FIN" }
  ];

  const TCP_STEPS = [
    {
      caption: "<b>SYN.</b> The client picks an initial sequence number <code>x=1000</code> and sends SYN with no data. It moves to SYN-SENT; the server is still LISTEN.",
      client: "SYN-SENT", server: "LISTEN", segment: "SYN · seq 1000",
      state: "opening", stateClass: "warn-text",
      active: ["client"], match: ["server"]
    },
    {
      caption: "<b>SYN/ACK.</b> The server picks <code>y=5000</code> and replies with SYN+ACK: <code>seq 5000</code>, <code>ack 1001</code>. SYN consumes one sequence number, so the client's next byte is 1001. The server is SYN-RECEIVED.",
      client: "SYN-SENT", server: "SYN-RECEIVED", segment: "SYN/ACK · seq 5000 · ack 1001",
      state: "opening", stateClass: "warn-text",
      active: ["server"], match: ["client"]
    },
    {
      caption: "<b>ACK.</b> The client acknowledges the server's SYN with <code>ack 5001</code>. Both sides are ESTABLISHED; no application data has been sent yet.",
      client: "ESTABLISHED", server: "ESTABLISHED", segment: "ACK · ack 5001",
      state: "established", stateClass: "good-text",
      active: ["client"], match: ["server"]
    },
    {
      caption: "<b>DATA is lost.</b> The client sends 100 bytes at <code>seq 1001</code> with ACK 5001. The segment never reaches the server, so no ACK comes back. The client keeps the bytes and starts a retransmission timer.",
      client: "ESTABLISHED", server: "ESTABLISHED", segment: "DATA · seq 1001 · len 100",
      state: "data lost", stateClass: "warn-text",
      active: ["client"], match: []
    },
    {
      caption: "<b>Retransmission.</b> The RTO expires and the client resends the same sequence range, <code>seq 1001</code>, length 100. TCP does not invent a new sequence number for a retransmission.",
      client: "ESTABLISHED", server: "ESTABLISHED", segment: "DATA · seq 1001 · retransmit",
      state: "retransmitting", stateClass: "warn-text",
      active: ["client"], match: ["server"]
    },
    {
      caption: "<b>ACK.</b> The server receives the retransmitted data and acknowledges the next expected byte, <code>ack 1101</code>. Both sides remain ESTABLISHED.",
      client: "ESTABLISHED", server: "ESTABLISHED", segment: "ACK · ack 1101",
      state: "established", stateClass: "good-text",
      active: ["server"], match: ["client"]
    },
    {
      caption: "<b>FIN.</b> The client has nothing more to send. It sends FIN with <code>seq 1101</code> and <code>ack 5001</code>. FIN consumes one sequence number. The client enters FIN-WAIT-1; the server enters CLOSE-WAIT when the FIN arrives.",
      client: "FIN-WAIT-1", server: "CLOSE-WAIT", segment: "FIN · seq 1101 · ack 5001",
      state: "closing", stateClass: "warn-text",
      active: ["client"], match: ["server"]
    },
    {
      caption: "<b>ACK of FIN.</b> The server acknowledges the client's FIN with <code>ack 1102</code>. The client moves to FIN-WAIT-2 while the server may still send data in the other direction.",
      client: "FIN-WAIT-2", server: "CLOSE-WAIT", segment: "ACK · ack 1102",
      state: "closing", stateClass: "warn-text",
      active: ["server"], match: ["client"]
    },
    {
      caption: "<b>FIN from the server.</b> The server closes its half with <code>seq 5001</code> and <code>ack 1102</code>. The client enters TIME-WAIT; the server enters LAST-ACK.",
      client: "TIME-WAIT", server: "LAST-ACK", segment: "FIN · seq 5001 · ack 1102",
      state: "closing", stateClass: "warn-text",
      active: ["server"], match: ["client"]
    },
    {
      caption: "<b>ACK.</b> The client acknowledges the server's FIN with <code>ack 5002</code>. The server is CLOSED. The client waits 2×MSL in TIME-WAIT so late duplicates cannot be mistaken for a new connection with the same port pair, then closes.",
      client: "TIME-WAIT", server: "CLOSED", segment: "ACK · ack 5002",
      state: "time-wait", stateClass: "good-text",
      active: ["client"], match: ["server"]
    }
  ];

  const TCP_TOKEN_HOME = {
    1: [220, 125], 2: [500, 165], 3: [220, 205], 4: [220, 245], 5: [220, 285],
    6: [500, 325], 7: [220, 365], 8: [500, 405], 9: [500, 445], 10: [220, 485]
  };
  const TCP_TOKEN_TARGET = {
    1: [500, 125], 2: [220, 165], 3: [500, 205], 4: [435, 245], 5: [500, 285],
    6: [220, 325], 7: [500, 365], 8: [220, 405], 9: [220, 445], 10: [500, 485]
  };

  function optionName(kind) { return OPTION_NAMES[kind] || ("Kind " + kind); }

  function flagsToByte(obj) {
    let byte = 0;
    FLAG_BITS.forEach((f) => { if (obj[f.key]) byte |= f.mask; });
    return byte;
  }

  function flagNames(byte) {
    return FLAG_BITS.filter((f) => byte & f.mask).map((f) => f.name);
  }

  function flagsToNotation(byte) {
    // tcpdump prints low-bit-first: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
    const order = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];
    const letters = order.filter((key) => {
      const f = FLAG_BITS.find((x) => x.key === key);
      return f && (byte & f.mask);
    }).map((key) => FLAG_BITS.find((x) => x.key === key).letter).join("");
    return "[" + (letters || "none") + "]";
  }

  function parsePort(n, label) {
    const v = Number(n);
    if (!Number.isInteger(v) || v < 0 || v > 65535) throw new Error(label + " must be 0–65535");
    return v;
  }
  function parse32(n, label) {
    const v = Number(n);
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error(label + " must be an unsigned 32-bit value");
    return v >>> 0;
  }

  function buildPseudoHeader(src, dst, tcpLength) {
    if (!src || !dst) return null;
    const pseudo = new Uint8Array(12);
    pseudo.set(src, 0);
    pseudo.set(dst, 4);
    pseudo[8] = 0;
    pseudo[9] = 6;
    PH.put16be(pseudo, 10, tcpLength);
    return pseudo;
  }

  function buildSegment(input) {
    const options = input.options ? PH.parseHex(input.options) : new Uint8Array(0);
    if (options.length > 40) throw new Error("Options exceed 40 bytes; Data Offset would exceed 15");
    let padded = options;
    if (options.length % 4) {
      padded = new Uint8Array(options.length + (4 - (options.length % 4)));
      padded.set(options);
    }
    const headerLen = 20 + padded.length;
    const dataOffset = headerLen / 4;
    if (dataOffset > 15) throw new Error("Header exceeds 60 bytes");
    const payload = input.payload ? PH.parseHex(input.payload) : new Uint8Array(0);
    const tcpLength = headerLen + payload.length;
    if (tcpLength > 65535) throw new Error("TCP length exceeds 65535");
    const sport = parsePort(input.sport, "Source port");
    const dport = parsePort(input.dport, "Destination port");
    const seq = parse32(input.seq, "Sequence number");
    const ack = parse32(input.ack == null ? 0 : input.ack, "Acknowledgment number");
    const window = parsePort(input.window, "Window");
    const urgent = parsePort(input.urgent || 0, "Urgent pointer");
    const reserved = Number(input.reserved) || 0;
    if (!Number.isInteger(reserved) || reserved < 0 || reserved > 15) throw new Error("Reserved field must be 0–15");
    const flags = input.flags != null ? Number(input.flags) : flagsToByte(input);
    if (!Number.isInteger(flags) || flags < 0 || flags > 255) throw new Error("Flags byte must be 0–255");
    let src = null;
    let dst = null;
    const hasSrc = Boolean(input.src && String(input.src).trim());
    const hasDst = Boolean(input.dst && String(input.dst).trim());
    if (hasSrc !== hasDst) throw new Error("Supply both IPv4 addresses or neither (checksum needs the pair)");
    if (hasSrc) {
      src = PH.parseIPv4(input.src);
      dst = PH.parseIPv4(input.dst);
    }
    const bytes = new Uint8Array(tcpLength);
    PH.put16be(bytes, 0, sport);
    PH.put16be(bytes, 2, dport);
    PH.put32be(bytes, 4, seq);
    PH.put32be(bytes, 8, ack);
    bytes[12] = ((dataOffset & 0x0f) << 4) | (reserved & 0x0f);
    bytes[13] = flags;
    PH.put16be(bytes, 14, window);
    PH.put16be(bytes, 16, 0);
    PH.put16be(bytes, 18, urgent);
    bytes.set(padded, 20);
    bytes.set(payload, headerLen);
    let checksum = 0;
    let pseudoHeader = false;
    if (src && dst) {
      const pseudo = buildPseudoHeader(src, dst, tcpLength);
      const all = PH.concatBytes(pseudo, bytes);
      checksum = PH.checksum16(all);
      PH.put16be(bytes, 16, checksum);
      pseudoHeader = true;
    }
    return {
      bytes, header: bytes.subarray(0, headerLen), payload, headerLen, dataOffset,
      tcpLength, checksum, pseudoHeader, flags, reserved, optionsBytes: options.length,
      optionsPadded: padded.length, sport, dport, seq, ack, window, urgent,
      src: src ? PH.ipv4String(src) : null, dst: dst ? PH.ipv4String(dst) : null
    };
  }

  function parseOptions(bytes) {
    const options = [];
    const warnings = [];
    let i = 0;
    while (i < bytes.length) {
      const kind = bytes[i];
      const offset = i;
      if (kind === 0) {
        options.push({ kind, name: "EOL", length: 1, offset, data: new Uint8Array(0), detail: "end of option list" });
        const rest = bytes.subarray(i + 1);
        if (rest.length) {
          if (rest.some((b) => b !== 0)) warnings.push(`EOL at options offset ${offset}; ${rest.length} trailing byte(s) are not zero`);
          else options[options.length - 1].detail += ` · ${rest.length} byte(s) padding`;
        }
        break;
      }
      if (kind === 1) {
        options.push({ kind, name: "NOP", length: 1, offset, data: new Uint8Array(0), detail: "alignment padding" });
        i += 1;
        continue;
      }
      if (i + 1 >= bytes.length) {
        warnings.push(`Option ${optionName(kind)} at offset ${offset} is truncated before its length byte`);
        break;
      }
      const length = bytes[i + 1];
      if (length < 2) {
        warnings.push(`Option ${optionName(kind)} at offset ${offset} has invalid length ${length}`);
        break;
      }
      if (i + length > bytes.length) {
        warnings.push(`Option ${optionName(kind)} at offset ${offset} claims ${length} bytes but only ${bytes.length - i} remain`);
        break;
      }
      const data = bytes.slice(i + 2, i + length);
      const option = { kind, name: optionName(kind), length, offset, data, detail: "" };
      switch (kind) {
        case 2:
          if (data.length !== 2) warnings.push(`MSS at offset ${offset} has ${data.length} data bytes; expected 2`);
          else {
            option.mss = PH.u16be(data, 0);
            option.detail = `MSS ${option.mss}`;
            if (option.mss === 0) warnings.push(`MSS at offset ${offset} is zero`);
          }
          break;
        case 3:
          if (data.length !== 1) warnings.push(`Window Scale at offset ${offset} has ${data.length} data bytes; expected 1`);
          else {
            option.shift = data[0];
            option.detail = `shift ${option.shift} · window × ${Math.pow(2, Math.min(option.shift, 14))}`;
            if (option.shift > 14) warnings.push(`Window Scale ${option.shift} at offset ${offset} exceeds the maximum useful shift 14`);
          }
          break;
        case 4:
          option.detail = data.length ? `${data.length} unexpected data byte(s)` : "SACK enabled";
          if (data.length) warnings.push(`SACK-permitted at offset ${offset} should have no data`);
          break;
        case 5: {
          const blocks = [];
          for (let j = 0; j + 8 <= data.length; j += 8) {
            blocks.push([PH.u32be(data, j), PH.u32be(data, j + 4)]);
          }
          option.blocks = blocks;
          option.detail = blocks.length + " block(s)" + (data.length % 8 ? " · trailing bytes" : "");
          if (data.length % 8) warnings.push(`SACK at offset ${offset} has a partial block (data length ${data.length})`);
          break;
        }
        case 8:
          if (data.length !== 8) warnings.push(`Timestamp at offset ${offset} has ${data.length} data bytes; expected 8`);
          else {
            option.tsval = PH.u32be(data, 0);
            option.tsecr = PH.u32be(data, 4);
            option.detail = `TSval ${option.tsval} · TSecr ${option.tsecr}`;
          }
          break;
        case 19:
          option.detail = data.length === 16 ? "MD5 digest " + PH.bytesToHex(data) : `${data.length} data byte(s); expected 16-byte digest`;
          if (data.length !== 16) warnings.push(`MD5 option at offset ${offset} should carry 16 data bytes`);
          break;
        case 28:
          if (data.length !== 2) warnings.push(`User Timeout at offset ${offset} has ${data.length} data bytes; expected 2`);
          else {
            const raw = PH.u16be(data, 0);
            option.timeoutGranularity = (raw >> 15) & 1;
            option.timeout = raw & 0x7fff;
            option.detail = `${option.timeout} ${option.timeoutGranularity ? "seconds" : "minutes"} (G=${option.timeoutGranularity})`;
          }
          break;
        case 29:
          if (data.length < 2) warnings.push(`TCP-AO at offset ${offset} is too short`);
          else {
            option.keyid = data[0];
            option.rnext = data[1];
            option.mac = data.subarray(2);
            option.detail = `KeyID ${option.keyid} · RNextKeyID ${option.rnext} · MAC ${option.mac.length} B`;
          }
          break;
        case 30:
          option.subtype = data.length ? (data[0] >> 4) : null;
          option.detail = `MPTCP subtype ${option.subtype == null ? "?" : option.subtype} · ${data.length} data B`;
          break;
        case 34:
          option.cookie = data;
          option.detail = data.length ? `cookie ${data.length} B` : "cookie request";
          if (data.length && (data.length < 4 || data.length > 16 || data.length % 2)) warnings.push(`TFO cookie length ${data.length} is outside the 4–16 even-byte range`);
          break;
        default:
          option.detail = data.length ? `${data.length} data byte(s)` : "no data";
      }
      options.push(option);
      i += length;
    }
    return { options, warnings };
  }

  function extractInput(bytes) {
    let base = 0;
    let ethernet = false;
    let vlan = false;
    if (bytes.length >= 14 && (bytes[0] >> 4) !== 4) {
      const ethertype = PH.u16be(bytes, 12);
      if (ethertype === 0x0800) { base = 14; ethernet = true; }
      else if ((ethertype === 0x8100 || ethertype === 0x88a8) && bytes.length >= 18 && PH.u16be(bytes, 16) === 0x0800) {
        base = 18; ethernet = true; vlan = true;
      }
    }
    const version = bytes.length > base ? bytes[base] >> 4 : null;
    if (version === 4 && bytes.length >= base + 20) {
      const ihl = bytes[base] & 15;
      const ipHeaderLen = ihl * 4;
      const protocol = bytes[base + 9];
      if (ihl >= 5 && protocol === 6 && bytes.length >= base + ipHeaderLen) {
        const flagsWord = PH.u16be(bytes, base + 6);
        const fragmentOffset = flagsWord & 0x1fff;
        if (fragmentOffset > 0) throw new Error("TCP is not present in a non-initial IPv4 fragment");
        const total = PH.u16be(bytes, base + 2);
        const src = PH.ipv4String(bytes, base + 12);
        const dst = PH.ipv4String(bytes, base + 16);
        const end = base + (total || bytes.length);
        return {
          segment: bytes.slice(base + ipHeaderLen, Math.min(end, bytes.length)),
          ipv4: {
            src, dst, protocol, ihl, headerLen: ipHeaderLen, totalLength: total,
            version, checksumOk: PH.checksumValid(bytes.subarray(base, base + ipHeaderLen)),
            packetBytes: bytes.subarray(base, Math.min(end, bytes.length))
          },
          tcpOffset: base + ipHeaderLen,
          ethernet, vlan
        };
      }
    }
    return { segment: bytes, ipv4: null, tcpOffset: 0, ethernet, vlan };
  }

  function decodeSegment(segment, context = {}) {
    if (segment.length < 20) throw new Error("Need at least 20 bytes of TCP header");
    const sport = PH.u16be(segment, 0);
    const dport = PH.u16be(segment, 2);
    const seq = PH.u32be(segment, 4);
    const ack = PH.u32be(segment, 8);
    const dataOffset = segment[12] >> 4;
    const reserved = segment[12] & 15;
    const flags = segment[13];
    const window = PH.u16be(segment, 14);
    const checksum = PH.u16be(segment, 16);
    const urgent = PH.u16be(segment, 18);
    if (dataOffset < 5) throw new Error(`Data Offset is ${dataOffset}; minimum is 5 (20 bytes)`);
    const headerLen = dataOffset * 4;
    if (segment.length < headerLen) throw new Error(`Data Offset says ${headerLen} bytes but only ${segment.length} are available`);
    if (headerLen > 60) throw new Error(`TCP header length ${headerLen} exceeds 60 bytes`);
    const optionsBytes = segment.subarray(20, headerLen);
    const parsed = parseOptions(optionsBytes);
    const warnings = parsed.warnings.slice();
    const payload = segment.subarray(headerLen);
    let checksumStatus = "unverified";
    let expected = null;
    if (context.src && context.dst) {
      const pseudo = buildPseudoHeader(PH.parseIPv4(context.src), PH.parseIPv4(context.dst), segment.length);
      const all = PH.concatBytes(pseudo, segment);
      expected = PH.checksum16(PH.concatBytes(pseudo, segment.subarray(0, 16), new Uint8Array([0, 0]), segment.subarray(18)));
      checksumStatus = PH.checksumValid(all) ? "valid" : "invalid";
      if (checksumStatus === "invalid") warnings.push("TCP checksum does not match the pseudo-header + segment");
    }
    if (reserved !== 0) warnings.push("Reserved nibble is non-zero; compliant receivers should ignore it");
    if (flags & 0x20 && urgent === 0) warnings.push("URG is set but the Urgent Pointer is zero");
    if ((flags & 0x01) && (flags & 0x02)) warnings.push("SYN and FIN are both set; unusual and often probe traffic");
    if (payload.length && (flags & 0x02)) warnings.push("SYN carries payload (TCP Fast Open or a malformed segment)");
    return {
      ok: true, sport, dport, seq, ack, dataOffset, reserved, flags, window, checksum, urgent,
      headerLen, optionsBytes: optionsBytes.length, options: parsed.options, payload,
      checksumStatus, expectedChecksum: expected, warnings, flagNames: flagNames(flags),
      notation: flagsToNotation(flags), context, segment
    };
  }

  function buildExamplePacket() {
    const src = "192.0.2.10";
    const dst = "198.51.100.20";
    const options = "02 04 05 b4 01 03 03 07 04 02 01 01 08 0a 00 00 00 00 00 00 00 00";
    const tcp = buildSegment({
      sport: 49152, dport: 443, seq: 0x1c4f9a02, ack: 0, flags: 0x02,
      window: 64240, urgent: 0, reserved: 0, src, dst, options, payload: ""
    });
    const ip = window.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: 0x1c46, ttl: 64, protocol: 6,
      fragmentOffset: 0, payloadLength: tcp.bytes.length, reserved: false, df: true, mf: false,
      src, dst, options: ""
    });
    return PH.concatBytes(ip.bytes, tcp.bytes);
  }

  window.TCPCodec = {
    buildSegment, extractInput, decodeSegment, parseOptions, buildExamplePacket,
    flagsToByte, flagNames, flagsToNotation, optionName, FLAG_BITS
  };

  /* ---------- field data ---------- */
  const fields = [
    { id: "sport", name: "Source Port", bits: 16, range: "0–65535", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Source port. Together with the source address it identifies the sending socket. Ports 0–1023 are the system range by convention, not a wire rule." },
    { id: "dport", name: "Destination Port", bits: 16, range: "0–65535", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Destination port, used by the receiver to demultiplex the connection. A SYN to port 443 is not necessarily TLS; flags and payload tell the rest of the story." },
    { id: "seq", name: "Sequence Number", bits: 32, range: "0–2³²−1", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Byte-stream sequence number of the first data octet in this segment (or the SYN's initial sequence number). It wraps modulo 2³²; comparisons must account for wrap." },
    { id: "ack", name: "Acknowledgment Number", bits: 32, range: "0–2³²−1", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Next sequence number the sender expects to receive. Meaningful only when ACK is set; the initial SYN carries zero here." },
    { id: "doff", name: "Data Offset", bits: 4, range: "5–15 words", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Length of the TCP header in 32-bit words. Multiply by four for bytes: 5 → 20 B, 15 → 60 B. The option list occupies the difference." },
    { id: "reserved", name: "Reserved", bits: 4, range: "0", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Four reserved bits. RFC 793 had six; CWR and ECE took two. RFC 3540 borrowed one as NS; RFC 8311 deprecated the nonce. Transmitters set zero." },
    { id: "flags", name: "Flags", bits: 8, range: "CWR ECE URG ACK PSH RST SYN FIN", rfc: "RFC 9293 · RFC 3168", rfcUrl: RFC.tcp + "#section-3.1", desc: "The control octet. High to low: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN. Each bit is explained in the flag explorer below." },
    { id: "window", name: "Window", bits: 16, range: "0–65535", rfc: "RFC 9293 · RFC 7323", rfcUrl: RFC.ws + "#section-2", desc: "Receive window advertised by the sender, in bytes before window scaling. The scale shift is negotiated separately and applies to later segments." },
    { id: "checksum", name: "Checksum", bits: 16, range: "0–65535", rfc: "RFC 9293 §3.1 · RFC 1071", rfcUrl: RFC.tcp + "#section-3.1", desc: "One's-complement checksum over an IP pseudo-header, TCP header and payload. This tool verifies it with an IPv4 pseudo-header; an IPv6 pseudo-header is 40 bytes and uses the next-header value instead of the protocol byte." },
    { id: "urgent", name: "Urgent Pointer", bits: 16, range: "0–65535", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "Offset from the sequence number to the last urgent byte. Only meaningful when URG is set; most stacks ignore it. Some middleboxes rewrite it badly." },
    { id: "options", name: "Options", bits: "var", varWidth: 32, range: "0–40 B", rfc: "RFC 9293 §3.1", rfcUrl: RFC.tcp + "#section-3.1", desc: "TLV options: MSS, Window Scale, SACK, timestamps, TFO, MD5 and more. Padded to a 4-byte boundary; Data Offset includes the padding. Drawn here at a nominal 32 bits.", tone: "j" }
  ];

  let diagramController = null;
  let applyFlagByte = null;

  function initDiagram() {
    diagramController = PH.diagram("#tcp-diagram", {
      title: "<b>TCP header</b> · 20–60 bytes",
      badge: "RFC 9293",
      fields,
      inspector: "#tcp-inspector",
      table: "#tcp-fields",
      note: "The flags octet is grouped in this diagram; each bit is interactive in the flag explorer. Options are drawn at a nominal 32 bits; the real list is 0–40 bytes and padded to four."
    });
    PH.fieldTable("#tcp-fields", diagramController, { columns: ["field", "bits", "offset", "range/values", "rfc"] });
  }

  function updateDiagram(r) {
    if (!diagramController) return;
    diagramController.setValues({
      sport: String(r.sport),
      dport: String(r.dport),
      seq: "0x" + PH.hex(r.seq, 8),
      ack: "0x" + PH.hex(r.ack, 8),
      doff: r.dataOffset + " / " + r.headerLen + "B",
      reserved: String(r.reserved),
      flags: flagNames(r.flags).join("+") || "none",
      window: String(r.window),
      checksum: "0x" + PH.hex(r.checksum, 4) + (r.checksumStatus === "valid" ? " ✓" : r.checksumStatus === "invalid" ? " ✗" : ""),
      urgent: String(r.urgent),
      options: r.optionsBytes + " B"
    });
  }

  function setFlagToggles(byte) {
    FLAG_BITS.forEach((f) => {
      const el = document.getElementById("tcp-" + f.key);
      if (el) el.checked = Boolean(byte & f.mask);
    });
    if (applyFlagByte) applyFlagByte();
    const encMap = { cwr: "tcp-enc-flag-cwr", ece: "tcp-enc-flag-ece", urg: "tcp-enc-flag-urg", ack: "tcp-enc-flag-ack", psh: "tcp-enc-flag-psh", rst: "tcp-enc-flag-rst", syn: "tcp-enc-flag-syn", fin: "tcp-enc-flag-fin" };
    Object.keys(encMap).forEach((key) => {
      const el = document.getElementById(encMap[key]);
      const flag = FLAG_BITS.find((f) => f.key === key);
      if (el && flag) el.checked = Boolean(byte & flag.mask);
    });
  }

  /* ---------- flag explorer ---------- */
  function initFlags() {
    const container = document.getElementById("tcp-flag-byte");
    if (!container) return;
    const byteOut = document.getElementById("tcp-flag-byte");
    const notationOut = document.getElementById("tcp-flag-notation");
    const namesOut = document.getElementById("tcp-flag-names");

    function readByte() {
      let byte = 0;
      FLAG_BITS.forEach((f) => {
        const el = document.getElementById("tcp-" + f.key);
        if (el && el.checked) byte |= f.mask;
      });
      return byte;
    }
    function update() {
      const byte = readByte();
      byteOut.textContent = "0x" + PH.hex(byte, 2);
      notationOut.textContent = flagsToNotation(byte);
      namesOut.textContent = flagNames(byte).join("+") || "none";
      if (diagramController) diagramController.setValues({ flags: flagNames(byte).join("+") || "none" });
    }
    applyFlagByte = update;
    FLAG_BITS.forEach((f) => {
      const el = document.getElementById("tcp-" + f.key);
      if (el) el.addEventListener("change", update);
    });
    document.querySelectorAll("[data-tcp-flags]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const names = btn.getAttribute("data-tcp-flags").split(",").filter(Boolean);
        let byte = 0;
        FLAG_BITS.forEach((f) => { if (names.includes(f.name)) byte |= f.mask; });
        FLAG_BITS.forEach((f) => {
          const el = document.getElementById("tcp-" + f.key);
          if (el) el.checked = Boolean(byte & f.mask);
        });
        update();
      });
    });
    update();
  }

  /* ---------- encoder ---------- */
  function readEncoder() {
    const num = (id, label) => {
      const v = PH.parseNumber(document.getElementById(id).value);
      if (v == null) throw new Error(label + " is not a number");
      return v;
    };
    return {
      sport: num("tcp-enc-sport", "Source port"),
      dport: num("tcp-enc-dport", "Destination port"),
      seq: num("tcp-enc-seq", "Sequence number"),
      ack: num("tcp-enc-ackno", "Acknowledgment number"),
      window: num("tcp-enc-window", "Window"),
      urgent: num("tcp-enc-urgent", "Urgent pointer"),
      reserved: num("tcp-enc-reserved", "Reserved"),
      options: document.getElementById("tcp-enc-options").value,
      payload: document.getElementById("tcp-enc-payload").value,
      src: document.getElementById("tcp-enc-src").value,
      dst: document.getElementById("tcp-enc-dst").value,
      flags: FLAG_BITS.reduce((byte, f) => {
        const el = document.getElementById("tcp-enc-flag-" + f.key);
        return el && el.checked ? byte | f.mask : byte;
      }, 0)
    };
  }

  function buildFromForm(showErrors = true) {
    const status = document.getElementById("tcp-encode-status");
    const output = document.getElementById("tcp-enc-output");
    const summary = document.getElementById("tcp-enc-summary");
    const tag = document.getElementById("tcp-enc-summary-tag");
    let r;
    try { r = buildSegment(readEncoder()); }
    catch (err) {
      if (showErrors) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(r.bytes);
    output.classList.remove("placeholder");
    summary.innerHTML = [
      `<span class="pill ${r.pseudoHeader ? "pill--good" : "pill--warn"}">${r.pseudoHeader ? "checksum 0x" + PH.hex(r.checksum, 4) : "checksum 0x0000 (no IPs)"}</span>`,
      `<span class="pill">header <b>${r.headerLen} B</b></span>`,
      `<span class="pill">data offset <b>${r.dataOffset}</b></span>`,
      `<span class="pill">options <b>${r.optionsBytes} B</b>${r.optionsPadded !== r.optionsBytes ? " (padded)" : ""}</span>`,
      `<span class="pill">payload <b>${r.payload.length} B</b></span>`,
      `<span class="pill">flags <b>${flagsToNotation(r.flags)}</b></span>`
    ].join("");
    tag.textContent = `${r.bytes.length} bytes`;
    PH.setStatus(status, `built ${r.headerLen}-byte TCP header + ${r.payload.length} B payload · ${r.pseudoHeader ? "checksum 0x" + PH.hex(r.checksum, 4) + " from " + r.src + " → " + r.dst : "checksum left zero (no IPv4 addresses)"}`, r.pseudoHeader ? "ok" : "warn");
    updateDiagram({
      sport: r.sport, dport: r.dport, seq: r.seq, ack: r.ack, dataOffset: r.dataOffset,
      headerLen: r.headerLen, reserved: r.reserved, flags: r.flags, window: r.window,
      checksum: r.checksum, checksumStatus: r.pseudoHeader ? "valid" : "unverified", urgent: r.urgent,
      optionsBytes: r.optionsBytes
    });
    setFlagToggles(r.flags);
    return r;
  }

  function initEncoder() {
    document.getElementById("tcp-build").addEventListener("click", () => buildFromForm());
    document.querySelectorAll("[data-tcp-opt]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("tcp-enc-options").value = btn.getAttribute("data-tcp-opt");
        buildFromForm(false);
      });
    });
    document.getElementById("tcp-load-example").addEventListener("click", () => {
      document.getElementById("tcp-enc-sport").value = "49152";
      document.getElementById("tcp-enc-dport").value = "443";
      document.getElementById("tcp-enc-seq").value = "0x1c4f9a02";
      document.getElementById("tcp-enc-ackno").value = "0";
      document.getElementById("tcp-enc-window").value = "64240";
      document.getElementById("tcp-enc-urgent").value = "0";
      document.getElementById("tcp-enc-reserved").value = "0";
      document.getElementById("tcp-enc-options").value = "02 04 05 b4 01 03 03 07 04 02 01 01 08 0a 00 00 00 00 00 00 00 00";
      document.getElementById("tcp-enc-payload").value = "";
      document.getElementById("tcp-enc-src").value = "192.0.2.10";
      document.getElementById("tcp-enc-dst").value = "198.51.100.20";
      setFlagToggles(0x02);
      buildFromForm();
    });
    ["tcp-enc-sport", "tcp-enc-dport", "tcp-enc-seq", "tcp-enc-ackno", "tcp-enc-window", "tcp-enc-urgent", "tcp-enc-reserved", "tcp-enc-src", "tcp-enc-dst"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", () => buildFromForm(false));
    });
    buildFromForm(false);
  }

  /* ---------- decoder ---------- */
  function renderDecoded(r, context) {
    const host = document.getElementById("tcp-decode-result");
    const pills = [
      `<span class="pill">${context.ipv4 ? "IPv4 packet" : "raw TCP segment"}</span>`,
      `<span class="pill">${r.sport} → ${r.dport}</span>`,
      `<span class="pill">flags <b>${PH.esc(r.notation)}</b></span>`,
      `<span class="pill">header <b>${r.headerLen} B</b></span>`,
      `<span class="pill">payload <b>${r.payload.length} B</b></span>`,
      `<span class="pill">options <b>${r.optionsBytes} B</b></span>`,
      `<span class="pill ${r.checksumStatus === "valid" ? "pill--good" : r.checksumStatus === "invalid" ? "pill--bad" : "pill--warn"}">checksum ${r.checksumStatus}</span>`
    ];
    if (context.ipv4) pills.push(`<span class="pill">${PH.esc(context.ipv4.src)} → ${PH.esc(context.ipv4.dst)}</span>`);
    if (context.ethernet) pills.push(`<span class="pill">Ethernet${context.vlan ? " + VLAN" : ""}</span>`);

    const rows = [
      ["Source Port", "16", "0–15", String(r.sport), ""],
      ["Destination Port", "16", "16–31", String(r.dport), ""],
      ["Sequence Number", "32", "32–63", "0x" + PH.hex(r.seq, 8), String(r.seq)],
      ["Acknowledgment Number", "32", "64–95", "0x" + PH.hex(r.ack, 8), r.flags & 0x10 ? String(r.ack) : "ACK not set"],
      ["Data Offset", "4", "96–99", `${r.dataOffset} (${r.headerLen} B)`, "units of 4 bytes"],
      ["Reserved", "4", "100–103", String(r.reserved), r.reserved ? "should be zero" : ""],
      ["Flags", "8", "104–111", `0x${PH.hex(r.flags, 2)} · ${flagNames(r.flags).join("+") || "none"}`, r.notation],
      ["Window", "16", "112–127", String(r.window), ""],
      ["Checksum", "16", "128–143", `0x${PH.hex(r.checksum, 4)} · ${r.checksumStatus}`, r.expectedChecksum != null ? "expected 0x" + PH.hex(r.expectedChecksum, 4) : "needs IPv4 pseudo-header"],
      ["Urgent Pointer", "16", "144–159", String(r.urgent), r.flags & 0x20 ? "URG set" : "URG not set"],
      ["Options", String(r.optionsBytes * 8), r.optionsBytes ? `160–${159 + r.optionsBytes * 8}` : "—", `${r.optionsBytes} B`, r.optionsBytes ? "parsed below" : "none"]
    ];
    const table = rows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    let optionsHtml = "";
    if (r.options.length) {
      optionsHtml = '<div class="decoded-head"><h3>option TLVs</h3><span class="dim">offset relative to the TCP header</span></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Offset</th><th>Kind</th><th>Name</th><th class="num">Length</th><th>Data</th><th>Decoded</th></tr></thead><tbody>' +
        r.options.map((o) =>
          `<tr><td class="num">${20 + o.offset}</td><td><code>${o.kind}</code></td><td><b>${PH.esc(o.name)}</b></td><td class="num">${o.length}</td><td><code>${o.data.length ? PH.bytesToHex(o.data) : "—"}</code></td><td class="small">${PH.esc(o.detail)}</td></tr>`
        ).join("") + "</tbody></table></div>";
    }

    const ctxHtml = context.ipv4
      ? `<div class="callout" style="margin-top:14px"><div class="callout__title">enclosing IPv4 packet</div><p>${PH.esc(context.ipv4.src)} → ${PH.esc(context.ipv4.dst)} · IHL ${context.ipv4.ihl} (${context.ipv4.headerLen} B) · IP total ${context.ipv4.totalLength} B · protocol 6 (TCP) · IP checksum ${context.ipv4.checksumOk ? "valid" : "invalid"}. The TCP checksum was verified with this pseudo-header.</p></div>`
      : `<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">checksum not verified</div><p>This looks like a raw TCP segment, so the IPv4 pseudo-header is unavailable. The checksum field is shown but cannot be validated. Paste a full IPv4 packet (or use the example) to verify it.</p></div>`;

    const warningHtml = r.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + r.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : "";

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>TCP segment bytes</span><span>${r.segment.length} B · ${r.headerLen} B header</span></div>${PH.hexdump(r.segment, { highlight: [{ start: 0, end: r.headerLen }] })}</div>` +
      `<div class="decoded-head"><h3>header fields</h3><span class="dim">offsets relative to the TCP header</span></div>` +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${table}</tbody></table></div>` +
      optionsHtml + ctxHtml + warningHtml;
  }

  function initDecoder() {
    const input = document.getElementById("tcp-decode-input");
    const status = document.getElementById("tcp-decode-status");
    const host = document.getElementById("tcp-decode-result");
    if (!input) return;

    function run(showErrors = true) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      let extracted;
      try { extracted = extractInput(bytes); }
      catch (err) {
        if (showErrors) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      let r;
      try {
        r = decodeSegment(extracted.segment, {
          src: extracted.ipv4 ? extracted.ipv4.src : null,
          dst: extracted.ipv4 ? extracted.ipv4.dst : null
        });
      } catch (err) {
        if (showErrors) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      const context = { ipv4: extracted.ipv4, ethernet: extracted.ethernet, vlan: extracted.vlan };
      renderDecoded(r, context);
      updateDiagram(r);
      setFlagToggles(r.flags);
      PH.setStatus(status,
        `decoded ${r.headerLen} B TCP header · ${r.payload.length} B payload · ${r.notation} · checksum ${r.checksumStatus}${r.warnings.length ? " · " + r.warnings.length + " note(s)" : ""}`,
        r.checksumStatus === "invalid" ? "bad" : (r.warnings.length || r.checksumStatus === "unverified" ? "warn" : "ok"));
    }

    document.getElementById("tcp-decode").addEventListener("click", () => run());
    document.getElementById("tcp-decode-example").addEventListener("click", () => {
      input.value = PH.bytesToHex(buildExamplePacket());
      run();
    });
    document.getElementById("tcp-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No input decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
  }

  function initLifecycle() {
    const flow = document.getElementById("tcp-flow");
    if (!flow) return;

    const caption = document.getElementById("tcp-flow-caption");
    const state = document.getElementById("tcp-flow-state");
    const table = document.getElementById("tcp-flow-table");
    const clientState = document.getElementById("tcp-node-client-state");
    const serverState = document.getElementById("tcp-node-server-state");
    const clientNode = flow.querySelector('[data-node="client"]');
    const serverNode = flow.querySelector('[data-node="server"]');
    const rows = Array.from(flow.querySelectorAll("[data-row]"));
    const tokens = Array.from(flow.querySelectorAll("[data-token]"));
    const loss = flow.querySelector("[data-loss]");

    function applyStep(index) {
      const step = TCP_STEPS[index - 1];
      caption.innerHTML = step.caption;
      clientState.textContent = step.client;
      serverState.textContent = step.server;
      state.textContent = step.state;
      state.className = step.stateClass;
      table.innerHTML =
        `<tr><td>client</td><td>${step.client}</td></tr>` +
        `<tr><td>server</td><td>${step.server}</td></tr>` +
        `<tr><td>segment</td><td>${step.segment}</td></tr>`;

      rows.forEach((row, i) => {
        const number = i + 1;
        row.classList.toggle("is-done", number < index);
        row.classList.toggle("is-active", number === index);
      });

      clientNode.classList.toggle("is-active", step.active.includes("client"));
      clientNode.classList.toggle("is-match", step.match.includes("client"));
      serverNode.classList.toggle("is-active", step.active.includes("server"));
      serverNode.classList.toggle("is-match", step.match.includes("server"));

      tokens.forEach((token, i) => {
        const number = i + 1;
        if (number <= index) {
          token.style.transform = `translate(${TCP_TOKEN_TARGET[number][0]}px, ${TCP_TOKEN_TARGET[number][1]}px)`;
          token.classList.add("is-visible");
          if (number === 4) token.classList.toggle("is-lost", index >= 4);
        } else {

          token.classList.remove("is-visible");
          token.classList.remove("is-lost");
          token.style.transform = `translate(${TCP_TOKEN_HOME[number][0]}px, ${TCP_TOKEN_HOME[number][1]}px)`;
        }
      });

      loss.classList.toggle("is-visible", index >= 4);
    }

    PH.stepFlow({ root: flow, count: TCP_STEPS.length, onStep: applyStep });
  }

  function init() {
    if (!document.getElementById("tcp-diagram")) return;
    initDiagram();
    initFlags();
    initEncoder();
    initDecoder();
    initLifecycle();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
