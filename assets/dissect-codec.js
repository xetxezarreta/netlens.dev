/* Cross-layer packet dissector. Walks Ethernet → VLAN → IPv4/IPv6 → TCP/UDP/ICMP
   → application payload, producing a flat list of annotated layers.

   It is intentionally defensive: every layer is parsed inside a try/catch and a
   malformed layer becomes an error node instead of aborting the whole walk. */
(function (global) {
  "use strict";

  const PH = global.PH;

  const ETHERTYPES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x8100: "802.1Q", 0x86dd: "IPv6",
    0x88a8: "802.1ad", 0x8847: "MPLS", 0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session", 0x8035: "RARP", 0x809b: "AppleTalk"
  };

  const IP_PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 4: "IPv4-in-IPv4", 6: "TCP", 17: "UDP", 41: "IPv6",
    43: "IPv6-Route", 44: "IPv6-Fragment", 47: "GRE", 50: "ESP", 51: "AH",
    58: "ICMPv6", 59: "No Next Header", 60: "IPv6-Destination", 89: "OSPF",
    103: "PIM", 112: "VRRP", 132: "SCTP", 136: "UDP-Lite", 137: "MPLS-in-IP"
  };

  const TLS_CONTENT = { 20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat" };
  const TLS_HANDSHAKE = { 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished", 24: "KeyUpdate" };

  function nameForProtocol(number) { return IP_PROTOCOLS[number] || ("protocol " + number); }
  function nameForEtherType(type) { return ETHERTYPES[type] || ("0x" + PH.hex(type, 4)); }

  function layer(spec) {
    return Object.assign({
      proto: "unknown", name: "Unknown", offset: 0, length: 0, summary: "",
      fields: [], warnings: [], depth: 0, href: "", error: null
    }, spec);
  }

  function field(name, value, note) {
    return { name, value: value == null ? "—" : String(value), note: note || "" };
  }

  function mac(bytes) {
    const codec = global.EthernetCodec;
    if (codec) return codec.macString(bytes);
    return Array.from(bytes).map((b) => PH.hex(b)).join(":");
  }

  function pushWarning(state, message) {
    if (message && state.warnings.indexOf(message) === -1) state.warnings.push(message);
  }

  function serviceLabel(port) {
    if (global.UDPCodec) return global.UDPCodec.portLabel(port);
    return String(port);
  }

  /* ---------- application heuristics ---------- */

  function looksLikeDns(bytes) {
    if (!bytes || bytes.length < 12) return false;
    if (!global.DNSCodec) return false;
    try {
      const message = global.DNSCodec.decodeMessage(bytes, { allowLarge: true });
      const severe = message.warnings.some((warning) =>
        /runs past|truncated|extends past|declares RDLENGTH|Unsupported label|Compression pointer|count says|Record .*truncated/i.test(warning));
      if (severe) return false;
      if (message.counts.questions > 8 || message.counts.answers > 128 ||
          message.counts.authority > 128 || message.counts.additional > 128) return false;
      return message.questions.length > 0 || message.answers.length > 0 ||
        message.authority.length > 0 || message.additional.length > 0 ||
        message.flags.qr === 1;
    } catch (_) { return false; }
  }

  function dnsLayer(bytes, offset, state, depth) {
    const message = global.DNSCodec.decodeMessage(bytes, { allowLarge: true });
    message.warnings.slice(0, 8).forEach((warning) => pushWarning(state, "DNS: " + warning));
    const first = message.questions[0];
    const qname = first ? first.name + " " + first.typeName : "no question";
    const answerCount = message.counts.answers;
    const summary = "DNS " + (message.header.qr ? "response" : "query") + " · " +
      message.header.opcodeName + " · " + message.header.effectiveRcodeName + " · " +
      answerCount + " answer(s) · " + qname;
    const fields = [
      field("Transaction ID", "0x" + PH.hex(message.id, 4)),
      field("QR", message.header.qr ? "1 · response" : "0 · query"),
      field("Opcode", message.header.opcode + " · " + message.header.opcodeName),
      field("AA / TC / RD", [message.header.aa, message.header.tc, message.header.rd].join(" / ")),
      field("RA / AD / CD", [message.header.ra, message.header.ad, message.header.cd].join(" / ")),
      field("RCODE", message.header.effectiveRcode + " · " + message.header.effectiveRcodeName),
      field("QDCOUNT", message.counts.questions),
      field("ANCOUNT", message.counts.answers),
      field("NSCOUNT", message.counts.authority),
      field("ARCOUNT", message.counts.additional)
    ];
    message.questions.slice(0, 4).forEach((question, index) => {
      fields.push(field("Question " + (index + 1), question.name + " " + question.typeName + " " + question.className));
    });
    message.answers.slice(0, 4).forEach((record, index) => {
      fields.push(field("Answer " + (index + 1), record.name + " " + record.typeName + " " + (record.rdata ? record.rdata.value : "")));
    });
    if (message.opt) fields.push(field("EDNS(0)", "UDP payload " + message.opt.udpPayloadSize + " B" + (message.opt.do ? " · DO" : "")));
    return layer({
      proto: "dns", name: "DNS", offset, length: bytes.length, summary, fields,
      warnings: message.warnings.slice(), depth, href: "dns.html",
      meta: { message }
    });
  }

  function looksLikeTls(bytes) {
    if (!bytes || bytes.length < 5) return false;
    const type = bytes[0];
    const major = bytes[1];
    const length = PH.u16be(bytes, 3);
    return type >= 20 && type <= 24 && major === 3 && length <= bytes.length - 5;
  }

  function tlsLayer(bytes, offset, state, depth) {
    if (global.TLSCodec && looksLikeTls(bytes)) {
      try {
        const decoded = global.TLSCodec.decodeTls(bytes);
        decoded.warnings.slice(0, 8).forEach((warning) => pushWarning(state, "TLS: " + warning));
        const fields = [
          field("Records", decoded.records.length + " · " + decoded.records.map((record) => record.typeName).join(", ")),
          field("Handshakes", decoded.handshakes.length
            ? decoded.handshakes.map((message) => message.typeName).join(" → ")
            : "none in plaintext")
        ];
        if (decoded.context.negotiatedVersion) {
          fields.push(field("Negotiated version", global.TLSCodec.versionName(decoded.context.negotiatedVersion)));
        } else if (decoded.context.clientVersions && decoded.context.clientVersions.length) {
          fields.push(field("Offered versions", decoded.context.clientVersions.map((code) => global.TLSCodec.versionName(code)).join(", ")));
        }
        if (decoded.context.sni) fields.push(field("SNI", decoded.context.sni));
        if (decoded.context.alpn) fields.push(field("ALPN", decoded.context.alpn.join(", ")));
        if (decoded.context.cipherSuite != null) fields.push(field("Cipher suite", global.TLSCodec.cipherName(decoded.context.cipherSuite)));
        if (decoded.alerts.length) fields.push(field("Alert", decoded.alerts[0].summary));
        if (decoded.records.some((record) => record.type === 23)) {
          fields.push(field("Encrypted", decoded.records.filter((record) => record.type === 23).length + " application-data record(s)"));
        }
        return layer({
          proto: "tls", name: "TLS", offset,
          length: Math.min(decoded.length || bytes.length, bytes.length),
          summary: decoded.summary, fields,
          warnings: decoded.warnings.slice(0, 8), depth, href: "tls.html",
          meta: { decoded }
        });
      } catch (err) {
        pushWarning(state, "TLS decode failed: " + err.message);
      }
    }
    const records = [];
    let position = 0;
    let guard = 0;
    while (position + 5 <= bytes.length && guard++ < 24) {
      const type = bytes[position];
      const major = bytes[position + 1];
      const minor = bytes[position + 2];
      const length = PH.u16be(bytes, position + 3);
      if (major !== 3 || TLS_CONTENT[type] == null) break;
      records.push({ type, version: major + "." + minor, length, offset: position });
      position += 5 + length;
      if (position > bytes.length) { pushWarning(state, "TLS record length overruns the captured payload"); break; }
    }
    if (!records.length) return null;
    const first = records[0];
    let handshake = "";
    if (first.type === 22 && bytes.length > 5) handshake = " · " + (TLS_HANDSHAKE[bytes[5]] || "handshake type " + bytes[5]);
    const fields = records.map((record, index) => field("Record " + (index + 1),
      TLS_CONTENT[record.type] + " · TLS " + record.version + " · " + record.length + " B"));
    fields.push(field("Records", records.length + " · " + position + " B parsed"));
    return layer({
      proto: "tls", name: "TLS", offset, length: Math.min(position, bytes.length),
      summary: "TLS " + first.version + " · " + TLS_CONTENT[first.type] + handshake + " · " + records.length + " record(s)",
      fields, warnings: [], depth, href: "tls.html"
    });
  }

  function httpLayer(bytes, offset, state, depth, hint) {
    const app = hint || {};
    if (global.HTTPCodec) {
      const preface = bytes.length >= global.HTTPCodec.H2_PREFACE.length &&
        global.HTTPCodec.asciiString(bytes.subarray(0, global.HTTPCodec.H2_PREFACE.length)) === global.HTTPCodec.H2_PREFACE;
      const h1 = global.HTTPCodec.looksLikeHttp1(bytes);
      const h2 = preface || (app.http && global.HTTPCodec.looksLikeHttp2(bytes));
      if (h1 || h2) {
        try {
          const decoded = global.HTTPCodec.decodeHttpMessage(bytes, { kind: preface ? "h2" : "auto" });
          decoded.warnings.slice(0, 8).forEach((warning) => pushWarning(state, "HTTP: " + warning));
          const fields = [];
          if (decoded.kind === "h1") {
            fields.push(field("Start line", decoded.startLine));
            fields.push(field("Headers", decoded.headers.length));
            fields.push(field("Framing", decoded.framing));
            fields.push(field("Body", decoded.body.length + " B" + (decoded.chunked ? " · " + decoded.chunks.length + " chunk(s)" : "")));
          } else if (decoded.kind === "h2") {
            fields.push(field("Preface", decoded.preface ? "client connection preface" : "absent"));
            fields.push(field("Frames", decoded.frames.length + " · " + decoded.frames.map((frame) => frame.typeName).join(", ")));
            fields.push(field("Header fields", decoded.headerCount));
            fields.push(field("HPACK", decoded.hpack.dynamicCount + " dynamic entr" + (decoded.hpack.dynamicCount === 1 ? "y" : "ies")));
          }
          return layer({
            proto: "http", name: decoded.kind === "h2" ? "HTTP/2" : "HTTP", offset,
            length: Math.min(decoded.messageLength || decoded.length || bytes.length, bytes.length),
            summary: decoded.summary, fields,
            warnings: decoded.warnings.slice(0, 8), depth, href: "http.html",
            meta: { decoded }
          });
        } catch (err) {
          pushWarning(state, "HTTP decode failed: " + err.message);
        }
      }
    }
    const preview = PH.bytesToAscii(bytes.subarray(0, Math.min(bytes.length, 96)));
    const firstLine = preview.split(/\r?\n/)[0];
    if (!/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|HTTP\/\d\.\d)\b/.test(firstLine)) return null;
    const request = /^[A-Z]+ /.test(firstLine);
    return layer({
      proto: "http", name: "HTTP", offset, length: bytes.length,
      summary: (request ? "HTTP request · " : "HTTP response · ") + firstLine,
      fields: [field("Start line", firstLine), field("Body", bytes.length + " B captured")],
      warnings: [], depth, href: "http.html"
    });
  }

  function sshLayer(bytes, offset, depth) {
    const preview = PH.bytesToAscii(bytes.subarray(0, Math.min(bytes.length, 64)));
    if (!/^SSH-/.test(preview)) return null;
    return layer({
      proto: "ssh", name: "SSH", offset, length: bytes.length,
      summary: "SSH version exchange · " + preview.split(/\r?\n/)[0],
      fields: [field("Identification", preview.split(/\r?\n/)[0])], warnings: [], depth
    });
  }

  function bgpLayer(bytes, offset, state, depth) {
    const marker = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF";
    if (bytes.length < 19 || PH.bytesToHex(bytes.subarray(0, 16)) !== marker) return null;
    const length = PH.u16be(bytes, 16);
    const type = bytes[18];
    const names = { 1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH" };
    if (length < 19) pushWarning(state, "BGP message length " + length + " is below the 19-byte minimum");
    return layer({
      proto: "bgp", name: "BGP", offset, length: Math.min(length, bytes.length),
      summary: "BGP " + (names[type] || "type " + type) + " · " + length + " B",
      fields: [field("Marker", "16 × 0xFF"), field("Length", length), field("Type", type + " · " + (names[type] || "unknown"))],
      warnings: length !== bytes.length ? ["BGP Length and captured bytes differ"] : [],
      depth, href: "bgp.html"
    });
  }

  function quicLayer(bytes, offset, depth) {
    if (bytes.length < 7) return null;
    const first = bytes[0];
    const longHeader = (first & 0x80) !== 0;
    let summary = "";
    if (longHeader) {
      const version = PH.u32be(bytes, 1);
      const types = { 0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry" };
      summary = "QUIC long header · " + (types[(first >> 4) & 3] || "type " + ((first >> 4) & 3)) +
        " · version 0x" + PH.hex(version, 8);
      return layer({
        proto: "quic", name: "QUIC", offset, length: bytes.length, summary,
        fields: [field("Header form", "Long"), field("Version", "0x" + PH.hex(version, 8))],
        warnings: [], depth, href: "quic.html"
      });
    }
    if (!global.UDPCodec) return null;
    return layer({
      proto: "quic", name: "QUIC", offset, length: bytes.length,
      summary: "QUIC short header · encrypted payload",
      fields: [field("Header form", "Short"), field("DCID length", "1–20 bytes by local agreement")],
      warnings: [], depth, href: "quic.html"
    });
  }

  function applicationLayer(bytes, offset, state, depth, hint) {
    if (!bytes || bytes.length === 0) return null;
    const app = hint || {};
    if (app.dns) {
      try {
        return dnsLayer(bytes, offset, state, depth);
      } catch (err) {
        pushWarning(state, "DNS decode failed: " + err.message);
      }
    }
    if (app.tls) {
      const tls = tlsLayer(bytes, offset, state, depth);
      if (tls) return tls;
    }
    if (looksLikeDns(bytes)) {
      try {
        return dnsLayer(bytes, offset, state, depth);
      } catch (err) {
        pushWarning(state, "DNS decode failed: " + err.message);
      }
    }
    if (looksLikeTls(bytes)) {
      const tls = tlsLayer(bytes, offset, state, depth);
      if (tls) return tls;
    }
    const http = httpLayer(bytes, offset, state, depth, { http: app.http, h2: app.h2 });
    if (http) return http;
    const ssh = sshLayer(bytes, offset, depth);
    if (ssh) return ssh;
    const bgp = bgpLayer(bytes, offset, state, depth);
    if (bgp) return bgp;
    if (app.quic) {
      const quic = quicLayer(bytes, offset, depth);
      if (quic) return quic;
    }
    return null;
  }

  function unknownPayload(bytes, offset, state, depth, note) {
    if (!bytes || bytes.length === 0) return null;
    const preview = bytes.length <= 16 ? PH.bytesToHex(bytes) : PH.bytesToHex(bytes.subarray(0, 16)) + " …";
    return layer({
      proto: "payload", name: "Payload", offset, length: bytes.length,
      summary: bytes.length + " B" + (note ? " · " + note : " · no decoder"),
      fields: [field("Length", bytes.length + " B"), field("First bytes", preview)],
      warnings: [], depth
    });
  }

  /* ---------- transport ---------- */

  function decodeTcp(bytes, offset, state, depth, context) {
    const checksumContext = context && context.ipVersion === 4 ? { src: context.src, dst: context.dst } : {};
    const parsed = global.TCPCodec.decodeSegment(bytes, checksumContext);
    parsed.warnings.forEach((warning) => pushWarning(state, "TCP: " + warning));
    const fields = [
      field("Source port", parsed.sport + " · " + serviceLabel(parsed.sport)),
      field("Destination port", parsed.dport + " · " + serviceLabel(parsed.dport)),
      field("Sequence", parsed.seq),
      field("Acknowledgment", parsed.ack),
      field("Flags", parsed.notation + " · " + parsed.flagNames.join(" ")),
      field("Window", parsed.window),
      field("Checksum", "0x" + PH.hex(parsed.checksum, 4) + " · " + parsed.checksumStatus),
      field("Data offset", parsed.headerLen + " B"),
      field("Options", parsed.optionsBytes + " B")
    ];
    const result = [layer({
      proto: "tcp", name: "TCP", offset, length: parsed.headerLen,
      summary: parsed.sport + " → " + parsed.dport + " · " + (parsed.notation || "no flags") +
        " · seq " + parsed.seq + " · " + parsed.payload.length + " B payload",
      fields, warnings: parsed.warnings.slice(), depth, href: "tcp.html", meta: { parsed }
    })];
    const payloadOffset = offset + parsed.headerLen;
    let payload = parsed.payload;
    if (payload.length && (parsed.sport === 53 || parsed.dport === 53)) {
      const prefixed = PH.u16be(payload, 0);
      if (prefixed + 2 <= payload.length) {
        const dnsBytes = payload.subarray(2, 2 + prefixed);
        const dns = applicationLayer(dnsBytes, payloadOffset + 2, state, depth + 1, { dns: true });
        if (dns) {
          dns.fields.unshift(field("TCP length prefix", prefixed + " B" + (prefixed + 2 !== payload.length ? " · " + (payload.length - 2 - prefixed) + " trailing byte(s)" : "")));
          result.push(dns);
          return result;
        }
      }
    }
    const app = applicationLayer(payload, payloadOffset, state, depth + 1, {
      tls: parsed.sport === 443 || parsed.dport === 443,
      http: parsed.sport === 80 || parsed.dport === 80 || parsed.sport === 8080 || parsed.dport === 8080 ||
        parsed.sport === 8000 || parsed.dport === 8000,
      quic: false
    });
    if (app) result.push(app);
    else {
      const payloadLayer = unknownPayload(payload, payloadOffset, state, depth + 1, "TCP payload");
      if (payloadLayer) result.push(payloadLayer);
    }
    return result;
  }

  function decodeUdp(bytes, offset, state, depth, context) {
    const parsed = global.UDPCodec.decodeUdp(bytes, context || {});
    parsed.warnings.forEach((warning) => pushWarning(state, "UDP: " + warning));
    const fields = [
      field("Source port", parsed.srcPort + " · " + serviceLabel(parsed.srcPort)),
      field("Destination port", parsed.dstPort + " · " + serviceLabel(parsed.dstPort)),
      field("Length", parsed.length + " B · " + parsed.payloadLength + " B payload"),
      field("Checksum", "0x" + PH.hex(parsed.checksum, 4) + " · " + parsed.checksumState)
    ];
    const result = [layer({
      proto: "udp", name: "UDP", offset, length: Math.min(parsed.length || 8, parsed.bytes.length),
      summary: parsed.srcPort + " → " + parsed.dstPort + " · " + parsed.length + " B · checksum " + parsed.checksumState,
      fields, warnings: parsed.warnings.slice(), depth, href: "udp.html", meta: { parsed }
    })];
    const app = applicationLayer(parsed.payload, offset + 8, state, depth + 1, {
      dns: parsed.srcPort === 53 || parsed.dstPort === 53 || parsed.srcPort === 5353 || parsed.dstPort === 5353,
      quic: parsed.srcPort === 443 || parsed.dstPort === 443
    });
    if (app) result.push(app);
    else {
      const payloadLayer = unknownPayload(parsed.payload, offset + 8, state, depth + 1, "UDP payload");
      if (payloadLayer) result.push(payloadLayer);
    }
    return result;
  }

  function decodeIcmpv4(bytes, offset, state, depth) {
    const parsed = global.ICMPCodec.decodeIcmp(bytes);
    parsed.warnings.forEach((warning) => pushWarning(state, "ICMP: " + warning));
    const fields = [
      field("Type", parsed.type + (parsed.typeName ? " · " + parsed.typeName : "")),
      field("Code", parsed.code + (parsed.codeName ? " · " + parsed.codeName : "")),
      field("Checksum", "0x" + PH.hex(parsed.checksum, 4) + (parsed.checksumOk ? " · valid" : " · invalid")),
      field("Payload", parsed.data.length + " B")
    ];
    return [layer({
      proto: "icmp", name: "ICMP", offset, length: bytes.length,
      summary: "ICMP " + (parsed.typeName || "type " + parsed.type) +
        (parsed.codeName ? " · " + parsed.codeName : "") + " · " + bytes.length + " B",
      fields, warnings: parsed.warnings.slice(), depth, href: "icmp.html", meta: { parsed }
    })];
  }

  function decodeIcmpv6(bytes, offset, state, depth) {
    if (!bytes || bytes.length < 4) {
      return [layer({ proto: "icmpv6", name: "ICMPv6", offset, length: bytes ? bytes.length : 0,
        summary: "ICMPv6 · truncated", fields: [], warnings: ["ICMPv6 needs at least 4 bytes"], depth, href: "ipv6.html" })];
    }
    const codec = global.IPv6Codec;
    const names = codec ? codec.ICMPV6_TYPES : {};
    const type = bytes[0];
    const code = bytes[1];
    const fields = [
      field("Type", type + (names[type] ? " · " + names[type] : "")),
      field("Code", code),
      field("Checksum", "0x" + PH.hex(PH.u16be(bytes, 2), 4)),
      field("Payload", Math.max(0, bytes.length - 4) + " B")
    ];
    return [layer({
      proto: "icmpv6", name: "ICMPv6", offset, length: bytes.length,
      summary: "ICMPv6 " + (names[type] || "type " + type) + " · " + bytes.length + " B",
      fields, warnings: [], depth, href: "ipv6.html"
    })];
  }

  function decodeTransport(nextHeader, bytes, offset, state, depth, context, family) {
    if (nextHeader === 6) {
      try { return decodeTcp(bytes, offset, state, depth, context); }
      catch (err) { return [layer({ proto: "tcp", name: "TCP", offset, length: bytes.length, summary: "TCP decode failed", fields: [], warnings: [err.message], depth, href: "tcp.html", error: err.message })]; }
    }
    if (nextHeader === 17) {
      try { return decodeUdp(bytes, offset, state, depth, context); }
      catch (err) { return [layer({ proto: "udp", name: "UDP", offset, length: bytes.length, summary: "UDP decode failed", fields: [], warnings: [err.message], depth, href: "udp.html", error: err.message })]; }
    }
    if (nextHeader === 1 && family === 4) {
      try { return decodeIcmpv4(bytes, offset, state, depth); }
      catch (err) { return [layer({ proto: "icmp", name: "ICMP", offset, length: bytes.length, summary: "ICMP decode failed", fields: [], warnings: [err.message], depth, href: "icmp.html", error: err.message })]; }
    }
    if (nextHeader === 58 && family === 6) {
      return decodeIcmpv6(bytes, offset, state, depth);
    }
    const note = nameForProtocol(nextHeader);
    if (nextHeader === 50 || nextHeader === 51) {
      return [layer({
        proto: "ipsec", name: nameForProtocol(nextHeader), offset, length: bytes.length,
        summary: nameForProtocol(nextHeader) + " · encrypted or authenticated payload",
        fields: [field("Next header", nextHeader + " · " + nameForProtocol(nextHeader)), field("Length", bytes.length + " B")],
        warnings: [], depth
      })];
    }
    if (nextHeader === 47) {
      return [layer({
        proto: "gre", name: "GRE", offset, length: bytes.length,
        summary: "GRE tunnel payload · " + bytes.length + " B",
        fields: [field("Flags/version", "0x" + PH.hex(bytes[0] || 0, 2) + " " + PH.hex(bytes[1] || 0, 2)), field("Protocol", "0x" + PH.hex(PH.u16be(bytes, 2), 4))],
        warnings: [], depth
      })];
    }
    if (nextHeader === 59 || bytes.length === 0) return [];
    const payload = unknownPayload(bytes, offset, state, depth, note);
    return payload ? [payload] : [];
  }

  /* ---------- network layer ---------- */

  function decodeIpv4(bytes, offset, state, familyContext) {
    const ip = global.IPv4Codec.decode(bytes.subarray(offset));
    ip.warnings.forEach((warning) => pushWarning(state, "IPv4: " + warning));
    const totalLength = ip.totalLength || (ip.headerLen + ip.payloadBytes.length);
    const layerLength = Math.min(totalLength, bytes.length - offset);
    const fields = [
      field("Version / IHL", ip.version + " / " + ip.ihl + " · " + ip.headerLen + " B header"),
      field("DSCP / ECN", ip.dscp + " · " + ip.dscpLabel + " / " + ip.ecn + " · " + ip.ecnLabel),
      field("Total length", ip.totalLength + " B"),
      field("Identification", "0x" + PH.hex(ip.id, 4)),
      field("Flags", (ip.reserved ? "R " : "") + (ip.df ? "DF " : "") + (ip.mf ? "MF" : "") + " · offset " + ip.fragmentOffset),
      field("TTL", ip.ttl),
      field("Protocol", ip.protocol + " · " + ip.protocolLabel),
      field("Header checksum", "0x" + PH.hex(ip.checksum, 4) + (ip.checksumOk ? " · valid" : " · invalid")),
      field("Source", ip.src),
      field("Destination", ip.dst)
    ];
    if (ip.options.length) fields.push(field("Options", ip.options.length + " · " + ip.optionsBytes + " B"));
    const layers = [layer({
      proto: "ipv4", name: "IPv4", offset, length: layerLength,
      summary: ip.src + " → " + ip.dst + " · " + ip.protocolLabel + " · TTL " + ip.ttl + " · " + layerLength + " B",
      fields, warnings: ip.warnings.slice(), depth: 2, href: "ipv4.html", meta: { ip }
    })];
    const payloadOffset = offset + ip.headerLen;
    if (ip.fragmentOffset > 0) {
      layers.push(layer({
        proto: "payload", name: "Fragment data", offset: payloadOffset, length: ip.payloadBytes.length,
        summary: "Non-initial IPv4 fragment · transport header is not present",
        fields: [field("Fragment offset", (ip.fragmentOffset * 8) + " B"), field("More fragments", ip.mf ? "yes" : "no")],
        warnings: [], depth: 3
      }));
      return layers;
    }
    const transport = decodeTransport(ip.protocol, ip.payloadBytes, payloadOffset, state, 3,
      { ipVersion: 4, srcIp: ip.src, dstIp: ip.dst, src: ip.src, dst: ip.dst }, 4);
    return layers.concat(transport);
  }

  function extensionFields(header) {
    const fields = [
      field("Next header", header.nextHeader + " · " + (header.nextHeaderName || nameForProtocol(header.nextHeader))),
      field("Length", header.length + " B")
    ];
    if (header.type === "fragment" || header.fragmentOffset != null) {
      fields.push(field("Fragment offset", (header.fragmentOffset || 0) * 8 + " B"));
      fields.push(field("More fragments", header.moreFragments ? "yes" : "no"));
      fields.push(field("Identification", "0x" + PH.hex(header.identification || 0, 8)));
    }
    if (header.options && header.options.length) fields.push(field("Options", header.options.length));
    return fields;
  }

  function decodeIpv6(bytes, offset, state) {
    const ip = global.IPv6Codec.decodeHeader(bytes, offset);
    const chain = global.IPv6Codec.walkChain(ip.payload, ip.nextHeader, offset + 40);
    ip.warnings.concat(chain.warnings).forEach((warning) => pushWarning(state, "IPv6: " + warning));
    const payloadLength = ip.payloadLength === 0 && chain.jumboPayloadLength != null
      ? chain.jumboPayloadLength : ip.payloadLength;
    const layerLength = Math.min(40 + payloadLength, bytes.length - offset);
    const fields = [
      field("Version / Traffic Class", ip.version + " / 0x" + PH.hex(ip.trafficClass, 2)),
      field("Flow label", "0x" + PH.hex(ip.flowLabel, 5)),
      field("Payload length", ip.payloadLength + (ip.payloadLengthZero ? " · jumbogram or empty" : "")),
      field("Next header", ip.nextHeader + " · " + ip.nextHeaderName),
      field("Hop limit", ip.hopLimit),
      field("Source", ip.src),
      field("Destination", ip.dst)
    ];
    const layers = [layer({
      proto: "ipv6", name: "IPv6", offset, length: Math.min(40, bytes.length - offset),
      summary: ip.src + " → " + ip.dst + " · next " + ip.nextHeaderName + " · hop " + ip.hopLimit + " · " + layerLength + " B",
      fields, warnings: ip.warnings.slice(), depth: 2, href: "ipv6.html", meta: { ip, chain }
    })];
    chain.headers.forEach((header, index) => {
      layers.push(layer({
        proto: "ipv6-ext", name: header.name || ("Extension " + (index + 1)), offset: header.offset, length: header.length,
        summary: header.name + " · " + header.length + " B · next " + (header.nextHeaderName || nameForProtocol(header.nextHeader)),
        fields: extensionFields(header), warnings: (header.optionWarnings || []).slice(), depth: 3, href: "ipv6.html"
      }));
    });
    const terminal = chain.terminal;
    const fragment = chain.headers.find((header) => header.type === 44 && header.fragmentOffset > 0);
    if (fragment) {
      layers.push(layer({
        proto: "payload", name: "Fragment data", offset: terminal.offset, length: terminal.bytes.length,
        summary: "Non-initial IPv6 fragment · transport header is not present",
        fields: [field("Fragment offset", (fragment.fragmentOffset * 8) + " B"),
          field("More fragments", fragment.moreFragments ? "yes" : "no"),
          field("Identification", "0x" + PH.hex(fragment.identification || 0, 8))],
        warnings: [], depth: 4
      }));
      return layers;
    }
    const transport = decodeTransport(terminal.nextHeader, terminal.bytes, terminal.offset, state, 4,
      { ipVersion: 6, srcIp: ip.src, dstIp: ip.dst, src: ip.src, dst: ip.dst }, 6);
    return layers.concat(transport);
  }

  /* ---------- link layer ---------- */

  function looksLikeEthernet(bytes) {
    if (bytes.length < 14) return false;
    /* A BGP marker is 16 bytes of 0xff and would otherwise look like a
       destination/source MAC plus an EtherType far above 0x0600. */
    if (bytes.length >= 16 && bytes.subarray(0, 16).every((b) => b === 0xff)) return false;
    const first = bytes[0] >> 4;
    if (first === 4 || first === 6) return false;
    let type = PH.u16be(bytes, 12);
    let cursor = 12;
    let guard = 0;
    while ((type === 0x8100 || type === 0x88a8) && guard++ < 4) {
      cursor += 4;
      if (bytes.length < cursor + 2) return false;
      type = PH.u16be(bytes, cursor);
    }
    return type >= 0x0600;
  }

  function decodeEthernet(bytes, state) {
    const eth = global.EthernetCodec.decodeFrame(bytes, { fcs: "auto" });
    eth.warnings.forEach((warning) => pushWarning(state, "Ethernet: " + warning));
    const fields = [
      field("Destination", eth.dstMac + (eth.dstFlags ? " · " + eth.dstFlags.label + " · " + eth.dstFlags.admin : "")),
      field("Source", eth.srcMac + (eth.srcFlags ? " · " + eth.srcFlags.label + " · " + eth.srcFlags.admin : "")),
      field("EtherType", "0x" + PH.hex(eth.etherType, 4) + " · " + eth.etherTypeName),
      field("Header", eth.headerLen + " B"),
      field("FCS", eth.fcsPresent ? (eth.fcsOk ? "present · valid" : "present · invalid") : "not captured")
    ];
    if (eth.vlanTags.length) {
      fields.push(field("VLAN tags", eth.vlanTags.map((tag) => "VID " + tag.vid + " · PCP " + tag.pcp).join(" → ")));
    }
    const layers = [layer({
      proto: "ethernet", name: "Ethernet II", offset: eth.offset, length: eth.headerLen,
      summary: eth.srcMac + " → " + eth.dstMac + " · " + eth.etherTypeName +
        (eth.vlanTags.length ? " · " + eth.vlanTags.length + " VLAN tag(s)" : "") + " · " + eth.frameLength + " B",
      fields, warnings: eth.warnings.slice(), depth: 0, href: "ethernet.html", meta: { eth }
    })];
    eth.vlanTags.forEach((tag, index) => {
      layers.push(layer({
        proto: "vlan", name: (tag.tpid === 0x88a8 ? "802.1ad" : "802.1Q") + " VLAN", offset: eth.offset + 12 + index * 4, length: 4,
        summary: "VID " + tag.vid + " · PCP " + tag.pcp + " · DEI " + tag.dei,
        fields: [field("TPID", "0x" + PH.hex(tag.tpid, 4)), field("PCP", tag.pcp),
          field("DEI", tag.dei), field("VID", tag.vid)],
        warnings: [], depth: 1, href: "ethernet.html"
      }));
    });
    let fcsLayer = null;
    if (eth.fcsPresent) {
      fcsLayer = layer({
        proto: "fcs", name: "Ethernet FCS", offset: eth.offset + eth.frameLength - 4, length: 4,
        summary: "CRC-32 · " + (eth.fcsOk ? "valid" : "invalid"),
        fields: [field("FCS", "0x" + PH.hex(PH.u32le(eth.fcs, 0), 8)), field("CRC-32", eth.fcsOk ? "valid" : "invalid")],
        warnings: [], depth: 1, href: "ethernet.html"
      });
    }
    const payloadOffset = eth.offset + eth.headerLen;
    const frameBytes = bytes.subarray(0, payloadOffset + eth.payload.length);
    let next;
    if (eth.etherType === 0x0800) next = decodeIpv4(frameBytes, payloadOffset, state, 4);
    else if (eth.etherType === 0x86dd) next = decodeIpv6(frameBytes, payloadOffset, state);
    else if (eth.etherType === 0x0806) {
      try {
        const arp = global.ARPCodec.decodeArp(eth.payload);
        arp.warnings.forEach((warning) => pushWarning(state, "ARP: " + warning));
        next = [layer({
          proto: "arp", name: "ARP", offset: payloadOffset, length: arp.messageLength,
          summary: arp.opcodeName + " · " + arp.senderIp + " (" + arp.senderMac + ") → " + arp.targetIp + " (" + arp.targetMac + ")",
          fields: [field("Hardware", arp.htype + " · " + arp.hardwareName), field("Protocol", "0x" + PH.hex(arp.ptype, 4) + " · " + arp.protocolName),
            field("Opcode", arp.opcode + " · " + arp.opcodeName), field("Sender MAC", arp.senderMac),
            field("Sender IP", arp.senderIp), field("Target MAC", arp.targetMac), field("Target IP", arp.targetIp),
            field("Padding", arp.paddingLength + " B")],
          warnings: arp.warnings.slice(), depth: 1, href: "arp.html", meta: { arp }
        })];
      } catch (err) {
        next = [layer({ proto: "arp", name: "ARP", offset: payloadOffset, length: eth.payload.length, summary: "ARP decode failed", fields: [], warnings: [err.message], depth: 1, href: "arp.html", error: err.message })];
      }
    } else {
      const payload = unknownPayload(eth.payload, payloadOffset, state, 1, eth.etherTypeName);
      next = payload ? [payload] : [];
    }
    const all = layers.concat(next);
    if (fcsLayer) all.push(fcsLayer);
    return all;
  }

  function dissect(input, opts) {
    let bytes = input instanceof Uint8Array ? input : Uint8Array.from(input || []);
    const options = opts || {};
    const state = { warnings: [] };
    let layers;
    try {
      if (options.kind === "ethernet" || (options.kind !== "ipv4" && options.kind !== "ipv6" && looksLikeEthernet(bytes))) {
        if (!global.EthernetCodec) throw new Error("Ethernet codec is not loaded");
        layers = decodeEthernet(bytes, state);
      } else if (options.kind === "ipv6" || ((bytes[0] >> 4) === 6 && !(options.kind === "ipv4"))) {
        if (!global.IPv6Codec) throw new Error("IPv6 codec is not loaded");
        layers = decodeIpv6(bytes, 0, state);
      } else if ((bytes[0] >> 4) === 4) {
        if (!global.IPv4Codec) throw new Error("IPv4 codec is not loaded");
        layers = decodeIpv4(bytes, 0, state, 4);
      } else {
        layers = [layer({
          proto: "raw", name: "Raw bytes", offset: 0, length: bytes.length,
          summary: bytes.length + " B · not an Ethernet frame, IPv4 packet or IPv6 packet",
          fields: [field("Length", bytes.length + " B"), field("First bytes", PH.bytesToHex(bytes.subarray(0, 16)))],
          warnings: [], depth: 0
        })];
      }
    } catch (err) {
      layers = [layer({
        proto: "error", name: "Undecodable", offset: 0, length: bytes.length,
        summary: "Decode stopped: " + err.message,
        fields: [field("Error", err.message)], warnings: [err.message], depth: 0, error: err.message
      })];
    }
    const warnings = state.warnings.slice();
    layers.forEach((item) => {
      if (item.error && warnings.indexOf(item.error) === -1) warnings.push(item.error);
    });
    return {
      bytes, layers, warnings,
      detectedAs: layers.length ? layers[0].name : "unknown",
      summary: layers.map((item) => item.name).join(" → "),
      totalBytes: bytes.length,
      deepest: layers.length ? layers[layers.length - 1] : null
    };
  }

  global.Dissector = { dissect, looksLikeEthernet, nameForProtocol, nameForEtherType, applicationLayer };
})(window);
