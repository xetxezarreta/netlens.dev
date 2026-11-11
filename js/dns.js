/* DNS explorer — RFC 1035 header, flags, names, records, EDNS, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const D = window.DNSCodec;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc1035",
    edns: "https://www.rfc-editor.org/rfc/rfc6891",
    negative: "https://www.rfc-editor.org/rfc/rfc2308",
    aaaa: "https://www.rfc-editor.org/rfc/rfc3596"
  };

  const DNS_STEPS = [
    {
      caption: "<b>Cache miss.</b> The stub resolver has no cached answer and sends a recursive query with <code>RD=1</code> to its configured recursive resolver. It expects one final answer, not referrals.",
      state: "miss", stateClass: "warn-text", mode: "",
      active: ["stub"], match: ["resolver"], link: "stub-resolver",
      stubNote: "cache miss", resolverNote: "cache miss",
      answer: "—", ttl: "—", cache: "miss"
    },
    {
      caption: "<b>Ask the root.</b> The resolver starts at a root server with an iterative query (<code>RD=0</code>) for <code>www.example.com A</code>.",
      state: "iterating", stateClass: "warn-text", mode: "",
      active: ["resolver"], match: ["root"], link: "resolver-root",
      stubNote: "waiting", resolverNote: "asking root",
      answer: "—", ttl: "—", cache: "miss"
    },
    {
      caption: "<b>Root referral.</b> The root does not know the address. It returns the NS records for <code>.com</code>; the resolver caches the referral and follows it.",
      state: "referral", stateClass: "warn-text", mode: "is-referral",
      active: ["root"], match: ["resolver"], link: "resolver-root",
      stubNote: "waiting", resolverNote: "referral cached",
      answer: "—", ttl: "—", cache: ".com NS"
    },
    {
      caption: "<b>Ask the .com TLD.</b> The resolver queries a <code>.com</code> name server for the same name.",
      state: "iterating", stateClass: "warn-text", mode: "",
      active: ["resolver"], match: ["tld"], link: "resolver-tld",
      stubNote: "waiting", resolverNote: "asking .com",
      answer: "—", ttl: "—", cache: ".com NS"
    },
    {
      caption: "<b>TLD referral.</b> The TLD returns the NS records for <code>example.com</code>. The resolver caches those names and continues down the tree.",
      state: "referral", stateClass: "warn-text", mode: "is-referral",
      active: ["tld"], match: ["resolver"], link: "resolver-tld",
      stubNote: "waiting", resolverNote: "referral cached",
      answer: "—", ttl: "—", cache: ".com + example.com NS"
    },
    {
      caption: "<b>Ask the authoritative server.</b> The resolver queries <code>example.com</code>'s authoritative name server.",
      state: "iterating", stateClass: "warn-text", mode: "",
      active: ["resolver"], match: ["auth"], link: "resolver-auth",
      stubNote: "waiting", resolverNote: "asking auth",
      answer: "—", ttl: "—", cache: ".com + example.com NS"
    },
    {
      caption: "<b>Answer.</b> The authoritative server returns the A record <code>192.0.2.80</code> with TTL 300. This is authoritative data, not a cached guess.",
      state: "answer", stateClass: "good-text", mode: "is-answer",
      active: ["auth"], match: ["resolver"], link: "resolver-auth",
      stubNote: "waiting", resolverNote: "answer received",
      answer: "<code>192.0.2.80</code>", ttl: "300 s", cache: "answer received"
    },
    {
      caption: "<b>Return the answer.</b> The resolver caches the record for 300 seconds and sends the final answer to the stub. The stub may cache it too.",
      state: "cached", stateClass: "good-text", mode: "is-answer",
      active: ["resolver"], match: ["stub"], link: "stub-resolver",
      stubNote: "answer received", resolverNote: "cached",
      answer: "<code>192.0.2.80</code>", ttl: "300 s", cache: "cached"
    },
    {
      caption: "<b>Cache hit.</b> A second query for the same name is answered from the resolver cache. No root, TLD or authoritative traffic is needed until the TTL expires.",
      state: "hit", stateClass: "good-text", mode: "is-cached",
      active: ["resolver"], match: ["stub"], link: "stub-resolver",
      stubNote: "cache hit", resolverNote: "cache hit",
      answer: "<code>192.0.2.80</code>", ttl: "300 s", cache: "hit · 300 s"
    }
  ];

  const DNS_TOKEN_HOME = {
    1: [165, 155], 2: [445, 145], 3: [510, 65], 4: [445, 155], 5: [510, 155],
    6: [445, 165], 7: [510, 245], 8: [235, 155], 9: [235, 155]
  };
  const DNS_TOKEN_TARGET = {
    1: [235, 155], 2: [510, 65], 3: [445, 145], 4: [510, 155], 5: [445, 155],
    6: [510, 245], 7: [445, 165], 8: [165, 155], 9: [165, 155]
  };

  const headerFields = [
    {
      id: "id", name: "ID", bits: 16, range: "0–65535", rfc: "RFC 1035 §4.1.1", rfcUrl: RFC.base,
      desc: "Transaction identifier. A resolver copies the query ID into the response and rejects a reply whose ID, question, source address or port does not match. It is a matching aid, not authentication."
    },
    {
      id: "flags", name: "Flags", bits: 16, range: "QR · Opcode · AA · TC · RD · RA · Z · AD · CD · RCODE", rfc: "RFC 1035 · RFC 4035", rfcUrl: RFC.base,
      desc: "One 16-bit word holding direction, opcode, authoritative and truncation bits, recursion bits, the reserved Z bit, DNSSEC AD/CD and the four-bit RCODE. See the flag walkthrough below."
    },
    {
      id: "qd", name: "QDCOUNT", bits: 16, range: "0–65535", rfc: "RFC 1035 §4.1.1", rfcUrl: RFC.base,
      desc: "Number of entries in the question section. Ordinary queries carry exactly one. UPDATE and some meta-queries use different counts."
    },
    {
      id: "an", name: "ANCOUNT", bits: 16, range: "0–65535", rfc: "RFC 1035 §4.1.1", rfcUrl: RFC.base,
      desc: "Number of resource records in the answer section. Zero is normal for a query and for a negative response."
    },
    {
      id: "ns", name: "NSCOUNT", bits: 16, range: "0–65535", rfc: "RFC 1035 §4.1.1", rfcUrl: RFC.base,
      desc: "Number of resource records in the authority section: delegation NS records or the SOA that supports negative caching."
    },
    {
      id: "ar", name: "ARCOUNT", bits: 16, range: "0–65535", rfc: "RFC 1035 §4.1.1", rfcUrl: RFC.base,
      desc: "Number of resource records in the additional section: glue A/AAAA, OPT (EDNS), TSIG and similar supporting records."
    }
  ];

  const flagFields = [
    { id: "qr", name: "QR", bits: 1, range: "0 query · 1 response", rfc: "RFC 1035", rfcUrl: RFC.base, desc: "Direction bit. 0 means query, 1 means response. A response that echoes a query's ID with QR=0 is malformed." },
    { id: "opcode", name: "Opcode", bits: 4, range: "0 QUERY · 5 UPDATE", rfc: "RFC 1035 · RFC 2136", rfcUrl: RFC.base, desc: "Operation: QUERY (0), IQUERY (1), STATUS (2), NOTIFY (4), UPDATE (5), DSO (6). Most traffic uses QUERY." },
    { id: "aa", name: "AA", bits: 1, range: "0 / 1", rfc: "RFC 1035", rfcUrl: RFC.base, desc: "Authoritative Answer. Set when the responding server owns the zone that contains the answer. Recursive resolvers normally clear it." },
    { id: "tc", name: "TC", bits: 1, range: "0 / 1", rfc: "RFC 1035", rfcUrl: RFC.base, desc: "TrunCation. The message was truncated to fit the transport. The client should retry over TCP to obtain the complete answer." },
    { id: "rd", name: "RD", bits: 1, range: "0 / 1", rfc: "RFC 1035", rfcUrl: RFC.base, desc: "Recursion Desired. A client asks the server to resolve the name recursively. Copies of this bit appear in the response for correlation." },
    { id: "ra", name: "RA", bits: 1, range: "0 / 1", rfc: "RFC 1035", rfcUrl: RFC.base, desc: "Recursion Available. The server is willing to perform recursion. A stub resolver should not expect recursion from a server that clears RA." },
    { id: "z", name: "Z", bits: 1, range: "0", rfc: "RFC 1035", rfcUrl: RFC.base, desc: "Reserved. Must be zero. Historically part of a three-bit Z field; AD and CD now occupy two of those bits." },
    { id: "ad", name: "AD", bits: 1, range: "0 / 1", rfc: "RFC 4035", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4035", desc: "Authentic Data. Set by a validating resolver when all data in the answer was DNSSEC-validated. It is a claim, not a signature you can verify from this message alone." },
    { id: "cd", name: "CD", bits: 1, range: "0 / 1", rfc: "RFC 4035", rfcUrl: "https://www.rfc-editor.org/rfc/rfc4035", desc: "Checking Disabled. A client asks a validating resolver not to reject data that fails DNSSEC validation, usually for debugging." },
    { id: "rcode", name: "RCODE", bits: 4, range: "0–15", rfc: "RFC 1035 · RFC 6891", rfcUrl: RFC.edns, desc: "Response code. 0 is NOERROR, 3 is NXDOMAIN. EDNS extends this to 12 bits using the OPT record's extended RCODE field." }
  ];

  let headerDiagram = null;
  let flagsDiagram = null;

  function initDiagrams() {
    headerDiagram = PH.diagram("#dns-diagram", {
      title: "<b>DNS</b> · message header", badge: "RFC 1035 §4.1.1",
      fields: headerFields, inspector: "#dns-inspector", table: "#dns-fields",
      note: "The header is always 12 bytes. Counts describe the four sections that follow; they do not include the header itself. Bit 0 is the MSB of the ID field."
    });
    PH.fieldTable("#dns-fields", headerDiagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    flagsDiagram = PH.diagram("#dns-flags-diagram", {
      title: "<b>DNS flags</b> · bit walkthrough", badge: "16 bits",
      fields: flagFields, inspector: "#dns-flags-inspector", table: "#dns-flags-fields",
      note: "Read the flags word MSB-first. QR is the most significant bit (bit 0 of this word as drawn); RCODE is the low nibble (bits 12–15). AD and CD share what used to be reserved Z bits."
    });
    PH.fieldTable("#dns-flags-fields", flagsDiagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#dns-question-lane", {
      title: "<b>Question</b> · QNAME + QTYPE + QCLASS", badge: "per question",
      fields: [
        { name: "QNAME", bytes: "var", variable: true, range: "1–255 B", desc: "Length-prefixed labels ending in a zero byte, or a compression pointer. The root name is a single zero byte.", rfc: "RFC 1035 §3.1", rfcUrl: RFC.base, tone: "a" },
        { name: "QTYPE", bytes: 2, range: "16-bit", desc: "The record type being asked for: A (1), AAAA (28), MX (15), TXT (16), HTTPS (65), ANY (255).", rfc: "RFC 1035 §3.2.2", rfcUrl: RFC.base, tone: "c" },
        { name: "QCLASS", bytes: 2, range: "16-bit", desc: "Usually IN (1). CH (3) is used for Chaos-class data such as version.bind; ANY (255) is a wildcard class in queries.", rfc: "RFC 1035 §3.2.4", rfcUrl: RFC.base, tone: "d" }
      ],
      inspector: "#dns-question-inspector",
      note: "A question has no TTL and no RDLENGTH. Only the three fields shown here follow the name."
    });

    PH.byteLane("#dns-answer-lane", {
      title: "<b>Resource record</b> · common envelope", badge: "answer / authority / additional",
      fields: [
        { name: "NAME", bytes: "var", variable: true, range: "1–255 B", desc: "Owner name, often a compression pointer such as C0 0C. The name is resolved against earlier bytes in the same message.", rfc: "RFC 1035 §4.1.3", rfcUrl: RFC.base, tone: "a" },
        { name: "TYPE", bytes: 2, range: "16-bit", desc: "Record type. The type determines how RDATA is parsed and which section may legitimately hold it.", rfc: "RFC 1035 §3.2.2", rfcUrl: RFC.base, tone: "b" },
        { name: "CLASS", bytes: 2, range: "16-bit", desc: "Usually IN (1). For an OPT pseudo-record this field is repurposed as the requestor's UDP payload size.", rfc: "RFC 1035 §3.2.4", rfcUrl: RFC.base, tone: "c" },
        { name: "TTL", bytes: 4, range: "0–2³¹−1", desc: "Cache lifetime in seconds. RFC 2181 makes this a 31-bit value; the high bit must be zero. OPT repurposes TTL for extended RCODE, version and flags.", rfc: "RFC 2181 §8", rfcUrl: "https://www.rfc-editor.org/rfc/rfc2181", tone: "d" },
        { name: "RDLENGTH", bytes: 2, range: "0–65535", desc: "Length of RDATA in bytes. It lets a parser skip a record type it does not understand, but a wrong value desynchronises the rest of the message.", rfc: "RFC 1035 §4.1.3", rfcUrl: RFC.base, tone: "e" },
        { name: "RDATA", bytes: "var", variable: true, range: "RDLENGTH bytes", desc: "Type-specific data: an address, a name, an MX preference, SOA timers, EDNS options, a DNSSEC key or signature.", rfc: "RFC 1035 §3.3", rfcUrl: RFC.base, tone: "f" }
      ],
      inspector: "#dns-answer-inspector",
      note: "The envelope is identical in the answer, authority and additional sections. Only the section and the record type change the interpretation."
    });

    PH.byteLane("#dns-tcp-lane", {
      title: "<b>DNS over TCP</b> · length-prefixed messages", badge: "RFC 1035 §4.2.2", compact: true,
      fields: [
        { name: "Length", bytes: 2, range: "0–65535", desc: "Length of the DNS message that follows, excluding this two-byte prefix. It must match the bytes available for one message.", rfc: "RFC 1035 §4.2.2", rfcUrl: RFC.base, tone: "a" },
        { name: "DNS message", bytes: "var", variable: true, range: "0–65535 B", desc: "A complete DNS message. Consecutive messages on the same TCP connection each carry their own prefix.", rfc: "RFC 1035 §4.2.2", rfcUrl: RFC.base, tone: "b" }
      ],
      inspector: "#dns-tcp-inspector",
      note: "TCP is a byte stream, so DNS needs a length prefix. UDP does not: one datagram is exactly one message."
    });
  }

  function updateDiagrams(message) {
    if (!message) return;
    if (headerDiagram) {
      headerDiagram.setValues({
        id: String(message.id),
        flags: "0x" + PH.hex(message.flagsRaw, 4),
        qd: String(message.counts.questions),
        an: String(message.counts.answers),
        ns: String(message.counts.authority),
        ar: String(message.counts.additional)
      });
    }
    if (flagsDiagram) {
      flagsDiagram.setValues({
        qr: String(message.header.qr),
        opcode: String(message.header.opcode),
        aa: String(message.header.aa),
        tc: String(message.header.tc),
        rd: String(message.header.rd),
        ra: String(message.header.ra),
        z: String(message.flags.z),
        ad: String(message.header.ad),
        cd: String(message.header.cd),
        rcode: String(message.header.rcode)
      });
    }
  }

  /* ---------- encoder ---------- */

  function idValue() {
    const n = PH.parseNumber(document.getElementById("dns-enc-id").value);
    if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error("Transaction ID must be 0–65535");
    return n;
  }

  function checked(id) {
    const el = document.getElementById(id);
    return !!(el && el.checked);
  }

  function readFlags() {
    return {
      qr: checked("dns-enc-qr"), aa: checked("dns-enc-aa"), tc: checked("dns-enc-tc"),
      rd: checked("dns-enc-rd"), ra: checked("dns-enc-ra"), ad: checked("dns-enc-ad"),
      cd: checked("dns-enc-cd"), z: false,
      opcode: Number(document.getElementById("dns-enc-opcode").value),
      rcode: Number(document.getElementById("dns-enc-rcode").value)
    };
  }

  function readRecords(id) {
    const el = document.getElementById(id);
    try {
      return D.parseRecordLines(el.value);
    } catch (err) {
      const line = el.value.split(/\r?\n/).findIndex((text) => {
        try { if (!text.trim() || text.trim().startsWith("#") || text.trim().startsWith(";")) return false; D.parseRecordLine(text); return false; }
        catch (_) { return true; }
      });
      throw new Error((id.replace("dns-enc-", "") + (line >= 0 ? " line " + (line + 1) : "")) + ": " + err.message);
    }
  }

  function buildSpec() {
    const questions = [];
    const qname = document.getElementById("dns-enc-qname").value.trim();
    if (qname) {
      questions.push({
        name: qname,
        type: document.getElementById("dns-enc-qtype").value,
        class: document.getElementById("dns-enc-qclass").value
      });
    }
    const flags = readFlags();
    const spec = Object.assign({ id: idValue() }, flags, {
      questions,
      answers: readRecords("dns-enc-answers"),
      authority: readRecords("dns-enc-authority"),
      additional: readRecords("dns-enc-additional")
    });
    if (checked("dns-enc-edns")) {
      if (spec.additional.some((record) => D.typeCode(record.type) === 41)) {
        throw new Error("EDNS is enabled and the additional section also contains an OPT record");
      }
      const size = Number(document.getElementById("dns-enc-edns-size").value);
      if (!Number.isInteger(size) || size < 512 || size > 65535) throw new Error("EDNS UDP size must be 512–65535");
      spec.additional.push({
        name: ".", type: "OPT", class: size, ttl: 0,
        data: { extendedRcode: 0, version: 0, flags: checked("dns-enc-edns-do") ? 0x8000 : 0, options: [] }
      });
    }
    return spec;
  }

  function wrapperAddress(version) {
    const prefix = version === 4 ? "dns-enc-v4" : "dns-enc-v6";
    return {
      src: document.getElementById(prefix + "-src").value.trim(),
      dst: document.getElementById(prefix + "-dst").value.trim()
    };
  }

  function buildMessageFromForm() {
    const spec = buildSpec();
    const message = D.buildMessage(spec);
    const mode = document.getElementById("dns-enc-output-mode").value;
    let bytes = message.bytes;
    let udp = null;
    let packet = null;
    if (mode === "udp4" || mode === "udp6") {
      const version = mode === "udp4" ? 4 : 6;
      const addresses = wrapperAddress(version);
      const srcPort = Number(document.getElementById("dns-enc-src-port").value);
      const dstPort = Number(document.getElementById("dns-enc-dst-port").value);
      udp = window.UDPCodec.buildUdp({
        srcPort, dstPort, payload: message.bytes, ipVersion: version,
        srcIp: addresses.src, dstIp: addresses.dst
      });
      if (version === 4) {
        packet = window.IPv4Codec.buildHeader({
          version: 4, dscp: 0, ecn: 0, id: 0x4444, ttl: 64, protocol: 17,
          fragmentOffset: 0, payloadLength: udp.bytes.length, reserved: false, df: true, mf: false,
          src: addresses.src, dst: addresses.dst, options: ""
        });
        bytes = PH.concatBytes(packet.bytes, udp.bytes);
      } else {
        packet = window.IPv6Codec.buildHeader({
          version: 6, dscp: 0, ecn: 0, flowLabel: 0, nextHeader: 17,
          hopLimit: 64, src: addresses.src, dst: addresses.dst, payload: udp.bytes
        });
        bytes = packet.bytes;
      }
    }
    return { spec, message, bytes, udp, packet, mode };
  }

  let lastBuild = null;

  function updateEncoder(result) {
    const message = result.message;
    document.getElementById("dns-enc-output").textContent = PH.bytesToHex(result.bytes);
    document.getElementById("dns-enc-output").classList.remove("placeholder");
    document.getElementById("dns-enc-tag").textContent = result.bytes.length + " B";
    document.getElementById("dns-enc-length").textContent = message.messageLength + " B DNS" + (result.packet ? " · " + result.bytes.length + " B packet" : "");
    document.getElementById("dns-enc-qcount").textContent = String(message.counts.questions);
    document.getElementById("dns-enc-acount").textContent = String(message.counts.answers);
    const pills = [
      `<span class="pill">ID 0x${PH.hex(message.id, 4)}</span>`,
      `<span class="pill">${message.flagsObject.qr ? "response" : "query"} · ${D.opcodeName(message.flagsObject.opcode)}</span>`,
      `<span class="pill ${message.flagsObject.rcode === 0 ? "pill--good" : "pill--warn"}">${D.rcodeName(message.flagsObject.rcode)}</span>`,
      `<span class="pill">Q <b>${message.counts.questions}</b> · A <b>${message.counts.answers}</b> · NS <b>${message.counts.authority}</b> · AR <b>${message.counts.additional}</b></span>`,
      `<span class="pill">${message.messageLength} B DNS</span>`
    ];
    if (result.udp) pills.push(`<span class="pill pill--good">UDP ${result.udp.srcPort} → ${result.udp.dstPort} · checksum ${result.udp.checksumState}</span>`);
    if (result.packet) pills.push(`<span class="pill">IPv${result.udp.ipVersion} wrapper</span>`);
    document.getElementById("dns-enc-summary").innerHTML = pills.join("");
    updateDiagrams(message.decoded);
    PH.setStatus(document.getElementById("dns-enc-status"),
      `built ${message.messageLength}-byte DNS ${message.flagsObject.qr ? "response" : "query"} · ${message.counts.answers} answer(s) · ${message.flagsObject.rcode ? D.rcodeName(message.flagsObject.rcode) : "NOERROR"}${result.packet ? " · " + result.bytes.length + " B IPv" + result.udp.ipVersion + " packet" : ""}`,
      message.warnings.length ? "warn" : "ok");
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("dns-enc-status");
    const tag = document.getElementById("dns-enc-tag");
    try {
      const result = buildMessageFromForm();
      lastBuild = result;
      updateEncoder(result);
      return result;
    } catch (err) {
      tag.textContent = "error";
      PH.setStatus(status, "error: " + err.message, "bad");
      return null;
    }
  }

  function syncWrapper() {
    const mode = document.getElementById("dns-enc-output-mode").value;
    document.getElementById("dns-enc-v4-fields").hidden = mode !== "udp4";
    document.getElementById("dns-enc-v6-fields").hidden = mode !== "udp6";
  }

  function recordsToText(records) {
    return (records || []).filter((record) => D.typeCode(record.type) !== 41).map((record) => {
      const head = record.name + " " + (record.ttl == null ? 300 : record.ttl) + " " + record.type;
      const data = record.data;
      if (data == null) return head;
      if (typeof data === "string") return head + " " + data;
      if (Array.isArray(data)) return head + " " + data.map((text) => JSON.stringify(text)).join(" ");
      switch (D.typeCode(record.type)) {
        case 15: return head + " " + data.preference + " " + data.exchange;
        case 6: return head + " " + [data.mname, data.rname, data.serial, data.refresh, data.retry, data.expire, data.minimum].join(" ");
        case 33: return head + " " + [data.priority, data.weight, data.port, data.target].join(" ");
        case 257: return head + " " + data.flags + " " + data.tag + " " + JSON.stringify(data.value);
        case 43: return head + " " + [data.keyTag, data.algorithm, data.digestType, data.digest].join(" ");
        case 48: return head + " " + [data.flags, data.protocol == null ? 3 : data.protocol, data.algorithm, data.publicKey].join(" ");
        default: return head + " " + JSON.stringify(data);
      }
    }).join("\n");
  }

  function setFlags(flags) {
    [["dns-enc-qr", "qr"], ["dns-enc-aa", "aa"], ["dns-enc-tc", "tc"], ["dns-enc-rd", "rd"],
      ["dns-enc-ra", "ra"], ["dns-enc-ad", "ad"], ["dns-enc-cd", "cd"]].forEach(([id, key]) => {
      document.getElementById(id).checked = !!(flags && flags[key]);
    });
    document.getElementById("dns-enc-opcode").value = String(flags && flags.opcode != null ? flags.opcode : 0);
    document.getElementById("dns-enc-rcode").value = String(flags && flags.rcode != null ? flags.rcode : 0);
  }

  function applyPreset(key) {
    const example = D.examples()[key];
    if (!example) return;
    document.getElementById("dns-enc-id").value = "0x" + PH.hex(example.id || 0, 4);
    setFlags(example);
    const question = (example.questions || [])[0];
    document.getElementById("dns-enc-qname").value = question ? question.name : "";
    document.getElementById("dns-enc-qtype").value = question ? question.type : "A";
    document.getElementById("dns-enc-qclass").value = question ? (question.class || "IN") : "IN";
    document.getElementById("dns-enc-answers").value = recordsToText(example.answers);
    document.getElementById("dns-enc-authority").value = recordsToText(example.authority);
    const additional = example.additional || [];
    const opt = additional.find((record) => D.typeCode(record.type) === 41);
    document.getElementById("dns-enc-additional").value = recordsToText(additional);
    document.getElementById("dns-enc-edns").checked = !!opt;
    if (opt) {
      const data = opt.data || {};
      document.getElementById("dns-enc-edns-size").value = String(opt.class || 1232);
      document.getElementById("dns-enc-edns-do").checked = !!(data.flags & 0x8000);
    } else {
      document.getElementById("dns-enc-edns-do").checked = false;
    }
    syncWrapper();
    buildFromForm(true);
  }

  function encoderState() {
    return {
      page: "dns-enc",
      id: document.getElementById("dns-enc-id").value,
      opcode: document.getElementById("dns-enc-opcode").value,
      rcode: document.getElementById("dns-enc-rcode").value,
      flags: {
        qr: checked("dns-enc-qr"), aa: checked("dns-enc-aa"), tc: checked("dns-enc-tc"),
        rd: checked("dns-enc-rd"), ra: checked("dns-enc-ra"), ad: checked("dns-enc-ad"), cd: checked("dns-enc-cd")
      },
      qname: document.getElementById("dns-enc-qname").value,
      qtype: document.getElementById("dns-enc-qtype").value,
      qclass: document.getElementById("dns-enc-qclass").value,
      answers: document.getElementById("dns-enc-answers").value,
      authority: document.getElementById("dns-enc-authority").value,
      additional: document.getElementById("dns-enc-additional").value,
      edns: checked("dns-enc-edns"),
      ednsSize: document.getElementById("dns-enc-edns-size").value,
      ednsDo: checked("dns-enc-edns-do"),
      mode: document.getElementById("dns-enc-output-mode").value,
      srcPort: document.getElementById("dns-enc-src-port").value,
      dstPort: document.getElementById("dns-enc-dst-port").value,
      v4src: document.getElementById("dns-enc-v4-src").value,
      v4dst: document.getElementById("dns-enc-v4-dst").value,
      v6src: document.getElementById("dns-enc-v6-src").value,
      v6dst: document.getElementById("dns-enc-v6-dst").value
    };
  }

  function applyEncoderState(state) {
    if (!state) return false;
    const byId = {
      "dns-enc-id": state.id, "dns-enc-opcode": state.opcode, "dns-enc-rcode": state.rcode,
      "dns-enc-qname": state.qname, "dns-enc-qtype": state.qtype, "dns-enc-qclass": state.qclass,
      "dns-enc-answers": state.answers, "dns-enc-authority": state.authority,
      "dns-enc-additional": state.additional, "dns-enc-edns-size": state.ednsSize,
      "dns-enc-output-mode": state.mode, "dns-enc-src-port": state.srcPort,
      "dns-enc-dst-port": state.dstPort, "dns-enc-v4-src": state.v4src,
      "dns-enc-v4-dst": state.v4dst, "dns-enc-v6-src": state.v6src, "dns-enc-v6-dst": state.v6dst
    };
    Object.keys(byId).forEach((id) => {
      const el = document.getElementById(id);
      if (el && byId[id] != null) el.value = byId[id];
    });
    if (state.flags) setFlags(Object.assign({}, state.flags, { opcode: state.opcode, rcode: state.rcode }));
    document.getElementById("dns-enc-edns").checked = !!state.edns;
    document.getElementById("dns-enc-edns-do").checked = !!state.ednsDo;
    syncWrapper();
    return true;
  }

  function sanitize(value) {
    if (value instanceof Uint8Array) return PH.bytesToHex(value);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach((key) => {
        if (key === "bytes" || key === "nameInfo") return;
        out[key] = sanitize(value[key]);
      });
      return out;
    }
    return value;
  }

  function initEncoder() {
    const build = document.getElementById("dns-enc-build");
    if (!build) return;
    document.getElementById("dns-enc-output-mode").addEventListener("change", () => {
      syncWrapper();
      buildFromForm(false);
    });
    ["dns-enc-id", "dns-enc-qname", "dns-enc-answers", "dns-enc-authority", "dns-enc-additional",
      "dns-enc-src-port", "dns-enc-dst-port", "dns-enc-v4-src", "dns-enc-v4-dst",
      "dns-enc-v6-src", "dns-enc-v6-dst", "dns-enc-edns-size"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", () => buildFromForm(false));
    });
    ["dns-enc-opcode", "dns-enc-rcode", "dns-enc-qtype", "dns-enc-qclass", "dns-enc-qr",
      "dns-enc-aa", "dns-enc-tc", "dns-enc-rd", "dns-enc-ra", "dns-enc-ad", "dns-enc-cd",
      "dns-enc-edns", "dns-enc-edns-do"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", () => buildFromForm(false));
    });
    build.addEventListener("click", () => buildFromForm(true));
    document.getElementById("dns-enc-example").addEventListener("click", () => applyPreset("responseA"));
    document.querySelectorAll("[data-dns-preset]").forEach((button) => {
      button.addEventListener("click", () => applyPreset(button.getAttribute("data-dns-preset")));
    });
    document.getElementById("dns-enc-permalink").addEventListener("click", () => {
      const result = lastBuild || buildFromForm(true);
      if (result) PH.shareState(encoderState(), "DNS encoder permalink copied");
    });
    document.getElementById("dns-enc-export").addEventListener("click", () => {
      const result = lastBuild || buildFromForm(true);
      if (!result) return;
      PH.downloadText("dns-message.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes),
        dnsHex: PH.bytesToHex(result.message.bytes),
        bytes: result.bytes.length,
        spec: sanitize(result.spec),
        counts: result.message.counts,
        warnings: result.message.warnings,
        transport: result.udp ? {
          ipVersion: result.udp.ipVersion, sourcePort: result.udp.srcPort,
          destinationPort: result.udp.dstPort, checksum: "0x" + PH.hex(result.udp.checksum, 4),
          checksumState: result.udp.checksumState
        } : null
      }, null, 2), "application/json");
    });
    syncWrapper();
    buildFromForm(false);
  }

  /* ---------- decoder ---------- */

  function plausibleDns(bytes) {
    if (bytes.length < 12) return null;
    try {
      const message = D.decodeMessage(bytes, { allowLarge: true });
      if (message.parsedLength !== bytes.length) return null;
      if (message.counts.questions > 8 || message.counts.answers > 128 ||
          message.counts.authority > 128 || message.counts.additional > 128) return null;
      if (message.warnings.some((warning) => /runs past|truncated|extends past|declares RDLENGTH/i.test(warning))) return null;
      return message;
    } catch (_) { return null; }
  }

  function fromTransportPayload(payload, context) {
    if (!payload || payload.length < 12) throw new Error("DNS payload is shorter than the 12-byte header");
    if (context.transport === "TCP") {
      const declared = PH.u16be(payload, 0);
      if (declared + 2 > payload.length) {
        throw new Error("TCP DNS length prefix says " + declared + " B but only " + (payload.length - 2) + " B follow");
      }
      return {
        dnsBytes: payload.subarray(2, 2 + declared),
        context: Object.assign({}, context, { prefix: declared, trailing: payload.length - 2 - declared })
      };
    }
    return { dnsBytes: payload, context };
  }

  function decodeUdpEnvelope(bytes, offset, baseContext) {
    const udp = window.UDPCodec.decodeUdp(bytes.subarray(offset), baseContext || {});
    const context = Object.assign({}, baseContext || {}, {
      transport: "UDP", srcPort: udp.srcPort, dstPort: udp.dstPort,
      checksum: udp.checksum, checksumState: udp.checksumState
    });
    return fromTransportPayload(udp.payload, context);
  }

  function decodeTcpEnvelope(bytes, offset, baseContext) {
    const tcpContext = baseContext && baseContext.ipVersion === 4 && baseContext.src
      ? { src: baseContext.src, dst: baseContext.dst } : {};
    const tcp = window.TCPCodec.decodeSegment(bytes.subarray(offset), tcpContext);
    const context = Object.assign({}, baseContext || {}, {
      transport: "TCP", srcPort: tcp.sport, dstPort: tcp.dport,
      checksum: tcp.checksum, checksumState: tcp.checksumStatus
    });
    return fromTransportPayload(tcp.payload, context);
  }

  function decodeIpv4Envelope(bytes) {
    const ip = window.IPv4Codec.decode(bytes);
    if (ip.protocol !== 17 && ip.protocol !== 6) {
      throw new Error("IPv4 Protocol is " + ip.protocol + " (" + ip.protocolLabel + "), not UDP (17) or TCP (6)");
    }
    if (ip.fragmentOffset > 0) throw new Error("Non-initial IPv4 fragment does not contain a DNS message");
    const base = { src: ip.src, dst: ip.dst, ipVersion: 4, outer: ip };
    const envelope = ip.protocol === 17
      ? decodeUdpEnvelope(ip.payloadBytes, 0, base)
      : decodeTcpEnvelope(ip.payloadBytes, 0, base);
    envelope.context.ip = ip;
    return envelope;
  }

  function decodeIpv6Envelope(bytes) {
    const packet = window.IPv6Codec.decodePacket(bytes);
    const terminal = packet.chain.terminal;
    if (terminal.nextHeader !== 17 && terminal.nextHeader !== 6) {
      throw new Error("IPv6 terminal Next Header is " + terminal.nextHeader + " (" + terminal.name + "), not UDP (17) or TCP (6)");
    }
    const fragment = packet.chain.headers.find((header) => header.type === 44);
    if (fragment && fragment.fragmentOffset > 0) {
      throw new Error("DNS is not present in a non-initial IPv6 fragment");
    }
    const base = { src: packet.ip.src, dst: packet.ip.dst, ipVersion: 6, ipv6: packet };
    const envelope = terminal.nextHeader === 17
      ? decodeUdpEnvelope(terminal.bytes, 0, base)
      : decodeTcpEnvelope(terminal.bytes, 0, base);
    envelope.context.ipv6 = packet;
    return envelope;
  }

  function decodeEthernetEnvelope(bytes) {
    const frame = window.EthernetCodec.decodeFrame(bytes, { fcs: "auto" });
    const end = frame.offset + frame.headerLen + frame.payload.length;
    const frameBytes = bytes.subarray(0, end);
    const payloadOffset = frame.offset + frame.headerLen;
    let envelope;
    if (frame.etherType === 0x0800) envelope = decodeIpv4Envelope(frameBytes.subarray(payloadOffset));
    else if (frame.etherType === 0x86dd) envelope = decodeIpv6Envelope(frameBytes.subarray(payloadOffset));
    else throw new Error("Ethernet EtherType is 0x" + PH.hex(frame.etherType, 4) + " (" + frame.etherTypeName + "), not IPv4 or IPv6");
    envelope.context.ethernet = { srcMac: frame.srcMac, dstMac: frame.dstMac, vlanTags: frame.vlanTags, fcsOk: frame.fcsOk, fcsPresent: frame.fcsPresent };
    return envelope;
  }

  function decodeAuto(bytes) {
    const direct = plausibleDns(bytes);
    if (direct) return { dnsBytes: bytes, context: { transport: "raw" }, direct };
    try {
      const udp = window.UDPCodec.decodeUdp(bytes);
      if (udp.payload.length >= 12 && plausibleDns(udp.payload)) {
        return {
          dnsBytes: udp.payload,
          context: { transport: "UDP", srcPort: udp.srcPort, dstPort: udp.dstPort,
            checksum: udp.checksum, checksumState: udp.checksumState }
        };
      }
    } catch (_) { /* not a raw UDP datagram */ }
    if (window.Dissector) {
      const result = window.Dissector.dissect(bytes);
      const layer = result.layers.find((item) => item.proto === "dns");
      if (layer) {
        const ipv4 = result.layers.find((item) => item.proto === "ipv4");
        const ipv6 = result.layers.find((item) => item.proto === "ipv6");
        const udp = result.layers.find((item) => item.proto === "udp");
        const tcp = result.layers.find((item) => item.proto === "tcp");
        const context = { transport: udp ? "UDP" : tcp ? "TCP" : "raw" };
        if (ipv4) { context.ip = ipv4.meta.ip; context.src = ipv4.meta.ip.src; context.dst = ipv4.meta.ip.dst; context.ipVersion = 4; }
        if (ipv6) { context.ipv6 = ipv6.meta; context.src = ipv6.meta.ip.src; context.dst = ipv6.meta.ip.dst; context.ipVersion = 6; }
        if (udp) {
          context.srcPort = udp.meta.parsed.srcPort; context.dstPort = udp.meta.parsed.dstPort;
          context.checksum = udp.meta.parsed.checksum; context.checksumState = udp.meta.parsed.checksumState;
        }
        if (tcp) {
          context.srcPort = tcp.meta.parsed.sport; context.dstPort = tcp.meta.parsed.dport;
          context.checksumState = tcp.meta.parsed.checksumStatus;
        }
        return { dnsBytes: bytes.subarray(layer.offset, layer.offset + layer.length), context };
      }
      const udpLayer = result.layers.find((item) => item.proto === "udp");
      if (udpLayer) {
        const start = udpLayer.offset;
        return decodeUdpEnvelope(bytes, start, {
          ipVersion: ipv4 ? 4 : ipv6 ? 6 : undefined,
          srcIp: ipv4 ? ipv4.meta.ip.src : ipv6 ? ipv6.meta.ip.src : undefined,
          dstIp: ipv4 ? ipv4.meta.ip.dst : ipv6 ? ipv6.meta.ip.dst : undefined
        });
      }
    }
    if ((bytes[0] >> 4) === 4) return decodeIpv4Envelope(bytes);
    if ((bytes[0] >> 4) === 6) return decodeIpv6Envelope(bytes);
    return { dnsBytes: bytes, context: { transport: "raw" } };
  }

  function decodeEnvelope(bytes, kind) {
    if (kind === "dns") return { dnsBytes: bytes, context: { transport: "raw" } };
    if (kind === "udp") return decodeUdpEnvelope(bytes, 0, {});
    if (kind === "ipv4") return decodeIpv4Envelope(bytes);
    if (kind === "ipv6") return decodeIpv6Envelope(bytes);
    if (kind === "ethernet") return decodeEthernetEnvelope(bytes);
    return decodeAuto(bytes);
  }

  function pill(text, tone) {
    return `<span class="pill${tone ? " pill--" + tone : ""}">${text}</span>`;
  }

  function sectionTable(label, items, isQuestion) {
    if (!items.length) return "";
    const headers = isQuestion
      ? ["Name", "Type", "Class"]
      : ["Name", "Type", "Class", "TTL", "RDLENGTH", "RDATA"];
    const rows = items.map((item) => {
      if (isQuestion) {
        return `<tr><td><code>${PH.esc(item.name)}</code></td><td>${PH.esc(item.typeName)}</td><td>${PH.esc(item.className)}</td></tr>`;
      }
      const value = item.type === 41
        ? `UDP ${item.udpPayloadSize} B · version ${item.version} · DO ${item.do} · ${item.rdata.value}`
        : (item.rdata ? item.rdata.value : "—");
      const detail = item.rdata && item.rdata.fields && item.rdata.fields.length
        ? '<details><summary>' + PH.esc(value) + '</summary><div class="table-wrap"><table class="data-table"><tbody>' +
          item.rdata.fields.map((field) => `<tr><th>${PH.esc(field.name)}</th><td><code>${PH.esc(field.value)}</code></td></tr>`).join("") +
          "</tbody></table></div>" +
          (item.rdata.bytes && item.rdata.bytes.length ? `<div class="output" style="margin-top:6px"><div class="output__label">RDATA · ${item.rdata.bytes.length} B</div><pre>${PH.esc(PH.bytesToHex(item.rdata.bytes))}</pre></div>` : "") +
          "</details>"
        : PH.esc(value);
      return `<tr><td><code>${PH.esc(item.name)}</code></td><td>${PH.esc(item.typeName)}</td><td>${PH.esc(item.className)}</td><td class="num">${item.ttl}</td><td class="num">${item.rdlength}</td><td>${detail}</td></tr>`;
    }).join("");
    return `<div class="decoded-head"><h3>${PH.esc(label)}</h3><span class="dim">${items.length} entr${items.length === 1 ? "y" : "ies"}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((header) => `<th>${header}</th>`).join("") +
      "</tr></thead><tbody>" + rows + "</tbody></table></div>";
  }

  function transportCallout(context) {
    if (!context || context.transport === "raw") {
      return '<div class="callout callout--warn"><div class="callout__title">raw DNS message</div><p>No IP or transport wrapper was supplied. The DNS bytes decode, but source and destination addresses, ports and transport checksums cannot be verified from this input alone.</p></div>';
    }
    const parts = [];
    if (context.src && context.dst) parts.push(`${PH.esc(context.src)} → ${PH.esc(context.dst)}`);
    if (context.srcPort != null) parts.push(`port ${context.srcPort} → ${context.dstPort}`);
    parts.push(context.transport);
    if (context.checksumState) parts.push("checksum " + PH.esc(context.checksumState));
    if (context.prefix != null) parts.push("TCP prefix " + context.prefix + " B");
    if (context.trailing) parts.push(context.trailing + " trailing byte(s) after the DNS message");
    const ethernet = context.ethernet
      ? ` · Ethernet ${PH.esc(context.ethernet.srcMac)} → ${PH.esc(context.ethernet.dstMac)}${context.ethernet.vlanTags && context.ethernet.vlanTags.length ? " · " + context.ethernet.vlanTags.length + " VLAN tag(s)" : ""}`
      : "";
    return `<div class="callout"><div class="callout__title">transport context</div><p>${parts.join(" · ")}${ethernet}. ${context.ip ? '<a href="ipv4.html">IPv4 explorer</a>' : context.ipv6 ? '<a href="ipv6.html">IPv6 explorer</a>' : ""} ${context.transport === "UDP" ? '<a href="udp.html">UDP explorer</a>' : context.transport === "TCP" ? '<a href="tcp.html">TCP explorer</a>' : ""}</p></div>`;
  }

  function renderDecoded(message, context, bytes, envelopeWarnings) {
    const host = document.getElementById("dns-decode-result");
    const pills = [
      pill("ID 0x" + PH.hex(message.id, 4)),
      pill(message.header.qr ? "response" : "query", message.header.qr ? "good" : null),
      pill(message.header.opcodeName),
      pill(message.header.effectiveRcodeName, message.header.effectiveRcode === 0 ? "good" : "warn"),
      pill("Q " + message.counts.questions + " · A " + message.counts.answers + " · NS " + message.counts.authority + " · AR " + message.counts.additional),
      pill(message.messageLength + " B")
    ];
    if (message.header.tc) pills.push(pill("TC truncated", "bad"));
    if (message.opt) pills.push(pill("EDNS(0) · " + message.opt.udpPayloadSize + " B" + (message.opt.do ? " · DO" : "")));
    if (context && context.transport !== "raw") pills.push(pill(context.transport + (context.srcPort != null ? " " + context.srcPort + " → " + context.dstPort : "")));

    const flagRows = [
      ["QR", message.header.qr + (message.header.qr ? " · response" : " · query")],
      ["Opcode", message.header.opcode + " · " + message.header.opcodeName],
      ["AA", message.header.aa + (message.header.aa ? " · authoritative" : "")],
      ["TC", message.header.tc + (message.header.tc ? " · truncated" : "")],
      ["RD / RA", message.header.rd + " / " + message.header.ra],
      ["Z", message.flags.z],
      ["AD / CD", message.header.ad + " / " + message.header.cd],
      ["RCODE", message.header.rcode + " · " + message.header.rcodeName],
      ["Effective RCODE", message.header.effectiveRcode + " · " + message.header.effectiveRcodeName]
    ];
    const headerTable = '<div class="decoded-head"><h3>Header</h3><span class="dim">flags 0x' + PH.hex(message.flagsRaw, 4) + ' · 12 bytes</span></div>' +
      '<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
      `<tr><td><b>ID</b></td><td><code>0x${PH.hex(message.id, 4)}</code> · ${message.id}</td><td>Matches response to query</td></tr>` +
      flagRows.map(([name, value]) => `<tr><td><b>${name}</b></td><td><code>${PH.esc(value)}</code></td><td class="small">—</td></tr>`).join("") +
      `<tr><td><b>QDCOUNT</b></td><td>${message.counts.questions}</td><td>Question section</td></tr>` +
      `<tr><td><b>ANCOUNT</b></td><td>${message.counts.answers}</td><td>Answer section</td></tr>` +
      `<tr><td><b>NSCOUNT</b></td><td>${message.counts.authority}</td><td>Authority section</td></tr>` +
      `<tr><td><b>ARCOUNT</b></td><td>${message.counts.additional}</td><td>Additional section</td></tr>` +
      "</tbody></table></div>";

    const sections = message.sections.map((section) =>
      sectionTable(section.label + " section", section.items, section.key === "questions")
    ).join("");

    const warnings = message.warnings.concat(envelopeWarnings || []);
    const warningBlock = warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean message</div><p>Counts, RDLENGTH values and compression pointers all agree. A clean parse does not prove the data is authentic; DNSSEC does that.</p></div>';

    host.innerHTML = '<div class="decode-summary">' + pills.join("") + "</div>" +
      '<div class="hexdump-wrap"><div class="hexdump-head"><span>DNS message</span><span>' + bytes.length + " B · header at +0</span></div>" +
      PH.hexdump(bytes, { highlight: [{ start: 0, end: Math.min(12, bytes.length) }] }) + "</div>" +
      headerTable + transportCallout(context) + sections +
      (message.opt ? '<div class="callout"><div class="callout__title">EDNS(0) OPT record</div><p>UDP payload size <b>' + message.opt.udpPayloadSize +
        " B</b> · extended RCODE " + message.opt.extRcode + " · version " + message.opt.version +
        " · DO " + message.opt.do + ". OPT is a pseudo-record in the additional section; it is never cached.</p></div>" : "") +
      warningBlock;
  }

  let lastDecode = null;

  function runDecode(showErrors) {
    const input = document.getElementById("dns-decode-input");
    const status = document.getElementById("dns-decode-status");
    const host = document.getElementById("dns-decode-result");
    const kind = document.getElementById("dns-decode-kind").value;
    let bytes;
    try {
      bytes = PH.parseHex(input.value);
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return null;
    }
    try {
      const envelope = decodeEnvelope(bytes, kind);
      const message = D.decodeMessage(envelope.dnsBytes, { allowLarge: true });
      renderDecoded(message, envelope.context, envelope.dnsBytes, []);
      updateDiagrams(message);
      lastDecode = { message, envelope, hex: PH.bytesToHex(bytes) };
      PH.setStatus(status,
        `${message.header.qr ? "response" : "query"} · ${message.header.effectiveRcodeName} · ` +
        `${message.counts.questions} question(s) · ${message.counts.answers} answer(s) · ` +
        `${message.messageLength} B${message.warnings.length ? " · " + message.warnings.length + " note(s)" : ""}`,
        message.warnings.length || message.header.effectiveRcode !== 0 ? "warn" : "ok");
      return lastDecode;
    } catch (err) {
      host.innerHTML = "";
      lastDecode = null;
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      return null;
    }
  }

  function loadExample(key) {
    const message = D.buildMessage(D.examples()[key]);
    document.getElementById("dns-decode-input").value = PH.bytesToHex(message.bytes);
    document.getElementById("dns-decode-kind").value = "dns";
    runDecode(true);
  }

  function decoderState() {
    return {
      page: "dns-dec",
      kind: document.getElementById("dns-decode-kind").value,
      hex: document.getElementById("dns-decode-input").value
    };
  }

  function initDecoder() {
    const run = document.getElementById("dns-decode");
    if (!run) return;
    run.addEventListener("click", () => runDecode(true));
    document.getElementById("dns-decode-query").addEventListener("click", () => loadExample("queryA"));
    document.getElementById("dns-decode-response").addEventListener("click", () => loadExample("responseA"));
    document.getElementById("dns-decode-nx").addEventListener("click", () => loadExample("nxdomain"));
    document.getElementById("dns-decode-clear").addEventListener("click", () => {
      document.getElementById("dns-decode-input").value = "";
      document.getElementById("dns-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("dns-decode-status"), "No DNS message decoded yet.", "");
    });
    document.getElementById("dns-decode-permalink").addEventListener("click", () => {
      const result = lastDecode || runDecode(true);
      if (result) PH.shareState(decoderState(), "DNS decoder permalink copied");
    });
    document.getElementById("dns-decode-export").addEventListener("click", () => {
      const result = lastDecode || runDecode(true);
      if (!result) return;
      PH.downloadText("dns-decoded.json", JSON.stringify({
        hex: result.hex,
        transport: sanitize(result.envelope.context),
        message: sanitize(result.message)
      }, null, 2), "application/json");
    });
    document.getElementById("dns-decode-input").addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runDecode(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state) return false;
    if (state.page === "dns-enc" && applyEncoderState(state)) {
      buildFromForm(true);
      return true;
    }
    if (state.page === "dns-dec") {
      document.getElementById("dns-decode-kind").value = state.kind || "auto";
      document.getElementById("dns-decode-input").value = state.hex || "";
      runDecode(true);
      return true;
    }
    return false;
  }

  function initResolution() {
    const flow = document.getElementById("dns-flow");
    if (!flow) return;

    const caption = document.getElementById("dns-flow-caption");
    const state = document.getElementById("dns-flow-state");
    const table = document.getElementById("dns-flow-table");
    const stubNote = document.getElementById("dns-node-stub-note");
    const resolverNote = document.getElementById("dns-node-resolver-note");
    const nodes = {};
    flow.querySelectorAll("[data-node]").forEach((node) => { nodes[node.dataset.node] = node; });
    const links = {};
    flow.querySelectorAll("[data-link]").forEach((link) => { links[link.dataset.link] = link; });
    const tokens = Array.from(flow.querySelectorAll("[data-token]"));

    function applyStep(index) {
      const step = DNS_STEPS[index - 1];
      caption.innerHTML = step.caption;
      state.textContent = step.state;
      state.className = step.stateClass;
      stubNote.textContent = step.stubNote;
      resolverNote.textContent = step.resolverNote;
      table.innerHTML =
        `<tr><td>answer</td><td>${step.answer}</td></tr>` +
        `<tr><td>TTL</td><td>${step.ttl}</td></tr>` +
        `<tr><td>cache</td><td>${step.cache}</td></tr>`;
      flow.classList.toggle("is-referral", step.mode === "is-referral");
      flow.classList.toggle("is-answer", step.mode === "is-answer");
      flow.classList.toggle("is-cached", step.mode === "is-cached");

      Object.keys(nodes).forEach((name) => {
        nodes[name].classList.toggle("is-active", step.active.includes(name));
        nodes[name].classList.toggle("is-match", step.match.includes(name));
      });

      Object.keys(links).forEach((name) => {
        links[name].classList.toggle("is-active", name === step.link);
      });

      tokens.forEach((token, i) => {
        const number = i + 1;
        if (number === index) {
          token.style.transform = `translate(${DNS_TOKEN_TARGET[number][0]}px, ${DNS_TOKEN_TARGET[number][1]}px)`;
          token.classList.add("is-visible");
        } else {
          token.classList.remove("is-visible");
          token.style.transform = `translate(${DNS_TOKEN_HOME[number][0]}px, ${DNS_TOKEN_HOME[number][1]}px)`;
        }
      });
    }

    PH.stepFlow({ root: flow, count: DNS_STEPS.length, onStep: applyStep });
  }

  function init() {
    if (!document.getElementById("dns-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    initResolution();
    if (!restoreState()) buildFromForm(false);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
