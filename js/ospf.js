/* OSPFv2 page: header diagram, Hello and LSA lanes, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const O = window.OSPFCodec;
  const RFC = "https://www.rfc-editor.org/rfc/rfc2328";

  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#ospf-diagram", {
      title: "<b>OSPFv2</b> · packet header", badge: "RFC 2328",
      fields: [
        { id: "version", name: "Version", bits: 8, value: "2", range: "2", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "OSPF version. 2 is OSPFv2 (IPv4). OSPFv3 uses version 3 and a different packet layout." },
        { id: "type", name: "Type", bits: 8, value: "1", range: "1–5", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "1 Hello, 2 Database Description, 3 Link State Request, 4 Link State Update, 5 Link State Ack." },
        { id: "length", name: "Packet Length", bits: 16, value: "44 B", range: "24–65535", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "Length of the OSPF packet in bytes, including the 24-byte header. It must not exceed the IP payload." },
        { id: "router", name: "Router ID", bits: 32, value: "192.0.2.1", range: "32-bit", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "32-bit identifier of the originating router, usually the highest loopback address or an explicit router-id." },
        { id: "area", name: "Area ID", bits: 32, value: "0.0.0.0", range: "32-bit", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "Area this packet belongs to. Area 0 is the backbone. The value is a 32-bit number displayed in dotted-quad form." },
        { id: "checksum", name: "Checksum", bits: 16, value: "0x0000", range: "16-bit", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "Internet checksum over the packet excluding the 64-bit authentication field. The checksum field itself is zeroed for the calculation." },
        { id: "autype", name: "AuType", bits: 16, value: "0", range: "0–2", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "0 null, 1 simple password, 2 cryptographic authentication. Authentication type 2 is defined further by RFC 5709 and related documents." },
        { id: "auth", name: "Authentication", bits: 64, value: "0", range: "8 B", rfc: "RFC 2328 §A.3.1", rfcUrl: RFC, desc: "Eight bytes interpreted according to AuType. For type 1 it is an eight-byte cleartext password; for type 2 it carries the key ID and digest." }
      ],
      inspector: "#ospf-inspector", table: "#ospf-fields",
      note: "The header is 24 bytes. Packet Length includes it. The authentication field is excluded from the OSPF checksum, so changing a password does not invalidate the checksum in the same way as changing a normal field."
    });
    PH.fieldTable("#ospf-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#ospf-hello-lane", {
      title: "<b>OSPF Hello</b> · body", badge: "type 1",
      fields: [
        { name: "Network Mask", bytes: 4, value: "255.255.255.0", range: "4 B", desc: "Subnet mask of the interface. Neighbours must agree on it on broadcast and NBMA networks.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "a" },
        { name: "Hello Interval", bytes: 2, value: "10 s", range: "1–65535", desc: "Seconds between Hello packets. Must match on both ends.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "b" },
        { name: "Options", bytes: 1, value: "E", range: "bit field", desc: "E, MC, NP, EA, DC, O, DN capability bits.", rfc: "RFC 2328 §A.2", rfcUrl: RFC, tone: "c" },
        { name: "Router Priority", bytes: 1, value: "1", range: "0–255", desc: "Used in DR/BDR election. Zero means the router is not eligible to become DR or BDR.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "d" },
        { name: "Dead Interval", bytes: 4, value: "40 s", range: "1–4294967295", desc: "Seconds before a silent neighbour is declared down. Normally four times the Hello interval.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "e" },
        { name: "Designated Router", bytes: 4, value: "192.0.2.1", range: "router ID", desc: "Router ID of the elected DR, or 0.0.0.0 if none is known.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "f" },
        { name: "Backup DR", bytes: 4, value: "0.0.0.0", range: "router ID", desc: "Router ID of the elected BDR, or 0.0.0.0.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "g" },
        { name: "Neighbours", bytes: "var", variable: true, range: "4 B each", desc: "Router IDs of all neighbours from which Hello packets were received recently.", rfc: "RFC 2328 §A.3.2", rfcUrl: RFC, tone: "h" }
      ],
      inspector: "#ospf-hello-inspector",
      note: "Hello bodies are 20 bytes before the neighbour list. All neighbours on the same segment must agree on area, mask, Hello/Dead intervals, authentication and options."
    });

    PH.byteLane("#ospf-lsa-lane", {
      title: "<b>LSA header</b> · 20 bytes", badge: "RFC 2328 §A.4.1",
      fields: [
        { name: "LS Age", bytes: 2, value: "0 s", range: "0–3600", desc: "Seconds since the LSA was originated. Incremented in the database; 3600 means MaxAge.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "a" },
        { name: "Options", bytes: 1, value: "E", range: "bit field", desc: "Capability bits. The E bit indicates external routing capability.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "b" },
        { name: "LS Type", bytes: 1, value: "1", range: "1–11", desc: "1 Router, 2 Network, 3/4 Summary, 5 AS External, 7 NSSA, 9–11 Opaque.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "c" },
        { name: "Link State ID", bytes: 4, value: "192.0.2.1", range: "32-bit", desc: "Identifies the object being described; meaning depends on LS Type.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "d" },
        { name: "Advertising Router", bytes: 4, value: "192.0.2.1", range: "router ID", desc: "Router that originated this LSA.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "e" },
        { name: "LS Sequence", bytes: 4, value: "0x80000001", range: "signed 32-bit", desc: "Starts at 0x80000001 and increases. A larger signed value is newer.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "f" },
        { name: "LS Checksum", bytes: 2, value: "0x0000", range: "16-bit", desc: "Checksum over this LSA only, excluding LS Age. Not the packet checksum.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "g" },
        { name: "Length", bytes: 2, value: "20 B", range: "20–65535", desc: "Length of the LSA header plus body in bytes.", rfc: "RFC 2328 §A.4.1", rfcUrl: RFC, tone: "h" }
      ],
      inspector: "#ospf-lsa-inspector",
      note: "The 20-byte header is followed by a type-specific body. The body length is Length minus 20."
    });
  }

  function parseNumber(value) {
    return PH.parseNumber(value);
  }

  function readEncoder() {
    const type = Number(document.getElementById("ospf-enc-type").value);
    const input = {
      type,
      routerId: document.getElementById("ospf-enc-router").value,
      areaId: document.getElementById("ospf-enc-area").value,
      authType: Number(document.getElementById("ospf-enc-auth").value),
      password: document.getElementById("ospf-enc-password").value,
      options: Number(document.getElementById("ospf-enc-options").value)
    };
    if (type === 1) {
      input.networkMask = document.getElementById("ospf-enc-mask").value;
      input.helloInterval = Number(document.getElementById("ospf-enc-hello").value);
      input.deadInterval = Number(document.getElementById("ospf-enc-dead").value);
      input.priority = Number(document.getElementById("ospf-enc-priority").value);
      input.designatedRouter = document.getElementById("ospf-enc-dr").value;
      input.backupRouter = document.getElementById("ospf-enc-bdr").value;
      input.neighbors = document.getElementById("ospf-enc-neighbors").value.split(/[\s,]+/).filter(Boolean);
    } else if (type === 2) {
      input.interfaceMtu = 1500;
      input.master = false; input.more = false; input.init = false;
      input.sequence = 1;
      input.lsas = [];
    } else if (type === 3) {
      input.requests = [];
    } else if (type === 4) {
      input.lsas = [{
        type: Number(document.getElementById("ospf-enc-lsa-type").value),
        linkStateId: document.getElementById("ospf-enc-lsa-id").value,
        advertisingRouter: document.getElementById("ospf-enc-lsa-router").value,
        sequence: parseNumber(document.getElementById("ospf-enc-lsa-seq").value),
        options: Number(document.getElementById("ospf-enc-options").value),
        age: 0,
        body: document.getElementById("ospf-enc-lsa-body").value
      }];
    } else {
      input.lsas = [];
    }
    return input;
  }

  function build(showErrors) {
    const status = document.getElementById("ospf-encode-status");
    const output = document.getElementById("ospf-enc-output");
    const tag = document.getElementById("ospf-enc-tag");
    const summary = document.getElementById("ospf-enc-summary");
    let result;
    try { result = O.buildOspf(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">type <b>${result.type}</b> · ${PH.esc(result.typeName)}</span>`,
      `<span class="pill">router <b>${PH.esc(result.routerId)}</b></span>`,
      `<span class="pill">area <b>${PH.esc(result.areaId)}</b></span>`,
      `<span class="pill">auth <b>${PH.esc(result.authTypeName)}</b></span>`,
      `<span class="pill pill--good">checksum <b>0x${PH.hex(result.checksum, 4)}</b></span>`
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte OSPF ${result.typeName} · area ${result.areaId} · checksum 0x${PH.hex(result.checksum, 4)}`, "ok");
    if (diagram) diagram.setValues({
      version: String(result.version), type: String(result.type), length: result.length + " B",
      router: result.routerId, area: result.areaId, checksum: "0x" + PH.hex(result.checksum, 4),
      autype: String(result.authType), auth: result.authType === 0 ? "0" : "set"
    });
    return result;
  }

  function encoderState() {
    const ids = ["ospf-enc-type", "ospf-enc-router", "ospf-enc-area", "ospf-enc-auth", "ospf-enc-password",
      "ospf-enc-mask", "ospf-enc-hello", "ospf-enc-dead", "ospf-enc-options", "ospf-enc-priority",
      "ospf-enc-dr", "ospf-enc-bdr", "ospf-enc-neighbors", "ospf-enc-lsa-type", "ospf-enc-lsa-id",
      "ospf-enc-lsa-router", "ospf-enc-lsa-seq", "ospf-enc-lsa-body"];
    const state = { page: "ospf-enc" };
    ids.forEach((id) => { const el = document.getElementById(id); if (el) state[id] = el.value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => {
      const el = document.getElementById(key);
      if (el) el.value = state[key];
    });
    build(true);
  }

  function initEncoder() {
    const type = document.getElementById("ospf-enc-type");
    if (!type) return;
    ["input", "change"].forEach((event) => document.querySelectorAll("#ospf-encode-form input, #ospf-encode-form select").forEach((el) => {
      el.addEventListener(event, () => build(false));
    }));
    document.getElementById("ospf-build").addEventListener("click", () => build(true));
    document.getElementById("ospf-example").addEventListener("click", () => {
      type.value = "1";
      document.getElementById("ospf-enc-neighbors").value = "192.0.2.2";
      build(true);
    });
    document.getElementById("ospf-permalink").addEventListener("click", () => {
      if (build(true)) PH.shareState(encoderState(), "OSPF encoder permalink copied");
    });
    document.getElementById("ospf-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("ospf-packet.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes), type: result.type, typeName: result.typeName,
        routerId: result.routerId, areaId: result.areaId, checksum: "0x" + PH.hex(result.checksum, 4),
        length: result.bytes.length, input: readEncoder()
      }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    if (!rows.length) return "";
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") +
      "</tbody></table></div>";
  }

  function lsaRows(lsas) {
    return lsas.map((lsa, i) => [
      `<b>${i + 1}</b>`, `<code>${lsa.type}</code> · ${PH.esc(lsa.typeName)}`,
      `<code>${PH.esc(lsa.linkStateIdText)}</code>`, `<code>${PH.esc(lsa.advertisingRouterText)}</code>`,
      `<code>0x${PH.hex(lsa.sequence, 8)}</code>`, `${lsa.age} s`, `${lsa.length} B`,
      lsa.body && lsa.body.metric != null ? `<code>${lsa.body.metric}</code>` : "—"
    ]);
  }

  function checksumPill(packet) {
    if (packet.checksumState === "valid") return '<span class="pill pill--good">checksum valid</span>';
    if (packet.checksumState === "invalid") return '<span class="pill pill--bad">checksum invalid</span>';
    return '<span class="pill pill--warn">checksum absent</span>';
  }

  function render(packet) {
    const host = document.getElementById("ospf-decode-result");
    const pills = [
      `<span class="pill">type <b>${packet.type}</b> · ${PH.esc(packet.typeName)}</span>`,
      `<span class="pill">router <b>${PH.esc(packet.routerId)}</b></span>`,
      `<span class="pill">area <b>${PH.esc(packet.areaId)}</b></span>`,
      checksumPill(packet),
      `<span class="pill">${packet.bytes.length} B</span>`
    ];
    const headerRows = [
      ["Version", "8", "0–7", packet.version, packet.version === 2 ? "OSPFv2" : "not OSPFv2"],
      ["Type", "8", "8–15", `${packet.type} · ${packet.typeName}`, "packet kind"],
      ["Packet Length", "16", "16–31", packet.length + " B", packet.length === packet.bytes.length ? "matches captured bytes" : "captured " + packet.bytes.length + " B"],
      ["Router ID", "32", "32–63", packet.routerId, "origin"],
      ["Area ID", "32", "64–95", packet.areaId, "area"],
      ["Checksum", "16", "96–111", "0x" + PH.hex(packet.checksum, 4), packet.checksumState],
      ["AuType", "16", "112–127", packet.authType + " · " + packet.authTypeName, "authentication"],
      ["Authentication", "64", "128–191", PH.bytesToHex(packet.auth) || "—", "excluded from checksum"]
    ];
    let extra = "";
    if (packet.hello) {
      extra += detailTable("Hello body", "neighbour discovery and DR election", ["Field", "Value"], [
        ["Network mask", `<code>${PH.esc(packet.hello.networkMask)}</code>`],
        ["Hello interval", `<code>${packet.hello.helloInterval} s</code>`],
        ["Dead interval", `<code>${packet.hello.deadInterval} s</code>`],
        ["Options", `<code>${packet.hello.options} · ${PH.esc(packet.hello.optionNames.join(" ")) || "none"}</code>`],
        ["Router priority", `<code>${packet.hello.priority}</code>`],
        ["Designated router", `<code>${PH.esc(packet.hello.designatedRouter)}</code>`],
        ["Backup DR", `<code>${PH.esc(packet.hello.backupRouter)}</code>`],
        ["Neighbours", `<code>${packet.hello.neighbors.length ? packet.hello.neighbors.map(PH.esc).join(", ") : "none"}</code>`]
      ]);
    }
    if (packet.dd) {
      extra += detailTable("Database Description", "I/M/MS flags and LSA headers", ["Field", "Value"], [
        ["Interface MTU", `<code>${packet.dd.interfaceMtu}</code>`],
        ["Options", `<code>${packet.dd.options} · ${PH.esc(packet.dd.optionNames.join(" ")) || "none"}</code>`],
        ["Flags", `<code>${packet.dd.init ? "I " : ""}${packet.dd.more ? "M " : ""}${packet.dd.master ? "MS" : ""}</code>`],
        ["DD sequence", `<code>0x${PH.hex(packet.dd.sequence, 8)}</code>`],
        ["LSA headers", `<code>${packet.dd.lsas.length}</code>`]
      ]);
      if (packet.dd.lsas.length) extra += detailTable("DD LSA headers", "summaries only; bodies are not present", ["#", "Type", "Link State ID", "Advertising router", "Sequence", "Age", "Length", "Metric"], lsaRows(packet.dd.lsas));
    }
    if (packet.requests) {
      extra += detailTable("Link State Requests", "full LSAs the neighbour should send", ["Type", "Link State ID", "Advertising router"],
        packet.requests.map((r) => [`<code>${r.type}</code> · ${PH.esc(r.typeName)}`, `<code>${PH.esc(r.linkStateId)}</code>`, `<code>${PH.esc(r.advertisingRouter)}</code>`]));
    }
    if (packet.update) {
      extra += detailTable("Link State Update", `${packet.update.count} LSA(s) declared`, ["#", "Type", "Link State ID", "Advertising router", "Sequence", "Age", "Length", "Metric"], lsaRows(packet.update.lsas));
      packet.update.lsas.forEach((lsa, index) => {
        if (lsa.type === 1 && lsa.body && lsa.body.links) {
          extra += detailTable("Router LSA " + (index + 1) + " links", "Router ID " + lsa.linkStateIdText,
            ["Link ID", "Link data", "Type", "Metric"],
            lsa.body.links.map((link) => [`<code>${PH.esc(link.linkId)}</code>`, `<code>${PH.esc(link.linkData)}</code>`, PH.esc(link.typeName), `<code>${link.metric}</code>`]));
        } else if (lsa.type === 2 && lsa.body && lsa.body.attachedRouters) {
          extra += detailTable("Network LSA " + (index + 1), "attached routers",
            ["Network mask", "Attached routers"],
            [[`<code>${PH.esc(lsa.body.networkMask || "—")}</code>`, `<code>${lsa.body.attachedRouters.map(PH.esc).join(", ") || "none"}</code>`]]);
        }
      });
    }
    if (packet.acks) {
      extra += detailTable("Link State Acknowledgments", `${packet.acks.length} LSA header(s)`, ["#", "Type", "Link State ID", "Advertising router", "Sequence", "Age", "Length", "Metric"], lsaRows(packet.acks));
    }
    const warnings = packet.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + packet.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean framing</div><p>The header, packet length and checksum agree. Adjacency state and LSA freshness are separate questions.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>OSPFv2 ${PH.esc(packet.typeName)}</span><span>${packet.bytes.length} B</span></div>${PH.hexdump(packet.bytes, { highlight: [{ start: 0, end: 24 }] })}</div>` +
      detailTable("OSPF header", "offsets relative to the OSPF header", ["Field", "Bits", "Offset", "Value", "Note"],
        headerRows.map(([a, b, c, d, e]) => [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${PH.esc(d)}</code>`, `<span class="small">${PH.esc(e)}</span>`])) +
      extra + warnings;
    if (diagram) diagram.setValues({
      version: String(packet.version), type: String(packet.type), length: packet.length + " B",
      router: packet.routerId, area: packet.areaId, checksum: "0x" + PH.hex(packet.checksum, 4),
      autype: String(packet.authType), auth: packet.authType === 0 ? "0" : "set"
    });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("ospf-decode-input");
    const status = document.getElementById("ospf-decode-status");
    const host = document.getElementById("ospf-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    let packet;
    try { packet = O.decodeOspf(bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(packet);
    PH.setStatus(status, `${packet.typeName} · area ${packet.areaId} · ${packet.bytes.length} B · checksum ${packet.checksumState}${packet.warnings.length ? " · " + packet.warnings.length + " note(s)" : ""}`,
      packet.checksumState === "invalid" ? "bad" : packet.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("ospf-decode-input");
    if (!input) return;
    document.getElementById("ospf-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("ospf-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("ospf-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("ospf-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("ospf-decode-example").addEventListener("click", () => {
      const packet = O.buildOspf({
        type: 1, routerId: "192.0.2.1", areaId: "0.0.0.0", networkMask: "255.255.255.0",
        helloInterval: 10, deadInterval: 40, priority: 1, designatedRouter: "192.0.2.1",
        backupRouter: "0.0.0.0", neighbors: ["192.0.2.2"], options: 2
      });
      input.value = PH.bytesToHex(packet.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "ospf-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("ospf-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
