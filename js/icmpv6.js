/* ICMPv6 page: message layout, ND options, RA fields, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const C = window.ICMPv6Codec;
  const V6 = window.IPv6Codec;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc4443",
    nd: "https://www.rfc-editor.org/rfc/rfc4861",
    slaac: "https://www.rfc-editor.org/rfc/rfc4862",
    ipv6: "https://www.rfc-editor.org/rfc/rfc8200"
  };

  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#icmpv6-diagram", {
      title: "<b>ICMPv6</b> · message header", badge: "RFC 4443",
      fields: [
        { id: "type", name: "Type", bits: 8, range: "0–255", rfc: "RFC 4443 §2.1", rfcUrl: RFC.base, desc: "Message type. Error types are 1–4, echo is 128/129, and Neighbor Discovery is 133–137. The type decides the body layout." },
        { id: "code", name: "Code", bits: 8, range: "0–255", rfc: "RFC 4443 §2.1", rfcUrl: RFC.base, desc: "Sub-type within the message type. Most types define only code 0; Destination Unreachable, Time Exceeded and Parameter Problem use several codes." },
        { id: "checksum", name: "Checksum", bits: 8, range: "16-bit", rfc: "RFC 4443 §2.3", rfcUrl: RFC.base, desc: "One's-complement checksum over the IPv6 pseudo-header, this header and the body. IPv6 makes it mandatory." },
        { id: "body", name: "Message Body", bits: "var", varWidth: 32, range: "type-specific", rfc: "RFC 4443 · RFC 4861", rfcUrl: RFC.nd, desc: "Type-specific fields and, for ND, an option TLV chain. Error messages quote the beginning of the invoking packet." }
      ],
      inspector: "#icmpv6-inspector", table: "#icmpv6-fields",
      note: "The first four bytes are fixed. Everything after them depends on Type: echo identifier/sequence, a 32-bit MTU or pointer, a reserved word before a target address, or RA lifetimes. Bit 0 is the MSB of Type."
    });
    PH.fieldTable("#icmpv6-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#icmpv6-nd-lane", {
      title: "<b>Neighbor Discovery option</b> · TLV", badge: "RFC 4861",
      fields: [
        { name: "Type", bytes: 1, value: "1–38", range: "1–38", desc: "Option type: 1 source link-layer address, 2 target link-layer address, 3 prefix information, 5 MTU, 25 RDNSS.", rfc: "RFC 4861 §4.6", rfcUrl: RFC.nd, tone: "a" },
        { name: "Length", bytes: 1, value: "× 8 B", range: "1–255", desc: "Length in units of eight bytes, including the Type and Length bytes. A length of 0 is malformed; 1 means eight bytes total.", rfc: "RFC 4861 §4.6", rfcUrl: RFC.nd, tone: "b" },
        { name: "Option Data", bytes: "var", variable: true, range: "length × 8 − 2 B", desc: "Type-specific value. A link-layer address option carries the six-byte MAC directly after the header; Prefix Information carries lifetimes and a 16-byte prefix.", rfc: "RFC 4861 §4.6", rfcUrl: RFC.nd, tone: "c" }
      ],
      inspector: "#icmpv6-nd-inspector",
      note: "The Length field counts eight-byte units. A 32-byte Prefix Information option therefore has Length 4, not 32. Options are not padded individually beyond this eight-byte rule."
    });

    PH.byteLane("#icmpv6-ra-lane", {
      title: "<b>Router Advertisement</b> · fixed body", badge: "type 134",
      fields: [
        { name: "Cur Hop Limit", bytes: 1, value: "64", range: "0–255", desc: "Default hop limit hosts should place in outgoing packets. Zero means unspecified.", rfc: "RFC 4861 §4.2", rfcUrl: RFC.nd, tone: "a" },
        { name: "Flags", bytes: 1, value: "M/O", range: "M O H Prf P", desc: "M = managed address configuration (DHCPv6), O = other configuration, H = home agent, Prf = default-router preference, P = ND proxy.", rfc: "RFC 4861 §4.2 · RFC 4191", rfcUrl: RFC.nd, tone: "b" },
        { name: "Router Lifetime", bytes: 2, value: "1800 s", range: "0–65535 s", desc: "How long the router may be used as a default router. Zero means the router is not a default router.", rfc: "RFC 4861 §4.2", rfcUrl: RFC.nd, tone: "c" },
        { name: "Reachable Time", bytes: 4, value: "0", range: "ms", desc: "Time a neighbour is considered reachable after a positive confirmation. Zero means unspecified; hosts may use a base value.", rfc: "RFC 4861 §4.2", rfcUrl: RFC.nd, tone: "d" },
        { name: "Retrans Timer", bytes: 4, value: "0", range: "ms", desc: "Retransmission interval for Neighbor Solicitation. Zero means unspecified.", rfc: "RFC 4861 §4.2", rfcUrl: RFC.nd, tone: "e" },
        { name: "Options", bytes: "var", variable: true, range: "ND TLVs", desc: "Source link-layer address, MTU, Prefix Information, Route Information, RDNSS, DNSSL and others.", rfc: "RFC 4861 §4.6", rfcUrl: RFC.nd, tone: "f" }
      ],
      inspector: "#icmpv6-ra-inspector",
      note: "Router Advertisements are sent from the link-local address of the router. The fixed body is 12 bytes, followed by options."
    });
  }

  const TYPE_CHOICES = [
    [1, "1 · Destination Unreachable"], [2, "2 · Packet Too Big"], [3, "3 · Time Exceeded"],
    [4, "4 · Parameter Problem"], [128, "128 · Echo Request"], [129, "129 · Echo Reply"],
    [130, "130 · MLD Query"], [131, "131 · MLD Report"], [132, "132 · MLD Done"],
    [133, "133 · Router Solicitation"], [134, "134 · Router Advertisement"],
    [135, "135 · Neighbor Solicitation"], [136, "136 · Neighbor Advertisement"],
    [137, "137 · Redirect"], [143, "143 · MLDv2 Report"]
  ];

  function populateTypes() {
    const select = document.getElementById("icmpv6-enc-type");
    if (!select) return;
    select.innerHTML = TYPE_CHOICES.map(([value, label]) => `<option value="${value}">${label}</option>`).join("");
    select.value = "128";
  }

  function show(id, visible) {
    const el = document.getElementById(id);
    if (!el) return;
    const field = el.closest(".form-field") || el.parentNode;
    if (field) field.hidden = !visible;
  }

  function syncFields() {
    const type = Number(document.getElementById("icmpv6-enc-type").value);
    const echo = type === 128 || type === 129;
    const ndTarget = type === 135 || type === 136;
    const ra = type === 134;
    const rs = type === 133;
    show("icmpv6-enc-id", echo);
    show("icmpv6-enc-seq", echo);
    show("icmpv6-enc-mtu", type === 2);
    show("icmpv6-enc-pointer", type === 4);
    show("icmpv6-enc-target-group", ndTarget);
    show("icmpv6-enc-curhop", ra);
    show("icmpv6-enc-router-life", ra);
    show("icmpv6-enc-reach", ra);
    show("icmpv6-enc-retrans", ra);
    show("icmpv6-enc-prefix", ra);
    show("icmpv6-enc-prefixlen", ra);
    document.getElementById("icmpv6-enc-opt-slla").closest("label").hidden = !(ra || rs || ndTarget);
    document.getElementById("icmpv6-enc-opt-prefix").closest("label").hidden = !ra;
    document.getElementById("icmpv6-enc-opt-mtu").closest("label").hidden = !ra;
    const code = document.getElementById("icmpv6-enc-code");
    code.disabled = false;
  }

  function optionList(type) {
    const options = [];
    const slla = document.getElementById("icmpv6-enc-opt-slla");
    if (slla && !slla.closest("label").hidden && slla.checked) {
      options.push({ kind: type === 136 ? "tlla" : "slla", mac: "02:00:00:00:00:01" });
    }
    const prefix = document.getElementById("icmpv6-enc-opt-prefix");
    if (prefix && !prefix.closest("label").hidden && prefix.checked) {
      options.push({
        kind: "prefix",
        prefix: document.getElementById("icmpv6-enc-prefix").value,
        prefixLength: Number(document.getElementById("icmpv6-enc-prefixlen").value),
        onLink: true, autonomous: true, validLifetime: 2592000, preferredLifetime: 604800
      });
    }
    const mtu = document.getElementById("icmpv6-enc-opt-mtu");
    if (mtu && !mtu.closest("label").hidden && mtu.checked) {
      options.push({ kind: "mtu", mtu: 1500 });
    }
    return options;
  }

  function readEncoder() {
    const type = Number(document.getElementById("icmpv6-enc-type").value);
    const input = {
      type,
      code: Number(document.getElementById("icmpv6-enc-code").value),
      src: document.getElementById("icmpv6-enc-src").value,
      dst: document.getElementById("icmpv6-enc-dst").value,
      data: document.getElementById("icmpv6-enc-data").value,
      options: optionList(type)
    };
    if (type === 128 || type === 129) {
      input.identifier = Number(document.getElementById("icmpv6-enc-id").value);
      input.sequence = Number(document.getElementById("icmpv6-enc-seq").value);
    } else if (type === 2) {
      input.mtu = Number(document.getElementById("icmpv6-enc-mtu").value);
    } else if (type === 4) {
      input.pointer = Number(document.getElementById("icmpv6-enc-pointer").value);
    } else if (type === 135 || type === 136) {
      input.target = document.getElementById("icmpv6-enc-target").value;
      input.router = document.getElementById("icmpv6-enc-router").checked;
      input.solicited = document.getElementById("icmpv6-enc-solicited").checked;
      input.override = document.getElementById("icmpv6-enc-override").checked;
    } else if (type === 134) {
      input.curHopLimit = Number(document.getElementById("icmpv6-enc-curhop").value);
      input.managed = document.getElementById("icmpv6-enc-managed").checked;
      input.other = document.getElementById("icmpv6-enc-other").checked;
      input.routerLifetime = Number(document.getElementById("icmpv6-enc-router-life").value);
      input.reachableTime = Number(document.getElementById("icmpv6-enc-reach").value);
      input.retransTimer = Number(document.getElementById("icmpv6-enc-retrans").value);
    }
    return input;
  }

  function build(showErrors) {
    const status = document.getElementById("icmpv6-encode-status");
    const output = document.getElementById("icmpv6-enc-output");
    const tag = document.getElementById("icmpv6-enc-tag");
    const summary = document.getElementById("icmpv6-enc-summary");
    let result;
    try {
      result = C.buildIcmpv6(readEncoder());
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    const nd = result.type >= 133 && result.type <= 137;
    summary.innerHTML = [
      `<span class="pill">type <b>${result.type}</b> · ${PH.esc(result.typeName)}</span>`,
      `<span class="pill">code <b>${result.code}</b>${result.codeName ? " · " + PH.esc(result.codeName) : ""}</span>`,
      `<span class="pill ${result.checksumState === "built" ? "pill--good" : "pill--warn"}">checksum <b>${result.checksumState === "built" ? "0x" + PH.hex(result.checksum, 4) : "unset"}</b></span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      nd ? '<span class="pill">Neighbor Discovery</span>' : ""
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte ${result.typeName} · code ${result.code} · checksum ${result.checksumState === "built" ? "0x" + PH.hex(result.checksum, 4) : "not computed"}`,
      result.checksumState === "built" ? "ok" : "warn");
    if (diagram) {
      diagram.setValues({
        type: String(result.type), code: String(result.code),
        checksum: result.checksumState === "built" ? "0x" + PH.hex(result.checksum, 4) : "unset",
        body: (result.bytes.length - 4) + " B"
      });
    }
    return result;
  }

  function encoderState() {
    return {
      page: "icmpv6-enc",
      type: document.getElementById("icmpv6-enc-type").value,
      code: document.getElementById("icmpv6-enc-code").value,
      src: document.getElementById("icmpv6-enc-src").value,
      dst: document.getElementById("icmpv6-enc-dst").value,
      data: document.getElementById("icmpv6-enc-data").value,
      id: document.getElementById("icmpv6-enc-id").value,
      seq: document.getElementById("icmpv6-enc-seq").value,
      mtu: document.getElementById("icmpv6-enc-mtu").value,
      pointer: document.getElementById("icmpv6-enc-pointer").value,
      target: document.getElementById("icmpv6-enc-target").value,
      curhop: document.getElementById("icmpv6-enc-curhop").value,
      life: document.getElementById("icmpv6-enc-router-life").value,
      reach: document.getElementById("icmpv6-enc-reach").value,
      retrans: document.getElementById("icmpv6-enc-retrans").value,
      prefix: document.getElementById("icmpv6-enc-prefix").value,
      prefixlen: document.getElementById("icmpv6-enc-prefixlen").value,
      managed: document.getElementById("icmpv6-enc-managed").checked,
      other: document.getElementById("icmpv6-enc-other").checked,
      router: document.getElementById("icmpv6-enc-router").checked,
      solicited: document.getElementById("icmpv6-enc-solicited").checked,
      override: document.getElementById("icmpv6-enc-override").checked,
      optSlla: document.getElementById("icmpv6-enc-opt-slla").checked,
      optPrefix: document.getElementById("icmpv6-enc-opt-prefix").checked,
      optMtu: document.getElementById("icmpv6-enc-opt-mtu").checked
    };
  }

  function applyEncoderState(state) {
    if (!state) return;
    const set = (id, value) => { const el = document.getElementById(id); if (el && value != null) el.value = value; };
    set("icmpv6-enc-type", state.type);
    set("icmpv6-enc-code", state.code);
    set("icmpv6-enc-src", state.src);
    set("icmpv6-enc-dst", state.dst);
    set("icmpv6-enc-data", state.data);
    set("icmpv6-enc-id", state.id);
    set("icmpv6-enc-seq", state.seq);
    set("icmpv6-enc-mtu", state.mtu);
    set("icmpv6-enc-pointer", state.pointer);
    set("icmpv6-enc-target", state.target);
    set("icmpv6-enc-curhop", state.curhop);
    set("icmpv6-enc-router-life", state.life);
    set("icmpv6-enc-reach", state.reach);
    set("icmpv6-enc-retrans", state.retrans);
    set("icmpv6-enc-prefix", state.prefix);
    set("icmpv6-enc-prefixlen", state.prefixlen);
    const check = (id, value) => { const el = document.getElementById(id); if (el) el.checked = !!value; };
    check("icmpv6-enc-managed", state.managed);
    check("icmpv6-enc-other", state.other);
    check("icmpv6-enc-router", state.router);
    check("icmpv6-enc-solicited", state.solicited);
    check("icmpv6-enc-override", state.override);
    check("icmpv6-enc-opt-slla", state.optSlla);
    check("icmpv6-enc-opt-prefix", state.optPrefix);
    check("icmpv6-enc-opt-mtu", state.optMtu);
    syncFields();
    build(true);
  }

  function initEncoder() {
    const type = document.getElementById("icmpv6-enc-type");
    if (!type) return;
    populateTypes();
    type.addEventListener("change", () => { syncFields(); build(false); });
    document.querySelectorAll("#icmpv6-encode-form input, #icmpv6-encode-form select").forEach((el) => {
      el.addEventListener("input", () => build(false));
      el.addEventListener("change", () => build(false));
    });
    document.getElementById("icmpv6-build").addEventListener("click", () => build(true));
    document.getElementById("icmpv6-example").addEventListener("click", () => {
      type.value = "128";
      document.getElementById("icmpv6-enc-code").value = "0";
      document.getElementById("icmpv6-enc-id").value = "4660";
      document.getElementById("icmpv6-enc-seq").value = "1";
      document.getElementById("icmpv6-enc-data").value = "de ad be ef";
      syncFields();
      build(true);
    });
    document.getElementById("icmpv6-permalink").addEventListener("click", () => {
      if (build(true)) PH.shareState(encoderState(), "ICMPv6 encoder permalink copied");
    });
    document.getElementById("icmpv6-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("icmpv6-message.json", JSON.stringify({
        hex: PH.bytesToHex(result.bytes),
        type: result.type, typeName: result.typeName, code: result.code,
        checksum: "0x" + PH.hex(result.checksum, 4), checksumState: result.checksumState,
        length: result.bytes.length, input: readEncoder()
      }, null, 2), "application/json");
    });
    syncFields();
    build(false);
  }

  function addrText(bytes) {
    return V6 ? V6.formatIPv6(bytes) : PH.bytesToHex(bytes);
  }

  function detailTable(title, hint, headers, rows) {
    if (!rows.length) return "";
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") +
      "</tbody></table></div>";
  }

  function optionRows(options) {
    return options.map((opt, index) => {
      const details = opt.fields && opt.fields.length
        ? opt.fields.map(([k, v]) => `${PH.esc(k)}: <code>${PH.esc(v)}</code>`).join("<br>")
        : `<code>${PH.esc(PH.bytesToHex(opt.raw || new Uint8Array(0)))}</code>`;
      return [
        `<b>${index + 1}</b>`,
        `${opt.type} · ${PH.esc(opt.name)}`,
        `${opt.length} B`,
        details
      ];
    });
  }

  function checksumPill(result) {
    if (result.checksumState === "valid") return '<span class="pill pill--good">checksum valid</span>';
    if (result.checksumState === "invalid") return '<span class="pill pill--bad">checksum invalid</span>';
    return '<span class="pill pill--warn">checksum not checked</span>';
  }

  function render(result) {
    const host = document.getElementById("icmpv6-decode-result");
    const d = result.details || {};
    const pills = [
      `<span class="pill">type <b>${result.type}</b> · ${PH.esc(result.typeName)}</span>`,
      `<span class="pill">code <b>${result.code}</b>${result.codeName ? " · " + PH.esc(result.codeName) : ""}</span>`,
      checksumPill(result),
      `<span class="pill">${result.bytes.length} B</span>`,
      result.nd ? '<span class="pill">ND message</span>' : ""
    ];
    const rows = [
      ["Type", "8", "0–7", `${result.type} · ${PH.esc(result.typeName)}`, "message kind"],
      ["Code", "8", "8–15", `${result.code}${result.codeName ? " · " + PH.esc(result.codeName) : ""}`, "sub-type"],
      ["Checksum", "16", "16–31", "0x" + PH.hex(result.checksum, 4), result.checksumState],
      ["Body", String(Math.max(0, (result.bytes.length - 4) * 8)), "32–…", `${result.bytes.length - 4} B`, "type-specific"]
    ];
    let extra = "";
    if (result.type === 128 || result.type === 129) {
      extra += detailTable("echo fields", "identifier and sequence", ["Field", "Value"],
        [["Identifier", `<code>${d.identifier == null ? "—" : d.identifier}</code>`],
         ["Sequence", `<code>${d.sequence == null ? "—" : d.sequence}</code>`],
         ["Data", `<code>${d.data ? d.data.length + " B" : "0 B"}</code>`]]);
    } else if (result.type === 2) {
      extra += detailTable("packet too big", "the MTU the sender must use", ["Field", "Value"],
        [["Next-hop MTU", `<code>${d.mtu == null ? "—" : d.mtu}</code>`],
         ["Quoted packet", `<code>${d.quoted ? d.quoted.length + " B" : "0 B"}</code>`]]);
    } else if (result.type === 4) {
      extra += detailTable("parameter problem", "offset of the problem", ["Field", "Value"],
        [["Pointer", `<code>${d.pointer == null ? "—" : d.pointer}</code>`],
         ["Quoted packet", `<code>${d.quoted ? d.quoted.length + " B" : "0 B"}</code>`]]);
    } else if (result.type === 134) {
      extra += detailTable("router advertisement", "default-router state", ["Field", "Value"],
        [["Current hop limit", `<code>${d.curHopLimit == null ? "—" : d.curHopLimit}</code>`],
         ["Managed (M)", `<code>${d.managed ? "1" : "0"}</code>`],
         ["Other (O)", `<code>${d.other ? "1" : "0"}</code>`],
         ["Router lifetime", `<code>${d.routerLifetime == null ? "—" : d.routerLifetime + " s"}</code>`],
         ["Reachable time", `<code>${d.reachableTime == null ? "—" : d.reachableTime + " ms"}</code>`],
         ["Retrans timer", `<code>${d.retransTimer == null ? "—" : d.retransTimer + " ms"}</code>`]]);
    } else if (result.type === 135 || result.type === 136) {
      const flags = result.type === 136
        ? [d.router ? "R" : "", d.solicited ? "S" : "", d.override ? "O" : ""].filter(Boolean).join(" ") || "none"
        : "—";
      extra += detailTable("neighbor discovery", "target and flags", ["Field", "Value"],
        [["Target", `<code>${PH.esc(d.target || "—")}</code>`],
         ["Flags", `<code>${PH.esc(flags)}</code>`]]);
    } else if (result.type === 137) {
      extra += detailTable("redirect", "better first hop", ["Field", "Value"],
        [["Target", `<code>${PH.esc(d.target || "—")}</code>`],
         ["Destination", `<code>${PH.esc(d.destination || "—")}</code>`]]);
    }
    if (d.options && d.options.length) {
      extra += detailTable("ND options", `${d.options.length} option(s)`, ["#", "Option", "Length", "Fields"], optionRows(d.options));
    }
    const quoted = result.quoted && result.quoted.length
      ? '<div class="hexdump-wrap"><div class="hexdump-head"><span>quoted invoking packet</span><span>' + result.quoted.length + ' B</span></div>' + PH.hexdump(result.quoted.subarray(0, Math.min(96, result.quoted.length))) + "</div>"
      : "";
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean structure</div><p>Type, code, length and checksum context agree. A clean parse does not authenticate the sender.</p></div>';
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>ICMPv6 message</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes, { highlight: [{ start: 0, end: 4 }] })}</div>` +
      detailTable("message header", "offsets relative to the ICMPv6 header", ["Field", "Bits", "Offset", "Value", "Note"], rows.map(([a, b, c, e, f]) =>
        [`<b>${PH.esc(a)}</b>`, `<span class="num">${PH.esc(b)}</span>`, `<span class="num">${PH.esc(c)}</span>`, `<code>${e}</code>`, `<span class="small">${PH.esc(f)}</span>`])) +
      extra + quoted + warnings;
    if (diagram) {
      diagram.setValues({
        type: String(result.type), code: String(result.code),
        checksum: "0x" + PH.hex(result.checksum, 4),
        body: (result.bytes.length - 4) + " B"
      });
    }
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("icmpv6-decode-input");
    const status = document.getElementById("icmpv6-decode-status");
    const host = document.getElementById("icmpv6-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    const src = document.getElementById("icmpv6-decode-src").value.trim();
    const dst = document.getElementById("icmpv6-decode-dst").value.trim();
    const context = src && dst ? { src, dst } : {};
    let result;
    try { result = C.decodeIcmpv6(bytes, context); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result);
    PH.setStatus(status, `${result.typeName} · code ${result.code} · ${result.bytes.length} B · checksum ${result.checksumState}${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.checksumState === "invalid" ? "bad" : result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("icmpv6-decode-input");
    if (!input) return;
    document.getElementById("icmpv6-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("icmpv6-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("icmpv6-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("icmpv6-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("icmpv6-decode-example").addEventListener("click", () => {
      const example = C.buildIcmpv6({ type: 128, code: 0, identifier: 4660, sequence: 1, data: "de ad be ef", src: "2001:db8::1", dst: "2001:db8::2" });
      input.value = PH.bytesToHex(example.bytes);
      document.getElementById("icmpv6-decode-src").value = "2001:db8::1";
      document.getElementById("icmpv6-decode-dst").value = "2001:db8::2";
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state) return;
    if (state.page === "icmpv6-enc") { applyEncoderState(state); return; }
    if (state.page === "icmpv6-dec") {
      document.getElementById("icmpv6-decode-input").value = state.hex || "";
      document.getElementById("icmpv6-decode-src").value = state.src || "";
      document.getElementById("icmpv6-decode-dst").value = state.dst || "";
      decodeRun(true);
    }
  }

  function init() {
    if (!document.getElementById("icmpv6-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
