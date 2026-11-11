/* ARP explorer — message layout, Ethernet wrapper, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const E = window.EthernetCodec;
  const A = window.ARPCodec;

  const fields = [
    { id: "htype", name: "Hardware Type", bits: 16, range: "1 = Ethernet", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "Link-layer hardware type. Ethernet is <code>1</code>. The IANA ARP parameters registry assigns other values for Frame Relay, ATM and experimental media." },
    { id: "ptype", name: "Protocol Type", bits: 16, range: "0x0800 = IPv4", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "Network-layer protocol being resolved. For IPv4 over Ethernet this is <code>0x0800</code>, the same value as the Ethernet EtherType." },
    { id: "hlen", name: "Hardware Length", bits: 8, range: "6 for Ethernet", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "Length in bytes of each hardware address. Ethernet MAC addresses are 6 bytes, so a normal value is <code>6</code>." },
    { id: "plen", name: "Protocol Length", bits: 8, range: "4 for IPv4", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "Length in bytes of each protocol address. IPv4 addresses are 4 bytes, so a normal value is <code>4</code>. A parser must use this rather than assuming 4." },
    { id: "oper", name: "Opcode", bits: 16, range: "1 request · 2 reply", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "Operation: <code>1</code> request, <code>2</code> reply. RARP and InARP reuse the same format with opcodes 3, 4, 8 and 9." },
    { id: "sha", name: "Sender Hardware Address", bits: 48, range: "6 B · MAC", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "The sender's hardware address. This is the MAC address the receiver learns for the sender IP, subject to the ARP cache policy." },
    { id: "spa", name: "Sender Protocol Address", bits: 32, range: "4 B · IPv4", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "The sender's protocol address. In an ARP probe this is deliberately <code>0.0.0.0</code> so the sender does not claim an address before checking for conflicts." },
    { id: "tha", name: "Target Hardware Address", bits: 48, range: "6 B · MAC", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "The target's hardware address. In a request this is normally all zeroes because it is the value being resolved; the Ethernet destination is broadcast." },
    { id: "tpa", name: "Target Protocol Address", bits: 32, range: "4 B · IPv4", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826", desc: "The IPv4 address being resolved. In a gratuitous ARP the sender and target protocol addresses are the same." }
  ];

  let diagramController = null;

  const FLOW_STEPS = [
    {
      caption: "<b>Cache miss.</b> Host A wants to send an IPv4 packet to <code>192.0.2.1</code>. It looks up the next hop in its ARP cache and finds no entry, so it cannot build the Ethernet destination yet.",
      cache: "empty",
      notes: { a: "cache: miss", b: "waiting", c: "waiting" },
      tokens: {},
      active: ["a"],
      match: [],
      ignored: [],
      links: []
    },
    {
      caption: "<b>A broadcasts the question.</b> A sends an ARP request from <code>192.0.2.10</code> asking who owns <code>192.0.2.1</code>. The target MAC is all zeroes and the Ethernet destination is <code>ff:ff:ff:ff:ff:ff</code>.",
      cache: "pending",
      notes: { a: "cache: resolving", b: "waiting", c: "waiting" },
      tokens: { reqA: [255, 172] },
      active: ["a"],
      match: [],
      ignored: [],
      links: ["a-switch"]
    },
    {
      caption: "<b>The switch floods every port.</b> Host C compares the target IP with its own address and discards the frame. Host B owns <code>192.0.2.1</code>, so it accepts the request and prepares a reply.",
      cache: "pending",
      notes: { a: "cache: resolving", b: "target matches", c: "not my IP" },
      tokens: { reqB: [470, 126], reqC: [470, 220] },
      active: ["switch"],
      match: ["b"],
      ignored: ["c"],
      links: ["switch-b", "switch-c"]
    },
    {
      caption: "<b>B answers with its MAC.</b> Host B sends a unicast ARP reply to A: <code>192.0.2.1 is-at 02:00:00:00:00:01</code>. Unlike the request, this frame is addressed to A's MAC.",
      cache: "pending",
      notes: { a: "cache: resolving", b: "sends reply", c: "discards" },
      tokens: { replyIn: [470, 126] },
      active: [],
      match: ["b"],
      ignored: ["c"],
      links: ["switch-b"]
    },
    {
      caption: "<b>A caches the mapping.</b> Host A stores <code>192.0.2.1 → 02:00:00:00:00:01</code>. The next IPv4 frame for B can now use B's MAC as the Ethernet destination and be unicast through the switch.",
      cache: "resolved",
      notes: { a: "cache: resolved", b: "target matches", c: "discards" },
      tokens: { replyOut: [255, 172] },
      active: ["a"],
      match: ["b"],
      ignored: ["c"],
      links: ["a-switch"]
    }
  ];

  const TOKEN_HOME = {
    reqA: [200, 172],
    reqB: [410, 172],
    reqC: [410, 172],
    replyIn: [530, 80],
    replyOut: [410, 172]
  };

  function buildSample() {
    const arp = A.buildArp({
      opcode: 1,
      senderMac: "02:00:00:00:00:0a",
      senderIp: "192.0.2.10",
      targetMac: "00:00:00:00:00:00",
      targetIp: "192.0.2.1"
    });
    const frame = A.buildEthernetWrapper(arp.bytes, {
      dstMac: "ff:ff:ff:ff:ff:ff",
      senderMac: "02:00:00:00:00:0a",
      pad: true,
      fcs: true
    });
    return { arp, frame };
  }

  function initDiagrams() {
    diagramController = PH.diagram("#arp-diagram", {
      title: "<b>ARP</b> · Ethernet / IPv4 message", badge: "RFC 826",
      fields, inspector: "#arp-inspector", table: "#arp-fields",
      note: "The 28-byte shape assumes HLEN=6 and PLEN=4. Other hardware/protocol combinations use the same field order with different address widths."
    });
    PH.fieldTable("#arp-fields", diagramController, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#arp-frame-lane", {
      title: "<b>ARP request</b> · Ethernet frame", badge: "EtherType 0x0806",
      fields: [
        { name: "Ethernet destination", bytes: 6, range: "6 B", desc: "ff:ff:ff:ff:ff:ff for a broadcast request; requester MAC for a reply.", tone: "a", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/" },
        { name: "Ethernet source", bytes: 6, range: "6 B", desc: "Sender's MAC; should equal the ARP Sender Hardware Address.", tone: "b", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/" },
        { name: "EtherType", bytes: 2, value: "0x0806", range: "0x0806", desc: "ARP EtherType. A VLAN tag would add four bytes before this field.", tone: "c", rfc: "IANA", rfcUrl: "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml" },
        { name: "ARP message", bytes: 28, range: "28 B", desc: "The fixed Ethernet/IPv4 ARP request or reply.", tone: "d", rfc: "RFC 826", rfcUrl: "https://www.rfc-editor.org/rfc/rfc826" },
        { name: "Padding", bytes: "var", variable: true, varBytes: 18, range: "18 B typical", desc: "Zero bytes added to bring the Ethernet payload to the 46-byte minimum. Not part of the ARP message.", tone: "e", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/" },
        { name: "FCS", bytes: 4, range: "4 B", desc: "Ethernet CRC-32. The ARP message itself has no checksum.", tone: "f", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/" }
      ],
      inspector: "#arp-frame-inspector",
      note: "A 28-byte ARP message inside a 46-byte minimum Ethernet payload is followed by 18 padding bytes. The FCS is outside the padding."
    });
  }

  function updateDiagram(a) {
    if (!diagramController) return;
    diagramController.setValues({
      htype: String(a.htype),
      ptype: "0x" + PH.hex(a.ptype, 4),
      hlen: String(a.hlen),
      plen: String(a.plen),
      oper: a.opcode + " " + a.opcodeName,
      sha: a.senderMac,
      spa: a.senderIp,
      tha: a.targetMac,
      tpa: a.targetIp
    });
  }

  function readEncoder() {
    return {
      opcode: Number(document.getElementById("arp-enc-opcode").value),
      senderMac: document.getElementById("arp-enc-sender-mac").value,
      senderIp: document.getElementById("arp-enc-sender-ip").value,
      targetMac: document.getElementById("arp-enc-target-mac").value,
      targetIp: document.getElementById("arp-enc-target-ip").value,
      wrap: document.getElementById("arp-enc-wrap").checked,
      pad: document.getElementById("arp-enc-pad").checked,
      fcs: document.getElementById("arp-enc-fcs").checked,
      dstMac: document.getElementById("arp-enc-dst-mac").value
    };
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("arp-enc-status");
    const out = document.getElementById("arp-enc-output");
    const summary = document.getElementById("arp-enc-summary");
    const tag = document.getElementById("arp-enc-tag");
    const v = readEncoder();
    let arp;
    let frame = null;
    try {
      arp = A.buildArp(v);
      if (v.wrap) frame = A.buildEthernetWrapper(arp.bytes, { dstMac: v.dstMac, senderMac: v.senderMac, pad: v.pad, fcs: v.fcs });
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    out.textContent = PH.bytesToHex(frame ? frame.bytes : arp.bytes);
    out.classList.remove("placeholder");
    tag.textContent = (frame ? frame.bytes.length : arp.bytes.length) + " B";
    summary.innerHTML = [
      `<span class="pill">${PH.esc(arp.opcodeName)}</span>`,
      `<span class="pill">ARP <b>${arp.messageLength} B</b></span>`,
      `<span class="pill">${v.wrap ? "Ethernet <b>" + frame.bytes.length + " B</b>" : "raw message"}</span>`,
      `<span class="pill">${v.wrap && v.fcs ? "FCS <b>4 B</b>" : "no FCS"}</span>`
    ].join("");
    PH.setStatus(status, `built ${arp.opcodeName.toLowerCase()} · ${arp.bytes.length} B ARP${v.wrap ? " · " + frame.bytes.length + " B Ethernet frame" + (v.fcs ? " with FCS" : "") : " (raw)"}`, "ok");
    updateDiagram({
      htype: arp.htype, ptype: arp.ptype, hlen: arp.hlen, plen: arp.plen, opcode: arp.opcode,
      opcodeName: arp.opcodeName, senderMac: arp.senderMac || E.macString(arp.sha), senderIp: PH.ipv4String(arp.spa),
      targetMac: E.macString(arp.tha), targetIp: PH.ipv4String(arp.tpa)
    });
    return arp;
  }

  function initEncoder() {
    document.getElementById("arp-enc-build").addEventListener("click", () => buildFromForm(true));
    document.getElementById("arp-enc-probe").addEventListener("click", () => {
      document.getElementById("arp-enc-opcode").value = "1";
      document.getElementById("arp-enc-sender-ip").value = "0.0.0.0";
      document.getElementById("arp-enc-target-mac").value = "00:00:00:00:00:00";
      document.getElementById("arp-enc-target-ip").value = "192.0.2.10";
      buildFromForm(true);
    });
    document.getElementById("arp-enc-gratuitous").addEventListener("click", () => {
      document.getElementById("arp-enc-opcode").value = "2";
      document.getElementById("arp-enc-sender-ip").value = "192.0.2.10";
      document.getElementById("arp-enc-target-ip").value = "192.0.2.10";
      document.getElementById("arp-enc-target-mac").value = "ff:ff:ff:ff:ff:ff";
      document.getElementById("arp-enc-dst-mac").value = "ff:ff:ff:ff:ff:ff";
      buildFromForm(true);
    });
    document.getElementById("arp-enc-example").addEventListener("click", () => {
      document.getElementById("arp-enc-opcode").value = "1";
      document.getElementById("arp-enc-sender-mac").value = "02:00:00:00:00:0a";
      document.getElementById("arp-enc-sender-ip").value = "192.0.2.10";
      document.getElementById("arp-enc-target-mac").value = "00:00:00:00:00:00";
      document.getElementById("arp-enc-target-ip").value = "192.0.2.1";
      document.getElementById("arp-enc-wrap").checked = true;
      document.getElementById("arp-enc-pad").checked = true;
      document.getElementById("arp-enc-fcs").checked = true;
      document.getElementById("arp-enc-dst-mac").value = "ff:ff:ff:ff:ff:ff";
      buildFromForm(true);
    });
    buildFromForm(false);
  }

  function mappingText(a) {
    if (a.opcode === 1) return `who-has ${a.targetIp} tell ${a.senderIp}`;
    if (a.opcode === 2) return `${a.senderIp} is-at ${a.senderMac}`;
    return `${a.opcodeName} · ${a.senderIp} → ${a.targetIp}`;
  }

  function renderDecoded(result) {
    const host = document.getElementById("arp-decode-result");
    const { arp, wrapper, bytes } = result;
    const pills = [
      `<span class="pill">${PH.esc(arp.opcodeName)}</span>`,
      `<span class="pill">ARP <b>${arp.messageLength} B</b></span>`,
      `<span class="pill">${PH.esc(mappingText(arp))}</span>`
    ];
    if (wrapper) {
      pills.push(`<span class="pill">Ethernet <b>${wrapper.frameLength} B</b></span>`);
      pills.push(`<span class="pill ${wrapper.fcsPresent ? (wrapper.fcsOk ? "pill--good" : "pill--bad") : "pill--warn"}">FCS ${wrapper.fcsPresent ? (wrapper.fcsOk ? "valid" : "invalid") : "absent"}</span>`);
      if (wrapper.vlanTags.length) pills.push(`<span class="pill">VLAN <b>${wrapper.vlanTags.map((v) => v.vid).join(" / ")}</b></span>`);
    }

    const rows = [
      ["Hardware Type", "16", "0–15", `${arp.htype} · ${arp.hardwareName}`, ""],
      ["Protocol Type", "16", "16–31", `0x${PH.hex(arp.ptype, 4)} · ${arp.protocolName}`, ""],
      ["Hardware Length", "8", "32–39", String(arp.hlen), arp.hlen === 6 ? "" : "unusual"],
      ["Protocol Length", "8", "40–47", String(arp.plen), arp.plen === 4 ? "" : "unusual"],
      ["Opcode", "16", "48–63", `${arp.opcode} · ${arp.opcodeName}`, ""],
      ["Sender Hardware", `${arp.hlen * 8}`, `64–${64 + arp.hlen * 8 - 1}`, arp.senderMac, ""],
      ["Sender Protocol", `${arp.plen * 8}`, `${64 + arp.hlen * 8}–${64 + arp.hlen * 8 + arp.plen * 8 - 1}`, arp.senderIp, ""],
      ["Target Hardware", `${arp.hlen * 8}`, `${64 + arp.hlen * 8 + arp.plen * 8}–${64 + 2 * arp.hlen * 8 + arp.plen * 8 - 1}`, arp.targetMac, ""],
      ["Target Protocol", `${arp.plen * 8}`, `${64 + 2 * arp.hlen * 8 + arp.plen * 8}–${64 + 2 * arp.hlen * 8 + 2 * arp.plen * 8 - 1}`, arp.targetIp, ""]
    ];
    const table = rows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    let wrapperHtml = "";
    if (wrapper) {
      wrapperHtml = '<div class="callout"><div class="callout__title">Ethernet wrapper</div><p>' +
        `${PH.esc(wrapper.srcMac)} → ${PH.esc(wrapper.dstMac)} · EtherType <code>0x0806</code>` +
        (wrapper.vlanTags.length ? ` · VLAN ${wrapper.vlanTags.map((v) => v.vid).join(" / ")}` : "") +
        ` · ARP payload <b>${arp.messageLength} B</b> · padding <b>${arp.paddingLength} B</b>` +
        (wrapper.fcsPresent ? ` · FCS ${wrapper.fcsOk ? "valid" : "invalid"}` : " · FCS not captured") +
        `. <a href="ethernet.html">Open the Ethernet explorer</a> for the full frame layout.</p></div>`;
    } else {
      wrapperHtml = '<div class="callout callout--warn"><div class="callout__title">raw ARP message</div><p>This input contains the ARP payload only. The Ethernet addresses, padding and FCS are not available; the ARP message itself has no checksum.</p></div>';
    }

    const warnings = arp.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + arp.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : "";
    const mappingHtml = `<div class="callout"><div class="callout__title">ARP mapping</div><p><b>${PH.esc(mappingText(arp))}</b>${arp.paddingLength ? ` · ${arp.paddingLength} padding byte(s)` : ""}</p></div>`;

    const highlight = wrapper
      ? [{ start: wrapper.offset + wrapper.headerLen, end: wrapper.offset + wrapper.headerLen + arp.messageLength }]
      : [{ start: 0, end: arp.messageLength }];

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${wrapper ? "Ethernet frame" : "ARP message"}</span><span>${bytes.length} B</span></div>${PH.hexdump(bytes, { highlight })}</div>` +
      `<div class="decoded-head"><h3>ARP fields</h3><span class="dim">offsets relative to the ARP message</span></div>` +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${table}</tbody></table></div>` +
      mappingHtml + wrapperHtml + warnings;
  }

  function detectDecode(bytes) {
    let wrapper = null;
    if (bytes.length >= 14) {
      try {
        const frame = E.decodeFrame(bytes);
        if (frame.etherType === 0x0806) wrapper = frame;
      } catch (_) { /* not an Ethernet frame */ }
    }
    if (wrapper) {
      const arp = A.decodeArp(wrapper.payload);
      return { arp, wrapper, bytes };
    }
    return { arp: A.decodeArp(bytes), wrapper: null, bytes };
  }

  function initDecoder() {
    const input = document.getElementById("arp-decode-input");
    const status = document.getElementById("arp-decode-status");
    const host = document.getElementById("arp-decode-result");
    if (!input) return;

    function run(showErrors) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      let result;
      try { result = detectDecode(bytes); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      renderDecoded(result);
      updateDiagram(result.arp);
      const a = result.arp;
      PH.setStatus(status, `${a.opcodeName} · ${mappingText(a)}${result.wrapper ? " · inside Ethernet" : " · raw ARP"}${a.warnings.length ? " · " + a.warnings.length + " note(s)" : ""}`, a.warnings.length ? "warn" : "ok");
    }

    document.getElementById("arp-decode").addEventListener("click", () => run(true));
    document.getElementById("arp-decode-example").addEventListener("click", () => {
      const sample = buildSample();
      input.value = PH.bytesToHex(sample.frame.bytes);
      run(true);
    });
    document.getElementById("arp-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No ARP message decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run(true);
    });
  }

  function initFlow() {
    const flow = document.getElementById("arp-flow");
    if (!flow) return;

    const caption = document.getElementById("arp-flow-caption");
    const counter = document.getElementById("arp-flow-counter");
    const stepLabel = document.getElementById("arp-flow-step");
    const cacheBody = document.getElementById("arp-flow-cache-body");
    const cacheState = document.getElementById("arp-flow-cache-state");
    const playBtn = document.getElementById("arp-flow-play");
    const prevBtn = document.getElementById("arp-flow-prev");
    const nextBtn = document.getElementById("arp-flow-next");
    const resetBtn = document.getElementById("arp-flow-reset");
    const dots = Array.from(document.querySelectorAll("#arp-flow-progress span"));
    const noteA = document.getElementById("arp-node-a-note");
    const noteB = document.getElementById("arp-node-b-note");
    const noteC = document.getElementById("arp-node-c-note");

    const nodes = {};
    flow.querySelectorAll("[data-node]").forEach((el) => { nodes[el.dataset.node] = el; });
    const links = {};
    flow.querySelectorAll("[data-link]").forEach((el) => { links[el.dataset.link] = el; });
    const tokens = {};
    flow.querySelectorAll("[data-token]").forEach((el) => { tokens[el.dataset.token] = el; });

    let step = 1;
    let playing = false;
    let timer = null;

    function syncControls() {
      playBtn.textContent = playing ? "Pause" : step >= FLOW_STEPS.length ? "Replay" : "Play";
      prevBtn.disabled = step <= 1;
      nextBtn.disabled = step >= FLOW_STEPS.length;
      counter.textContent = `step ${step} / ${FLOW_STEPS.length}`;
      stepLabel.textContent = String(step);
      dots.forEach((dot, index) => dot.classList.toggle("is-current", index === step - 1));
    }

    function renderCache(state) {
      if (state === "empty") {
        cacheBody.innerHTML = '<tr><td colspan="3" class="is-empty">no entries</td></tr>';
        cacheState.textContent = "empty";
        cacheState.className = "is-empty";
      } else if (state === "pending") {
        cacheBody.innerHTML = '<tr><td><code>192.0.2.1</code></td><td><code>?</code></td><td class="is-pending">pending</td></tr>';
        cacheState.textContent = "1 pending";
        cacheState.className = "is-pending";
      } else {
        cacheBody.innerHTML = '<tr><td><code>192.0.2.1</code></td><td><code>02:00:00:00:00:01</code></td><td class="is-resolved">resolved</td></tr>';
        cacheState.textContent = "1 entry";
        cacheState.className = "is-resolved";
      }
    }

    function applyStep(index) {
      const current = FLOW_STEPS[index - 1];
      caption.innerHTML = current.caption;
      noteA.textContent = current.notes.a;
      noteB.textContent = current.notes.b;
      noteC.textContent = current.notes.c;

      Object.keys(tokens).forEach((name) => {
        const el = tokens[name];
        const position = current.tokens[name];
        if (position) {
          el.style.transform = `translate(${position[0]}px, ${position[1]}px)`;
          el.classList.add("is-visible");
        } else {
          el.classList.remove("is-visible");
          const home = TOKEN_HOME[name];
          if (home) el.style.transform = `translate(${home[0]}px, ${home[1]}px)`;
        }
      });

      Object.keys(nodes).forEach((name) => {
        nodes[name].classList.toggle("is-active", current.active.includes(name));
        nodes[name].classList.toggle("is-match", current.match.includes(name));
        nodes[name].classList.toggle("is-ignored", current.ignored.includes(name));
      });

      Object.keys(links).forEach((name) => {
        links[name].classList.toggle("is-active", current.links.includes(name));
      });

      renderCache(current.cache);
      syncControls();
    }

    function pause() {
      if (timer) { clearTimeout(timer); timer = null; }
      playing = false;
      syncControls();
    }

    function tick() {
      timer = setTimeout(() => {
        timer = null;
        if (!playing) return;
        if (step >= FLOW_STEPS.length) { pause(); return; }
        step += 1;
        applyStep(step);
        if (step >= FLOW_STEPS.length) pause();
        else tick();
      }, 1900);
    }

    playBtn.addEventListener("click", () => {
      if (playing) { pause(); return; }
      if (step >= FLOW_STEPS.length) { step = 1; applyStep(step); }
      playing = true;
      syncControls();
      tick();
    });

    prevBtn.addEventListener("click", () => {
      pause();
      if (step > 1) { step -= 1; applyStep(step); }
    });

    nextBtn.addEventListener("click", () => {
      pause();
      if (step < FLOW_STEPS.length) { step += 1; applyStep(step); }
    });

    resetBtn.addEventListener("click", () => {
      pause();
      step = 1;
      applyStep(step);
    });

    applyStep(step);
  }

  function init() {
    if (!document.getElementById("arp-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    initFlow();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
