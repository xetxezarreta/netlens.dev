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
        { name: "Padding", bytes: "var", variable: true, range: "18 B typical", desc: "Zero bytes added to bring the Ethernet payload to the 46-byte minimum. Not part of the ARP message.", tone: "e", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/" },
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

  function init() {
    if (!document.getElementById("arp-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
