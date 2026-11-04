/* Ethernet II frame explorer — pure codec wiring */
(function () {
  "use strict";

  const PH = window.PH;
  const E = window.EthernetCodec;
  const ARP_REQUEST = "00 01 08 00 06 04 00 01 02 00 00 00 00 0A C0 00 02 0A 00 00 00 00 00 00 C0 00 02 01";

  const fields = [
    {
      id: "dst", name: "Destination MAC", bits: 48, range: "48 bits · 6 B",
      rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/",
      desc: "The receiving NIC's hardware address. <code>ff:ff:ff:ff:ff:ff</code> is broadcast; a multicast address has the I/G bit set in the first octet. The I/G bit is the least-significant bit of the first octet, which is bit 7 in this MSB-first diagram."
    },
    {
      id: "src", name: "Source MAC", bits: 48, range: "48 bits · 6 B",
      rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/",
      desc: "The sending NIC's hardware address. The U/L bit (bit 6 of the first octet) distinguishes globally assigned addresses from locally administered ones. Switches learn source MACs from this field."
    },
    {
      id: "type", name: "EtherType", bits: 16, range: "0x0600–0xFFFF",
      rfc: "IANA EtherTypes", rfcUrl: "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml",
      desc: "Payload protocol identifier: <code>0x0800</code> IPv4, <code>0x0806</code> ARP, <code>0x86DD</code> IPv6, <code>0x8100</code> 802.1Q VLAN. Values at or below 1500 are an IEEE 802.3 length field instead of an EtherType."
    }
  ];

  let headerController = null;
  let vlanController = null;

  function initDiagrams() {
    headerController = PH.diagram("#ethernet-diagram", {
      title: "<b>Ethernet II</b> · MAC header", badge: "IEEE 802.3",
      fields, inspector: "#ethernet-inspector", table: "#ethernet-fields",
      note: "The 48-bit MAC fields are shown MSB-first like every other field on the site. On the wire, each octet is transmitted LSB-first; the I/G and U/L bits are in the low bits of the first octet."
    });
    PH.fieldTable("#ethernet-fields", headerController, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#ethernet-frame-lane", {
      title: "<b>Ethernet II frame</b> · untagged", badge: "14 B header",
      fields: [
        { name: "Destination MAC", bytes: 6, range: "6 B", desc: "Receiver's MAC address.", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/", tone: "a" },
        { name: "Source MAC", bytes: 6, range: "6 B", desc: "Sender's MAC address.", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/", tone: "b" },
        { name: "EtherType", bytes: 2, range: "2 B", desc: "Payload protocol, or an 802.1Q TPID if tagged.", rfc: "IANA", rfcUrl: "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml", tone: "c" },
        { name: "Payload", bytes: "var", variable: true, range: "46–1500 B", desc: "Network-layer payload plus any padding needed to reach the 64-byte frame minimum. A VLAN tag adds 4 bytes before the EtherType and shifts the payload.", rfc: "IEEE 802.3", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/", tone: "d" },
        { name: "FCS", bytes: 4, range: "32-bit CRC", desc: "Frame Check Sequence over the destination MAC through padding. Usually appended by the NIC and often stripped from captures.", rfc: "IEEE 802.3 §3.2.9", rfcUrl: "https://standards.ieee.org/ieee/802.3/7071/", tone: "e" }
      ],
      inspector: "#ethernet-frame-inspector",
      note: "This is the untagged frame shape. A single 802.1Q tag adds a 4-byte TPID/TCI pair between the source MAC and the inner EtherType."
    });

    vlanController = PH.diagram("#vlan-diagram", {
      title: "<b>802.1Q</b> · VLAN tag", badge: "4 bytes", bitsPerRow: 32,
      fields: [
        { id: "tpid", name: "TPID", bits: 16, range: "0x8100 / 0x88A8", rfc: "IEEE 802.1Q", rfcUrl: "https://standards.ieee.org/ieee/802.1Q/6844/", desc: "<code>0x8100</code> marks an 802.1Q tag; <code>0x88A8</code> marks an 802.1ad service-provider tag (QinQ). The TPID occupies the EtherType position." },
        { id: "pcp", name: "PCP", bits: 3, range: "0–7", rfc: "IEEE 802.1Q", rfcUrl: "https://standards.ieee.org/ieee/802.1Q/6844/", desc: "Priority Code Point: 3-bit 802.1p traffic class. 0 is best effort, 6 is internetwork control, 7 is network control. It is a queuing hint, not a bandwidth guarantee." },
        { id: "dei", name: "DEI", bits: 1, range: "0/1", rfc: "IEEE 802.1Q", rfcUrl: "https://standards.ieee.org/ieee/802.1Q/6844/", desc: "Drop Eligible Indicator. When set, the frame may be dropped before other traffic of the same class under congestion. Formerly called CFI." },
        { id: "vid", name: "VID", bits: 12, range: "0–4095", rfc: "IEEE 802.1Q", rfcUrl: "https://standards.ieee.org/ieee/802.1Q/6844/", desc: "VLAN Identifier. 0 is the priority-tag value (no VLAN membership), 1 is usually the default/native VLAN, 4095 is reserved. Normal range is 1–4094." }
      ],
      inspector: "#vlan-inspector",
      note: "The tag is inserted after the source MAC. Tagged frames carry the inner EtherType after the TCI; stacked tags repeat the TPID/TCI pair."
    });
  }

  function buildSample(includeVlan) {
    return E.buildFrame({
      dst: "ff:ff:ff:ff:ff:ff",
      src: "02:00:00:00:00:0a",
      etherType: 0x0806,
      payload: ARP_REQUEST,
      pad: true,
      fcs: true,
      vlan: includeVlan ? { pcp: 3, dei: 0, vid: 100, tpid: 0x8100 } : null
    });
  }

  function updateHeaderDiagram(result) {
    if (headerController) headerController.setValues({
      dst: result.dstMac || E.macString(result.dst),
      src: result.srcMac || E.macString(result.src),
      type: "0x" + PH.hex(result.etherType, 4) + " " + E.etherTypeName(result.etherType)
    });
    if (vlanController) {
      if (result.vlanTags && result.vlanTags.length) {
        const v = result.vlanTags[0];
        vlanController.setValues({
          tpid: "0x" + PH.hex(v.tpid, 4),
          pcp: String(v.pcp),
          dei: String(v.dei),
          vid: String(v.vid)
        });
      } else {
        vlanController.setValues({ tpid: "—", pcp: "0", dei: "0", vid: "—" });
      }
    }
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("eth-enc-status");
    const out = document.getElementById("eth-enc-output");
    const summary = document.getElementById("eth-enc-summary");
    const tag = document.getElementById("eth-enc-tag");
    const vlan = document.getElementById("eth-enc-vlan").checked;
    let r;
    try {
      r = E.buildFrame({
        dst: document.getElementById("eth-enc-dst").value,
        src: document.getElementById("eth-enc-src").value,
        etherType: PH.parseNumber(document.getElementById("eth-enc-type").value),
        payload: document.getElementById("eth-enc-payload").value,
        vlan: vlan ? {
          pcp: Number(document.getElementById("eth-enc-pcp").value),
          dei: document.getElementById("eth-enc-dei").checked,
          vid: Number(document.getElementById("eth-enc-vid").value),
          tpid: 0x8100
        } : null,
        pad: document.getElementById("eth-enc-pad").checked,
        fcs: document.getElementById("eth-enc-fcs").checked
      });
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    out.textContent = PH.bytesToHex(r.bytes);
    out.classList.remove("placeholder");
    tag.textContent = r.bytes.length + " bytes";
    summary.innerHTML = [
      `<span class="pill">header <b>${r.headerLen} B</b></span>`,
      `<span class="pill">payload <b>${r.payloadLength} B</b></span>`,
      `<span class="pill">padding <b>${r.paddingLength} B</b></span>`,
      `<span class="pill">FCS <b>${r.fcs ? "4 B" : "none"}</b></span>`,
      `<span class="pill">frame <b>${r.bytes.length} B</b></span>`
    ].join("");
    PH.setStatus(status, `built ${r.bytes.length}-byte frame · ${E.etherTypeName(r.etherType)}${vlan ? " · VLAN" : ""}${r.fcs ? " · FCS appended" : ""}`, "ok");
    updateHeaderDiagram({
      dst: E.parseMac(document.getElementById("eth-enc-dst").value),
      src: E.parseMac(document.getElementById("eth-enc-src").value),
      etherType: r.etherType,
      vlanTags: vlan ? [{ tpid: 0x8100, pcp: Number(document.getElementById("eth-enc-pcp").value), dei: document.getElementById("eth-enc-dei").checked ? 1 : 0, vid: Number(document.getElementById("eth-enc-vid").value) }] : []
    });
    return r;
  }

  function initEncoder() {
    document.getElementById("eth-enc-build").addEventListener("click", () => buildFromForm(true));
    document.querySelectorAll("[data-eth-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const kind = btn.getAttribute("data-eth-preset");
        if (kind === "arp") {
          document.getElementById("eth-enc-type").value = "0x0806";
          document.getElementById("eth-enc-payload").value = ARP_REQUEST;
          document.getElementById("eth-enc-dst").value = "ff:ff:ff:ff:ff:ff";
        } else {
          document.getElementById("eth-enc-payload").value = "";
        }
        buildFromForm(false);
      });
    });
    document.getElementById("eth-enc-example").addEventListener("click", () => {
      document.getElementById("eth-enc-dst").value = "ff:ff:ff:ff:ff:ff";
      document.getElementById("eth-enc-src").value = "02:00:00:00:00:0a";
      document.getElementById("eth-enc-type").value = "0x0806";
      document.getElementById("eth-enc-payload").value = ARP_REQUEST;
      document.getElementById("eth-enc-vlan").checked = true;
      document.getElementById("eth-enc-pcp").value = "3";
      document.getElementById("eth-enc-dei").checked = false;
      document.getElementById("eth-enc-vid").value = "100";
      document.getElementById("eth-enc-pad").checked = true;
      document.getElementById("eth-enc-fcs").checked = true;
      buildFromForm(true);
    });
    buildFromForm(false);
  }

  function renderDecoded(r) {
    const host = document.getElementById("eth-decode-result");
    const pills = [
      `<span class="pill">frame <b>${r.frameLength} B</b></span>`,
      `<span class="pill">${PH.esc(r.etherTypeName)} <b>0x${PH.hex(r.etherType, 4)}</b></span>`,
      `<span class="pill">payload <b>${r.payloadLength} B</b></span>`,
      `<span class="pill ${r.fcsPresent ? (r.fcsOk ? "pill--good" : "pill--bad") : "pill--warn"}">FCS ${r.fcsPresent ? (r.fcsOk ? "valid" : "invalid") : "absent"}</span>`,
      `<span class="pill ${r.dstFlags.broadcast ? "pill--warn" : ""}">dest ${r.dstFlags.label}</span>`,
      `<span class="pill">src ${r.srcFlags.label}</span>`
    ];
    if (r.vlanTags.length) pills.push(`<span class="pill">VLAN <b>${r.vlanTags.map((v) => v.vid).join(" / ")}</b></span>`);
    if (r.preamble) pills.push(`<span class="pill">preamble skipped</span>`);

    const fcsValue = r.fcs ? r.fcs[0] | (r.fcs[1] << 8) | (r.fcs[2] << 16) | (r.fcs[3] << 24) : null;
    const rows = [
      ["Destination MAC", "48", "0–47", `${r.dstMac} · ${r.dstFlags.label}`, r.dstFlags.admin],
      ["Source MAC", "48", "48–95", `${r.srcMac} · ${r.srcFlags.label}`, r.srcFlags.admin],
      ["EtherType / Length", "16", "96–111", `0x${PH.hex(r.etherType, 4)} · ${r.etherTypeName}`, r.typeKind],
      ["VLAN tags", "var", "after source MAC", r.vlanTags.length ? r.vlanTags.map((v) => "VID " + v.vid + " · PCP " + v.pcp + " · DEI " + v.dei).join(", ") : "none", r.vlanTags.length ? "tagged frame" : ""],
      ["Payload", `${r.payloadLength * 8}`, "after header", `${r.payloadLength} B`, r.trailingZeros ? `${r.trailingZeros} trailing zero B` : ""],
      ["FCS", "32", "last 4 B", r.fcsPresent ? (r.fcsOk ? "valid" : "invalid") : "not present", fcsValue != null ? "0x" + PH.hex(fcsValue >>> 0, 8) + " LE" : "often stripped"],
      ["Frame length", "—", "—", `${r.frameLength} B`, r.wireLength !== r.frameLength ? `~${r.wireLength} B with expected FCS` : ""]
    ];
    const table = rows.map(([name, bits, off, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(off)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    let vlanHtml = "";
    if (r.vlanTags.length) {
      vlanHtml = '<div class="decoded-head"><h3>VLAN tags</h3><span class="dim">outer to inner</span></div><div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>TPID</th><th class="num">PCP</th><th class="num">DEI</th><th class="num">VID</th><th>TCI</th></tr></thead><tbody>' +
        r.vlanTags.map((v, i) => `<tr><td>${i + 1}</td><td><code>0x${PH.hex(v.tpid, 4)}</code></td><td class="num">${v.pcp}</td><td class="num">${v.dei}</td><td class="num">${v.vid}</td><td><code>0x${PH.hex(v.tci, 4)}</code></td></tr>`).join("") +
        "</tbody></table></div>";
    }

    let linkHtml = "";
    if (r.etherType === 0x0806) {
      linkHtml = '<div class="callout"><div class="callout__title">ARP payload detected</div><p>The payload starts with ARP. Open the <a href="arp.html">ARP explorer</a> to decode the address resolution message, or paste this frame into its decoder.</p></div>';
    } else if (r.etherType === 0x0800) {
      linkHtml = '<div class="callout"><div class="callout__title">IPv4 payload detected</div><p>The payload starts with IPv4. Open the <a href="ipv4.html">IPv4 explorer</a> for header fields, options and checksum validation.</p></div>';
    } else if (r.etherType === 0x86dd) {
      linkHtml = '<div class="callout"><div class="callout__title">IPv6 payload</div><p>This is an IPv6 datagram. IPv6 is a planned protocol page; the frame itself ends at the payload boundary.</p></div>';
    }

    const warningHtml = r.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + r.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean frame</div><p>Length, EtherType and FCS status are consistent. The payload is still opaque to the link layer.</p></div>';

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>frame bytes</span><span>${r.bytes.length} B captured${r.preamble ? " · preamble skipped" : ""}</span></div>${PH.hexdump(r.bytes, { highlight: [{ start: r.offset, end: r.offset + r.headerLen }] })}</div>` +
      `<div class="decoded-head"><h3>frame fields</h3><span class="dim">offsets from the start of the MAC frame</span></div>` +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${table}</tbody></table></div>` +
      vlanHtml + linkHtml + warningHtml;
  }

  function initDecoder() {
    const input = document.getElementById("eth-decode-input");
    const status = document.getElementById("eth-decode-status");
    const host = document.getElementById("eth-decode-result");
    if (!input) return;

    function run(showErrors) {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      let r;
      try { r = E.decodeFrame(bytes, { fcs: document.getElementById("eth-decode-fcs").value }); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      renderDecoded(r);
      updateHeaderDiagram(r);
      PH.setStatus(status, `${r.frameLength} B frame · ${r.etherTypeName}${r.vlanTags.length ? " · tagged" : ""} · FCS ${r.fcsPresent ? (r.fcsOk ? "valid" : "invalid") : "absent"}${r.warnings.length ? " · " + r.warnings.length + " note(s)" : ""}`, r.fcsPresent && !r.fcsOk ? "bad" : r.warnings.length ? "warn" : "ok");
    }

    document.getElementById("eth-decode").addEventListener("click", () => run(true));
    document.getElementById("eth-decode-example").addEventListener("click", () => {
      input.value = PH.bytesToHex(buildSample(true).bytes);
      document.getElementById("eth-decode-fcs").value = "auto";
      run(true);
    });
    document.getElementById("eth-decode-clear").addEventListener("click", () => {
      input.value = "";
      host.innerHTML = "";
      PH.setStatus(status, "No frame decoded yet.", "");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run(true);
    });
  }

  function init() {
    if (!document.getElementById("ethernet-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
