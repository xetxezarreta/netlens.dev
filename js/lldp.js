/* LLDP page: TLV diagram, frame lane, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const L = window.LLDPCodec;
  let diagram = null;

  function initDiagrams() {
    diagram = PH.diagram("#lldp-diagram", {
      title: "<b>LLDP</b> · TLV header", badge: "IEEE 802.1AB",
      fields: [
        { id: "type", name: "TLV Type", bits: 7, value: "1", range: "0–127", desc: "0 End, 1 Chassis ID, 2 Port ID, 3 TTL, 4 Port Description, 5 System Name, 6 System Description, 7 Capabilities, 8 Management Address, 127 Organizationally Specific." },
        { id: "length", name: "TLV Length", bits: 9, value: "7", range: "0–511", desc: "Length of the TLV value in bytes, excluding the two-byte type/length header." },
        { id: "value", name: "TLV Value", bits: "var", varWidth: 32, value: "…", range: "length B", desc: "Type-specific value. Chassis/Port ID begin with an 8-bit subtype; TTL is a 16-bit number of seconds; Capabilities are two 16-bit masks." }
      ],
      inspector: "#lldp-inspector", table: "#lldp-fields",
      note: "The header is a single 16-bit value: type in the top 7 bits, length in the low 9 bits. The End TLV has type 0 and length 0. The mandatory sequence is Chassis ID, Port ID, TTL, then optional TLVs."
    });
    PH.fieldTable("#lldp-fields", diagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    PH.byteLane("#lldp-frame-lane", {
      title: "<b>LLDP frame</b> · Ethernet + LLDPDU", badge: "EtherType 0x88CC",
      fields: [
        { name: "Destination MAC", bytes: 6, value: "01:80:c2:00:00:0e", range: "6 B", desc: "LLDP multicast group. Bridges do not forward these frames.", tone: "a" },
        { name: "Source MAC", bytes: 6, value: "02:00:00:00:00:01", range: "6 B", desc: "Sending port's MAC address.", tone: "b" },
        { name: "EtherType", bytes: 2, value: "0x88CC", range: "0x88CC", desc: "LLDP EtherType.", tone: "c" },
        { name: "LLDPDU", bytes: "var", variable: true, range: "TLVs", desc: "Chassis ID, Port ID, TTL, optional TLVs and End TLV.", tone: "d" }
      ],
      inspector: "#lldp-frame-inspector",
      note: "LLDP has no IP header. It is a link-layer frame only. Capture filters usually use `ether proto 0x88cc` or `lldp`."
    });
  }

  function vlanValue(id) {
    const bytes = new Uint8Array(2);
    PH.put16be(bytes, 0, id);
    return PH.bytesToHex(bytes);
  }

  function readEncoder() {
    const vlan = document.getElementById("lldp-enc-vlan").value;
    const input = {
      chassis: { subtype: 4, address: document.getElementById("lldp-enc-chassis").value },
      port: { subtype: 5, address: document.getElementById("lldp-enc-port").value },
      ttl: Number(document.getElementById("lldp-enc-ttl").value),
      systemName: document.getElementById("lldp-enc-name").value,
      systemDescription: document.getElementById("lldp-enc-desc").value,
      capabilities: PH.parseNumber(document.getElementById("lldp-enc-caps").value),
      enabled: PH.parseNumber(document.getElementById("lldp-enc-enabled").value),
      managementAddress: document.getElementById("lldp-enc-mgmt").value,
      orgSpecific: []
    };
    if (vlan) input.orgSpecific.push({ oui: "00 80 c2", subtype: 1, value: vlanValue(Number(vlan)) });
    return input;
  }

  function build(showErrors) {
    const status = document.getElementById("lldp-encode-status");
    const output = document.getElementById("lldp-enc-output");
    const tag = document.getElementById("lldp-enc-tag");
    const summary = document.getElementById("lldp-enc-summary");
    let result;
    try { result = L.buildLldp(readEncoder()); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    output.textContent = PH.bytesToHex(result.bytes);
    output.classList.remove("placeholder");
    tag.textContent = result.bytes.length + " B";
    summary.innerHTML = [
      `<span class="pill">${result.tlvs} TLV(s)</span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      `<span class="pill">LLDPDU only</span>`
    ].join("");
    PH.setStatus(status, `built ${result.bytes.length}-byte LLDPDU · ${result.tlvs} TLV(s)`, "ok");
    if (diagram) diagram.setValues({ type: "1", length: "7", value: "…" });
    return result;
  }

  function encoderState() {
    const ids = ["lldp-enc-chassis", "lldp-enc-port", "lldp-enc-ttl", "lldp-enc-name", "lldp-enc-desc", "lldp-enc-caps", "lldp-enc-enabled", "lldp-enc-mgmt", "lldp-enc-vlan"];
    const state = { page: "lldp-enc" };
    ids.forEach((id) => { state[id] = document.getElementById(id).value; });
    return state;
  }

  function applyEncoderState(state) {
    if (!state) return;
    Object.keys(state).forEach((key) => { const el = document.getElementById(key); if (el) el.value = state[key]; });
    build(true);
  }

  function initEncoder() {
    const form = document.getElementById("lldp-encode-form");
    if (!form) return;
    ["input", "change"].forEach((event) => form.querySelectorAll("input").forEach((el) => el.addEventListener(event, () => build(false))));
    document.getElementById("lldp-build").addEventListener("click", () => build(true));
    document.getElementById("lldp-permalink").addEventListener("click", () => { if (build(true)) PH.shareState(encoderState(), "LLDP encoder permalink copied"); });
    document.getElementById("lldp-export").addEventListener("click", () => {
      const result = build(true);
      if (!result) return;
      PH.downloadText("lldp-lldpdu.json", JSON.stringify({ hex: PH.bytesToHex(result.bytes), length: result.bytes.length, input: readEncoder() }, null, 2), "application/json");
    });
    build(false);
  }

  function detailTable(title, hint, headers, rows) {
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' + headers.map((h) => `<th>${PH.esc(h)}</th>`).join("") + "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") + "</tbody></table></div>";
  }

  function cutEthernet(bytes) {
    if (bytes.length >= 14 && PH.u16be(bytes, 12) === 0x88cc) {
      return { bytes: bytes.subarray(14), frame: { dst: Array.from(bytes.subarray(0, 6), (b) => PH.hex(b).toLowerCase()).join(":"), src: Array.from(bytes.subarray(6, 12), (b) => PH.hex(b).toLowerCase()).join(":") } };
    }
    return { bytes, frame: null };
  }

  function render(result, frame) {
    const host = document.getElementById("lldp-decode-result");
    const pills = [
      `<span class="pill">${result.tlvs.length} TLV(s)</span>`,
      `<span class="pill">${result.bytes.length} B</span>`,
      result.ttl == null ? '<span class="pill pill--warn">no TTL</span>' : `<span class="pill">TTL <b>${result.ttl} s</b></span>`,
      result.shutdown ? '<span class="pill pill--bad">shutdown</span>' : "",
      frame ? '<span class="pill">Ethernet frame</span>' : ""
    ];
    const rows = result.tlvs.map((tlv, i) => {
      let value = "—";
      if (tlv.type === 1 || tlv.type === 2) value = `${tlv.subtypeName || "subtype " + tlv.subtype} · ${tlv.address || "—"}`;
      else if (tlv.type === 3) value = `${tlv.ttl} s`;
      else if (tlv.type === 4 || tlv.type === 5 || tlv.type === 6) value = tlv.text || "—";
      else if (tlv.type === 7) value = `${tlv.capabilityNames.join(", ") || "none"} · enabled ${tlv.enabledNames.join(", ") || "none"}`;
      else if (tlv.type === 8) value = `${tlv.address || "—"} · if ${tlv.interfaceNumber == null ? "—" : tlv.interfaceNumber}`;
      else if (tlv.type === 127) value = `${tlv.ouiName || tlv.oui || "unknown OUI"} · subtype ${tlv.subtype}${tlv.vlanId != null ? " · VLAN " + tlv.vlanId : ""}`;
      else if (tlv.type === 0) value = "end";
      return [`<b>${i + 1}</b>`, `<code>${tlv.type}</code>`, PH.esc(tlv.name), `${tlv.length} B`, `<span class="small">${PH.esc(value)}</span>`];
    });
    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean LLDPDU</div><p>The mandatory TLVs and End TLV are present. LLDP is unauthenticated; a neighbour advertisement is a claim, not proof.</p></div>';
    const frameInfo = frame
      ? detailTable("Ethernet wrapper", "LLDP is link-local", ["Field", "Value"], [["Destination", `<code>${PH.esc(frame.dst)}</code>`], ["Source", `<code>${PH.esc(frame.src)}</code>`], ["EtherType", "<code>0x88CC</code>"]])
      : "";
    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      frameInfo +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>LLDPDU</span><span>${result.bytes.length} B</span></div>${PH.hexdump(result.bytes)}</div>` +
      detailTable("TLVs", "type, length and decoded value", ["#", "Type", "Name", "Length", "Value"], rows) +
      warnings;
    if (diagram && result.tlvs[0]) diagram.setValues({ type: String(result.tlvs[0].type), length: String(result.tlvs[0].length), value: "…" });
  }

  function decodeRun(showErrors) {
    const input = document.getElementById("lldp-decode-input");
    const status = document.getElementById("lldp-decode-status");
    const host = document.getElementById("lldp-decode-result");
    if (!input) return;
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    const cut = cutEthernet(bytes);
    let result;
    try { result = L.decodeLldp(cut.bytes); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      host.innerHTML = "";
      return;
    }
    render(result, cut.frame);
    PH.setStatus(status, `${result.tlvs.length} TLV(s) · ${result.bytes.length} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function initDecoder() {
    const input = document.getElementById("lldp-decode-input");
    if (!input) return;
    document.getElementById("lldp-decode").addEventListener("click", () => decodeRun(true));
    document.getElementById("lldp-decode-clear").addEventListener("click", () => {
      input.value = "";
      document.getElementById("lldp-decode-result").innerHTML = "";
      PH.setStatus(document.getElementById("lldp-decode-status"), "No input decoded yet.", "");
    });
    document.getElementById("lldp-decode-example").addEventListener("click", () => {
      const result = L.buildLldp({
        chassis: { subtype: 4, address: "02:00:00:00:00:01" },
        port: { subtype: 5, address: "eth0" }, ttl: 120,
        systemName: "edge-sw-1", capabilities: 0x0014, enabled: 0x0014,
        managementAddress: "192.0.2.1",
        orgSpecific: [{ oui: "00 80 c2", subtype: 1, value: "00 0a" }]
      });
      input.value = PH.bytesToHex(result.bytes);
      decodeRun(true);
    });
    input.addEventListener("keydown", (event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") decodeRun(true); });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (state && state.page === "lldp-enc") applyEncoderState(state);
  }

  function init() {
    if (!document.getElementById("lldp-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
