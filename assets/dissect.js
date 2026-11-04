/* Packet dissector page — layer tree, offset-linked hex and field detail. */
(function () {
  "use strict";

  const PH = window.PH;
  const Dissector = window.Dissector;

  let result = null;
  let selected = 0;

  function exampleTcp() {
    const packet = window.TCPCodec.buildExamplePacket();
    return window.EthernetCodec.buildFrame({
      dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
      etherType: 0x0800, payload: packet, pad: false, fcs: true
    }).bytes;
  }

  function exampleDns() {
    const dns = window.DNSCodec.buildMessage(window.DNSCodec.examples().responseA).bytes;
    const udp = window.UDPCodec.buildUdp({
      srcPort: 53, dstPort: 53000, payload: dns, ipVersion: 4,
      srcIp: "198.51.100.20", dstIp: "192.0.2.10"
    });
    const ip = window.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: 0x4e20, ttl: 64, protocol: 17,
      fragmentOffset: 0, payloadLength: udp.bytes.length, reserved: false, df: true, mf: false,
      src: "198.51.100.20", dst: "192.0.2.10", options: ""
    });
    return window.EthernetCodec.buildFrame({
      dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
      etherType: 0x0800, payload: PH.concatBytes(ip.bytes, udp.bytes), pad: false, fcs: true
    }).bytes;
  }

  function exampleV6() {
    const dns = window.DNSCodec.buildMessage(window.DNSCodec.examples().queryA).bytes;
    const udp = window.UDPCodec.buildUdp({
      srcPort: 53000, dstPort: 53, payload: dns, ipVersion: 6,
      srcIp: "2001:db8::1", dstIp: "2001:db8::2"
    });
    const ip = window.IPv6Codec.buildHeader({
      version: 6, dscp: 0, ecn: 0, flowLabel: 0x12345, nextHeader: 17,
      hopLimit: 64, src: "2001:db8::1", dst: "2001:db8::2", payload: udp.bytes
    });
    return window.EthernetCodec.buildFrame({
      dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
      etherType: 0x86dd, payload: ip.bytes, pad: false, fcs: true
    }).bytes;
  }

  function exampleArp() {
    const arp = window.ARPCodec.buildArp({
      htype: 1, ptype: 0x0800, opcode: 1,
      senderMac: "02:00:00:00:00:02", senderIp: "192.0.2.10",
      targetMac: "00:00:00:00:00:00", targetIp: "192.0.2.1"
    });
    return window.ARPCodec.buildEthernetWrapper(arp.bytes, {
      dstMac: "ff:ff:ff:ff:ff:ff", senderMac: "02:00:00:00:00:02", fcs: true
    }).bytes;
  }

  function exampleIcmp() {
    const icmp = window.ICMPCodec.buildIcmp({
      type: 8, code: 0, identifier: 0x1234, sequence: 1, data: "68 65 6c 6c 6f 20 70 61 63 6b 65 74 20 77 6f 72 6c 64"
    });
    const ip = window.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: 0x0001, ttl: 64, protocol: 1,
      fragmentOffset: 0, payloadLength: icmp.bytes.length, reserved: false, df: true, mf: false,
      src: "192.0.2.10", dst: "198.51.100.20", options: ""
    });
    return window.EthernetCodec.buildFrame({
      dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
      etherType: 0x0800, payload: PH.concatBytes(ip.bytes, icmp.bytes), pad: false, fcs: true
    }).bytes;
  }

  function exampleVlan() {
    const packet = window.TCPCodec.buildExamplePacket();
    return window.EthernetCodec.buildFrame({
      dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
      etherType: 0x0800, payload: packet, pad: false, fcs: true,
      vlan: { vid: 100, pcp: 5, dei: 0 }
    }).bytes;
  }

  const EXAMPLES = {
    tcp: exampleTcp, dns: exampleDns, v6: exampleV6,
    arp: exampleArp, icmp: exampleIcmp, vlan: exampleVlan
  };

  function layerNode(item, index) {
    const depth = Math.min(item.depth || 0, 6);
    const tone = ["ethernet", "vlan", "fcs", "ipv4", "ipv6", "arp", "tcp", "udp", "icmp", "dns", "tls", "http", "payload"].indexOf(item.proto);
    return `<button type="button" class="layer-node${index === selected ? " is-active" : ""}${item.error ? " has-error" : ""}" ` +
      `data-layer="${index}" style="--depth:${depth};--node-tone:var(--tone-${"abcdefghij"[(tone + 10) % 10]})" ` +
      `aria-pressed="${index === selected ? "true" : "false"}">` +
      `<span class="layer-node__marker" aria-hidden="true"></span>` +
      `<span class="layer-node__body"><span class="layer-node__name">${PH.esc(item.name)}</span>` +
      `<span class="layer-node__summary">${PH.esc(item.summary || "")}</span></span>` +
      `<span class="layer-node__len">${item.length} B</span>` +
      `</button>`;
  }

  function renderTree() {
    const host = document.getElementById("dissect-tree");
    host.innerHTML = result.layers.map(layerNode).join("");
    host.querySelectorAll("[data-layer]").forEach((node) => {
      node.addEventListener("click", () => selectLayer(Number(node.dataset.layer)));
    });
  }

  function renderHexdump() {
    const host = document.getElementById("dissect-hexdump");
    if (!result) { host.innerHTML = ""; return; }
    const item = result.layers[selected];
    if (!item) { host.innerHTML = PH.hexdump(result.bytes); return; }
    const start = Math.max(0, Math.min(item.offset, result.bytes.length));
    const end = Math.max(start, Math.min(item.offset + item.length, result.bytes.length));
    host.innerHTML = '<div class="hexdump-wrap"><div class="hexdump-head"><span>frame bytes</span><span>' +
      result.bytes.length + " B · highlight +" + start + "…+" + end + "</span></div>" +
      PH.hexdump(result.bytes, { highlight: [{ start, end }] }) + "</div>";
  }

  function renderDetail() {
    const host = document.getElementById("dissect-detail");
    const item = result && result.layers[selected];
    if (!item) { host.innerHTML = ""; return; }
    const link = item.href
      ? `<a class="badge" href="${PH.esc(item.href)}">open ${PH.esc(item.name)} explorer →</a>`
      : "";
    const fields = item.fields && item.fields.length
      ? '<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
        item.fields.map((field) => `<tr><td><b>${PH.esc(field.name)}</b></td><td><code>${PH.esc(field.value)}</code></td><td class="small">${PH.esc(field.note || "")}</td></tr>`).join("") +
        "</tbody></table></div>"
      : '<p class="dim">No field breakdown for this layer.</p>';
    const warnings = item.warnings && item.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:10px"><div class="callout__title">layer warnings</div><ul class="dashed" style="margin:0">' +
        item.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : "";
    const bytes = result.bytes.subarray(item.offset, Math.min(result.bytes.length, item.offset + item.length));
    const preview = bytes.length
      ? '<div class="output" style="margin-top:10px"><div class="output__label">layer bytes · ' + bytes.length + ' B</div><pre>' +
        PH.esc(bytes.length > 160 ? PH.bytesToHex(bytes.subarray(0, 160)) + " …" : PH.bytesToHex(bytes)) + "</pre></div>"
      : "";
    host.innerHTML = `<div class="dissect-detail__head"><div><h3>${PH.esc(item.name)}</h3>` +
      `<p class="dim">offset +${item.offset} · length ${item.length} B · depth ${item.depth}${item.error ? " · decode error" : ""}</p></div>${link}</div>` +
      fields + warnings + preview;
  }

  function selectLayer(index) {
    if (!result) return;
    selected = index;
    renderTree();
    renderHexdump();
    renderDetail();
  }

  function renderWarnings() {
    const host = document.getElementById("dissect-warnings");
    if (!result) { host.innerHTML = ""; return; }
    const warnings = result.warnings || [];
    if (!warnings.length) {
      host.innerHTML = '<div class="callout"><div class="callout__title">clean walk</div><p>Every length and selector agreed, and each layer’s decoder consumed the bytes it expected. Clean parsing is not a security guarantee.</p></div>';
      return;
    }
    host.innerHTML = '<div class="callout callout--warn"><div class="callout__title">' + warnings.length + ' parser note(s)</div><ul class="dashed" style="margin:0">' +
      warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>";
  }

  function render() {
    if (!result) return;
    document.getElementById("dissect-tag").textContent = result.totalBytes + " B";
    document.getElementById("dissect-summary").innerHTML = result.layers.map((item) =>
      `<span class="pill${item.error ? " pill--bad" : ""}">${PH.esc(item.name)} · ${item.length} B</span>`
    ).join("");
    selected = Math.min(selected, Math.max(0, result.layers.length - 1));
    renderTree();
    renderHexdump();
    renderDetail();
    renderWarnings();
    PH.setStatus(document.getElementById("dissect-status"),
      `${result.summary} · ${result.layers.length} layer(s) · ${result.totalBytes} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
      result.warnings.length ? "warn" : "ok");
  }

  function dissect(showErrors) {
    const input = document.getElementById("dissect-input");
    let bytes;
    try {
      bytes = PH.parseHex(input.value);
    } catch (err) {
      if (showErrors !== false) PH.setStatus(document.getElementById("dissect-status"), "hex error: " + err.message, "bad");
      return null;
    }
    try {
      result = Dissector.dissect(bytes, { kind: document.getElementById("dissect-kind").value });
      selected = 0;
      render();
      return result;
    } catch (err) {
      result = null;
      if (showErrors !== false) PH.setStatus(document.getElementById("dissect-status"), "dissect error: " + err.message, "bad");
      return null;
    }
  }

  function loadExample(key) {
    const builder = EXAMPLES[key];
    if (!builder) return;
    try {
      const bytes = builder();
      document.getElementById("dissect-input").value = PH.bytesToHex(bytes);
      document.getElementById("dissect-kind").value = "auto";
      dissect(true);
    } catch (err) {
      PH.setStatus(document.getElementById("dissect-status"), "example build error: " + err.message, "bad");
    }
  }

  function permalinkState() {
    return {
      page: "dissect",
      kind: document.getElementById("dissect-kind").value,
      hex: document.getElementById("dissect-input").value
    };
  }

  function sanitize(value) {
    if (value instanceof Uint8Array) return PH.bytesToHex(value);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach((key) => {
        if (key === "meta" || key === "bytes") return;
        out[key] = sanitize(value[key]);
      });
      return out;
    }
    return value;
  }

  function bpfFilter(current) {
    const layers = current.layers;
    const ipv4 = layers.find((item) => item.proto === "ipv4");
    const ipv6 = layers.find((item) => item.proto === "ipv6");
    const tcp = layers.find((item) => item.proto === "tcp");
    const udp = layers.find((item) => item.proto === "udp");
    const icmp = layers.find((item) => item.proto === "icmp" || item.proto === "icmpv6");
    const arp = layers.find((item) => item.proto === "arp");
    const parts = [];
    if (ipv4) parts.push("ip");
    else if (ipv6) parts.push("ip6");
    if (arp) parts.push("arp");
    if (tcp) parts.push("tcp");
    else if (udp) parts.push("udp");
    else if (icmp) parts.push("icmp");
    const network = ipv4 ? ipv4.meta.ip : ipv6 ? ipv6.meta.ip : null;
    if (network) {
      parts.push("host " + network.src);
      parts.push("host " + network.dst);
    }
    if (tcp) {
      parts.push("port " + tcp.meta.parsed.dport);
    } else if (udp) {
      parts.push("port " + udp.meta.parsed.dstPort);
    }
    if (layers.some((item) => item.proto === "vlan")) parts.push("vlan");
    return parts.length ? parts.join(" and ") : "ip or ip6 or arp";
  }

  function scapySnippet(current) {
    const hex = PH.bytesToHex(current.bytes);
    const first = current.layers[0] && current.layers[0].proto;
    const cls = first === "ipv4" ? "IP" : first === "ipv6" ? "IPv6" : first === "ethernet" ? "Ether" : "Raw";
    const imports = cls === "IP" ? "IP" : cls === "IPv6" ? "IPv6" : cls === "Ether" ? "Ether" : "Raw";
    return "from scapy.all import " + imports + "\n\n" +
      "pkt = " + cls + "(bytes.fromhex(\"" + hex + "\"))\n" +
      "pkt.show()\n" +
      "# sendp(pkt) / send(pkt) only on a lab network you control.\n";
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state || state.page !== "dissect") return false;
    document.getElementById("dissect-kind").value = state.kind || "auto";
    document.getElementById("dissect-input").value = state.hex || "";
    return !!dissect(true);
  }

  function init() {
    const run = document.getElementById("dissect-run");
    if (!run) return;
    run.addEventListener("click", () => dissect(true));
    document.getElementById("dissect-input").addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") dissect(true);
    });
    document.getElementById("dissect-clear").addEventListener("click", () => {
      result = null;
      document.getElementById("dissect-input").value = "";
      document.getElementById("dissect-summary").innerHTML = "";
      document.getElementById("dissect-tree").innerHTML = "";
      document.getElementById("dissect-hexdump").innerHTML = "";
      document.getElementById("dissect-detail").innerHTML = "";
      document.getElementById("dissect-warnings").innerHTML = "";
      document.getElementById("dissect-tag").textContent = "waiting";
      PH.setStatus(document.getElementById("dissect-status"), "No frame dissected yet.", "");
    });
    Object.keys(EXAMPLES).forEach((key) => {
      const button = document.getElementById("dissect-example-" + key);
      if (button) button.addEventListener("click", () => loadExample(key));
    });
    document.getElementById("dissect-permalink").addEventListener("click", () => {
      const current = result || dissect(true);
      if (current) PH.shareState(permalinkState(), "dissector permalink copied");
    });
    document.getElementById("dissect-export").addEventListener("click", () => {
      const current = result || dissect(true);
      if (!current) return;
      PH.downloadText("packet-dissect.json", JSON.stringify({
        hex: PH.bytesToHex(current.bytes),
        bytes: current.totalBytes,
        detectedAs: current.detectedAs,
        summary: current.summary,
        layers: sanitize(current.layers),
        warnings: current.warnings
      }, null, 2), "application/json");
    });
    document.getElementById("dissect-copy-hex").addEventListener("click", () => {
      if (result) PH.copyText(PH.bytesToHex(result.bytes));
    });
    document.getElementById("dissect-copy-bpf").addEventListener("click", () => {
      const current = result || dissect(true);
      if (current) PH.copyText(bpfFilter(current));
    });
    document.getElementById("dissect-copy-scapy").addEventListener("click", () => {
      const current = result || dissect(true);
      if (current) PH.copyText(scapySnippet(current));
    });
    if (!restoreState()) loadExample("tcp");
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
