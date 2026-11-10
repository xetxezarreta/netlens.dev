/* Packet workbench: local pcap/pcapng loading, packet list, filters, stats,
 * follow-stream and exports. All parsing stays in this tab. */
(function () {
  "use strict";

  const PH = window.PH;
  const PCap = window.PCapCodec;
  const Dissector = window.Dissector;
  const MAX_PACKETS = 20000;
  const MAX_BYTES = 50 * 1024 * 1024;
  const PAGE = 300;

  let view = null;
  let capture = null;
  let records = [];
  let filtered = [];
  let selected = null;
  let firstTs = 0;
  let visible = PAGE;
  let filterAst = null;
  let loadToken = 0;
  let streamState = null;
  let streamDir = "aToB";
  let streamMode = "text";

  const $ = (id) => document.getElementById(id);
  const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

  function formatAbsolute(ts) {
    if (!ts) return "no timestamp";
    return new Date(ts * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
  }

  function formatRelative(ts) {
    if (!ts || !firstTs) return "—";
    return (ts - firstTs).toFixed(6);
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) return "0 s";
    if (seconds < 0.001) return (seconds * 1e6).toFixed(0) + " µs";
    if (seconds < 1) return (seconds * 1000).toFixed(2) + " ms";
    if (seconds < 60) return seconds.toFixed(3) + " s";
    return Math.floor(seconds / 60) + " m " + (seconds % 60).toFixed(1) + " s";
  }

  function countText(value) {
    return Number(value || 0).toLocaleString("en-US");
  }

  function tcpFlags(flags) {
    const names = [
      ["CWR", 0x80], ["ECE", 0x40], ["URG", 0x20], ["ACK", 0x10],
      ["PSH", 0x08], ["RST", 0x04], ["SYN", 0x02], ["FIN", 0x01]
    ];
    const set = names.filter((pair) => flags & pair[1]).map((pair) => pair[0]);
    return set.length ? set.join(",") : "none";
  }

  function protoLabel(index) {
    if (index.http) return index.http.kind === "h2" ? "HTTP/2" : "HTTP";
    if (index.dns) return "DNS";
    if (index.tls) return "TLS";
    if (index.dhcp) return "DHCP";
    if (index.quic) return "QUIC";
    if (index.bgp) return "BGP";
    if (index.tcp) return "TCP";
    if (index.udp) return "UDP";
    if (index.icmpv6) return "ICMPv6";
    if (index.icmp) return "ICMP";
    if (index.arp) return "ARP";
    if (index.ipv6) return "IPv6";
    if (index.ipv4) return "IPv4";
    if (index.vlan) return "VLAN";
    if (index.eth) return "Ethernet";
    return "raw";
  }

  function endpointsOf(index) {
    if (index.ipv4) {
      return {
        src: index.ipv4.src, dst: index.ipv4.dst,
        sport: index.tcp ? index.tcp.sport : index.udp ? index.udp.sport : 0,
        dport: index.tcp ? index.tcp.dport : index.udp ? index.udp.dport : 0
      };
    }
    if (index.ipv6) {
      return {
        src: index.ipv6.src, dst: index.ipv6.dst,
        sport: index.tcp ? index.tcp.sport : index.udp ? index.udp.sport : 0,
        dport: index.tcp ? index.tcp.dport : index.udp ? index.udp.dport : 0
      };
    }
    if (index.arp) {
      return { src: index.arp.senderIp, dst: index.arp.targetIp, sport: 0, dport: 0 };
    }
    if (index.eth) {
      return { src: index.eth.src, dst: index.eth.dst, sport: 0, dport: 0 };
    }
    return { src: "—", dst: "—", sport: 0, dport: 0 };
  }

  function endpointText(endpoint) {
    if (!endpoint) return "—";
    return endpoint.addr + (endpoint.port ? ":" + endpoint.port : "");
  }

  function packetInfo(index) {
    if (index.http && index.http.summary) return index.http.summary;
    if (index.dns && index.dns.summary) return index.dns.summary;
    if (index.tls && index.tls.summary) return index.tls.summary;
    if (index.dhcp && index.dhcp.summary) return index.dhcp.summary;
    if (index.bgp && index.bgp.summary) return index.bgp.summary;
    if (index.tcp) return index.tcp.sport + " → " + index.tcp.dport + " [" + tcpFlags(index.tcp.flags) + "] Seq=" + index.tcp.seq + " Len=" + index.tcp.payloadLen;
    if (index.udp) return index.udp.sport + " → " + index.udp.dport + " Len=" + index.udp.len;
    if (index.icmp) return "ICMP type " + index.icmp.type + " code " + index.icmp.code;
    if (index.icmpv6) return "ICMPv6 type " + index.icmpv6.type + " code " + index.icmpv6.code;
    if (index.arp) return (index.arp.opcodeName || ("opcode " + index.arp.opcode)) + " " + index.arp.senderIp + " → " + index.arp.targetIp;
    return index.summary || "";
  }

  function makeIndex(record, bytes, result) {
    const index = {
      number: record.number,
      ts: record.ts,
      len: record.caplen,
      protos: [],
      frame: { number: record.number, time: record.ts, len: record.caplen },
      summary: result.summary || ""
    };
    result.layers.forEach((layer) => {
      if (layer.proto && index.protos.indexOf(layer.proto) === -1) index.protos.push(layer.proto);
    });
    const find = (proto) => result.layers.find((layer) => layer.proto === proto);

    const eth = find("ethernet");
    if (eth && eth.meta && eth.meta.eth) {
      const value = eth.meta.eth;
      index.eth = { src: value.srcMac, dst: value.dstMac, type: value.etherType };
      if (value.vlanTags && value.vlanTags.length) {
        index.vlan = { id: value.vlanTags[0].vid, pcp: value.vlanTags[0].pcp };
      }
    }
    const vlan = find("vlan");
    if (vlan && !index.vlan) {
      const vid = vlan.fields.find((field) => field.name === "VID");
      const pcp = vlan.fields.find((field) => field.name === "PCP");
      if (vid) index.vlan = { id: Number(vid.value), pcp: pcp ? Number(pcp.value) : 0 };
    }
    const ipv4 = find("ipv4");
    if (ipv4 && ipv4.meta && ipv4.meta.ip) {
      const value = ipv4.meta.ip;
      index.ipv4 = { src: value.src, dst: value.dst, proto: value.protocol, ttl: value.ttl, len: value.totalLength };
    }
    const ipv6 = find("ipv6");
    if (ipv6 && ipv6.meta && ipv6.meta.ip) {
      const value = ipv6.meta.ip;
      index.ipv6 = { src: value.src, dst: value.dst, next: value.nextHeader, hopLimit: value.hopLimit, len: (value.payloadLength || 0) + 40 };
    }
    const arp = find("arp");
    if (arp && arp.meta && arp.meta.arp) {
      const value = arp.meta.arp;
      index.arp = {
        opcode: value.opcode, opcodeName: value.opcodeName,
        senderIp: value.senderIp, targetIp: value.targetIp,
        senderMac: value.senderMac, targetMac: value.targetMac
      };
    }
    const tcp = find("tcp");
    if (tcp && tcp.meta && tcp.meta.parsed) {
      const value = tcp.meta.parsed;
      index.tcp = {
        sport: value.sport, dport: value.dport, seq: value.seq, ack: value.ack,
        flags: value.flags, syn: Boolean(value.flags & 0x02), ackFlag: Boolean(value.flags & 0x10),
        fin: Boolean(value.flags & 0x01), rst: Boolean(value.flags & 0x04),
        psh: Boolean(value.flags & 0x08), urg: Boolean(value.flags & 0x20),
        ece: Boolean(value.flags & 0x40), cwr: Boolean(value.flags & 0x80),
        headerLen: value.headerLen, payloadLen: value.payload.length,
        payloadOffset: tcp.offset + value.headerLen
      };
    }
    const udp = find("udp");
    if (udp && udp.meta && udp.meta.parsed) {
      const value = udp.meta.parsed;
      index.udp = {
        sport: value.srcPort, dport: value.dstPort, len: value.length,
        payloadLen: value.payloadLength, payloadOffset: udp.offset + 8
      };
    }
    const icmp = find("icmp");
    if (icmp && icmp.meta && icmp.meta.parsed) {
      index.icmp = { type: icmp.meta.parsed.type, code: icmp.meta.parsed.code };
    }
    const icmpv6 = find("icmpv6");
    if (icmpv6) {
      index.icmpv6 = {
        type: bytes[icmpv6.offset] == null ? 0 : bytes[icmpv6.offset],
        code: bytes[icmpv6.offset + 1] == null ? 0 : bytes[icmpv6.offset + 1]
      };
    }
    const dns = find("dns");
    if (dns && dns.meta && dns.meta.message) {
      const message = dns.meta.message;
      const question = message.questions && message.questions[0];
      index.dns = {
        id: message.header ? message.header.id : null,
        qname: question ? question.name : "",
        response: Boolean(message.header && message.header.qr),
        summary: dns.summary
      };
    }
    const dhcp = find("dhcp");
    if (dhcp && dhcp.meta && dhcp.meta.message) {
      const message = dhcp.meta.message;
      index.dhcp = { type: message.messageTypeName, xid: message.xid, summary: dhcp.summary };
    }
    const http = find("http");
    if (http && http.meta && http.meta.decoded) {
      const decoded = http.meta.decoded;
      let host = "";
      if (decoded.headers) {
        const header = decoded.headers.find((item) => (item.lower || item.name || "").toLowerCase() === "host" || (item.lower || item.name || "").toLowerCase() === ":authority");
        if (header) host = header.value;
      }
      index.http = {
        kind: decoded.kind, method: decoded.method || "", target: decoded.target || "",
        status: decoded.status == null ? null : decoded.status, host, summary: http.summary
      };
    }
    const tls = find("tls");
    if (tls && tls.meta && tls.meta.decoded) {
      const decoded = tls.meta.decoded;
      const handshake = decoded.handshakes && decoded.handshakes[0];
      index.tls = {
        sni: decoded.context && decoded.context.sni ? decoded.context.sni : "",
        version: decoded.context && decoded.context.negotiatedVersion ? decoded.context.negotiatedVersion : null,
        handshakeType: handshake ? handshake.type : null,
        summary: tls.summary
      };
    }
    const bgp = find("bgp");
    if (bgp && bgp.meta && bgp.meta.message) {
      index.bgp = { type: bgp.meta.message.type, summary: bgp.summary };
    }
    index.info = packetInfo(index);
    return index;
  }

  function renderFilterChips() {
    const host = $("wb-filter-chips");
    if (!host) return;
    host.innerHTML = "";
    (window.PHFilter ? window.PHFilter.examples : []).forEach((example) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "wb-chip";
      button.textContent = example;
      button.addEventListener("click", () => {
        $("wb-filter").value = example;
        applyFilter();
      });
      host.appendChild(button);
    });
  }

  function setFilterStatus(text, kind) {
    PH.setStatus($("wb-filter-status"), text, kind);
  }

  function applyFilter() {
    const input = $("wb-filter");
    const text = input ? input.value.trim() : "";
    if (!text) {
      filterAst = null;
      setFilterStatus("all packets", "");
      renderList(true);
      if (!selected && filtered.length) selectRecord(filtered[0]);
      return;
    }
    try {
      filterAst = window.PHFilter.parse(text);
    } catch (err) {
      setFilterStatus("filter error: " + err.message, "bad");
      return;
    }
    renderList(true);
    setFilterStatus(filtered.length + " of " + records.length + " packet" + (records.length === 1 ? "" : "s"), filtered.length ? "ok" : "warn");
    if (!selected && filtered.length) selectRecord(filtered[0]);
  }

  function rowHtml(record) {
    const index = record._index || {};
    const endpoints = endpointsOf(index);
    const isSelected = selected && selected.index === record.index;
    return `<div class="wb-packet${isSelected ? " is-selected" : ""}" role="option" id="wb-packet-${record.index}" data-record="${record.index}" ` +
      `aria-selected="${isSelected ? "true" : "false"}" tabindex="-1">` +
      `<span class="wb-col wb-col-num">${record.number}</span>` +
      `<span class="wb-col wb-col-time" title="${PH.esc(formatAbsolute(record.ts))}">${PH.esc(formatRelative(record.ts))}</span>` +
      `<span class="wb-col wb-col-src">${PH.esc(endpoints.src || "—")}</span>` +
      `<span class="wb-col wb-col-dst">${PH.esc(endpoints.dst || "—")}</span>` +
      `<span class="wb-col wb-col-proto"><b>${PH.esc(protoLabel(index))}</b></span>` +
      `<span class="wb-col wb-col-len">${record.caplen}</span>` +
      `<span class="wb-col wb-col-info">${PH.esc(index.info || index.summary || "")}</span>` +
      `</div>`;
  }

  function updateSelectionUi() {
    const list = $("wb-list");
    if (!list) return;
    list.querySelectorAll(".wb-packet").forEach((row) => {
      const on = selected && Number(row.dataset.record) === selected.index;
      row.classList.toggle("is-selected", Boolean(on));
      row.setAttribute("aria-selected", on ? "true" : "false");
    });
    if (selected) list.setAttribute("aria-activedescendant", "wb-packet-" + selected.index);
    else list.removeAttribute("aria-activedescendant");
  }

  function renderList(reset) {
    if (reset) visible = PAGE;
    filtered = records.filter((record) => !filterAst || window.PHFilter.evaluate(filterAst, record._index));
    if (selected && filtered.indexOf(selected) === -1) {
      selected = null;
      view.clear("Select a packet in the list.");
    }
    const shown = filtered.slice(0, visible);
    const list = $("wb-list");
    if (list) list.innerHTML = shown.map(rowHtml).join("");
    const empty = $("wb-empty");
    if (empty) {
      empty.hidden = filtered.length > 0;
      empty.textContent = records.length ? "No packets match this filter." : "Open a capture to see packets here.";
    }
    const count = $("wb-list-count");
    if (count) count.textContent = countText(filtered.length) + " of " + countText(records.length) + " packet" + (records.length === 1 ? "" : "s");
    const more = $("wb-more");
    if (more) more.hidden = visible >= filtered.length;
    updateSelectionUi();
    renderStats();
  }

  function selectRecord(record) {
    if (!record || !capture) return;
    selected = record;
    updateSelectionUi();
    const bytes = PCap.recordBytes(capture, record);
    let result;
    try {
      result = Dissector.dissectLink(bytes, record.linkType);
    } catch (err) {
      result = Dissector.dissect(bytes, { kind: "raw", note: "decode failed: " + err.message });
      result.warnings.push("Workbench decode failed: " + err.message);
    }
    view.render(result);
  }

  function protoName(proto) {
    return ({
      ethernet: "Ethernet", vlan: "VLAN", arp: "ARP", ipv4: "IPv4", ipv6: "IPv6",
      tcp: "TCP", udp: "UDP", icmp: "ICMP", icmpv6: "ICMPv6", dns: "DNS",
      dhcp: "DHCP", http: "HTTP", tls: "TLS", quic: "QUIC", bgp: "BGP",
      payload: "Payload", fcs: "FCS", link: "Link", raw: "Raw"
    })[proto] || proto;
  }

  function renderTable(host, headers, rows) {
    if (!host) return;
    if (!rows.length) {
      host.innerHTML = '<p class="dim">No packets in the current filter.</p>';
      return;
    }
    host.innerHTML = '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((header) => '<th>' + PH.esc(header) + '</th>').join("") +
      '</tr></thead><tbody>' +
      rows.map((row) => '<tr>' + row.map((cell) => '<td>' + PH.esc(cell == null ? "" : cell) + '</td>').join("") + '</tr>').join("") +
      '</tbody></table></div>';
  }

  function renderStats() {
    if (!records.length) {
      ["wb-stats-conv", "wb-stats-protos", "wb-stats-endpoints"].forEach((id) => {
        const host = $(id);
        if (host) host.innerHTML = '<p class="dim">Open a capture to see statistics.</p>';
      });
      return;
    }
    const conversations = new Map();
    const protocols = new Map();
    const endpoints = new Map();
    filtered.forEach((record) => {
      const index = record._index || {};
      const ep = endpointsOf(index);
      const left = ep.src + (ep.sport ? ":" + ep.sport : "");
      const right = ep.dst + (ep.dport ? ":" + ep.dport : "");
      const key = [left, right].sort().join(" ↔ ");
      const conversation = conversations.get(key) || {
        left, right, proto: protoLabel(index), packets: 0, bytes: 0,
        first: record.ts || 0, last: record.ts || 0
      };
      conversation.packets += 1;
      conversation.bytes += record.caplen;
      if (record.ts) {
        if (!conversation.first || record.ts < conversation.first) conversation.first = record.ts;
        if (record.ts > conversation.last) conversation.last = record.ts;
      }
      conversations.set(key, conversation);

      (index.protos || []).forEach((proto) => {
        const entry = protocols.get(proto) || { packets: 0, bytes: 0 };
        entry.packets += 1;
        entry.bytes += record.caplen;
        protocols.set(proto, entry);
      });

      [ep.src, ep.dst].forEach((addr) => {
        if (!addr || addr === "—") return;
        const entry = endpoints.get(addr) || { packets: 0, bytes: 0, first: record.ts || 0, last: record.ts || 0 };
        entry.packets += 1;
        entry.bytes += record.caplen;
        if (record.ts) {
          if (!entry.first || record.ts < entry.first) entry.first = record.ts;
          if (record.ts > entry.last) entry.last = record.ts;
        }
        endpoints.set(addr, entry);
      });
    });

    renderTable($("wb-stats-conv"), ["conversation", "proto", "packets", "bytes", "duration"],
      Array.from(conversations.values()).sort((a, b) => b.packets - a.packets).map((entry) =>
        [entry.left + " ↔ " + entry.right, entry.proto, countText(entry.packets), countText(entry.bytes), formatDuration(entry.last - entry.first)]));

    renderTable($("wb-stats-protos"), ["protocol", "packets", "bytes"],
      Array.from(protocols.entries()).sort((a, b) => b[1].packets - a[1].packets).map(([proto, entry]) =>
        [protoName(proto), countText(entry.packets), countText(entry.bytes)]));

    renderTable($("wb-stats-endpoints"), ["endpoint", "packets", "bytes", "first", "last"],
      Array.from(endpoints.entries()).sort((a, b) => b[1].packets - a[1].packets).map(([address, entry]) =>
        [address, countText(entry.packets), countText(entry.bytes), formatAbsolute(entry.first), formatAbsolute(entry.last)]));
  }

  function updateProgress(done, total) {
    const host = $("wb-progress");
    const fill = $("wb-progress-fill");
    const text = $("wb-progress-text");
    if (!host) return;
    host.hidden = false;
    host.setAttribute("role", "progressbar");
    host.setAttribute("aria-label", "Indexing capture");
    host.setAttribute("aria-valuemin", "0");
    host.setAttribute("aria-valuemax", String(total));
    host.setAttribute("aria-valuenow", String(done));
    if (fill) fill.style.width = (total ? Math.round((done / total) * 100) : 100) + "%";
    if (text) text.textContent = "Indexing " + countText(done) + " / " + countText(total) + " packets…";
  }

  function hideProgress() {
    const host = $("wb-progress");
    if (host) host.hidden = true;
    const fill = $("wb-progress-fill");
    if (fill) fill.style.width = "0%";
  }

  function renderCaptureSummary(label) {
    const summary = $("wb-capture-summary");
    if (!summary) return;
    if (!capture) { summary.innerHTML = ""; return; }
    const info = PCap.summary(capture);
    const linkTypes = info.linkTypes.length ? info.linkTypes.join(", ") : "unknown link type";
    summary.innerHTML = [
      '<span class="pill"><b>' + PH.esc(capture.format) + "</b> · " + PH.esc(label || "capture") + "</span>",
      '<span class="pill">' + countText(info.packets) + " packet" + (info.packets === 1 ? "" : "s") + "</span>",
      '<span class="pill">' + PH.esc(linkTypes) + "</span>",
      '<span class="pill">' + formatDuration(info.duration) + "</span>",
      '<span class="pill">' + countText(info.warnings) + " capture note" + (info.warnings === 1 ? "" : "s") + "</span>"
    ].join("");
    const tag = $("wb-file-tag");
    if (tag) tag.textContent = capture.format + " · " + countText(info.packets) + " pkt";
  }

  function renderLoadWarnings() {
    const host = $("wb-load-warnings");
    if (!host) return;
    if (!capture || !capture.warnings.length) { host.innerHTML = ""; return; }
    host.innerHTML = '<div class="callout callout--warn"><div class="callout__title">capture notes</div><ul class="dashed" style="margin:0">' +
      capture.warnings.map((warning) => "<li>" + PH.esc(warning) + "</li>").join("") + "</ul></div>";
  }

  async function indexRecords(token) {
    const total = records.length;
    if (!total) { hideProgress(); return true; }
    updateProgress(0, total);
    for (let i = 0; i < total; i += 1) {
      if (token !== loadToken) { hideProgress(); return false; }
      const record = records[i];
      const bytes = PCap.recordBytes(capture, record);
      let result;
      try {
        result = Dissector.dissectLink(bytes, record.linkType);
      } catch (err) {
        result = Dissector.dissect(bytes, { kind: "raw", note: "decode failed: " + err.message });
        result.warnings.push("Workbench decode failed: " + err.message);
      }
      try {
        record._index = makeIndex(record, bytes, result);
      } catch (err) {
        record._index = {
          number: record.number, ts: record.ts, len: record.caplen, protos: ["raw"],
          frame: { number: record.number, time: record.ts, len: record.caplen },
          summary: "Index failed: " + err.message, info: "Index failed: " + err.message
        };
      }
      if (i % 200 === 0 || i === total - 1) {
        updateProgress(i + 1, total);
        await tick();
      }
    }
    hideProgress();
    return true;
  }

  async function loadCapture(next, label) {
    const token = ++loadToken;
    streamState = null;
    const openDialog = $("wb-stream-dialog");
    if (openDialog && openDialog.open) openDialog.close();
    capture = next;
    records = capture.records.slice(0, MAX_PACKETS);
    if (capture.records.length > MAX_PACKETS) {
      const total = capture.records.length;
      capture.records = records;
      capture.warnings.push("This build shows the first " + countText(MAX_PACKETS) + " packets; " + countText(total - MAX_PACKETS) + " were not loaded.");
    }
    firstTs = 0;
    for (let i = 0; i < records.length; i += 1) {
      if (records[i].ts > 0) { firstTs = records[i].ts; break; }
    }
    selected = null;
    visible = PAGE;
    filterAst = null;
    const filterInput = $("wb-filter");
    if (filterInput) filterInput.value = "";
    setFilterStatus("all packets", "");
    view.clear("Select a packet in the list.");
    renderCaptureSummary(label);
    renderLoadWarnings();
    const status = $("wb-status");
    if (status) PH.setStatus(status, "Indexing " + countText(records.length) + " packets…", "warn");
    await indexRecords(token);
    if (token !== loadToken) return;
    renderList(true);
    if (filterInput && filterInput.value.trim()) applyFilter();
    if (records.length) selectRecord(records[0]);
    if (status) {
      PH.setStatus(status,
        (label || "capture") + " · " + capture.format + " · " + countText(records.length) + " packet" + (records.length === 1 ? "" : "s") + " · " +
        (capture.interfaces.length ? capture.interfaces.map((iface) => PCap.linkTypeName(iface.linkType)).filter((name, i, all) => all.indexOf(name) === i).join(", ") : "unknown link") +
        " · " + formatDuration(PCap.summary(capture).duration) +
        (capture.warnings.length ? " · " + capture.warnings.length + " note(s)" : ""),
        capture.warnings.length ? "warn" : "ok");
    }
  }

  async function loadBuffer(buffer, label) {
    const status = $("wb-status");
    if (buffer && buffer.byteLength > MAX_BYTES) {
      if (status) PH.setStatus(status, "capture is larger than 50 MB; this build refuses to load it", "bad");
      return;
    }
    let parsed;
    try {
      parsed = PCap.parse(buffer);
    } catch (err) {
      if (status) PH.setStatus(status, "capture error: " + err.message, "bad");
      return;
    }
    await loadCapture(parsed, label);
  }

  function readFile(file) {
    if (file && typeof file.arrayBuffer === "function") return file.arrayBuffer();
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error("File read failed"));
      reader.readAsArrayBuffer(file);
    });
  }

  async function loadFile(file) {
    if (!file) return;
    const status = $("wb-status");
    if (file.size > MAX_BYTES) {
      if (status) PH.setStatus(status, "file is larger than 50 MB; this build refuses to load it", "bad");
      return;
    }
    if (status) PH.setStatus(status, "Reading " + file.name + "…", "warn");
    try {
      const buffer = await readFile(file);
      await loadBuffer(buffer, file.name);
    } catch (err) {
      if (status) PH.setStatus(status, "file read error: " + err.message, "bad");
    }
  }

  function tcpFrame(options) {
    const tcp = window.TCPCodec.buildSegment({
      sport: options.sport, dport: options.dport, seq: options.seq, ack: options.ack,
      flags: options.flags, window: 64240, urgent: 0, reserved: 0,
      src: options.src, dst: options.dst, options: "",
      payload: options.payload || new Uint8Array(0)
    }).bytes;
    const ip = window.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: options.id || 1, ttl: 64, protocol: 6,
      fragmentOffset: 0, payloadLength: tcp.length, reserved: false, df: true, mf: false,
      src: options.src, dst: options.dst, options: ""
    }).bytes;
    return window.EthernetCodec.buildFrame({
      dst: options.dstMac, src: options.srcMac, etherType: 0x0800,
      payload: PH.concatBytes(ip, tcp), pad: false, fcs: true
    }).bytes;
  }

  function udpFrame(options) {
    const udp = window.UDPCodec.buildUdp({
      srcPort: options.sport, dstPort: options.dport, payload: options.payload,
      ipVersion: 4, srcIp: options.src, dstIp: options.dst
    }).bytes;
    const ip = window.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: options.id || 1, ttl: 64, protocol: 17,
      fragmentOffset: 0, payloadLength: udp.length, reserved: false, df: true, mf: false,
      src: options.src, dst: options.dst, options: ""
    }).bytes;
    return window.EthernetCodec.buildFrame({
      dst: options.dstMac, src: options.srcMac, etherType: 0x0800,
      payload: PH.concatBytes(ip, udp), pad: false, fcs: true
    }).bytes;
  }

  function buildExampleFrames() {
    const client = "192.0.2.10";
    const server = "198.51.100.20";
    const clientMac = "02:00:00:00:00:0a";
    const serverMac = "02:00:00:00:00:01";
    const gatewayMac = "02:00:00:00:00:fe";
    const frames = [];
    frames.push({ bytes: tcpFrame({ src: client, dst: server, srcMac: clientMac, dstMac: serverMac, sport: 50000, dport: 80, seq: 1000, ack: 0, flags: 0x02, id: 1 }), linkType: 1 });
    frames.push({ bytes: tcpFrame({ src: server, dst: client, srcMac: serverMac, dstMac: clientMac, sport: 80, dport: 50000, seq: 5000, ack: 1001, flags: 0x12, id: 2 }), linkType: 1 });
    frames.push({ bytes: tcpFrame({ src: client, dst: server, srcMac: clientMac, dstMac: serverMac, sport: 50000, dport: 80, seq: 1001, ack: 5001, flags: 0x10, id: 3 }), linkType: 1 });
    const request = window.HTTPCodec.buildHttp1({
      kind: "request", method: "GET", target: "/index.html", host: "example.com",
      headers: [{ name: "User-Agent", value: "netlens.dev/1.0" }, { name: "Accept", value: "text/html" }]
    }).bytes;
    frames.push({ bytes: tcpFrame({ src: client, dst: server, srcMac: clientMac, dstMac: serverMac, sport: 50000, dport: 80, seq: 1002, ack: 5001, flags: 0x18, id: 4, payload: request }), linkType: 1 });
    const response = window.HTTPCodec.buildHttp1({
      kind: "response", status: 200,
      headers: [{ name: "Content-Type", value: "text/html" }],
      body: "<html><body><h1>netlens example</h1></body></html>"
    }).bytes;
    frames.push({ bytes: tcpFrame({ src: server, dst: client, srcMac: serverMac, dstMac: clientMac, sport: 80, dport: 50000, seq: 5002, ack: 1002 + request.length, flags: 0x18, id: 5, payload: response }), linkType: 1 });

    const query = window.DNSCodec.buildMessage(window.DNSCodec.examples().queryA).bytes;
    frames.push({ bytes: udpFrame({ src: client, dst: server, srcMac: clientMac, dstMac: serverMac, sport: 53000, dport: 53, id: 6, payload: query }), linkType: 1 });

    const arp = window.ARPCodec.buildArp({
      htype: 1, ptype: 0x0800, opcode: 1,
      senderMac: clientMac, senderIp: client,
      targetMac: "00:00:00:00:00:00", targetIp: "192.0.2.1"
    }).bytes;
    frames.push({ bytes: window.ARPCodec.buildEthernetWrapper(arp.bytes, { dstMac: gatewayMac, senderMac: clientMac, fcs: true }).bytes, linkType: 1 });

    const hello = window.TLSCodec.buildClientHello({ sni: "example.com", alpn: ["h2", "http/1.1"] }).bytes;
    frames.push({ bytes: tcpFrame({ src: client, dst: server, srcMac: clientMac, dstMac: serverMac, sport: 50001, dport: 443, seq: 7000, ack: 0, flags: 0x02, id: 7 }), linkType: 1 });
    frames.push({ bytes: tcpFrame({ src: client, dst: server, srcMac: clientMac, dstMac: serverMac, sport: 50001, dport: 443, seq: 7001, ack: 1, flags: 0x18, id: 8, payload: hello }), linkType: 1 });

    const base = 1700000000;
    frames.forEach((frame, index) => { frame.ts = base + index * 0.001; });
    return frames;
  }

  function loadExampleCapture() {
    try {
      const frames = buildExampleFrames();
      const synthetic = PCap.fromFrames(frames);
      const bytes = PCap.encodeClassic(synthetic, synthetic.records);
      return loadBuffer(bytes, "example.pcap");
    } catch (err) {
      const status = $("wb-status");
      if (status) PH.setStatus(status, "example build error: " + err.message, "bad");
      return null;
    }
  }

  function clearCapture() {
    loadToken += 1;
    capture = null;
    records = [];
    filtered = [];
    selected = null;
    firstTs = 0;
    visible = PAGE;
    filterAst = null;
    streamState = null;
    const openDialog = $("wb-stream-dialog");
    if (openDialog && openDialog.open) openDialog.close();
    const filterInput = $("wb-filter");
    if (filterInput) filterInput.value = "";
    setFilterStatus("all packets", "");
    view.clear("Select a packet in the list.");
    const list = $("wb-list");
    if (list) list.innerHTML = "";
    const empty = $("wb-empty");
    if (empty) { empty.hidden = false; empty.textContent = "Open a capture to see packets here."; }
    const count = $("wb-list-count");
    if (count) count.textContent = "0 packets";
    const more = $("wb-more");
    if (more) more.hidden = true;
    ["wb-stats-conv", "wb-stats-protos", "wb-stats-endpoints"].forEach((id) => {
      const host = $(id);
      if (host) host.innerHTML = '<p class="dim">Open a capture to see statistics.</p>';
    });
    const summary = $("wb-capture-summary");
    if (summary) summary.innerHTML = "";
    const warnings = $("wb-load-warnings");
    if (warnings) warnings.innerHTML = "";
    const tag = $("wb-file-tag");
    if (tag) tag.textContent = "waiting";
    const status = $("wb-status");
    if (status) PH.setStatus(status, "No capture loaded yet.", "");
    hideProgress();
  }

  function ensureStreamDialog() {
    let dialog = $("wb-stream-dialog");
    if (dialog) return dialog;
    dialog = document.createElement("dialog");
    dialog.id = "wb-stream-dialog";
    dialog.className = "wb-dialog";
    dialog.setAttribute("aria-label", "Follow TCP stream");
    dialog.innerHTML =
      '<div class="wb-dialog__head"><div><h3>Follow TCP stream</h3><p class="dim" id="wb-stream-endpoints"></p></div>' +
      '<button class="btn btn--ghost" type="button" data-stream-close>close</button></div>' +
      '<div class="wb-dialog__meta" id="wb-stream-meta"></div>' +
      '<div class="btn-row">' +
      '<button class="btn btn--ghost" type="button" data-stream-dir="aToB">A → B</button>' +
      '<button class="btn btn--ghost" type="button" data-stream-dir="bToA">B → A</button>' +
      '<button class="btn btn--ghost" type="button" data-stream-mode>show hex</button>' +
      '<button class="btn btn--ghost" type="button" data-stream-copy>copy</button>' +
      '<button class="btn btn--ghost" type="button" data-stream-download>download</button>' +
      '</div>' +
      '<pre class="wb-stream-output" id="wb-stream-output" tabindex="0"></pre>' +
      '<p class="small dim" style="margin-top:8px">Best-effort reassembly: payload is ordered by sequence, exact retransmissions are dropped and gaps are marked. Encrypted bytes stay opaque.</p>';
    document.body.appendChild(dialog);

    function closeDialog() {
      if (typeof dialog.close === "function" && dialog.open) dialog.close();
      else dialog.removeAttribute("open");
    }
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) { closeDialog(); return; }
      const close = event.target.closest("[data-stream-close]");
      if (close) { closeDialog(); return; }
      const dir = event.target.closest("[data-stream-dir]");
      if (dir) { streamDir = dir.dataset.streamDir; renderStream(); return; }
      if (event.target.closest("[data-stream-mode]")) {
        streamMode = streamMode === "text" ? "hex" : "text";
        renderStream();
        return;
      }
      if (event.target.closest("[data-stream-copy]")) {
        const output = $("wb-stream-output");
        if (output) PH.copyText(output.textContent);
        return;
      }
      if (event.target.closest("[data-stream-download]")) {
        const output = $("wb-stream-output");
        if (output) PH.downloadText("tcp-stream-" + streamDir + ".txt", output.textContent);
      }
    });
    dialog.addEventListener("close", () => {
      streamState = null;
      if (dialog.__returnFocus && typeof dialog.__returnFocus.focus === "function") dialog.__returnFocus.focus();
    });
    dialog.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeDialog();
    });
    return dialog;
  }

  function renderStream() {
    if (!streamState) return;
    const dialog = $("wb-stream-dialog");
    if (!dialog) return;
    const output = $("wb-stream-output");
    const meta = $("wb-stream-meta");
    const endpoints = $("wb-stream-endpoints");
    if (endpoints) {
      endpoints.textContent = endpointText(streamState.a) + "  ↔  " + endpointText(streamState.b) + " · " + (streamState.app || "unknown").toUpperCase();
    }
    const direction = streamState.directions[streamDir];
    const data = window.PHStreams.textAndHex(streamState, streamDir);
    const text = streamMode === "hex" ? data.hex : data.text;
    if (output) output.textContent = text || "(no payload in this direction)";
    if (meta) {
      meta.textContent = countText(streamState.packets) + " packets · " + countText(streamState.totalBytes) + " B payload · " +
        (direction.retransmits || 0) + " retransmit(s) · " + (direction.gaps || 0) + " gap(s) · " + (direction.gapBytes || 0) + " missing byte(s)";
    }
    dialog.querySelectorAll("[data-stream-dir]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.streamDir === streamDir);
    });
    const modeButton = dialog.querySelector("[data-stream-mode]");
    if (modeButton) modeButton.textContent = streamMode === "hex" ? "show text" : "show hex";
  }

  function openStream() {
    if (!selected || !capture) {
      PH.toast("Select a TCP packet first");
      return;
    }
    const stream = window.PHStreams.build(
      records,
      selected,
      (record) => PCap.recordBytes(capture, record),
      (record) => record._index
    );
    if (stream.error) {
      PH.toast(stream.error);
      return;
    }
    streamState = stream;
    streamDir = "aToB";
    streamMode = stream.app === "tls" ? "hex" : "text";
    const dialog = ensureStreamDialog();
    renderStream();
    dialog.__returnFocus = document.activeElement;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    const close = dialog.querySelector("[data-stream-close]");
    if (close) close.focus();
  }

  function csvEscape(value) {
    return '"' + String(value == null ? "" : value).replace(/"/g, '""') + '"';
  }

  function exportCsv() {
    if (!filtered.length) { PH.toast("No packets to export"); return; }
    const lines = ["number,time,source,destination,protocol,length,info"];
    filtered.forEach((record) => {
      const index = record._index || {};
      const ep = endpointsOf(index);
      lines.push([
        record.number,
        record.ts ? record.ts.toFixed(6) : "",
        ep.src,
        ep.dst,
        protoLabel(index),
        record.caplen,
        index.info || index.summary || ""
      ].map(csvEscape).join(","));
    });
    PH.downloadText("netlens-packets.csv", lines.join("\n"), "text/csv");
  }

  function exportJson() {
    if (!filtered.length) { PH.toast("No packets to export"); return; }
    const payload = {
      tool: "netlens.dev packet workbench",
      generated: new Date().toISOString(),
      filter: $("wb-filter") ? $("wb-filter").value : "",
      capture: capture ? {
        format: capture.format,
        linkTypes: capture.interfaces.map((iface) => iface.linkType),
        packets: records.length
      } : null,
      packets: filtered.map((record) => ({
        number: record.number,
        ts: record.ts,
        caplen: record.caplen,
        origlen: record.origlen,
        linkType: record.linkType,
        index: record._index
      }))
    };
    PH.downloadText("netlens-analysis.json", JSON.stringify(payload, null, 2), "application/json");
  }

  function exportPcap() {
    if (!capture || !filtered.length) { PH.toast("No packets to export"); return; }
    let format = capture.format === "pcapng" ? "pcapng" : "pcap";
    let bytes;
    try {
      bytes = PCap.encode(capture, filtered, { format });
    } catch (firstError) {
      try {
        format = "pcapng";
        bytes = PCap.encode(capture, filtered, { format });
      } catch (secondError) {
        PH.toast("export failed: " + secondError.message);
        return;
      }
    }
    PH.downloadBytes("netlens-filtered." + (format === "pcapng" ? "pcapng" : "pcap"), bytes, "application/vnd.tcpdump.pcap");
  }

  function copyPermalink() {
    if (!capture || !selected) {
      PH.toast("Select a packet first");
      return;
    }
    PH.shareState({
      page: "workbench",
      filter: $("wb-filter") ? $("wb-filter").value : "",
      sel: selected.number,
      hex: PH.bytesToHex(PCap.recordBytes(capture, selected)),
      linkType: selected.linkType
    }, "packet link copied");
  }

  function bindEvents() {
    const file = $("wb-file");
    if (file) {
      file.addEventListener("change", () => {
        const chosen = file.files && file.files[0];
        file.value = "";
        if (chosen) loadFile(chosen);
      });
    }

    const drop = $("wb-drop");
    if (drop) {
      ["dragenter", "dragover"].forEach((name) => drop.addEventListener(name, (event) => {
        event.preventDefault();
        drop.classList.add("is-over");
      }));
      ["dragleave", "drop"].forEach((name) => drop.addEventListener(name, () => drop.classList.remove("is-over")));
      drop.addEventListener("drop", (event) => {
        event.preventDefault();
        const chosen = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
        if (chosen) loadFile(chosen);
      });
      drop.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          if (file) file.click();
        }
      });
    }

    const example = $("wb-example");
    if (example) example.addEventListener("click", () => loadExampleCapture());
    const clear = $("wb-clear");
    if (clear) clear.addEventListener("click", clearCapture);

    const hexLoad = $("wb-hex-load");
    if (hexLoad) {
      hexLoad.addEventListener("click", () => {
        const status = $("wb-status");
        let bytes;
        try {
          bytes = PH.parseHex($("wb-hex").value);
        } catch (err) {
          if (status) PH.setStatus(status, "hex error: " + err.message, "bad");
          return;
        }
        if (!bytes.length) {
          if (status) PH.setStatus(status, "hex error: no bytes", "bad");
          return;
        }
        const version = bytes[0] >> 4;
        const linkType = version === 4 || version === 6 ? 101 : 1;
        const synthetic = PCap.fromFrames([{ bytes, linkType, ts: Date.now() / 1000 }]);
        loadCapture(synthetic, "pasted frame");
      });
    }

    const filter = $("wb-filter");
    if (filter) {
      let timer = null;
      filter.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(applyFilter, 200);
      });
      filter.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          clearTimeout(timer);
          applyFilter();
        }
      });
    }
    const filterApply = $("wb-filter-apply");
    if (filterApply) filterApply.addEventListener("click", applyFilter);
    const filterClear = $("wb-filter-clear");
    if (filterClear) filterClear.addEventListener("click", () => {
      const input = $("wb-filter");
      if (input) input.value = "";
      applyFilter();
    });

    const more = $("wb-more");
    if (more) more.addEventListener("click", () => {
      visible += PAGE;
      renderList(false);
    });

    const list = $("wb-list");
    if (list) {
      list.addEventListener("click", (event) => {
        const row = event.target.closest("[data-record]");
        if (!row) return;
        const record = records.find((item) => item.index === Number(row.dataset.record));
        if (record) selectRecord(record);
      });
      list.addEventListener("focus", () => {
        if (!selected && filtered.length) selectRecord(filtered[0]);
      });
      list.addEventListener("keydown", (event) => {
        if (!filtered.length) return;
        const pos = selected ? filtered.indexOf(selected) : -1;
        let next = pos;
        if (event.key === "ArrowDown") next = Math.min(filtered.length - 1, pos + 1);
        else if (event.key === "ArrowUp") next = Math.max(0, pos - 1);
        else if (event.key === "PageDown") next = Math.min(filtered.length - 1, pos + 10);
        else if (event.key === "PageUp") next = Math.max(0, pos - 10);
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = filtered.length - 1;
        else if (event.key === "Enter") {
          event.preventDefault();
          const detail = $("detail");
          if (detail) detail.scrollIntoView({ behavior: "smooth", block: "start" });
          return;
        } else {
          return;
        }
        event.preventDefault();
        if (next < 0) next = 0;
        if (next >= visible) {
          visible = Math.min(filtered.length, Math.ceil((next + 1) / PAGE) * PAGE);
          renderList(false);
        }
        selectRecord(filtered[next]);
        const row = $("wb-packet-" + filtered[next].index);
        if (row) row.scrollIntoView({ block: "nearest" });
      });
    }

    const detail = $("wb-detail");
    if (detail) {
      detail.addEventListener("click", (event) => {
        if (event.target.closest("[data-follow-stream]")) openStream();
      });
    }

    const permalink = $("wb-permalink");
    if (permalink) permalink.addEventListener("click", copyPermalink);
    const csv = $("wb-export-csv");
    if (csv) csv.addEventListener("click", exportCsv);
    const json = $("wb-export-json");
    if (json) json.addEventListener("click", exportJson);
    const pcap = $("wb-export-pcap");
    if (pcap) pcap.addEventListener("click", exportPcap);

    window.addEventListener("hashchange", () => {
      if (PH.readHashState()) restoreState();
    });

    ensureStreamDialog();
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state || state.page !== "workbench") return false;
    const filterInput = $("wb-filter");
    if (!state.hex) {
      if (state.filter && filterInput) filterInput.value = state.filter;
      return false;
    }
    let bytes;
    try {
      bytes = PH.parseHex(state.hex);
    } catch (_) {
      return false;
    }
    if (!bytes.length) return false;
    const version = bytes[0] >> 4;
    const linkType = state.linkType || ((version === 4 || version === 6) ? 101 : 1);
    const synthetic = PCap.fromFrames([{ bytes, linkType, ts: Date.now() / 1000 }]);
    const promise = loadCapture(synthetic, "shared packet");
    if (promise && typeof promise.then === "function") {
      promise.then(() => {
        if (state.filter && filterInput) {
          filterInput.value = state.filter;
          applyFilter();
        }
        if (state.sel) {
          const record = records.find((item) => item.number === state.sel);
          if (record) selectRecord(record);
        }
      });
    }
    return true;
  }





  function init() {
    const file = $("wb-file");
    if (!file) return;
    view = window.DissectView.create({
      tree: "wb-tree",
      hex: "wb-hexdump",
      detail: "wb-detail",
      warnings: "wb-warnings",
      summary: "wb-detail-summary",
      tag: "wb-detail-tag",
      status: "wb-detail-status",
      detailActions: (layer, result) => {
        const tcp = result && result.layers.find((item) => item.proto === "tcp" && item.meta && item.meta.parsed && item.meta.parsed.payload.length);
        if (tcp) return '<button class="btn btn--ghost" type="button" data-follow-stream>Follow TCP stream</button>';
        return "";
      }
    });
    view.clear("Select a packet in the list.");
    bindEvents();
    renderFilterChips();
    if (!restoreState()) loadExampleCapture();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
