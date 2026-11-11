/* Packet workbench: local pcap/pcapng loading, packet list, filters, stats,
 * follow-stream and exports. All parsing stays in this tab. */
(function () {
  "use strict";

  const PH = window.PH;
  const PCap = window.PCapCodec;
  const Dissector = window.Dissector;
  const Flows = window.PHFlows;
  const IndexBuilder = window.PHIndexBuilder;
  const MAX_PACKETS = 250000;
  const MAX_BYTES = 500 * 1024 * 1024;
  const PAGE = 300;
  const ROW_OVERSCAN = 4;

  let view = null;
  let capture = null;
  let records = [];
  let filtered = [];
  let selected = null;
  let firstTs = 0;
  let visible = PAGE;
  let filterAst = null;
  let filterFn = null;
  let loadToken = 0;
  let streamState = null;
  let streamDir = "aToB";
  let streamMode = "text";
  let flowData = null;
  let sortState = { key: "number", dir: 1 };
  let timeMode = "relative";
  let rowHeight = 29;
  let scrollFrame = null;
  let findState = { query: "", index: -1 };
  let filterHistory = [];
  let statsTimer = null;
  let workerBroken = false;
  let watchedFile = null;
  let watchedSize = 0;
  let watchTimer = null;
  const recordByNumber = new Map();

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

  function formatTime(record, position) {
    if (!record.ts) return "—";
    if (timeMode === "absolute") return new Date(record.ts * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
    if (timeMode === "delta") {
      const previous = position > 0 ? filtered[position - 1] : null;
      if (!previous || !previous.ts) return "—";
      return (record.ts - previous.ts).toFixed(6);
    }
    return formatRelative(record.ts);
  }

  function sortFiltered() {
    if (sortState.key === "number" && sortState.dir === 1) return;
    if (sortState.key === "number") {
      filtered.sort((left, right) => (left.number - right.number) * sortState.dir);
      return;
    }
    const decorated = filtered.map((record) => {
      let key;
      if (sortState.key === "time") key = record.ts || 0;
      else if (sortState.key === "len") key = record.caplen;
      else {
        const index = record._index || {};
        const ep = endpointsOf(index);
        if (sortState.key === "src") key = (ep.src || "") + ":" + String(ep.sport || "").padStart(5, "0");
        else if (sortState.key === "dst") key = (ep.dst || "") + ":" + String(ep.dport || "").padStart(5, "0");
        else if (sortState.key === "proto") key = protoLabel(index);
        else key = index.info || index.summary || "";
      }
      return { record, key };
    });
    decorated.sort((left, right) => {
      const a = left.key;
      const b = right.key;
      let result = 0;
      if (typeof a === "number" && typeof b === "number") result = a - b;
      else result = String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
      if (!result) result = left.record.number - right.record.number;
      return result * sortState.dir;
    });
    filtered = decorated.map((item) => item.record);
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
    if (index.appKind === "h2") return "HTTP/2";
    if (index.appKind === "http") return "HTTP";
    if (index.appKind === "dns") return "DNS";
    if (index.appKind === "tls") return "TLS";
    if (index.appKind === "dhcp") return "DHCP";
    if (index.appKind === "quic") return "QUIC";
    if (index.appKind === "bgp") return "BGP";
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
    if (IndexBuilder) return IndexBuilder.packetInfo(index);
    if (index.appSummary) return index.appSummary;
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
    if (IndexBuilder) return IndexBuilder.makeIndex(record, bytes, result);
    return legacyMakeIndex(record, bytes, result);
  }

  function legacyMakeIndex(record, bytes, result) {
    const index = {
      number: record.number,
      ts: record.ts,
      len: record.caplen,
      frameBytes: bytes,
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
      index.ipv4 = {
        src: value.src, dst: value.dst, proto: value.protocol, ttl: value.ttl,
        len: value.totalLength, fragmentOffset: value.fragmentOffset, mf: value.mf,
        checksumStatus: value.checksumOk ? "good" : "bad"
      };
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

  function renderFilterSuggestions() {
    const host = $("wb-filter-fields");
    if (!host || !window.PHFilter) return;
    const fields = window.PHFilter.fields().map((field) => field.name);
    const values = fields.concat(filterHistory).filter((value, index, all) => all.indexOf(value) === index);
    host.innerHTML = values.slice(0, 400).map((value) => '<option value="' + PH.esc(value) + '"></option>').join("");
  }

  function renderFilterChips() {
    renderFilterSuggestions();
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
      filterFn = null;
      setFilterStatus("all packets", "");
      renderList(true);
      if (!selected && filtered.length) selectRecord(filtered[0]);
      return;
    }
    try {
      filterAst = window.PHFilter.parse(text);
      filterFn = window.PHFilter.compile(filterAst);
      input.removeAttribute("aria-invalid");
    } catch (err) {
      input.setAttribute("aria-invalid", "true");
      setFilterStatus("filter error: " + err.message, "bad");
      return;
    }
    if (filterHistory[0] !== text) {
      filterHistory.unshift(text);
      filterHistory = filterHistory.slice(0, 20);
      setTimeout(renderFilterSuggestions, 0);
    }
    renderList(true);
    setFilterStatus(filtered.length + " of " + records.length + " packet" + (records.length === 1 ? "" : "s"), filtered.length ? "ok" : "warn");
    if (!selected && filtered.length) selectRecord(filtered[0]);
  }

  function rowHtml(record, position) {
    const index = record._index || {};
    const endpoints = endpointsOf(index);
    const isSelected = selected && selected.index === record.index;
    const expert = index.expert === "bad" ? " is-bad" : index.expert === "warn" ? " is-warn" : "";
    const marked = record._marked ? " is-marked" : "";
    return `<div class="wb-packet${isSelected ? " is-selected" : ""}${expert}${marked}" role="option" id="wb-packet-${record.index}" data-record="${record.index}" ` +
      `style="top:${position * rowHeight}px" aria-selected="${isSelected ? "true" : "false"}" ` +
      `aria-posinset="${position + 1}" aria-setsize="${filtered.length}" tabindex="-1">` +
      `<span class="wb-col wb-col-num">${record.number}${record._marked ? " *" : ""}</span>` +
      `<span class="wb-col wb-col-time" title="${PH.esc(formatAbsolute(record.ts))}">${PH.esc(formatTime(record, position))}</span>` +
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
    if (!filterFn) {
      filtered = records.slice();
    } else {
      const next = [];
      for (let i = 0; i < records.length; i += 1) {
        const record = records[i];
        if (filterFn(record._index)) next.push(record);
      }
      filtered = next;
    }
    sortFiltered();
    if (selected && filtered.indexOf(selected) === -1) {
      selected = null;
      view.clear("Select a packet in the list.");
    }
    const list = $("wb-list");
    if (list && reset) list.scrollTop = 0;
    const empty = $("wb-empty");
    if (empty) {
      empty.hidden = filtered.length > 0;
      empty.textContent = records.length ? "No packets match this filter." : "Open a capture to see packets here.";
    }
    const count = $("wb-list-count");
    if (count) count.textContent = countText(filtered.length) + " of " + countText(records.length) + " packet" + (records.length === 1 ? "" : "s");
    const more = $("wb-more");
    if (more) more.hidden = true;
    const spacer = $("wb-list-spacer");
    if (spacer) spacer.style.height = (filtered.length * rowHeight) + "px";
    renderWindow();
    scheduleStats();
  }

  function renderWindow() {
    const list = $("wb-list");
    const spacer = $("wb-list-spacer");
    if (!list || !spacer) return;
    const height = list.clientHeight || 480;
    const top = list.scrollTop || 0;
    const start = Math.max(0, Math.floor(top / rowHeight) - ROW_OVERSCAN);
    const end = Math.min(filtered.length, start + Math.ceil(height / rowHeight) + ROW_OVERSCAN * 2);
    spacer.innerHTML = filtered.slice(start, end).map((record, index) => rowHtml(record, start + index)).join("");
    updateSelectionUi();
  }

  function updateRowHeight() {
    const list = $("wb-list");
    if (!list) return;
    const cssHeight = parseFloat(getComputedStyle(list).getPropertyValue("--wb-row-h"));
    rowHeight = cssHeight > 0 ? cssHeight : 30;
    const spacer = $("wb-list-spacer");
    if (spacer) spacer.style.height = (filtered.length * rowHeight) + "px";
  }

  function scrollToRecord(record) {
    const list = $("wb-list");
    if (!list || !record) return;
    const position = filtered.indexOf(record);
    if (position < 0) return;
    const target = Math.max(0, position * rowHeight - Math.floor((list.clientHeight || 480) / 2));
    if (Math.abs(list.scrollTop - target) > rowHeight * 2) list.scrollTop = target;
    renderWindow();
  }

  function scapyForRecord(record) {
    if (!capture || !record) return "";
    const layer = record.linkType === 101 || record.linkType === 228 ? "IP"
      : record.linkType === 229 ? "IPv6" : "Ether";
    return layer + '(bytes.fromhex("' + PH.bytesToHex(PCap.recordBytes(capture, record)) + '"))';
  }

  function bpfForRecord(record) {
    const index = record && record._index ? record._index : {};
    if (index.arp) return "arp";
    if (index.ipv6) {
      const src = index.ipv6.src;
      const dst = index.ipv6.dst;
      if (index.tcp) return "ip6 and tcp and (host " + src + " and host " + dst + ")";
      if (index.udp) return "ip6 and udp and (host " + src + " and host " + dst + ")";
      return "ip6 and (host " + src + " and host " + dst + ")";
    }
    if (index.ipv4) {
      const src = index.ipv4.src;
      const dst = index.ipv4.dst;
      if (index.tcp) return "ip and tcp and (host " + src + " and host " + dst + ")";
      if (index.udp) return "ip and udp and (host " + src + " and host " + dst + ")";
      if (index.icmp) return "icmp and (host " + src + " and host " + dst + ")";
      return "ip and (host " + src + " and host " + dst + ")";
    }
    if (index.eth) return "ether host " + index.eth.src + " or ether host " + index.eth.dst;
    return "";
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
    const info = record._flowInfo;
    if (info && info.layers && info.layers.length) {
      info.layers.forEach((layer) => {
        result.layers.push(Object.assign({}, layer, {
          offset: 0, length: result.bytes.length, depth: 6,
          meta: layer.meta || { stream: true }
        }));
      });
      result.summary = result.layers.map((layer) => layer.name).join(" → ");
      result.deepest = result.layers[result.layers.length - 1];
      if (info.experts && info.experts.length) {
        info.experts.forEach((expert) => {
          if (result.warnings.indexOf(expert.message) === -1) result.warnings.push(expert.message);
        });
      }
    }
    view.render(result);
    renderDiagnosis(record);
  }

  function renderDiagnosis(record) {
    const host = $("wb-diagnosis");
    if (!host) return;
    const info = record && record._flowInfo;
    const items = info && info.diagnosis ? info.diagnosis : [];
    if (!items.length) {
      host.innerHTML = "";
      return;
    }
    host.innerHTML = '<div class="callout callout--warn"><div class="callout__title">flow diagnosis · ' +
      items.length + ' finding' + (items.length === 1 ? "" : "s") + '</div><ul class="dashed" style="margin:0">' +
      items.map((item) => '<li><b class="' + (item.severity === "bad" ? "bad-text" : "") + '">' +
        PH.esc(item.title) + '</b> — ' + PH.esc(item.detail) +
        (item.packets && item.packets.length ? ' <span class="dim">(packets ' + item.packets.slice(0, 6).join(", ") + ')</span>' : "") +
        '</li>').join("") + '</ul></div>';
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

  function scheduleStats() {
    if (statsTimer) clearTimeout(statsTimer);
    statsTimer = setTimeout(() => {
      statsTimer = null;
      renderStats();
    }, 180);
  }

  function renderStats() {
    if (!records.length) {
      ["wb-stats-conv", "wb-stats-protos", "wb-stats-endpoints", "wb-stats-expert", "wb-stats-hierarchy", "wb-stats-timeline"].forEach((id) => {
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

    const expertHost = $("wb-stats-expert");
    if (expertHost) {
      const experts = flowData && flowData.experts ? flowData.experts : [];
      const visibleExperts = experts.filter((entry) => !filterFn ||
        entry.packets.some((number) => {
          const record = recordByNumber.get(number);
          return record && filterFn(record._index);
        }));
      renderTable(expertHost, ["severity", "finding", "packets", "flow"],
        visibleExperts.slice(0, 500).map((entry) => [
          entry.severity || "info", entry.message, entry.packets.slice(0, 12).join(", "), "#" + entry.flow
        ]));
    }

    const hierarchyHost = $("wb-stats-hierarchy");
    if (hierarchyHost) {
      const hierarchy = new Map();
      filtered.forEach((record) => {
        (record._index.protos || []).forEach((proto) => {
          const entry = hierarchy.get(proto) || { packets: 0, bytes: 0 };
          entry.packets += 1;
          entry.bytes += record.caplen;
          hierarchy.set(proto, entry);
        });
      });
      renderTable(hierarchyHost, ["protocol", "packets", "bytes", "packet share"],
        Array.from(hierarchy.entries()).sort((a, b) => b[1].packets - a[1].packets).map(([proto, entry]) => [
          protoName(proto), countText(entry.packets), countText(entry.bytes),
          (filtered.length ? ((entry.packets / filtered.length) * 100).toFixed(1) : "0.0") + "%"
        ]));
    }

    const timelineHost = $("wb-stats-timeline");
    if (timelineHost) {
      const times = filtered.map((record) => record.ts).filter((value) => value > 0);
      if (!times.length) {
        timelineHost.innerHTML = '<p class="dim">No timestamps in the current filter.</p>';
      } else {
        let min = Infinity;
        let max = -Infinity;
        times.forEach((value) => {
          if (value < min) min = value;
          if (value > max) max = value;
        });
        const buckets = 60;
        const counts = new Array(buckets).fill(0);
        const bytes = new Array(buckets).fill(0);
        const span = Math.max(1e-9, max - min);
        filtered.forEach((record) => {
          if (!record.ts) return;
          const index = Math.min(buckets - 1, Math.max(0, Math.floor(((record.ts - min) / span) * buckets)));
          counts[index] += 1;
          bytes[index] += record.caplen;
        });
        const peak = Math.max.apply(null, counts) || 1;
        const width = 720;
        const height = 150;
        const bar = width / buckets;
        const bars = counts.map((count, index) => {
          const h = Math.max(0, (count / peak) * (height - 24));
          const x = index * bar;
          return '<rect x="' + x.toFixed(1) + '" y="' + (height - 20 - h).toFixed(1) + '" width="' +
            Math.max(1, bar - 1).toFixed(1) + '" height="' + h.toFixed(1) + '" fill="var(--accent)">' +
            '<title>' + count + " packet(s) · " + countText(bytes[index]) + ' B</title></rect>';
        }).join("");
        timelineHost.innerHTML = '<div class="table-wrap" style="padding:8px"><svg viewBox="0 0 ' + width + ' ' + height +
          '" width="100%" role="img" aria-label="Packet timeline, ' + countText(filtered.length) + ' packets from ' +
          PH.esc(formatAbsolute(min)) + ' to ' + PH.esc(formatAbsolute(max)) + '">' +
          '<line x1="0" y1="' + (height - 20) + '" x2="' + width + '" y2="' + (height - 20) + '" stroke="var(--line-strong)"></line>' +
          bars + '<text x="0" y="' + (height - 5) + '" fill="var(--dim)" font-size="9">' + PH.esc(formatAbsolute(min)) + '</text>' +
          '<text x="' + width + '" y="' + (height - 5) + '" text-anchor="end" fill="var(--dim)" font-size="9">' +
          PH.esc(formatAbsolute(max)) + '</text></svg></div>' +
          '<p class="small dim" style="margin:8px 0 0">Peak ' + countText(peak) + ' packets per bucket · ' +
          formatDuration(span) + ' total span · hover a bar for details.</p>';
      }
    }
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

  async function indexRecordsMain(token) {
    const total = records.length;
    recordByNumber.clear();
    flowData = null;
    if (!total) { hideProgress(); return true; }
    updateProgress(0, total);
    const engine = Flows ? Flows.create() : null;
    for (let i = 0; i < total; i += 1) {
      if (token !== loadToken) { hideProgress(); return false; }
      const record = records[i];
      recordByNumber.set(record.number, record);
      const bytes = PCap.recordBytes(capture, record);
      let result;
      try {
        result = Dissector.dissectLink(bytes, record.linkType, { headersOnly: true });
      } catch (err) {
        result = Dissector.dissect(bytes, { kind: "raw", note: "decode failed: " + err.message, headersOnly: true });
        result.warnings.push("Workbench decode failed: " + err.message);
      }
      try {
        record._index = makeIndex(record, bytes, result);
      } catch (err) {
        record._index = {
          number: record.number, ts: record.ts, len: record.caplen, protos: ["raw"],
          frameBytes: bytes,
          frame: { number: record.number, time: record.ts, len: record.caplen },
          summary: "Index failed: " + err.message, info: "Index failed: " + err.message
        };
      }
      if (engine) {
        try {
          engine.add(record, result);
        } catch (err) {
          result.warnings.push("Flow indexing failed: " + err.message);
        }
      }
      if (i % 400 === 0 || i === total - 1) {
        updateProgress(i + 1, total);
        await tick();
      }
    }
    if (engine) {
      try {
        flowData = engine.finish();
      } catch (err) {
        flowData = { flows: [], byNumber: new Map(), warnings: ["Flow analysis failed: " + err.message], stats: {}, experts: [], fieldCatalog: {} };
      }
      flowData.byNumber.forEach((info, number) => {
        const record = recordByNumber.get(number);
        if (!record) return;
        record._flowInfo = info;
        record._flow = info.flow || null;
        const index = record._index || {};
        if (info.appKind) {
          index.appKind = info.appKind;
          if (index.protos && index.protos.indexOf(info.appKind) === -1) index.protos.push(info.appKind);
        }
        if (info.flow && info.flow.proto && index.protos && index.protos.indexOf(info.flow.proto) === -1) {
          index.protos.push(info.flow.proto);
        }
        if (info.summary) index.appSummary = info.summary;
        if (info.fragmentOf) index.fragmentOf = info.fragmentOf;
        if (info.flowFields) index.flowFields = info.flowFields;
        if (info.experts) index.experts = info.experts;
        if (info.expert) index.expert = info.expert;
        if (info.diagnosis) index.diagnosis = info.diagnosis;
        index.info = packetInfo(index);
        record._index = index;
      });
      if (flowData.warnings && flowData.warnings.length) {
        flowData.warnings.slice(0, 20).forEach((warning) => {
          if (capture.warnings.indexOf(warning) === -1) capture.warnings.push(warning);
        });
      }
      if (window.PHFilter && typeof window.PHFilter.registerFields === "function") {
        window.PHFilter.registerFields(flowData.fieldCatalog || {});
        renderFilterSuggestions();
      }
    }
    hideProgress();
    return true;
  }

  function mergeFlowInfo(record, info) {
    if (!record || !info) return;
    record._flowInfo = info;
    record._flow = info.flow || null;
    const index = record._index || {};
    if (info.appKind) {
      index.appKind = info.appKind;
      if (index.protos && index.protos.indexOf(info.appKind) === -1) index.protos.push(info.appKind);
    }
    if (info.flow && info.flow.proto && index.protos && index.protos.indexOf(info.flow.proto) === -1) {
      index.protos.push(info.flow.proto);
    }
    if (info.summary) index.appSummary = info.summary;
    if (info.fragmentOf) index.fragmentOf = info.fragmentOf;
    if (info.flowFields) index.flowFields = info.flowFields;
    if (info.experts) index.experts = info.experts;
    if (info.expert) index.expert = info.expert;
    if (info.diagnosis) index.diagnosis = info.diagnosis;
    index.info = packetInfo(index);
    record._index = index;
  }

  function applyWorkerData(data) {
    records.forEach((record, position) => {
      const index = data.indexes[position];
      if (!index) return;
      index.frameBytes = PCap.recordBytes(capture, record);
      record._index = index;
    });
    const byNumber = new Map(data.byNumber || []);
    byNumber.forEach((info, number) => {
      const record = recordByNumber.get(number);
      if (record) mergeFlowInfo(record, info);
    });
    flowData = {
      flows: data.flows || [],
      byNumber,
      warnings: data.warnings || [],
      stats: data.stats || {},
      experts: data.experts || [],
      fieldCatalog: data.fieldCatalog || {}
    };
    (data.captureWarnings || []).forEach((warning) => {
      if (capture.warnings.indexOf(warning) === -1) capture.warnings.push(warning);
    });
    (data.warnings || []).slice(0, 20).forEach((warning) => {
      if (capture.warnings.indexOf(warning) === -1) capture.warnings.push(warning);
    });
    if (data.truncated) capture.warnings.push("This build shows the first " + countText(records.length) + " packets.");
    if (window.PHFilter && typeof window.PHFilter.registerFields === "function") {
      window.PHFilter.registerFields(flowData.fieldCatalog || {});
      renderFilterSuggestions();
    }
    hideProgress();
  }

  function canUseWorker() {
    return !workerBroken && typeof Worker !== "undefined" && location.protocol !== "file:" &&
      capture && capture.bytes && capture.bytes.length <= 200 * 1024 * 1024;
  }

  function runWorkerParse(token) {
    return new Promise((resolve, reject) => {
      let worker;
      try {
        worker = new Worker("js/workbench-worker.js");
      } catch (err) {
        workerBroken = true;
        reject(err);
        return;
      }
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        worker.terminate();
        reject(new Error("parser worker timed out"));
      }, 180000);
      function finish(fn) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        worker.terminate();
        fn();
      }
      worker.onmessage = (event) => {
        const data = event.data || {};
        if (data.type === "progress") {
          updateProgress(data.done, data.total);
          return;
        }
        if (token !== loadToken) { finish(() => resolve(null)); return; }
        if (data.type === "done") finish(() => resolve(data));
        else if (data.type === "error") finish(() => reject(new Error(data.message || "worker parse failed")));
      };
      worker.onerror = (event) => {
        finish(() => reject(new Error(event.message || "parser worker failed to load")));
      };
      try {
        worker.postMessage({ type: "parse", buffer: capture.bytes.slice().buffer, maxPackets: records.length });
      } catch (err) {
        finish(() => reject(err));
      }
    });
  }

  async function indexRecords(token) {
    recordByNumber.clear();
    flowData = null;
    records.forEach((record) => recordByNumber.set(record.number, record));
    if (canUseWorker() && records.length >= 1200) {
      try {
        const data = await runWorkerParse(token);
        if (token !== loadToken) return false;
        if (data) {
          applyWorkerData(data);
          return true;
        }
      } catch (err) {
        capture.warnings.push("Parser worker unavailable (" + err.message + "); using the main thread.");
      }
    }
    return indexRecordsMain(token);
  }

  async function loadCapture(next, label) {
    const token = ++loadToken;
    streamState = null;
    const openDialog = $("wb-stream-dialog");
    if (openDialog && openDialog.open) openDialog.close();
    capture = next;
    const tlsSecret = (capture.decryptionSecrets || []).find((secret) => secret.type === 0x544c534b);
    const keylogInput = $("wb-tls-keys");
    if (tlsSecret && keylogInput && !keylogInput.value.trim() && tlsSecret.data && tlsSecret.data.length) {
      try {
        keylogInput.value = new TextDecoder("utf-8", { fatal: false }).decode(tlsSecret.data);
        PH.setStatus($("wb-tls-status"), "Loaded TLS key log from pcapng Decryption Secrets Block", "ok");
      } catch (_) { /* leave the field alone */ }
    }
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
    filterFn = null;
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
    renderCaptureSummary(label);
    renderLoadWarnings();
    renderList(true);
    if (filterInput && filterInput.value.trim()) applyFilter();
    if (filtered.length) selectRecord(filtered[0]);
    else if (records.length) selectRecord(records[0]);
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
      if (status) PH.setStatus(status, "capture is larger than 500 MB; this build refuses to load it", "bad");
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
      if (status) PH.setStatus(status, "file is larger than 500 MB; this build refuses to load it", "bad");
      return;
    }
    watchedFile = file;
    watchedSize = file.size;
    if (status) PH.setStatus(status, "Reading " + file.name + "…", "warn");
    try {
      const buffer = await readFile(file);
      await loadBuffer(buffer, file.name);
    } catch (err) {
      if (status) PH.setStatus(status, "file read error: " + err.message, "bad");
    }
  }

  function stopWatch() {
    if (watchTimer) clearInterval(watchTimer);
    watchTimer = null;
    const button = $("wb-watch");
    if (button) button.textContent = "Watch file for growth";
  }

  function toggleWatch() {
    const button = $("wb-watch");
    if (watchTimer) {
      stopWatch();
      PH.toast("Stopped watching the capture file");
      return;
    }
    if (!watchedFile) {
      PH.toast("Open a capture file first");
      return;
    }
    if (location.protocol === "file:") {
      PH.toast("File watching needs a local HTTP server; reload the file manually");
      return;
    }
    watchedSize = watchedFile.size;
    watchTimer = setInterval(() => {
      if (!watchedFile) return;
      if (watchedFile.size === watchedSize) return;
      watchedSize = watchedFile.size;
      loadFile(watchedFile);
    }, 2000);
    if (button) button.textContent = "Stop watching file";
    PH.toast("Watching " + watchedFile.name + " for appended records");
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
    stopWatch();
    watchedFile = null;
    capture = null;
    records = [];
    filtered = [];
    selected = null;
    firstTs = 0;
    visible = PAGE;
    filterAst = null;
    filterFn = null;
    streamState = null;
    flowData = null;
    recordByNumber.clear();
    findState = { query: "", index: -1 };
    const diagnosis = $("wb-diagnosis");
    if (diagnosis) diagnosis.innerHTML = "";
    const openDialog = $("wb-stream-dialog");
    if (openDialog && openDialog.open) openDialog.close();
    const filterInput = $("wb-filter");
    if (filterInput) filterInput.value = "";
    setFilterStatus("all packets", "");
    view.clear("Select a packet in the list.");
    const list = $("wb-list");
    if (list) list.innerHTML = '<div id="wb-list-spacer"></div>';
    const empty = $("wb-empty");
    if (empty) { empty.hidden = false; empty.textContent = "Open a capture to see packets here."; }
    const count = $("wb-list-count");
    if (count) count.textContent = "0 packets";
    const more = $("wb-more");
    if (more) more.hidden = true;
    ["wb-stats-conv", "wb-stats-protos", "wb-stats-endpoints", "wb-stats-expert", "wb-stats-hierarchy", "wb-stats-timeline"].forEach((id) => {
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
    const flow = selected._flowInfo && selected._flowInfo.flow;
    let stream;
    if (flow && flow.proto === "tcp" && flow.dirs) {
      stream = {
        key: flow.key, a: flow.a, b: flow.b,
        directions: {
          aToB: Object.assign({}, flow.dirs.aToB, { retransmits: flow.dirs.aToB.retransmissions }),
          bToA: Object.assign({}, flow.dirs.bToA, { retransmits: flow.dirs.bToA.retransmissions })
        },
        app: flow.app ? flow.app.kind : "unknown",
        packets: flow.packetCount, totalBytes: flow.bytes,
        warnings: flow.warnings || []
      };
    } else {
      stream = window.PHStreams.build(
        records,
        selected,
        (record) => PCap.recordBytes(capture, record),
        (record) => record._index
      );
    }
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
      flows: flowData ? flowData.flows.map((flow) => ({
        index: flow.index, proto: flow.proto,
        a: flow.a, b: flow.b,
        app: flow.app ? flow.app.kind : "",
        summary: flow.summary,
        packets: flow.packetCount, bytes: flow.bytes,
        expert: flow.expert, diagnosis: flow.diagnosis
      })) : [],
      experts: flowData ? flowData.experts : [],
      packets: filtered.map((record) => ({
        number: record.number,
        ts: record.ts,
        caplen: record.caplen,
        origlen: record.origlen,
        linkType: record.linkType,
        index: record._index,
        flow: record._flowInfo ? {
          app: record._flowInfo.appKind,
          summary: record._flowInfo.summary,
          fields: record._flowInfo.flowFields,
          experts: record._flowInfo.experts,
          diagnosis: record._flowInfo.diagnosis
        } : null
      }))
    };
    PH.downloadText("netlens-analysis.json", JSON.stringify(payload, null, 2), "application/json");
  }

  function headerPairs(headers) {
    return (headers || []).map((header) => ({ name: header.name || header.lower || "", value: String(header.value == null ? "" : header.value) }));
  }

  function harUrl(flow, request) {
    const headers = request.message.headers || [];
    const host = httpHeader(headers, "host") || httpHeader(headers, ":authority") ||
      (flow.app && flow.app.context && flow.app.context.sni) || flow.b.addr;
    const port = flow.b.port;
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    const target = request.message.target || "/";
    return scheme + "://" + host + (port && port !== 80 && port !== 443 ? ":" + port : "") + (target.startsWith("/") ? target : "/" + target);
  }

  function httpHeader(headers, name) {
    const lower = String(name).toLowerCase();
    const found = (headers || []).find((header) => String(header.lower || header.name || "").toLowerCase() === lower);
    return found ? found.value : "";
  }

  function bodyText(bytes) {
    if (!bytes || !bytes.length) return "";
    try { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
    catch (_) { return PH.bytesToAscii(bytes); }
  }

  async function decodedBodyText(bytes, headers) {
    if (!bytes || !bytes.length) return "";
    const encoding = httpHeader(headers, "content-encoding").toLowerCase();
    if (!encoding || encoding === "identity" || typeof DecompressionStream === "undefined") return bodyText(bytes);
    const format = encoding.indexOf("gzip") !== -1 ? "gzip" : encoding.indexOf("deflate") !== -1 ? "deflate" : null;
    if (!format) return bodyText(bytes);
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
      const buffer = await new Response(stream).arrayBuffer();
      return bodyText(new Uint8Array(buffer));
    } catch (_) {
      return bodyText(bytes);
    }
  }

  async function harEntry(flow, request, response) {
    const requestMessage = request.message || {};
    const responseMessage = response ? response.message : null;
    const started = request.ts || flow.firstTs || 0;
    const time = response && response.ts && started ? Math.max(0, (response.ts - started) * 1000) : 0;
    const url = harUrl(flow, request);
    const entry = {
      startedDateTime: new Date(started * 1000).toISOString(),
      time: Math.round(time * 1000) / 1000,
      request: {
        method: requestMessage.method || "GET",
        url: url,
        httpVersion: requestMessage.version || "HTTP/1.1",
        cookies: [],
        headers: headerPairs(requestMessage.headers),
        queryString: [],
        headersSize: -1,
        bodySize: requestMessage.body ? requestMessage.body.length : 0
      },
      response: {
        status: responseMessage && responseMessage.status != null ? responseMessage.status : 0,
        statusText: responseMessage ? (responseMessage.reason || "") : "",
        httpVersion: responseMessage ? (responseMessage.version || "HTTP/1.1") : "HTTP/1.1",
        cookies: [],
        headers: responseMessage ? headerPairs(responseMessage.headers) : [],
        content: {
          size: responseMessage && responseMessage.body ? responseMessage.body.length : 0,
          mimeType: responseMessage ? (httpHeader(responseMessage.headers, "content-type") || "application/octet-stream") : "application/octet-stream",
          text: responseMessage ? await decodedBodyText(responseMessage.body, responseMessage.headers) : ""
        },
        redirectURL: responseMessage ? httpHeader(responseMessage.headers, "location") : "",
        headersSize: -1,
        bodySize: responseMessage && responseMessage.body ? responseMessage.body.length : 0
      },
      cache: {},
      timings: { send: 0, wait: Math.max(0, Math.round(time * 1000) / 1000), receive: 0 },
      serverIPAddress: flow.b.addr,
      connection: String(flow.index)
    };
    if (requestMessage.body && requestMessage.body.length) {
      entry.request.postData = {
        mimeType: httpHeader(requestMessage.headers, "content-type") || "application/octet-stream",
        text: await decodedBodyText(requestMessage.body, requestMessage.headers)
      };
    }
    return entry;
  }

  async function exportHar() {
    if (!flowData || !flowData.flows) { PH.toast("No capture loaded"); return; }
    const entries = [];
    for (const flow of flowData.flows) {
      if (!flow.app) continue;
      if (flow.app.kind === "http" && flow.app.messages) {
        const requests = flow.app.messages.filter((entry) => entry.message && entry.message.messageKind === "request");
        const responses = flow.app.messages.filter((entry) => entry.message && entry.message.messageKind === "response");
        for (let index = 0; index < requests.length; index += 1) {
          entries.push(await harEntry(flow, requests[index], responses[index] || null));
        }
      } else if (flow.app.kind === "h2" && flow.app.messages) {
        for (const stream of flow.app.messages) {
          if (!stream.method) continue;
          const request = { message: { method: stream.method, target: stream.path || "/", version: "HTTP/2", headers: stream.headers || [], body: new Uint8Array(0) }, ts: flow.firstTs };
          const response = stream.status != null ? { message: { status: stream.status, reason: "", version: "HTTP/2", headers: stream.headers || [], body: stream.body || new Uint8Array(0) }, ts: flow.lastTs } : null;
          entries.push(await harEntry(flow, request, response));
        }
      }
    }
    if (!entries.length) { PH.toast("No HTTP flows to export"); return; }
    const har = {
      log: {
        version: "1.2",
        creator: { name: "netlens.dev packet workbench", version: "1.0" },
        pages: [],
        entries: entries
      }
    };
    PH.downloadText("netlens-http.har", JSON.stringify(har, null, 2), "application/json");
  }

  async function exportReport() {
    if (!capture) { PH.toast("Load a capture first"); return; }
    let hash = "";
    try {
      if (window.crypto && window.crypto.subtle && capture.bytes) {
        const digest = await window.crypto.subtle.digest("SHA-256", capture.bytes);
        hash = Array.from(new Uint8Array(digest)).map((value) => ("0" + value.toString(16)).slice(-2)).join("");
      }
    } catch (_) { hash = "unavailable"; }
    const flows = flowData && flowData.flows ? flowData.flows.slice(0, 500) : [];
    const experts = flowData && flowData.experts ? flowData.experts : [];
    const rows = flows.map((flow) => '<tr><td>' + flow.index + '</td><td>' + PH.esc(flow.summary) +
      '</td><td>' + flow.packetCount + '</td><td>' + flow.bytes + '</td><td>' +
      PH.esc((flow.expert || []).map((item) => item.message).join("; ")) + '</td></tr>').join("");
    const expertRows = experts.slice(0, 200).map((item) => '<li><b>' + PH.esc(item.severity) + '</b> ' +
      PH.esc(item.message) + ' <span class="dim">flow #' + item.flow + '</span></li>').join("");
    const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>netlens capture report</title>' +
      '<style>body{font-family:ui-monospace,monospace;background:#0b0e14;color:#c0caf5;margin:2rem;line-height:1.5}' +
      'h1,h2{color:#9ece6a}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #2a2f3a;padding:4px 6px;text-align:left;vertical-align:top}' +
      'th{color:#7aa2f7}.dim{color:#565f89}code{color:#e0af68}</style></head><body>' +
      '<h1>netlens.dev capture report</h1>' +
      '<p>Generated ' + PH.esc(new Date().toISOString()) + '</p>' +
      '<p>Capture: <code>' + PH.esc(capture.format) + '</code> · ' + countText(records.length) + ' packets · ' +
      PH.esc(capture.interfaces.map((iface) => PCap.linkTypeName(iface.linkType)).filter((name, index, all) => all.indexOf(name) === index).join(", ")) + '</p>' +
      '<p>SHA-256: <code>' + PH.esc(hash) + '</code></p>' +
      '<h2>Flows</h2><table><thead><tr><th>#</th><th>summary</th><th>packets</th><th>bytes</th><th>expert</th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="5" class="dim">No flows</td></tr>') + '</tbody></table>' +
      '<h2>Expert information</h2><ul>' + (expertRows || '<li class="dim">No expert findings</li>') + '</ul>' +
      '<p class="dim">This report is generated locally from the capture. It contains packet-derived text; review it before sharing.</p>' +
      '</body></html>';
    PH.downloadText("netlens-report.html", html, "text/html");
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

  async function decryptTlsFlows() {
    const status = $("wb-tls-status");
    const output = $("wb-tls-output");
    if (!window.PHTLSKeys) {
      if (status) PH.setStatus(status, "TLS key support is not loaded", "bad");
      return;
    }
    const parsed = window.PHTLSKeys.parse($("wb-tls-keys") ? $("wb-tls-keys").value : "");
    if (!parsed.count) {
      if (status) PH.setStatus(status, "No usable SSLKEYLOGFILE lines found", "bad");
      if (output) output.innerHTML = "";
      return;
    }
    const tlsFlows = flowData && flowData.flows ? flowData.flows.filter((flow) => flow.app && flow.app.kind === "tls") : [];
    if (!tlsFlows.length) {
      if (status) PH.setStatus(status, "No TLS flows in this capture", "warn");
      return;
    }
    if (status) PH.setStatus(status, "Deriving TLS 1.3 keys and decrypting " + tlsFlows.length + " flow(s)…", "warn");
    let html = "";
    let ok = 0;
    let failed = 0;
    for (const flow of tlsFlows) {
      const result = await window.PHTLSKeys.decryptFlow(flow, parsed);
      if (result.error) {
        failed += 1;
        html += '<div class="callout callout--warn"><div class="callout__title">TLS flow ' + flow.index + ' · not decrypted</div><p>' + PH.esc(result.error) + '</p></div>';
        continue;
      }
      ok += 1;
      const clientApp = window.PHTLSKeys.applicationBytes(result, "aToB");
      const serverApp = window.PHTLSKeys.applicationBytes(result, "bToA");
      const clientHs = window.PHTLSKeys.handshakeBytes(result, "aToB");
      const serverHs = window.PHTLSKeys.handshakeBytes(result, "bToA");
      let appSummary = "";
      if (clientApp.length || serverApp.length) {
        try {
          const h2c = clientApp.length ? window.HTTPCodec.decodeHttp2(clientApp) : null;
          const h2s = serverApp.length ? window.HTTPCodec.decodeHttp2(serverApp) : null;
          if (h2c || h2s) {
            appSummary = "HTTP/2 after decryption · " +
              (h2c ? h2c.frames.length + " client frame(s)" : "no client frames") + " · " +
              (h2s ? h2s.frames.length + " server frame(s)" : "no server frames");
          }
        } catch (_) {
          try {
            const h1 = window.HTTPCodec.decodeHttp1(serverApp.length ? serverApp : clientApp);
            appSummary = "HTTP/1.1 after decryption · " + h1.summary;
          } catch (_) {
            appSummary = "Decrypted application bytes · " + clientApp.length + " B client · " + serverApp.length + " B server";
          }
        }
      }
      let hsSummary = "";
      if (clientHs.length || serverHs.length) {
        try {
          const record = window.TLSCodec.buildRecord(22, PH.concatBytes(clientHs, serverHs), 0x0303);
          const decoded = window.TLSCodec.decodeTls(record);
          const names = decoded.handshakes.map((message) => message.typeName).join(" → ");
          const certs = decoded.handshakes.find((message) => message.type === 11 && message.certs);
          hsSummary = "Decrypted handshake · " + names +
            (certs ? " · " + certs.certs.length + " certificate(s)" : "");
        } catch (_) {
          hsSummary = "Decrypted handshake bytes · " + clientHs.length + " B client · " + serverHs.length + " B server";
        }
      }
      const previewSource = clientApp.length ? clientApp : serverApp;
      const preview = previewSource.length
        ? PH.esc(PH.bytesToAscii(previewSource.subarray(0, Math.min(512, previewSource.length))).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "·"))
        : "(no decrypted application data)";
      html += '<div class="callout"><div class="callout__title">TLS flow ' + flow.index + ' · ' +
        PH.esc(flow.app.context && flow.app.context.sni ? flow.app.context.sni : "no SNI") + '</div>' +
        '<p class="small dim">client_random ' + PH.esc(result.clientRandom) + ' · ' + PH.esc(result.cipher.name) + '</p>' +
        '<p class="small">' + PH.esc(hsSummary || "No decrypted handshake bytes") + '</p>' +
        '<p class="small">' + PH.esc(appSummary || "No decrypted application records") + '</p>' +
        '<div class="output" style="margin-top:8px"><div class="output__label">decrypted preview · ' + previewSource.length + ' B</div><pre>' + preview + '</pre></div></div>';
    }
    if (output) output.innerHTML = html;
    if (status) {
      PH.setStatus(status, ok + " TLS flow(s) decrypted" + (failed ? " · " + failed + " not decrypted" : ""), failed ? "warn" : "ok");
    }
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
    if (example) example.addEventListener("click", () => { stopWatch(); watchedFile = null; loadExampleCapture(); });
    const clear = $("wb-clear");
    if (clear) clear.addEventListener("click", () => { stopWatch(); watchedFile = null; clearCapture(); });
    const watch = $("wb-watch");
    if (watch) watch.addEventListener("click", toggleWatch);

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

    const timeSelect = $("wb-time-mode");
    if (timeSelect) {
      timeSelect.value = timeMode;
      timeSelect.addEventListener("change", () => {
        timeMode = timeSelect.value;
        renderWindow();
      });
    }

    function findNext() {
      const input = $("wb-find");
      if (!input) return;
      const query = input.value.trim().toLowerCase();
      if (!query) return;
      if (findState.query !== query) {
        findState = { query, index: -1 };
      }
      let start = findState.index + 1;
      if (start >= filtered.length) start = 0;
      for (let step = 0; step < filtered.length; step += 1) {
        const position = (start + step) % filtered.length;
        const record = filtered[position];
        const index = record._index || {};
        const ep = endpointsOf(index);
        const haystack = [
          String(record.number), ep.src, ep.dst, protoLabel(index),
          index.info || "", index.summary || "", index.appKind || ""
        ].join(" ").toLowerCase();
        if (haystack.indexOf(query) !== -1) {
          findState.index = position;
          selectRecord(record);
          scrollToRecord(record);
          PH.setStatus($("wb-filter-status"), "found packet " + record.number, "ok");
          return;
        }
      }
      PH.setStatus($("wb-filter-status"), "no packet matched '" + input.value.trim() + "'", "warn");
    }
    const findButton = $("wb-find-next");
    if (findButton) findButton.addEventListener("click", findNext);
    const findInput = $("wb-find");
    if (findInput) findInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); findNext(); }
    });

    const gotoButton = $("wb-goto-run");
    if (gotoButton) gotoButton.addEventListener("click", () => {
      const input = $("wb-goto");
      const number = input ? Number(input.value) : 0;
      if (!number) return;
      const record = recordByNumber.get(number);
      if (!record) { PH.toast("No packet #" + number + " in this capture"); return; }
      selectRecord(record);
      scrollToRecord(record);
    });

    const markButton = $("wb-mark");
    if (markButton) markButton.addEventListener("click", () => {
      if (!selected) { PH.toast("Select a packet first"); return; }
      selected._marked = !selected._marked;
      selected._index.marked = Boolean(selected._marked);
      renderWindow();
      PH.toast(selected._marked ? "packet #" + selected.number + " marked" : "mark removed");
    });

    ["wb-tab-conv", "wb-tab-protos", "wb-tab-endpoints", "wb-tab-expert", "wb-tab-hierarchy", "wb-tab-timeline"].forEach((id) => {
      const button = $(id);
      if (button) button.addEventListener("click", () => setTimeout(renderStats, 0));
    });

    const diagnoseButton = $("wb-diagnose");
    if (diagnoseButton) diagnoseButton.addEventListener("click", () => {
      if (!selected) { PH.toast("Select a packet first"); return; }
      renderDiagnosis(selected);
      const host = $("wb-diagnosis");
      if (host && host.scrollIntoView) host.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });

    const tlsDecrypt = $("wb-tls-decrypt");
    if (tlsDecrypt) tlsDecrypt.addEventListener("click", decryptTlsFlows);
    document.querySelectorAll(".wb-sort").forEach((button) => {
      const key = button.dataset.sort;
      const syncSortButton = () => {
        document.querySelectorAll(".wb-sort").forEach((item) => {
          const active = item.dataset.sort === sortState.key;
          item.setAttribute("aria-pressed", active ? "true" : "false");
          if (active) item.dataset.dir = sortState.dir === 1 ? "asc" : "desc";
          else item.removeAttribute("data-dir");
        });
      };
      syncSortButton();
      button.addEventListener("click", () => {
        if (sortState.key === key) sortState.dir *= -1;
        else { sortState.key = key; sortState.dir = 1; }
        syncSortButton();
        renderList(false);
      });
    });

    document.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        const find = $("wb-find");
        if (find) find.focus();
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "g") {
        event.preventDefault();
        const goto = $("wb-goto");
        if (goto) goto.focus();
      }
    });

    let resizeTimer = null;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        updateRowHeight();
        renderWindow();
      }, 120);
    });

    const more = $("wb-more");
    if (more) more.addEventListener("click", () => {
      renderWindow();
    });

    const list = $("wb-list");
    if (list) {
      list.addEventListener("click", (event) => {
        const row = event.target.closest("[data-record]");
        if (!row) return;
        const record = records[Number(row.dataset.record)];
        if (record) selectRecord(record);
      });
      list.addEventListener("scroll", () => {
        if (scrollFrame) return;
        scrollFrame = requestAnimationFrame(() => {
          scrollFrame = null;
          renderWindow();
        });
      }, { passive: true });
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
        selectRecord(filtered[next]);
        scrollToRecord(filtered[next]);
      });
    }

    const detail = $("wb-detail");
    if (detail) {
      detail.addEventListener("click", (event) => {
        if (event.target.closest("[data-follow-stream]")) { openStream(); return; }
        if (event.target.closest("[data-copy-scapy]")) {
          if (selected) PH.copyText(scapyForRecord(selected), "Scapy snippet copied");
          return;
        }
        if (event.target.closest("[data-copy-bpf]")) {
          if (selected) PH.copyText(bpfForRecord(selected), "BPF filter copied");
        }
      });
    }

    const permalink = $("wb-permalink");
    if (permalink) permalink.addEventListener("click", copyPermalink);
    const csv = $("wb-export-csv");
    if (csv) csv.addEventListener("click", exportCsv);
    const json = $("wb-export-json");
    if (json) json.addEventListener("click", exportJson);
    const har = $("wb-export-har");
    if (har) har.addEventListener("click", exportHar);
    const report = $("wb-export-report");
    if (report) report.addEventListener("click", exportReport);
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
        const flowTcp = selected && selected._flowInfo && selected._flowInfo.flow && selected._flowInfo.flow.proto === "tcp";
        const actions = [];
        if (tcp || flowTcp) actions.push('<button class="btn btn--ghost" type="button" data-follow-stream>Follow TCP stream</button>');
        if (selected) {
          actions.push('<button class="btn btn--ghost" type="button" data-copy-scapy>Copy as Scapy</button>');
          actions.push('<button class="btn btn--ghost" type="button" data-copy-bpf>Copy BPF</button>');
        }
        return actions.join("");
      }
    });
    view.clear("Select a packet in the list.");
    bindEvents();
    updateRowHeight();
    renderFilterChips();
    if (!restoreState()) loadExampleCapture();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
