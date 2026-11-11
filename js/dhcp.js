/* DHCPv4 explorer — BOOTP header, options, encoder and decoder. */
(function () {
  "use strict";

  const PH = window.PH;
  const D = window.DHCPCodec;
  const RFC = {
    base: "https://www.rfc-editor.org/rfc/rfc2131",
    options: "https://www.rfc-editor.org/rfc/rfc2132",
    concat: "https://www.rfc-editor.org/rfc/rfc3396",
    relay: "https://www.rfc-editor.org/rfc/rfc3046",
    route: "https://www.rfc-editor.org/rfc/rfc3442"
  };

  const headerFields = [
    { id: "op", name: "op", bytes: 1, range: "1 / 2", desc: "Message operation: 1 BOOTREQUEST, 2 BOOTREPLY.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "a" },
    { id: "htype", name: "htype", bytes: 1, range: "1 = Ethernet", desc: "Hardware address type. Ethernet is 1.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "b" },
    { id: "hlen", name: "hlen", bytes: 1, range: "0–16", desc: "Length of the client hardware address; Ethernet uses 6.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "c" },
    { id: "hops", name: "hops", bytes: 1, range: "0–255", desc: "Relay hop count. A client sets zero; a relay increments it.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "d" },
    { id: "xid", name: "xid", bytes: 4, range: "0–2³²−1", desc: "Transaction identifier selected by the client and echoed by the server.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "e" },
    { id: "secs", name: "secs", bytes: 2, range: "0–65535 s", desc: "Seconds since the client began address acquisition.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "f" },
    { id: "flags", name: "flags", bytes: 2, range: "broadcast + reserved", desc: "The high bit is the broadcast flag; the remaining 15 bits are reserved and zero.", rfc: "RFC 2131 §2 · RFC 2132 §2", rfcUrl: RFC.options + "#section-2", tone: "g" },
    { id: "ciaddr", name: "ciaddr", bytes: 4, range: "IPv4", desc: "Client IP address, filled in when the client already has one.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "h" },
    { id: "yiaddr", name: "yiaddr", bytes: 4, range: "IPv4", desc: "Address offered or assigned to the client.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "i" },
    { id: "siaddr", name: "siaddr", bytes: 4, range: "IPv4", desc: "Next server address used for bootstrap or boot file retrieval.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "j" },
    { id: "giaddr", name: "giaddr", bytes: 4, range: "IPv4", desc: "Relay agent address; zero when the client is on the server's link.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "a" },
    { id: "chaddr", name: "chaddr", bytes: 16, range: "16 B · first hlen used", desc: "Client hardware address, padded to 16 bytes.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "b" },
    { id: "sname", name: "sname", bytes: 64, range: "64 B · optional", desc: "Optional server host name. Option overload may replace it with options.", rfc: "RFC 2131 §2 · RFC 2132 §9.3", rfcUrl: RFC.options + "#section-9.3", tone: "c" },
    { id: "file", name: "file", bytes: 128, range: "128 B · optional", desc: "Boot file name. Option overload may replace it with options.", rfc: "RFC 2131 §2 · RFC 2132 §9.3", rfcUrl: RFC.options + "#section-9.3", tone: "d" },
    { id: "cookie", name: "magic cookie", bytes: 4, value: "63 82 53 63", range: "0x63825363", desc: "Marks the start of the DHCP option area.", rfc: "RFC 2131 §3", rfcUrl: RFC.base + "#section-3", tone: "e" },
    { id: "options", name: "options", bytes: "var", variable: true, varBytes: 4, range: "TLVs", desc: "Option code, length and value, ending with option 255. Option 0 pads; options may be overloaded or concatenated.", rfc: "RFC 2132", rfcUrl: RFC.options, tone: "f" }
  ];

  const flagFields = [
    { id: "broadcast", name: "Broadcast", bits: 1, range: "0/1", desc: "Set when the client cannot receive a unicast reply before it has an IP address.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "a" },
    { id: "reserved", name: "Reserved", bits: 15, range: "0", desc: "Reserved flag bits; transmitters set them to zero.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "b" }
  ];

  let headerLane = null;
  let flagsDiagram = null;
  let optionLane = null;

  function initDiagrams() {
    headerLane = PH.byteLane("#dhcp-diagram", {
      title: "<b>DHCPv4</b> · BOOTP header and options", badge: "RFC 2131",
      fields: headerFields, inspector: "#dhcp-inspector",
      note: "The fixed header is 236 bytes. A DHCP message then carries the magic cookie and an option area; the option area is drawn at a nominal width."
    });

    flagsDiagram = PH.diagram("#dhcp-flags-diagram", {
      title: "<b>DHCP flags</b> · 16-bit word", badge: "RFC 2131 §2", bitsPerRow: 16,
      fields: flagFields, inspector: "#dhcp-flags-inspector", table: "#dhcp-flags-fields",
      note: "Bit 0 is the most significant bit, so the broadcast flag is the first bit drawn. The remaining 15 bits are reserved."
    });
    PH.fieldTable("#dhcp-flags-fields", flagsDiagram, { columns: ["field", "bits", "offset", "range/values", "rfc"] });

    optionLane = PH.byteLane("#dhcp-option-lane", {
      title: "<b>DHCP option</b> · TLV", badge: "RFC 2132",
      fields: [
        { name: "Code", bytes: 1, range: "0–255", desc: "Option code. 0 = Pad, 255 = End; other codes identify the option.", rfc: "RFC 2132 §2", rfcUrl: RFC.options + "#section-2", tone: "a" },
        { name: "Length", bytes: 1, range: "0–255", desc: "Length of the value that follows. Pad and End have no length byte.", rfc: "RFC 2132 §2", rfcUrl: RFC.options + "#section-2", tone: "b" },
        { name: "Value", bytes: "var", variable: true, varBytes: 4, range: "Length bytes", desc: "Type-specific value: IPv4 addresses, strings, integers or nested sub-options.", rfc: "RFC 2132 §3–§9", rfcUrl: RFC.options, tone: "c" }
      ],
      inspector: "#dhcp-option-inspector",
      note: "A TLV is usually code + length + value. Pad and End are the two one-byte exceptions."
    });

    PH.byteLane("#dhcp-frame-lane", {
      title: "<b>DHCP in UDP/IPv4</b> · packet shape", badge: "UDP 67/68",
      fields: [
        { name: "IPv4 header", bytes: 20, range: "20–60 B", desc: "IPv4 header with Protocol 17. A relayed or fragmented packet may add options or a fragment header.", rfc: "RFC 791", rfcUrl: "https://www.rfc-editor.org/rfc/rfc791", tone: "a" },
        { name: "UDP header", bytes: 8, range: "8 B", desc: "UDP source and destination ports; clients use 68, servers use 67.", rfc: "RFC 768", rfcUrl: "https://www.rfc-editor.org/rfc/rfc768", tone: "b" },
        { name: "DHCP fixed header", bytes: 236, range: "236 B", desc: "BOOTP operation, addresses, transaction ID, flags and the client hardware address.", rfc: "RFC 2131 §2", rfcUrl: RFC.base + "#section-2", tone: "c" },
        { name: "Magic cookie + options", bytes: "var", variable: true, range: "4 + n B", desc: "Magic cookie 63 82 53 63, option TLVs and an End option.", rfc: "RFC 2132", rfcUrl: RFC.options, tone: "d" }
      ],
      inspector: "#dhcp-frame-inspector",
      note: "The first DHCP message from a client is normally an IPv4 broadcast because the client has no address yet."
    });
  }

  function updateHeaderDiagram(result) {
    if (!headerLane || !result) return;
    headerLane.setValues({
      op: result.op + " " + result.opName,
      htype: String(result.htype),
      hlen: String(result.hlen),
      hops: String(result.hops),
      xid: "0x" + PH.hex(result.xid, 8),
      secs: String(result.secs),
      flags: "0x" + PH.hex(result.flags, 4) + (result.broadcast ? " · broadcast" : ""),
      ciaddr: result.ciaddr,
      yiaddr: result.yiaddr,
      siaddr: result.siaddr,
      giaddr: result.giaddr,
      chaddr: result.chaddrText,
      sname: result.sname || "—",
      file: result.file || "—",
      cookie: result.cookieOk ? "0x63825363" : "missing",
      options: result.optionCount + " option(s)"
    });
  }

  function el(id) { return document.getElementById(id); }
  function val(id, fallback) { const node = el(id); return node ? node.value : fallback; }
  function checked(id) { const node = el(id); return !!(node && node.checked); }

  function messageTypeSelect() {
    const select = el("dhcp-enc-message-type");
    if (!select) return;
    select.innerHTML = Object.keys(D.MESSAGE_TYPES).map((code) =>
      `<option value="${code}">${code} · ${D.MESSAGE_TYPES[code]}</option>`
    ).join("");
    select.value = "1";
  }

  const PRESETS = {
    discover: {
      op: "1", yiaddr: "0.0.0.0", siaddr: "0.0.0.0", broadcast: true, messageType: "1",
      serverId: "", subnet: "", routers: "", dns: "", lease: "", renewal: "", rebinding: "", domain: "",
      extra: "parameter-request-list = 1,3,6,15,51,54\nmax-message-size = 1500\nclient-id = 01:02:00:00:00:0a"
    },
    offer: {
      op: "2", yiaddr: "192.0.2.100", siaddr: "192.0.2.1", broadcast: false, messageType: "2",
      serverId: "192.0.2.1", subnet: "255.255.255.0", routers: "192.0.2.1", dns: "192.0.2.53",
      lease: "3600", renewal: "1800", rebinding: "3150", domain: "example.com", extra: ""
    },
    request: {
      op: "1", yiaddr: "0.0.0.0", siaddr: "0.0.0.0", broadcast: false, messageType: "3",
      serverId: "192.0.2.1", subnet: "", routers: "", dns: "", lease: "", renewal: "", rebinding: "", domain: "",
      extra: "requested-ip = 192.0.2.100\nparameter-request-list = 1,3,6,15,51,54\nclient-id = 01:02:00:00:00:0a"
    },
    ack: {
      op: "2", yiaddr: "192.0.2.100", siaddr: "192.0.2.1", broadcast: false, messageType: "5",
      serverId: "192.0.2.1", subnet: "255.255.255.0", routers: "192.0.2.1", dns: "192.0.2.53",
      lease: "3600", renewal: "1800", rebinding: "3150", domain: "example.com", extra: ""
    },
    nak: {
      op: "2", yiaddr: "0.0.0.0", siaddr: "192.0.2.1", broadcast: true, messageType: "6",
      serverId: "192.0.2.1", subnet: "", routers: "", dns: "", lease: "", renewal: "", rebinding: "", domain: "",
      extra: "message = \"Requested address is not available\""
    }
  };

  const DORA_STEPS = [
    {
      caption: "<b>No address yet.</b> The client boots with no usable IPv4 configuration. It needs an address, a default route, DNS servers and a lease before it can use the LAN.",
      state: "no lease",
      stateClass: "dim",
      mode: "",
      ip: "0.0.0.0",
      clientNote: "no address · UDP 68",
      lanNote: "waiting",
      serverNote: "waiting · UDP 67",
      tokens: {},
      active: ["client"],
      match: [],
      bound: [],
      links: [],
      lease: [
        ["address", "<code>0.0.0.0</code>", ""],
        ["xid", "—", ""],
        ["server", "—", ""],
        ["lease", "—", ""],
        ["options", "—", ""]
      ]
    },
    {
      caption: "<b>DISCOVER.</b> The client broadcasts UDP/68 → UDP/67 with source <code>0.0.0.0</code> and destination <code>255.255.255.255</code>. Option 53 = 1, <code>xid</code> matches the transaction and <code>chaddr</code> carries its MAC. Option 55 lists the parameters it wants.",
      state: "discover sent",
      stateClass: "warn-text",
      mode: "is-broadcast",
      ip: "0.0.0.0",
      clientNote: "selecting · UDP 68",
      lanNote: "flood",
      serverNote: "DISCOVER received",
      tokens: { discover: [465, 150] },
      active: ["client", "lan"],
      match: ["server"],
      bound: [],
      links: ["client-lan", "lan-server"],
      lease: [
        ["address", "<code>0.0.0.0</code>", "is-pending"],
        ["xid", "<code>0x3903f326</code>", ""],
        ["server", "—", ""],
        ["lease", "—", ""],
        ["options", "—", ""]
      ]
    },
    {
      caption: "<b>OFFER.</b> A server picks <code>192.0.2.50</code> from its pool and returns DHCPOFFER with <code>yiaddr</code>, option 54 (server identifier), the mask, router, DNS and a 3600-second lease. The reply goes to the client's MAC; a client that sets the broadcast flag gets it broadcast instead.",
      state: "offer received",
      stateClass: "warn-text",
      mode: "is-unicast",
      ip: "0.0.0.0",
      clientNote: "offer: .50",
      lanNote: "forward",
      serverNote: "OFFER sent",
      tokens: { offer: [255, 150] },
      active: ["server", "lan"],
      match: ["client"],
      bound: [],
      links: ["client-lan", "lan-server"],
      lease: [
        ["address", "<code>192.0.2.50</code>", "is-pending"],
        ["xid", "<code>0x3903f326</code>", ""],
        ["server", "<code>192.0.2.1</code>", ""],
        ["lease", "3600 s · offered", "is-pending"],
        ["options", "mask /24 · router · DNS", ""]
      ]
    },
    {
      caption: "<b>REQUEST.</b> The client broadcasts DHCPREQUEST with option 50 (requested address) and option 54 (chosen server). Every server on the link sees which offer was accepted.",
      state: "requesting",
      stateClass: "warn-text",
      mode: "is-broadcast",
      ip: "0.0.0.0",
      clientNote: "requesting · .50",
      lanNote: "flood",
      serverNote: "REQUEST received",
      tokens: { request: [465, 150] },
      active: ["client", "lan"],
      match: ["server"],
      bound: [],
      links: ["client-lan", "lan-server"],
      lease: [
        ["address", "<code>192.0.2.50</code>", "is-pending"],
        ["xid", "<code>0x3903f326</code>", ""],
        ["server", "<code>192.0.2.1</code>", ""],
        ["lease", "3600 s · requested", "is-pending"],
        ["options", "mask /24 · router · DNS", ""]
      ]
    },
    {
      caption: "<b>ACK and bind.</b> The server commits the lease with DHCPACK. The client can use <code>192.0.2.50</code> after checking the address is not already in use. A NAK restarts acquisition; a lost reply is retransmitted with the same <code>xid</code>. Renewal later unicasts REQUEST to the same server.",
      state: "bound",
      stateClass: "good-text",
      mode: "is-unicast",
      ip: "192.0.2.50",
      clientNote: "bound · lease 3600 s",
      lanNote: "forward",
      serverNote: "ACK sent · lease committed",
      tokens: { ack: [255, 150] },
      active: ["server", "lan"],
      match: [],
      bound: ["client"],
      links: ["client-lan", "lan-server"],
      lease: [
        ["address", "<code>192.0.2.50</code>", "is-resolved"],
        ["xid", "<code>0x3903f326</code>", ""],
        ["server", "<code>192.0.2.1</code>", ""],
        ["lease", "3600 s · T1 1800 s", "is-resolved"],
        ["options", "mask /24 · gw .1 · dns .53", "is-resolved"]
      ]
    }
  ];

  const DORA_TOKEN_HOME = {
    discover: [255, 150],
    offer: [465, 150],
    request: [255, 150],
    ack: [465, 150]
  };

  function applyPreset(name) {
    const preset = PRESETS[name];
    if (!preset) return;
    el("dhcp-enc-op").value = preset.op;
    el("dhcp-enc-htype").value = "1";
    el("dhcp-enc-hlen").value = "6";
    el("dhcp-enc-hops").value = "0";
    el("dhcp-enc-xid").value = "0x3903f326";
    el("dhcp-enc-secs").value = "0";
    el("dhcp-enc-ciaddr").value = "0.0.0.0";
    el("dhcp-enc-yiaddr").value = preset.yiaddr;
    el("dhcp-enc-siaddr").value = preset.siaddr;
    el("dhcp-enc-giaddr").value = "0.0.0.0";
    el("dhcp-enc-chaddr").value = "02:00:00:00:00:0a";
    el("dhcp-enc-message-type").value = preset.messageType;
    el("dhcp-enc-broadcast").checked = preset.broadcast;
    el("dhcp-enc-server-id").value = preset.serverId;
    el("dhcp-enc-subnet").value = preset.subnet;
    el("dhcp-enc-routers").value = preset.routers;
    el("dhcp-enc-dns").value = preset.dns;
    el("dhcp-enc-lease").value = preset.lease;
    el("dhcp-enc-renewal").value = preset.renewal;
    el("dhcp-enc-rebinding").value = preset.rebinding;
    el("dhcp-enc-domain").value = preset.domain;
    el("dhcp-enc-sname").value = "";
    el("dhcp-enc-file").value = "";
    el("dhcp-enc-extra").value = preset.extra;
    buildFromForm(true);
  }

  function readEncoder() {
    return {
      op: Number(val("dhcp-enc-op", "1")),
      htype: Number(val("dhcp-enc-htype", "1")),
      hlen: Number(val("dhcp-enc-hlen", "6")),
      hops: Number(val("dhcp-enc-hops", "0")),
      xid: PH.parseNumber(val("dhcp-enc-xid", "0")),
      secs: Number(val("dhcp-enc-secs", "0")),
      broadcast: checked("dhcp-enc-broadcast"),
      ciaddr: val("dhcp-enc-ciaddr", "0.0.0.0"),
      yiaddr: val("dhcp-enc-yiaddr", "0.0.0.0"),
      siaddr: val("dhcp-enc-siaddr", "0.0.0.0"),
      giaddr: val("dhcp-enc-giaddr", "0.0.0.0"),
      chaddr: val("dhcp-enc-chaddr", ""),
      sname: val("dhcp-enc-sname", ""),
      file: val("dhcp-enc-file", ""),
      messageType: Number(val("dhcp-enc-message-type", "1")),
      serverIdentifier: val("dhcp-enc-server-id", "").trim(),
      subnetMask: val("dhcp-enc-subnet", "").trim(),
      routers: val("dhcp-enc-routers", "").trim(),
      dnsServers: val("dhcp-enc-dns", "").trim(),
      leaseTime: val("dhcp-enc-lease", "").trim(),
      renewalTime: val("dhcp-enc-renewal", "").trim(),
      rebindingTime: val("dhcp-enc-rebinding", "").trim(),
      domainName: val("dhcp-enc-domain", "").trim(),
      extraOptions: val("dhcp-enc-extra", "")
    };
  }

  function setStatus(text, kind) { PH.setStatus(el("dhcp-enc-status"), text, kind); }

  function buildFromForm(showErrors) {
    const out = el("dhcp-enc-output");
    const tag = el("dhcp-enc-tag");
    let built;
    try {
      built = D.buildDhcp(readEncoder());
    } catch (err) {
      if (showErrors !== false) setStatus("error: " + err.message, "bad");
      tag.textContent = "error";
      return null;
    }
    out.textContent = PH.bytesToHex(built.bytes);
    out.classList.remove("placeholder");
    tag.textContent = built.bytes.length + " bytes";
    el("dhcp-enc-length").textContent = built.bytes.length + " B";
    el("dhcp-enc-option-count").textContent = String(built.optionCount);
    el("dhcp-enc-type").textContent = built.messageTypeName;
    el("dhcp-enc-summary").innerHTML = [
      `<span class="pill">${PH.esc(built.opName || (built.op === 1 ? "BOOTREQUEST" : "BOOTREPLY"))}</span>`,
      `<span class="pill">${PH.esc(built.messageTypeName)}</span>`,
      `<span class="pill">xid <b>0x${PH.hex(built.xid, 8)}</b></span>`,
      `<span class="pill">yiaddr <b>${PH.esc(built.yiaddr)}</b></span>`,
      `<span class="pill">${built.bytes.length} B</span>`
    ].join("");
    setStatus(`built ${built.messageTypeName} · ${built.bytes.length} bytes · ${built.optionCount} option(s) · ${built.options} option byte(s)`, "ok");
    updateHeaderDiagram(Object.assign({}, built, {
      opName: built.op === 1 ? "BOOTREQUEST" : "BOOTREPLY",
      flags: built.flags,
      ciaddr: built.ciaddr,
      yiaddr: built.yiaddr,
      siaddr: built.siaddr,
      giaddr: built.giaddr,
      chaddrText: built.chaddr,
      sname: built.sname,
      file: built.file,
      cookieOk: true,
      optionCount: built.optionCount
    }));
    lastBuild = built;
    return built;
  }

  function initEncoder() {
    messageTypeSelect();
    el("dhcp-enc-build").addEventListener("click", () => buildFromForm(true));
    el("dhcp-enc-example").addEventListener("click", () => applyPreset("discover"));
    document.querySelectorAll("[data-dhcp-preset]").forEach((button) => {
      button.addEventListener("click", () => applyPreset(button.getAttribute("data-dhcp-preset")));
    });
    ["dhcp-enc-op", "dhcp-enc-htype", "dhcp-enc-hlen", "dhcp-enc-hops", "dhcp-enc-xid",
      "dhcp-enc-secs", "dhcp-enc-ciaddr", "dhcp-enc-yiaddr", "dhcp-enc-siaddr", "dhcp-enc-giaddr",
      "dhcp-enc-chaddr", "dhcp-enc-sname", "dhcp-enc-file", "dhcp-enc-message-type",
      "dhcp-enc-server-id", "dhcp-enc-subnet", "dhcp-enc-routers", "dhcp-enc-dns",
      "dhcp-enc-lease", "dhcp-enc-renewal", "dhcp-enc-rebinding", "dhcp-enc-domain",
      "dhcp-enc-extra"].forEach((id) => {
      const node = el(id);
      if (!node) return;
      node.addEventListener("input", () => buildFromForm(false));
      node.addEventListener("change", () => buildFromForm(false));
    });
    el("dhcp-enc-broadcast").addEventListener("change", () => buildFromForm(false));
    el("dhcp-enc-permalink").addEventListener("click", () => {
      if (lastBuild || buildFromForm(true)) PH.shareState(encoderState(), "DHCP encoder permalink copied");
    });
    el("dhcp-enc-export").addEventListener("click", () => {
      const current = lastBuild || buildFromForm(true);
      if (!current) return;
      PH.downloadText("dhcp-message.json", JSON.stringify({
        hex: PH.bytesToHex(current.bytes),
        bytes: current.bytes.length,
        messageType: current.messageTypeName,
        xid: "0x" + PH.hex(current.xid, 8),
        parameters: sanitize(readEncoder())
      }, null, 2), "application/json");
    });
    applyPreset("discover");
  }

  let lastBuild = null;
  let lastDecode = null;

  function encodeContext(udp) {
    return udp ? { transport: "UDP", srcPort: udp.srcPort, dstPort: udp.dstPort, checksumState: udp.checksumState } : { transport: "raw" };
  }

  function decodeUdpPayload(bytes, context) {
    const udp = window.UDPCodec.decodeUdp(bytes, context || {});
    return {
      dhcp: D.decodeDhcp(udp.payload),
      udp, ip: null, ipVersion: context && context.ipVersion, ethernet: null,
      udpOffset: 0, dhcpOffset: 8,
      detectedAs: "raw UDP datagram",
      contextWarnings: udp.warnings.slice()
    };
  }

  function decodeIpv4(bytes) {
    const ip = window.IPv4Codec.decode(bytes);
    if (ip.protocol !== 17) throw new Error("IPv4 Protocol is " + ip.protocol + " (" + ip.protocolLabel + "), not UDP (17)");
    if (ip.fragmentOffset > 0) throw new Error("DHCP is not present in a non-initial IPv4 fragment");
    const udp = window.UDPCodec.decodeUdp(ip.payloadBytes, { ipVersion: 4, srcIp: ip.src, dstIp: ip.dst });
    let ethernet = null;
    if (ip.ethernet) {
      try { ethernet = window.EthernetCodec.decodeFrame(bytes, { fcs: "auto" }); } catch (_) { ethernet = null; }
    }
    return {
      dhcp: D.decodeDhcp(udp.payload),
      udp, ip, ipVersion: 4, ethernet,
      udpOffset: ip.base + ip.headerLen, dhcpOffset: ip.base + ip.headerLen + 8,
      detectedAs: ip.ethernet ? "Ethernet frame with IPv4/UDP/DHCP" : "IPv4 packet with UDP/DHCP",
      contextWarnings: ip.warnings.concat(udp.warnings)
    };
  }

  function decodeEthernet(bytes) {
    const frame = window.EthernetCodec.decodeFrame(bytes, { fcs: "auto" });
    if (frame.etherType !== 0x0800) throw new Error("Ethernet EtherType is 0x" + PH.hex(frame.etherType, 4) + " (" + frame.etherTypeName + "), not IPv4");
    const start = frame.offset + frame.headerLen;
    const end = start + frame.payload.length;
    const result = decodeIpv4(bytes.subarray(start, end));
    result.ethernet = frame;
    result.detectedAs = "Ethernet frame with IPv4/UDP/DHCP";
    result.dhcpOffset = start + result.dhcpOffset;
    result.udpOffset = start + result.udpOffset;
    return result;
  }

  function looksLikeDhcp(bytes) { return D.looksLikeDhcp(bytes); }

  function ethernetInnerType(bytes) {
    if (bytes.length < 14) return null;
    let offset = 12;
    let type = PH.u16be(bytes, offset);
    while ((type === 0x8100 || type === 0x88a8) && bytes.length >= offset + 6) {
      offset += 4;
      type = PH.u16be(bytes, offset);
    }
    return type;
  }

  function decodeAny(bytes, kind) {
    if (kind === "raw") return { dhcp: D.decodeDhcp(bytes), udp: null, ip: null, ipVersion: null, ethernet: null, udpOffset: 0, dhcpOffset: 0, detectedAs: "raw DHCP message", contextWarnings: [] };
    if (kind === "udp") return decodeUdpPayload(bytes, {});
    if (kind === "ipv4") return decodeIpv4(bytes);
    if (kind === "ethernet") return decodeEthernet(bytes);
    if (looksLikeDhcp(bytes)) {
      return { dhcp: D.decodeDhcp(bytes), udp: null, ip: null, ipVersion: null, ethernet: null, udpOffset: 0, dhcpOffset: 0, detectedAs: "raw DHCP message", contextWarnings: [] };
    }
    if ((bytes[0] >> 4) === 6) throw new Error("IPv6 packet detected. DHCPv6 is a different protocol (UDP 546/547, RFC 8415).");
    const innerType = ethernetInnerType(bytes);
    if (innerType === 0x0800) return decodeEthernet(bytes);
    if ((bytes[0] >> 4) === 4) return decodeIpv4(bytes);
    try {
      const raw = decodeUdpPayload(bytes, {});
      if (looksLikeDhcp(raw.dhcp.bytes)) return raw;
    } catch (_) { /* fall through */ }
    return { dhcp: D.decodeDhcp(bytes), udp: null, ip: null, ipVersion: null, ethernet: null, udpOffset: 0, dhcpOffset: 0, detectedAs: "raw DHCP message", contextWarnings: [] };
  }

  function detailTable(title, hint, headers, rows) {
    if (!rows.length) return "";
    return `<div class="decoded-head"><h3>${PH.esc(title)}</h3><span class="dim">${PH.esc(hint)}</span></div>` +
      '<div class="table-wrap"><table class="data-table"><thead><tr>' +
      headers.map((header) => `<th>${PH.esc(header)}</th>`).join("") +
      "</tr></thead><tbody>" +
      rows.map((row) => "<tr>" + row.map((cell) => `<td>${cell}</td>`).join("") + "</tr>").join("") +
      "</tbody></table></div>";
  }

  function flowText(type) {
    const flows = {
      1: "Client broadcasts a DISCOVER to UDP/67. The server may answer with OFFER.",
      2: "Server offers an address in yiaddr and configuration options. The client may REQUEST it.",
      3: "Client requests the offered address and identifies the selected server with option 54.",
      4: "Client reports that the offered address is already in use; the server should mark it unavailable.",
      5: "Server commits the lease and returns the final configuration.",
      6: "Server rejects the request; the client must restart address acquisition.",
      7: "Client releases its lease and returns the address to the server.",
      8: "Client already has an address and asks only for additional configuration parameters."
    };
    return flows[type] || "DHCP message type not identified.";
  }

  function renderDecoded(result) {
    const host = el("dhcp-decode-result");
    const dhcp = result.dhcp;
    const pills = [
      `<span class="pill">${PH.esc(dhcp.messageTypeName)}</span>`,
      `<span class="pill">${PH.esc(dhcp.opName)}</span>`,
      `<span class="pill">xid <b>0x${PH.hex(dhcp.xid, 8)}</b></span>`,
      `<span class="pill">yiaddr <b>${PH.esc(dhcp.yiaddr)}</b></span>`,
      `<span class="pill">${dhcp.optionCount} option(s)</span>`,
      `<span class="pill ${dhcp.cookieOk ? "pill--good" : "pill--bad"}">${dhcp.cookieOk ? "magic cookie" : "no cookie"}</span>`
    ];
    if (result.ethernet) pills.push(`<span class="pill pill--good">Ethernet${result.ethernet.vlanTags && result.ethernet.vlanTags.length ? " + VLAN" : ""}</span>`);
    if (result.ip) pills.push(`<span class="pill">IPv4 ${PH.esc(result.ip.src)} → ${PH.esc(result.ip.dst)}</span>`);
    if (result.udp) pills.push(`<span class="pill">UDP ${result.udp.srcPort} → ${result.udp.dstPort}</span>`);

    const rows = [
      ["op", "8", "0", `${dhcp.op} · ${dhcp.opName}`, "BOOTREQUEST or BOOTREPLY"],
      ["htype", "8", "1", `${dhcp.htype}${dhcp.htype === 1 ? " · Ethernet" : ""}`, "hardware type"],
      ["hlen", "8", "2", String(dhcp.hlen), dhcp.hlen === 6 ? "Ethernet address length" : "non-Ethernet address length"],
      ["hops", "8", "3", String(dhcp.hops), "relay hop count"],
      ["xid", "32", "4–7", "0x" + PH.hex(dhcp.xid, 8), "transaction identifier"],
      ["secs", "16", "8–9", String(dhcp.secs) + " s", "time since acquisition began"],
      ["flags", "16", "10–11", "0x" + PH.hex(dhcp.flags, 4) + (dhcp.broadcast ? " · broadcast" : ""), dhcp.reservedFlags ? "reserved bits set" : "reserved bits clear"],
      ["ciaddr", "32", "12–15", dhcp.ciaddr, "client address"],
      ["yiaddr", "32", "16–19", dhcp.yiaddr, "offered address"],
      ["siaddr", "32", "20–23", dhcp.siaddr, "next server"],
      ["giaddr", "32", "24–27", dhcp.giaddr, "relay agent"],
      ["chaddr", String(dhcp.hlen * 8), "28–" + (28 + dhcp.hlen - 1), dhcp.chaddrText, "client hardware address"],
      ["sname", "512", "44–107", dhcp.sname || "—", "server name"],
      ["file", "1024", "108–235", dhcp.file || "—", "boot file"],
      ["magic cookie", "32", "236–239", dhcp.magicCookie, dhcp.cookieOk ? "DHCP options follow" : "missing"],
      ["options", "var", dhcp.optionsStart == null ? "—" : String(dhcp.optionsStart), dhcp.optionCount + " option(s)", "TLV area"]
    ];
    const table = rows.map(([name, bits, offset, value, note]) =>
      `<tr><td><b>${PH.esc(name)}</b></td><td class="num">${PH.esc(bits)}</td><td class="num">${PH.esc(offset)}</td><td><code>${PH.esc(value)}</code></td><td class="small">${PH.esc(note)}</td></tr>`
    ).join("");

    const optionRows = dhcp.options.map((option) => [
      `<code>${option.code}</code>`,
      `<b>${PH.esc(option.name)}</b>`,
      `<span class="num">${option.length} B</span>`,
      `<span class="dim">${PH.esc(option.source)}</span>`,
      `<code>${PH.esc(option.valueText)}</code>`
    ]);
    const optionsHtml = detailTable("options", "offsets are relative to the option area source", ["Code", "Name", "Length", "Source", "Value"], optionRows);

    let overloadHtml = "";
    const overload = dhcp.options.find((option) => option.code === 52);
    if (overload) {
      overloadHtml = `<div class="callout"><div class="callout__title">option overload</div><p>Option 52 requests options from ${PH.esc(overload.valueText)}. The decoder has included overloaded options in the table above and labels their source column.</p></div>`;
    }

    const context = result.udp
      ? `<div class="callout"><div class="callout__title">transport context</div><p>${result.ip ? `${PH.esc(result.ip.src)} → ${PH.esc(result.ip.dst)} · ` : ""}UDP ${result.udp.srcPort} → ${result.udp.dstPort} · checksum ${PH.esc(result.udp.checksumState)}${result.ethernet ? ` · Ethernet ${PH.esc(result.ethernet.srcMac)} → ${PH.esc(result.ethernet.dstMac)}` : ""}. ${result.ipVersion === 4 ? '<a href="ipv4.html">IPv4 explorer</a> · ' : ""}<a href="udp.html">UDP explorer</a>.</p></div>`
      : '<div class="callout callout--warn"><div class="callout__title">raw DHCP message</div><p>No IP or UDP wrapper was supplied, so source and destination addresses and the UDP checksum cannot be verified from this input alone.</p></div>';

    const warnings = dhcp.warnings.concat(result.contextWarnings || []);
    const warningHtml = warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean message</div><p>Header, magic cookie, option lengths and message type agree. A clean parse does not prove the sender is an authorized DHCP server.</p></div>';

    host.innerHTML =
      `<div class="decode-summary">${pills.join("")}</div>` +
      `<div class="hexdump-wrap"><div class="hexdump-head"><span>${PH.esc(result.detectedAs)}</span><span>${result.dhcp.messageLength} B · DHCP at +${result.dhcpOffset}</span></div>${PH.hexdump(result.dhcp.bytes, { highlight: [{ start: 0, end: Math.min(240, result.dhcp.messageLength) }] })}</div>` +
      '<div class="decoded-head"><h3>BOOTP fields</h3><span class="dim">offsets relative to the DHCP message</span></div>' +
      `<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th class="num">Bits</th><th class="num">Offset</th><th>Value</th><th>Note</th></tr></thead><tbody>${table}</tbody></table></div>` +
      optionsHtml + overloadHtml + `<div class="callout"><div class="callout__title">${PH.esc(dhcp.messageTypeName)}</div><p>${PH.esc(flowText(dhcp.messageType))}</p></div>` +
      context + warningHtml;
  }

  function sanitize(value) {
    if (value instanceof Uint8Array) return PH.bytesToHex(value);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach((key) => {
        if (key === "bytes" || key === "chaddr16" || key === "snameBytes" || key === "fileBytes" || key === "vendorBytes") return;
        out[key] = sanitize(value[key]);
      });
      return out;
    }
    return value;
  }

  function runDecode(showErrors) {
    const input = el("dhcp-decode-input");
    const status = el("dhcp-decode-status");
    const host = el("dhcp-decode-result");
    let bytes;
    try { bytes = PH.parseHex(input.value); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return null;
    }
    try {
      const result = decodeAny(bytes, el("dhcp-decode-kind").value);
      renderDecoded(result);
      updateHeaderDiagram(result.dhcp);
      lastDecode = { result, hex: PH.bytesToHex(bytes) };
      PH.setStatus(status,
        `${result.dhcp.messageTypeName} · xid 0x${PH.hex(result.dhcp.xid, 8)} · ${result.dhcp.optionCount} option(s) · ${result.dhcp.messageLength} B${result.dhcp.warnings.length ? " · " + result.dhcp.warnings.length + " note(s)" : ""}`,
        result.dhcp.warnings.length ? "warn" : "ok");
      return lastDecode;
    } catch (err) {
      host.innerHTML = "";
      lastDecode = null;
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      return null;
    }
  }

  function exampleBytes(kind) { return D.buildDhcp(readExample(kind)).bytes; }

  function readExample(kind) {
    const preset = PRESETS[kind] || PRESETS.discover;
    return {
      op: Number(preset.op), htype: 1, hlen: 6, hops: 0, xid: 0x3903f326,
      secs: 0, broadcast: preset.broadcast, ciaddr: "0.0.0.0", yiaddr: preset.yiaddr,
      siaddr: preset.siaddr, giaddr: "0.0.0.0", chaddr: "02:00:00:00:00:0a",
      sname: "", file: "", messageType: Number(preset.messageType),
      serverIdentifier: preset.serverId, subnetMask: preset.subnet, routers: preset.routers,
      dnsServers: preset.dns, leaseTime: preset.lease, renewalTime: preset.renewal,
      rebindingTime: preset.rebinding, domainName: preset.domain, extraOptions: preset.extra
    };
  }

  function initDecoder() {
    const input = el("dhcp-decode-input");
    if (!input) return;
    el("dhcp-decode").addEventListener("click", () => runDecode(true));
    el("dhcp-decode-discover").addEventListener("click", () => { input.value = PH.bytesToHex(exampleBytes("discover")); el("dhcp-decode-kind").value = "raw"; runDecode(true); });
    el("dhcp-decode-offer").addEventListener("click", () => { input.value = PH.bytesToHex(exampleBytes("offer")); el("dhcp-decode-kind").value = "raw"; runDecode(true); });
    el("dhcp-decode-ack").addEventListener("click", () => { input.value = PH.bytesToHex(exampleBytes("ack")); el("dhcp-decode-kind").value = "raw"; runDecode(true); });
    el("dhcp-decode-nak").addEventListener("click", () => { input.value = PH.bytesToHex(exampleBytes("nak")); el("dhcp-decode-kind").value = "raw"; runDecode(true); });
    el("dhcp-decode-clear").addEventListener("click", () => {
      input.value = "";
      el("dhcp-decode-result").innerHTML = "";
      lastDecode = null;
      PH.setStatus(el("dhcp-decode-status"), "No DHCP message decoded yet.", "");
    });
    el("dhcp-decode-permalink").addEventListener("click", () => {
      const current = lastDecode || runDecode(true);
      if (current) PH.shareState(decoderState(), "DHCP decoder permalink copied");
    });
    el("dhcp-decode-export").addEventListener("click", () => {
      const current = lastDecode || runDecode(true);
      if (!current) return;
      PH.downloadText("dhcp-decoded.json", JSON.stringify({
        hex: current.hex,
        decoded: sanitize(current.result.dhcp),
        transport: sanitize({ ip: current.result.ip, udp: current.result.udp, ethernet: current.result.ethernet })
      }, null, 2), "application/json");
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runDecode(true);
    });
  }

  function encoderState() {
    return {
      page: "dhcp-enc",
      values: {
        op: val("dhcp-enc-op", "1"), htype: val("dhcp-enc-htype", "1"),
        hlen: val("dhcp-enc-hlen", "6"), hops: val("dhcp-enc-hops", "0"),
        xid: val("dhcp-enc-xid", ""), secs: val("dhcp-enc-secs", "0"),
        broadcast: checked("dhcp-enc-broadcast"),
        ciaddr: val("dhcp-enc-ciaddr", ""), yiaddr: val("dhcp-enc-yiaddr", ""),
        siaddr: val("dhcp-enc-siaddr", ""), giaddr: val("dhcp-enc-giaddr", ""),
        chaddr: val("dhcp-enc-chaddr", ""), sname: val("dhcp-enc-sname", ""), file: val("dhcp-enc-file", ""),
        messageType: val("dhcp-enc-message-type", "1"),
        serverId: val("dhcp-enc-server-id", ""), subnet: val("dhcp-enc-subnet", ""),
        routers: val("dhcp-enc-routers", ""), dns: val("dhcp-enc-dns", ""),
        lease: val("dhcp-enc-lease", ""), renewal: val("dhcp-enc-renewal", ""),
        rebinding: val("dhcp-enc-rebinding", ""), domain: val("dhcp-enc-domain", ""),
        extra: val("dhcp-enc-extra", "")
      }
    };
  }

  function applyEncoderState(state) {
    const values = state && state.values;
    if (!values) return false;
    const map = {
      "dhcp-enc-op": values.op, "dhcp-enc-htype": values.htype, "dhcp-enc-hlen": values.hlen,
      "dhcp-enc-hops": values.hops, "dhcp-enc-xid": values.xid, "dhcp-enc-secs": values.secs,
      "dhcp-enc-ciaddr": values.ciaddr, "dhcp-enc-yiaddr": values.yiaddr,
      "dhcp-enc-siaddr": values.siaddr, "dhcp-enc-giaddr": values.giaddr,
      "dhcp-enc-chaddr": values.chaddr, "dhcp-enc-sname": values.sname, "dhcp-enc-file": values.file,
      "dhcp-enc-message-type": values.messageType, "dhcp-enc-server-id": values.serverId,
      "dhcp-enc-subnet": values.subnet, "dhcp-enc-routers": values.routers, "dhcp-enc-dns": values.dns,
      "dhcp-enc-lease": values.lease, "dhcp-enc-renewal": values.renewal,
      "dhcp-enc-rebinding": values.rebinding, "dhcp-enc-domain": values.domain,
      "dhcp-enc-extra": values.extra
    };
    Object.keys(map).forEach((id) => { if (map[id] != null) el(id).value = map[id]; });
    el("dhcp-enc-broadcast").checked = !!values.broadcast;
    buildFromForm(true);
    return true;
  }

  function decoderState() {
    return { page: "dhcp-dec", kind: el("dhcp-decode-kind").value, hex: el("dhcp-decode-input").value };
  }

  function initDora() {
    const flow = el("dhcp-flow");
    if (!flow) return;

    const caption = el("dhcp-flow-caption");
    const state = el("dhcp-flow-state");
    const leaseBody = el("dhcp-flow-lease");
    const clientIp = el("dhcp-node-client-ip");
    const clientNote = el("dhcp-node-client-note");
    const lanNote = el("dhcp-node-lan-note");
    const serverNote = el("dhcp-node-server-note");
    const nodes = {};
    flow.querySelectorAll("[data-node]").forEach((node) => { nodes[node.dataset.node] = node; });
    const links = {};
    flow.querySelectorAll("[data-link]").forEach((link) => { links[link.dataset.link] = link; });
    const tokens = {};
    flow.querySelectorAll("[data-token]").forEach((token) => { tokens[token.dataset.token] = token; });

    function applyStep(index) {
      const step = DORA_STEPS[index - 1];
      caption.innerHTML = step.caption;
      state.textContent = step.state;
      state.className = step.stateClass;
      clientIp.textContent = step.ip;
      clientNote.textContent = step.clientNote;
      lanNote.textContent = step.lanNote;
      serverNote.textContent = step.serverNote;
      flow.classList.toggle("is-broadcast", step.mode === "is-broadcast");
      flow.classList.toggle("is-unicast", step.mode === "is-unicast");

      if (index === 1) {
        Object.keys(tokens).forEach((name) => {
          const token = tokens[name];
          token.classList.remove("is-visible");
          const home = DORA_TOKEN_HOME[name];
          if (home) token.style.transform = `translate(${home[0]}px, ${home[1]}px)`;
        });
      }

      Object.keys(tokens).forEach((name) => {
        const token = tokens[name];
        const position = step.tokens[name];
        if (position) {
          token.style.transform = `translate(${position[0]}px, ${position[1]}px)`;
          token.classList.add("is-visible");
        } else {
          token.classList.remove("is-visible");
        }
      });

      Object.keys(nodes).forEach((name) => {
        nodes[name].classList.toggle("is-active", step.active.includes(name));
        nodes[name].classList.toggle("is-match", step.match.includes(name));
        nodes[name].classList.toggle("is-bound", step.bound.includes(name));
      });

      Object.keys(links).forEach((name) => {
        links[name].classList.toggle("is-active", step.links.includes(name));
      });

      leaseBody.innerHTML = step.lease.map(([field, value, cls]) =>
        `<tr><td>${field}</td><td${cls ? ` class="${cls}"` : ""}>${value}</td></tr>`
      ).join("");
    }

    PH.stepFlow({ root: flow, count: DORA_STEPS.length, onStep: applyStep });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state) return false;
    if (state.page === "dhcp-enc" && applyEncoderState(state)) return true;
    if (state.page === "dhcp-dec") {
      el("dhcp-decode-kind").value = state.kind || "auto";
      el("dhcp-decode-input").value = state.hex || "";
      runDecode(true);
      return true;
    }
    return false;
  }

  function init() {
    if (!el("dhcp-diagram")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    initDora();
    if (!restoreState()) buildFromForm(false);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
