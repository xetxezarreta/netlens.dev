/* DHCPv4 (RFC 2131 / RFC 2132) message codec — BOOTP header and options. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const MAGIC_COOKIE = Uint8Array.from([0x63, 0x82, 0x53, 0x63]);
  const OP_NAMES = { 1: "BOOTREQUEST", 2: "BOOTREPLY" };
  const MESSAGE_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"
  };
  const MESSAGE_TYPE_VALUES = Object.fromEntries(Object.keys(MESSAGE_TYPES).map((code) => [MESSAGE_TYPES[code], Number(code)]));

  const OPTION_NAMES = {
    0: "Pad", 1: "Subnet Mask", 2: "Time Offset", 3: "Router", 4: "Time Server",
    5: "Name Server", 6: "Domain Name Server", 7: "Log Server", 8: "Cookie Server",
    9: "LPR Server", 10: "Impress Server", 11: "Resource Location Server",
    12: "Host Name", 13: "Boot File Size", 14: "Merit Dump File", 15: "Domain Name",
    16: "Swap Server", 17: "Root Path", 18: "Extensions Path", 19: "IP Forwarding",
    20: "Non-Local Source Routing", 21: "Policy Filter", 22: "Maximum Datagram Reassembly Size",
    23: "Default IP TTL", 24: "Path MTU Aging Timeout", 25: "Path MTU Plateau Table",
    26: "Interface MTU", 27: "All Subnets Are Local", 28: "Broadcast Address",
    29: "Perform Mask Discovery", 30: "Mask Supplier", 31: "Perform Router Discovery",
    32: "Router Solicitation Address", 33: "Static Route", 34: "Trailer Encapsulation",
    35: "ARP Cache Timeout", 36: "Ethernet Encapsulation", 37: "TCP Default TTL",
    38: "TCP Keepalive Interval", 39: "TCP Keepalive Garbage",
    40: "Network Information Service Domain", 41: "NIS Servers", 42: "NTP Servers",
    43: "Vendor Specific Information", 44: "NetBIOS Name Server",
    45: "NetBIOS Datagram Distribution Server", 46: "NetBIOS Node Type",
    47: "NetBIOS Scope", 48: "X Window System Font Server", 49: "X Window System Display Manager",
    50: "Requested IP Address", 51: "IP Address Lease Time", 52: "Option Overload",
    53: "DHCP Message Type", 54: "Server Identifier", 55: "Parameter Request List",
    56: "Message", 57: "Maximum DHCP Message Size", 58: "Renewal Time Value",
    59: "Rebinding Time Value", 60: "Vendor Class Identifier", 61: "Client Identifier",
    62: "NetWare/IP Domain Name", 63: "NetWare/IP Information", 64: "NIS+ Domain Name",
    65: "NIS+ Servers", 66: "TFTP Server Name", 67: "Bootfile Name",
    68: "Mobile IP Home Agents", 69: "SMTP Servers", 70: "POP3 Servers",
    71: "NNTP Servers", 72: "WWW Servers", 73: "Finger Servers", 74: "IRC Servers",
    75: "StreetTalk Servers", 76: "STDA Servers", 80: "Rapid Commit",
    81: "Client FQDN", 82: "Relay Agent Information", 83: "iSNS",
    90: "Authentication", 91: "Client Last Transaction Time", 92: "Associated IP",
    93: "Client System Architecture", 94: "Client Network Interface Identifier",
    97: "UUID/GUID", 100: "TZ String", 101: "TZ Database", 108: "IPv6-Only Preferred",
    114: "Captive Portal", 118: "Subnet Selection", 119: "Domain Search",
    121: "Classless Static Route", 208: "PXELinux Magic", 209: "PXELinux Config File",
    210: "PXELinux Path Prefix", 249: "Microsoft Classless Static Route",
    252: "Web Proxy Auto-Discovery", 255: "End"
  };

  const OPTION_KINDS = {
    1: "ipv4", 3: "ipv4-list", 4: "ipv4-list", 5: "ipv4-list", 6: "ipv4-list",
    7: "ipv4-list", 8: "ipv4-list", 9: "ipv4-list", 10: "ipv4-list", 11: "ipv4-list",
    28: "ipv4", 32: "ipv4", 41: "ipv4-list", 42: "ipv4-list", 44: "ipv4-list",
    45: "ipv4-list", 48: "ipv4-list", 49: "ipv4-list", 50: "ipv4", 54: "ipv4",
    65: "ipv4-list", 68: "ipv4-list", 69: "ipv4-list", 70: "ipv4-list",
    71: "ipv4-list", 72: "ipv4-list", 73: "ipv4-list", 74: "ipv4-list",
    75: "ipv4-list", 76: "ipv4-list", 118: "ipv4",
    12: "string", 14: "string", 15: "string", 17: "string", 18: "string",
    40: "string", 56: "string", 60: "string", 62: "string", 66: "string",
    67: "string", 81: "string", 100: "string", 101: "string", 114: "string",
    252: "string",
    2: "i32", 51: "u32", 58: "u32", 59: "u32", 91: "u32",
    13: "u16", 22: "u16", 26: "u16", 57: "u16", 80: "u8", 93: "u16-list",
    23: "u8", 24: "u32", 27: "u8", 29: "u8", 30: "u8", 31: "u8", 34: "u8",
    35: "u32", 36: "u8", 37: "u8", 38: "u32", 39: "u8", 46: "u8", 52: "u8",
    53: "message-type", 55: "u8-list", 61: "hex", 82: "hex", 90: "hex",
    94: "hex", 97: "hex", 119: "hex", 121: "hex", 208: "hex", 209: "string",
    210: "string", 249: "hex"
  };

  const OPTION_ALIASES = {
    "subnet-mask": 1, "router": 3, "routers": 3, "dns": 6, "dns-servers": 6,
    "host-name": 12, "hostname": 12, "domain-name": 15,
    "requested-ip": 50, "requested-address": 50, "lease-time": 51,
    "message-type": 53, "server-id": 54, "server-identifier": 54,
    "parameter-request-list": 55, "parameter-request": 55, "message": 56,
    "max-message-size": 57, "renewal-time": 58, "rebinding-time": 59,
    "vendor-class": 60, "client-id": 61, "client-identifier": 61,
    "tftp-server": 66, "bootfile": 67, "relay-agent": 82,
    "domain-search": 119, "classless-route": 121
  };

  function be16(n) { const a = new Uint8Array(2); PH.put16be(a, 0, n); return a; }
  function be32(n) { const a = new Uint8Array(4); PH.put32be(a, 0, n); return a; }
  function asciiBytes(text) {
    if (global.TextEncoder) return new TextEncoder().encode(String(text));
    return Uint8Array.from(Array.from(String(text), (c) => c.charCodeAt(0) & 255));
  }
  function asciiString(bytes) {
    let out = "";
    for (const b of bytes) out += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
    return out;
  }
  function cString(bytes) {
    let end = bytes.indexOf(0);
    if (end < 0) end = bytes.length;
    return asciiString(bytes.subarray(0, end));
  }
  function parseMac(text) {
    const s = String(text == null ? "" : text).trim().replace(/[^0-9a-fA-F]/g, "");
    if (s.length !== 12) throw new Error("MAC address needs 12 hex digits");
    const out = new Uint8Array(6);
    for (let i = 0; i < 6; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  function macString(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(":");
  }
  function ipv4List(bytes, warnings) {
    if (bytes.length % 4) warnings.push("IPv4 option length " + bytes.length + " is not a multiple of 4");
    const out = [];
    for (let i = 0; i + 4 <= bytes.length; i += 4) out.push(PH.ipv4String(bytes, i));
    return out;
  }
  function secondsText(value) {
    if (!Number.isFinite(value)) return "?";
    if (value % 86400 === 0) return value + " s (" + (value / 86400) + " d)";
    if (value % 3600 === 0) return value + " s (" + (value / 3600) + " h)";
    if (value % 60 === 0) return value + " s (" + (value / 60) + " min)";
    return value + " s";
  }
  function splitList(text) {
    return String(text == null ? "" : text).split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);
  }
  function unquote(text) {
    const s = String(text == null ? "" : text).trim();
    return s.length >= 2 && ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) ? s.slice(1, -1) : s;
  }
  function toInt(value, label, min, max) {
    const n = Number(String(value).trim());
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(label + " must be " + min + "–" + max);
    return n;
  }
  function optionCode(value) {
    const text = String(value == null ? "" : value).trim().toLowerCase();
    if (OPTION_ALIASES[text] != null) return OPTION_ALIASES[text];
    if (/^0x[0-9a-f]+$/.test(text)) return parseInt(text.slice(2), 16);
    if (/^\d+$/.test(text)) return Number(text);
    throw new Error("Unknown DHCP option code or name: " + value);
  }
  function messageTypeCode(value) {
    const text = String(value == null ? "" : value).trim().toUpperCase();
    if (MESSAGE_TYPE_VALUES[text] != null) return MESSAGE_TYPE_VALUES[text];
    return toInt(value, "DHCP message type", 1, 255);
  }
  function encodeOptionValue(code, raw) {
    const text = String(raw == null ? "" : raw).trim();
    const kind = OPTION_KINDS[code] || "hex";
    switch (kind) {
      case "ipv4":
        return PH.parseIPv4(text);
      case "ipv4-list":
        return PH.concatBytes(...splitList(text).map((item) => PH.parseIPv4(item)));
      case "string":
        return asciiBytes(unquote(raw));
      case "message-type":
        return Uint8Array.from([messageTypeCode(text)]);
      case "u8":
        return Uint8Array.from([toInt(text, "Option " + code, 0, 255)]);
      case "u16":
        return be16(toInt(text, "Option " + code, 0, 65535));
      case "u32":
        return be32(toInt(text, "Option " + code, 0, 0xffffffff));
      case "i32": {
        const n = Number(text);
        if (!Number.isInteger(n) || n < -0x80000000 || n > 0x7fffffff) throw new Error("Option " + code + " must be a signed 32-bit value");
        return be32(n >>> 0);
      }
      case "u8-list":
        return Uint8Array.from(splitList(text).map((item) => toInt(item, "Option " + code, 0, 255)));
      case "u16-list": {
        const parts = splitList(text).map((item) => be16(toInt(item, "Option " + code, 0, 65535)));
        return PH.concatBytes(...parts);
      }
      default:
        return PH.parseHex(text);
    }
  }
  function optionBytes(code, value) {
    if (!Number.isInteger(code) || code < 1 || code > 254) throw new Error("DHCP option code must be 1–254");
    if (!(value instanceof Uint8Array)) value = Uint8Array.from(value);
    if (value.length > 255) throw new Error("DHCP option " + code + " exceeds 255 bytes");
    return PH.concatBytes(Uint8Array.from([code, value.length]), value);
  }
  function buildOptionLines(text) {
    const options = [];
    String(text || "").split(/\r?\n/).forEach((rawLine, index) => {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) return;
      const eq = line.indexOf("=");
      if (eq < 1) throw new Error("Option line " + (index + 1) + " needs code = value");
      const code = optionCode(line.slice(0, eq));
      if (code === 0 || code === 255) throw new Error("Pad and End options are added automatically");
      const value = encodeOptionValue(code, line.slice(eq + 1));
      options.push({ code, value });
    });
    return options;
  }
  function readOptionList(bytes, start, end, source, warnings) {
    const options = [];
    let pos = start;
    let ended = false;
    while (pos < end) {
      const offset = pos;
      const code = bytes[pos++];
      if (code === 0) {
        options.push({ code, name: "Pad", length: 1, value: new Uint8Array(0), offset, source, control: true });
        continue;
      }
      if (code === 255) {
        options.push({ code, name: "End", length: 1, value: new Uint8Array(0), offset, source, control: true });
        ended = true;
        break;
      }
      if (pos >= end) {
        warnings.push("Option " + code + " at " + source + " offset " + offset + " has no length byte");
        break;
      }
      const length = bytes[pos++];
      if (pos + length > end) {
        warnings.push("Option " + code + " at " + source + " offset " + offset + " claims " + length + " bytes, only " + (end - pos) + " remain");
        break;
      }
      options.push({ code, name: OPTION_NAMES[code] || "Option " + code, length, value: bytes.slice(pos, pos + length), offset, source });
      pos += length;
    }
    if (!ended) warnings.push(source + " option list has no End option");
    return { options, end: pos, ended };
  }
  function decodeOption(option, warnings) {
    const code = option.code;
    const value = option.value;
    const name = option.name;
    if (option.control) return Object.assign(option, { valueText: code === 0 ? "pad" : "end" });
    let valueText = PH.bytesToHex(value);
    let fields = [];
    switch (code) {
      case 1: case 28: case 32: case 50: case 54: case 118:
        if (value.length !== 4) warnings.push(name + " should be 4 bytes, found " + value.length);
        valueText = value.length >= 4 ? PH.ipv4String(value, 0) : valueText;
        break;
      case 3: case 4: case 5: case 6: case 7: case 8: case 9: case 10: case 11:
      case 41: case 42: case 44: case 45: case 48: case 49: case 65: case 68:
      case 69: case 70: case 71: case 72: case 73: case 74: case 75: case 76: {
        const addresses = ipv4List(value, warnings);
        valueText = addresses.join(", ") || "empty";
        fields = addresses.map((address, i) => ({ name: "Address " + (i + 1), value: address }));
        break;
      }
      case 12: case 14: case 15: case 17: case 18: case 40: case 56: case 60:
      case 62: case 66: case 67: case 81: case 100: case 101: case 114: case 252:
        valueText = cString(value);
        break;
      case 51: case 58: case 59:
        if (value.length !== 4) warnings.push(name + " should be 4 bytes, found " + value.length);
        if (value.length >= 4) valueText = secondsText(PH.u32be(value, 0));
        break;
      case 53:
        if (value.length !== 1) warnings.push("DHCP Message Type should be 1 byte, found " + value.length);
        if (value.length >= 1) valueText = MESSAGE_TYPES[value[0]] || ("type " + value[0]);
        break;
      case 55:
        valueText = Array.from(value, (codeValue) => OPTION_NAMES[codeValue] || String(codeValue)).join(", ");
        break;
      case 52:
        valueText = value.length >= 1 ? ({ 1: "file", 2: "sname", 3: "file + sname" }[value[0]] || "value " + value[0]) : "empty";
        break;
      case 57:
        if (value.length !== 2) warnings.push("Maximum DHCP Message Size should be 2 bytes, found " + value.length);
        if (value.length >= 2) valueText = PH.u16be(value, 0) + " B";
        break;
      case 61:
        valueText = value.length ? "type " + value[0] + " · " + PH.bytesToHex(value.subarray(1)) : "empty";
        break;
      case 82:
        valueText = decodeRelayAgent(value, warnings);
        break;
      case 121: case 249:
        valueText = decodeClasslessRoutes(value, warnings);
        break;
      case 0: valueText = "pad"; break;
      case 255: valueText = "end"; break;
      default:
        valueText = PH.bytesToHex(value) || "empty";
        break;
    }
    return Object.assign(option, { valueText, fields });
  }
  function decodeRelayAgent(bytes, warnings) {
    const parts = [];
    let pos = 0;
    while (pos + 2 <= bytes.length) {
      const code = bytes[pos++];
      const length = bytes[pos++];
      if (pos + length > bytes.length) { warnings.push("Relay Agent sub-option " + code + " overruns the option"); break; }
      const data = bytes.subarray(pos, pos + length);
      let text = PH.bytesToHex(data);
      if (code === 1) text = "circuit-id " + text;
      else if (code === 2) text = "remote-id " + text;
      else if (code === 5) text = "link-selection " + (data.length >= 4 ? PH.ipv4String(data, 0) : text);
      else if (code === 6) text = "subscriber-id " + text;
      parts.push(code + ": " + text);
      pos += length;
    }
    if (pos < bytes.length) warnings.push("Relay Agent Information has " + (bytes.length - pos) + " trailing byte(s)");
    return parts.join(" · ") || "empty";
  }
  function decodeClasslessRoutes(bytes, warnings) {
    const parts = [];
    let pos = 0;
    while (pos < bytes.length) {
      const width = bytes[pos++];
      if (width > 32) { warnings.push("Classless route prefix " + width + " exceeds 32 bits"); break; }
      const octets = Math.ceil(width / 8);
      if (pos + octets + 4 > bytes.length) { warnings.push("Classless route is truncated"); break; }
      const prefix = new Uint8Array(4);
      prefix.set(bytes.subarray(pos, pos + octets));
      pos += octets;
      const gateway = PH.ipv4String(bytes, pos);
      pos += 4;
      parts.push(PH.ipv4String(prefix, 0) + "/" + width + " via " + gateway);
    }
    return parts.join(" · ") || "empty";
  }

  function buildDhcp(input) {
    const spec = input || {};
    const op = toInt(spec.op == null ? 1 : spec.op, "Op", 1, 2);
    const htype = toInt(spec.htype == null ? 1 : spec.htype, "Hardware type", 0, 255);
    const hlen = toInt(spec.hlen == null ? 6 : spec.hlen, "Hardware length", 0, 16);
    const hops = toInt(spec.hops == null ? 0 : spec.hops, "Hops", 0, 255);
    const xid = toInt(spec.xid == null ? 0 : spec.xid, "Transaction ID", 0, 0xffffffff);
    const secs = toInt(spec.secs == null ? 0 : spec.secs, "Seconds", 0, 65535);
    const broadcast = !!spec.broadcast;
    const ciaddr = parseAddress(spec.ciaddr, "Client address");
    const yiaddr = parseAddress(spec.yiaddr, "Your address");
    const siaddr = parseAddress(spec.siaddr, "Server address");
    const giaddr = parseAddress(spec.giaddr, "Relay address");
    const chaddrText = String(spec.chaddr == null ? "" : spec.chaddr).trim();
    let chaddr;
    if (hlen === 6 && chaddrText && chaddrText.includes(":")) chaddr = parseMac(chaddrText);
    else if (chaddrText) chaddr = PH.parseHex(chaddrText);
    else chaddr = new Uint8Array(0);
    if (chaddr.length !== hlen) throw new Error("Client hardware address is " + chaddr.length + " bytes but HLEN is " + hlen);
    if (chaddr.length > 16) throw new Error("Client hardware address exceeds the 16-byte chaddr field");
    const sname = asciiBytes(spec.sname == null ? "" : spec.sname);
    const file = asciiBytes(spec.file == null ? "" : spec.file);
    if (sname.length > 64) throw new Error("sname exceeds 64 bytes");
    if (file.length > 128) throw new Error("file exceeds 128 bytes");
    const messageType = messageTypeCode(spec.messageType == null ? 1 : spec.messageType);
    const optionList = [{ code: 53, value: Uint8Array.from([messageType]) }];
    if (spec.serverIdentifier) optionList.push({ code: 54, value: PH.parseIPv4(spec.serverIdentifier) });
    if (spec.subnetMask) optionList.push({ code: 1, value: PH.parseIPv4(spec.subnetMask) });
    if (spec.routers) optionList.push({ code: 3, value: encodeOptionValue(3, spec.routers) });
    if (spec.dnsServers) optionList.push({ code: 6, value: encodeOptionValue(6, spec.dnsServers) });
    if (spec.leaseTime != null && spec.leaseTime !== "") optionList.push({ code: 51, value: encodeOptionValue(51, spec.leaseTime) });
    if (spec.renewalTime != null && spec.renewalTime !== "") optionList.push({ code: 58, value: encodeOptionValue(58, spec.renewalTime) });
    if (spec.rebindingTime != null && spec.rebindingTime !== "") optionList.push({ code: 59, value: encodeOptionValue(59, spec.rebindingTime) });
    if (spec.domainName) optionList.push({ code: 15, value: asciiBytes(spec.domainName) });
    buildOptionLines(spec.extraOptions).forEach((option) => optionList.push(option));
    const seen = new Set();
    optionList.forEach((option) => {
      if (seen.has(option.code)) throw new Error("Duplicate DHCP option " + option.code + " (" + (OPTION_NAMES[option.code] || "option") + ")");
      seen.add(option.code);
    });
    const options = PH.concatBytes(...optionList.map((option) => optionBytes(option.code, option.value)), Uint8Array.from([255]));
    const bytes = new Uint8Array(240 + options.length);
    bytes[0] = op;
    bytes[1] = htype;
    bytes[2] = hlen;
    bytes[3] = hops;
    PH.put32be(bytes, 4, xid);
    PH.put16be(bytes, 8, secs);
    PH.put16be(bytes, 10, broadcast ? 0x8000 : 0);
    bytes.set(ciaddr, 12); bytes.set(yiaddr, 16); bytes.set(siaddr, 20); bytes.set(giaddr, 24);
    bytes.set(chaddr, 28);
    bytes.set(sname, 44);
    bytes.set(file, 108);
    bytes.set(MAGIC_COOKIE, 236);
    bytes.set(options, 240);
    if (bytes.length > 65507) throw new Error("DHCP message exceeds the UDP payload limit of 65507 bytes");
    return { bytes, op, htype, hlen, hops, xid, secs, flags: broadcast ? 0x8000 : 0, broadcast,
      ciaddr: PH.ipv4String(ciaddr), yiaddr: PH.ipv4String(yiaddr), siaddr: PH.ipv4String(siaddr),
      giaddr: PH.ipv4String(giaddr), chaddr: chaddr.length === 6 ? macString(chaddr) : PH.bytesToHex(chaddr),
      sname: spec.sname || "", file: spec.file || "", messageType,
      messageTypeName: MESSAGE_TYPES[messageType] || "type " + messageType, options: options.length,
      optionCount: optionList.length };
  }
  function parseAddress(value, label) {
    if (value == null || String(value).trim() === "") return new Uint8Array(4);
    const text = String(value).trim();
    if (text === "0" || text === "0.0.0.0") return new Uint8Array(4);
    return PH.parseIPv4(text);
  }
  function looksLikeDhcp(bytes) {
    if (!bytes || bytes.length < 240) return false;
    if (bytes[0] !== 1 && bytes[0] !== 2) return false;
    return bytes[236] === 0x63 && bytes[237] === 0x82 && bytes[238] === 0x53 && bytes[239] === 0x63;
  }

  function decodeDhcp(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 236) throw new Error("DHCP needs at least 236 bytes for the BOOTP fixed header");
    const warnings = [];
    const op = bytes[0], htype = bytes[1], hlen = bytes[2], hops = bytes[3];
    const xid = PH.u32be(bytes, 4);
    const secs = PH.u16be(bytes, 8);
    const flags = PH.u16be(bytes, 10);
    const ciaddr = PH.ipv4String(bytes, 12);
    const yiaddr = PH.ipv4String(bytes, 16);
    const siaddr = PH.ipv4String(bytes, 20);
    const giaddr = PH.ipv4String(bytes, 24);
    const chaddrField = bytes.subarray(28, 44);
    const snameBytes = bytes.subarray(44, 108);
    const fileBytes = bytes.subarray(108, 236);
    const chaddr = hlen <= 16 ? chaddrField.subarray(0, hlen) : chaddrField;
    if (op !== 1 && op !== 2) warnings.push("Op is " + op + "; expected 1 (BOOTREQUEST) or 2 (BOOTREPLY)");
    if (htype !== 1) warnings.push("Hardware type is " + htype + "; Ethernet is 1");
    if (hlen > 16) warnings.push("HLEN is " + hlen + "; chaddr is only 16 bytes");
    if (hlen !== 6) warnings.push("HLEN is " + hlen + "; Ethernet DHCP normally uses 6");
    if (flags & 0x7fff) warnings.push("Reserved DHCP flag bits are set: 0x" + PH.hex(flags & 0x7fff, 4));
    const cookieOk = bytes.length >= 240 && PH.u32be(bytes, 236) === 0x63825363;
    let options = [];
    let vendorBytes = new Uint8Array(0);
    let optionsStart = null;
    if (cookieOk) {
      optionsStart = 240;
      const parsed = readOptionList(bytes, 240, bytes.length, "main", warnings);
      options = parsed.options;
      const overload = options.find((option) => option.code === 52 && option.value.length >= 1);
      if (overload) {
        const value = overload.value[0];
        if (value & 1) options = options.concat(readOptionList(fileBytes, 0, fileBytes.length, "file", warnings).options);
        if (value & 2) options = options.concat(readOptionList(snameBytes, 0, snameBytes.length, "sname", warnings).options);
        if (value & ~3) warnings.push("Option Overload has reserved bits set: 0x" + PH.hex(value, 2));
      }
    } else {
      vendorBytes = bytes.length > 236 ? bytes.subarray(236) : new Uint8Array(0);
      warnings.push("DHCP magic cookie 63 82 53 63 is missing; this is BOOTP or a malformed DHCP message");
    }
    const decodedOptions = options.map((option) => decodeOption(option, warnings));
    const messageTypeOption = decodedOptions.find((option) => option.code === 53);
    let messageType = null;
    if (messageTypeOption && messageTypeOption.value.length >= 1) messageType = messageTypeOption.value[0];
    else if (cookieOk) warnings.push("DHCP Message Type option (53) is missing");
    const messageTypeName = messageType != null ? (MESSAGE_TYPES[messageType] || "type " + messageType) : "unknown";
    if (messageType == null && cookieOk) warnings.push("Cannot identify the DHCP message without option 53");
    const messageAddresses = decodedOptions.filter((option) => !option.control);
    return {
      bytes, op, opName: OP_NAMES[op] || "op " + op, htype, hlen, hops, xid, secs, flags,
      broadcast: (flags & 0x8000) !== 0, reservedFlags: flags & 0x7fff,
      ciaddr, yiaddr, siaddr, giaddr, chaddr, chaddr16: chaddrField,
      chaddrText: hlen === 6 ? macString(chaddr) : PH.bytesToHex(chaddr),
      sname: cString(snameBytes), file: cString(fileBytes), snameBytes, fileBytes,
      magicCookie: cookieOk ? "0x63825363" : PH.bytesToHex(bytes.subarray(236, Math.min(240, bytes.length))),
      cookieOk, optionsStart, options: decodedOptions, optionCount: messageAddresses.length,
      messageType, messageTypeName, warnings, vendorBytes,
      messageLength: bytes.length
    };
  }

  function optionSummary(options) {
    return (options || []).filter((option) => !option.control).map((option) => option.name).join(", ") || "none";
  }

  global.DHCPCodec = {
    MAGIC_COOKIE, OP_NAMES, MESSAGE_TYPES, MESSAGE_TYPE_VALUES, OPTION_NAMES, OPTION_KINDS, OPTION_ALIASES,
    buildDhcp, decodeDhcp, looksLikeDhcp, buildOptionLines, optionBytes, encodeOptionValue,
    optionCode, messageTypeCode, decodeRelayAgent, decodeClasslessRoutes, optionSummary
  };
})(window);
