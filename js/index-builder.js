/* Shared per-packet index builder.
 *
 * The workbench uses this on the main thread and the optional parser worker
 * uses the same function. Keep it free of DOM access so the worker can load it
 * with importScripts().
 */
(function (global) {
  "use strict";

  function find(layers, proto) {
    return (layers || []).find((layer) => layer.proto === proto) || null;
  }

  function packetInfo(index) {
    if (index.appSummary) return index.appSummary;
    if (index.http && index.http.summary) return index.http.summary;
    if (index.dns && index.dns.summary) return index.dns.summary;
    if (index.tls && index.tls.summary) return index.tls.summary;
    if (index.dhcp && index.dhcp.summary) return index.dhcp.summary;
    if (index.dhcpv6 && index.dhcpv6.summary) return index.dhcpv6.summary;
    if (index.bgp && index.bgp.summary) return index.bgp.summary;
    if (index.ospf && index.ospf.summary) return index.ospf.summary;
    if (index.ntp && index.ntp.summary) return index.ntp.summary;
    if (index.wireguard && index.wireguard.summary) return index.wireguard.summary;
    if (index.ipsec && index.ipsec.summary) return index.ipsec.summary;
    if (index.lldp && index.lldp.summary) return index.lldp.summary;
    if (index.gre) return "GRE · protocol 0x" + (index.gre.protocol || 0).toString(16).padStart(4, "0") + (index.gre.key != null ? " · key " + index.gre.key : "");
    if (index.vxlan) return "VXLAN · VNI " + (index.vxlan.vni == null ? "—" : index.vxlan.vni);
    if (index.sctp) return index.sctp.sport + " → " + index.sctp.dport + " · SCTP · " + (index.sctp.chunks || 0) + " chunk(s)";
    if (index.tcp) return index.tcp.sport + " → " + index.tcp.dport + " [" + flags(index.tcp.flags) + "] Seq=" + index.tcp.seq + " Len=" + index.tcp.payloadLen;
    if (index.udp) return index.udp.sport + " → " + index.udp.dport + " Len=" + index.udp.len;
    if (index.icmp) return "ICMP type " + index.icmp.type + " code " + index.icmp.code;
    if (index.icmpv6) return "ICMPv6 type " + index.icmpv6.type + " code " + index.icmpv6.code;
    if (index.arp) return (index.arp.opcodeName || ("opcode " + index.arp.opcode)) + " " + index.arp.senderIp + " → " + index.arp.targetIp;
    return index.summary || "";
  }

  function flags(value) {
    const names = [
      ["CWR", 0x80], ["ECE", 0x40], ["URG", 0x20], ["ACK", 0x10],
      ["PSH", 0x08], ["RST", 0x04], ["SYN", 0x02], ["FIN", 0x01]
    ];
    const set = names.filter((pair) => value & pair[1]).map((pair) => pair[0]);
    return set.length ? set.join(",") : "none";
  }

  function makeIndex(record, bytes, result) {
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

    const eth = find(result.layers, "ethernet");
    if (eth && eth.meta && eth.meta.eth) {
      const value = eth.meta.eth;
      index.eth = { src: value.srcMac, dst: value.dstMac, type: value.etherType };
      if (value.vlanTags && value.vlanTags.length) {
        index.vlan = { id: value.vlanTags[0].vid, pcp: value.vlanTags[0].pcp };
      }
    }
    const vlan = find(result.layers, "vlan");
    if (vlan && !index.vlan) {
      const vid = vlan.fields.find((field) => field.name === "VID");
      const pcp = vlan.fields.find((field) => field.name === "PCP");
      if (vid) index.vlan = { id: Number(vid.value), pcp: pcp ? Number(pcp.value) : 0 };
    }
    const ipv4 = find(result.layers, "ipv4");
    if (ipv4 && ipv4.meta && ipv4.meta.ip) {
      const value = ipv4.meta.ip;
      index.ipv4 = {
        src: value.src, dst: value.dst, proto: value.protocol, ttl: value.ttl,
        len: value.totalLength, fragmentOffset: value.fragmentOffset, mf: value.mf,
        checksumStatus: value.checksumOk ? "good" : "bad"
      };
    }
    const ipv6 = find(result.layers, "ipv6");
    if (ipv6 && ipv6.meta && ipv6.meta.ip) {
      const value = ipv6.meta.ip;
      index.ipv6 = { src: value.src, dst: value.dst, next: value.nextHeader, hopLimit: value.hopLimit, len: (value.payloadLength || 0) + 40 };
    }
    const arp = find(result.layers, "arp");
    if (arp && arp.meta && arp.meta.arp) {
      const value = arp.meta.arp;
      index.arp = {
        opcode: value.opcode, opcodeName: value.opcodeName,
        senderIp: value.senderIp, targetIp: value.targetIp,
        senderMac: value.senderMac, targetMac: value.targetMac
      };
    }
    const tcp = find(result.layers, "tcp");
    if (tcp && tcp.meta && tcp.meta.parsed) {
      const value = tcp.meta.parsed;
      index.tcp = {
        sport: value.sport, dport: value.dport, seq: value.seq, ack: value.ack,
        flags: value.flags, syn: Boolean(value.flags & 0x02), ackFlag: Boolean(value.flags & 0x10),
        fin: Boolean(value.flags & 0x01), rst: Boolean(value.flags & 0x04),
        psh: Boolean(value.flags & 0x08), urg: Boolean(value.flags & 0x20),
        ece: Boolean(value.flags & 0x40), cwr: Boolean(value.flags & 0x80),
        headerLen: value.headerLen, payloadLen: value.payload.length,
        payloadOffset: tcp.offset + value.headerLen, window: value.window
      };
    }
    const udp = find(result.layers, "udp");
    if (udp && udp.meta && udp.meta.parsed) {
      const value = udp.meta.parsed;
      index.udp = {
        sport: value.srcPort, dport: value.dstPort, len: value.length,
        payloadLen: value.payloadLength, payloadOffset: udp.offset + 8
      };
    }
    const icmp = find(result.layers, "icmp");
    if (icmp && icmp.meta && icmp.meta.parsed) {
      index.icmp = { type: icmp.meta.parsed.type, code: icmp.meta.parsed.code };
    }
    const icmpv6 = find(result.layers, "icmpv6");
    if (icmpv6) {
      index.icmpv6 = {
        type: bytes[icmpv6.offset] == null ? 0 : bytes[icmpv6.offset],
        code: bytes[icmpv6.offset + 1] == null ? 0 : bytes[icmpv6.offset + 1]
      };
    }
    const ospf = find(result.layers, "ospf");
    if (ospf && ospf.meta && ospf.meta.parsed) {
      const value = ospf.meta.parsed;
      index.ospf = { type: value.type, area: value.areaId, router: value.routerId, summary: ospf.summary };
    }
    const gre = find(result.layers, "gre");
    if (gre && gre.meta && gre.meta.parsed) {
      const value = gre.meta.parsed;
      index.gre = { protocol: value.protocol, key: value.key, sequence: value.sequence, headerLen: value.headerLength };
    }
    const vxlan = find(result.layers, "vxlan") || find(result.layers, "geneve");
    if (vxlan) {
      const vni = vxlan.fields.find((field) => field.name === "VNI");
      index.vxlan = { vni: vni ? Number(vni.value) : null };
    }
    const sctp = find(result.layers, "sctp");
    if (sctp && sctp.meta && sctp.meta.parsed) {
      const value = sctp.meta.parsed;
      index.sctp = { sport: value.srcPort, dport: value.dstPort, tag: value.verificationTag, chunks: value.chunks.length };
    }
    const ntp = find(result.layers, "ntp");
    if (ntp && ntp.meta && ntp.meta.ntp) {
      const value = ntp.meta.ntp;
      index.ntp = { mode: value.mode, stratum: value.stratum, summary: ntp.summary };
    }
    const dhcpv6 = find(result.layers, "dhcpv6");
    if (dhcpv6 && dhcpv6.meta && dhcpv6.meta.dhcp6) {
      const value = dhcpv6.meta.dhcp6;
      index.dhcpv6 = { type: value.type, xid: value.transactionId, summary: dhcpv6.summary };
    }
    const wireguard = find(result.layers, "wireguard");
    if (wireguard && wireguard.meta && wireguard.meta.wg) {
      index.wireguard = { type: wireguard.meta.wg.type, summary: wireguard.summary };
    }
    const ipsec = find(result.layers, "ipsec");
    if (ipsec && ipsec.meta && ipsec.meta.parsed) {
      const value = ipsec.meta.parsed;
      index.ipsec = { spi: value.spi, sequence: value.sequence, summary: ipsec.summary };
    }
    const lldp = find(result.layers, "lldp");
    if (lldp && lldp.meta && lldp.meta.lldp) {
      const value = lldp.meta.lldp;
      index.lldp = {
        ttl: value.ttl, chassis: value.chassis && value.chassis.address,
        port: value.port && value.port.address, summary: lldp.summary
      };
    }
    const dns = find(result.layers, "dns");
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
    const dhcp = find(result.layers, "dhcp");
    if (dhcp && dhcp.meta && dhcp.meta.message) {
      const message = dhcp.meta.message;
      index.dhcp = { type: message.messageTypeName, xid: message.xid, summary: dhcp.summary };
    }
    const http = find(result.layers, "http");
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
    const tls = find(result.layers, "tls");
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
    const bgp = find(result.layers, "bgp");
    if (bgp && bgp.meta && bgp.meta.message) {
      index.bgp = { type: bgp.meta.message.type, summary: bgp.summary };
    }
    index.info = packetInfo(index);
    return index;
  }

  global.PHIndexBuilder = { makeIndex, packetInfo, flags };
})(typeof window !== "undefined" ? window : globalThis);
