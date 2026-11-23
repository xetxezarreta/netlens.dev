"use strict";

const { createRuntime, loadCodecs, run, DISSECT_SCRIPTS } = require("./harness");

const runtime = createRuntime();
loadCodecs(runtime, DISSECT_SCRIPTS);
const sandbox = runtime.sandbox;
const PH = sandbox.PH;
const Dissector = sandbox.Dissector;

function ipv4TcpBytes() {
  const tcp = sandbox.TCPCodec.buildExamplePacket();
  const ip = sandbox.IPv4Codec.buildHeader({
    version: 4, dscp: 0, ecn: 0, id: 1, ttl: 64, protocol: 6,
    fragmentOffset: 0, payloadLength: tcp.length, reserved: false, df: true, mf: false,
    src: "192.0.2.10", dst: "198.51.100.20", options: ""
  }).bytes;
  return PH.concatBytes(ip, tcp);
}

function ethernet(payload, etherType) {
  return sandbox.EthernetCodec.buildFrame({
    dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
    etherType, payload, pad: false, fcs: false
  }).bytes;
}

function ipv4(bytes, protocol, id) {
  return sandbox.IPv4Codec.buildHeader({
    version: 4, dscp: 0, ecn: 0, id: id || 9, ttl: 64, protocol,
    fragmentOffset: 0, payloadLength: bytes.length, reserved: false, df: true, mf: false,
    src: "192.0.2.10", dst: "198.51.100.20", options: ""
  }).bytes;
}

function udp(payload, srcPort, dstPort) {
  const bytes = new Uint8Array(8 + payload.length);
  PH.put16be(bytes, 0, srcPort);
  PH.put16be(bytes, 2, dstPort);
  PH.put16be(bytes, 4, bytes.length);
  bytes.set(payload, 8);
  return bytes;
}

function ipv6(payload, nextHeader) {
  return sandbox.IPv6Codec.buildHeader({
    version: 6, dscp: 0, ecn: 0, flowLabel: 0, nextHeader,
    hopLimit: 64, src: "2001:db8::1", dst: "2001:db8::2", payload
  }).bytes;
}

run("tunnels", (test, assert) => {
  const ip = ipv4TcpBytes();

  test("PPPoE session reaches IPv4", () => {
    const pppoe = new Uint8Array(8 + ip.length);
    pppoe[0] = 0x11; pppoe[1] = 0x00;
    PH.put16be(pppoe, 2, 0x1234);
    PH.put16be(pppoe, 4, ip.length);
    PH.put16be(pppoe, 6, 0x0021);
    pppoe.set(ip, 8);
    const result = Dissector.dissectLink(ethernet(pppoe, 0x8864), 1);
    const ppp = result.layers.find((layer) => layer.proto === "pppoe");
    const ipv4 = result.layers.find((layer) => layer.proto === "ipv4");
    assert.ok(ppp);
    assert.strictEqual(ipv4.offset, 22);
  });

  test("MPLS label stack reaches IPv4", () => {
    const mpls = new Uint8Array(4 + ip.length);
    PH.put32be(mpls, 0, (100 << 12) | (1 << 8) | 64);
    mpls.set(ip, 4);
    const result = Dissector.dissectLink(ethernet(mpls, 0x8847), 1);
    assert.ok(result.layers.find((layer) => layer.proto === "mpls"));
    assert.strictEqual(result.layers.find((layer) => layer.proto === "ipv4").offset, 18);
  });

  test("VXLAN reaches the inner Ethernet frame", () => {
    const inner = ethernet(ip, 0x0800);
    const vxlan = new Uint8Array(8 + inner.length);
    vxlan[0] = 0x08;
    vxlan[4] = 0x00; vxlan[5] = 0x00; vxlan[6] = 0x2a;
    vxlan.set(inner, 8);
    const udp = new Uint8Array(8 + vxlan.length);
    PH.put16be(udp, 0, 50000);
    PH.put16be(udp, 2, 4789);
    PH.put16be(udp, 4, udp.length);
    udp.set(vxlan, 8);
    const outer = sandbox.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: 2, ttl: 64, protocol: 17,
      fragmentOffset: 0, payloadLength: udp.length, reserved: false, df: true, mf: false,
      src: "192.0.2.10", dst: "198.51.100.20", options: ""
    }).bytes;
    const result = Dissector.dissectLink(ethernet(PH.concatBytes(outer, udp), 0x0800), 1);
    assert.ok(result.layers.find((layer) => layer.proto === "vxlan"));
    const innerIpv4 = result.layers.find((layer) => layer.proto === "ipv4" && layer.offset > 14);
    assert.ok(innerIpv4);
    assert.strictEqual(innerIpv4.offset, 14 + 20 + 8 + 8 + 14);
  });

  test("OSPF Hello is decoded", () => {
    const hello = sandbox.OSPFCodec.buildOspf({
      type: 1, routerId: "192.0.2.1", areaId: "0", networkMask: "255.255.255.0",
      helloInterval: 10, deadInterval: 40, priority: 1,
      designatedRouter: "192.0.2.1", backupRouter: "0.0.0.0", neighbors: ["192.0.2.2"]
    }).bytes;
    const packet = PH.concatBytes(ipv4(hello, 89, 10), hello);
    const result = Dissector.dissectLink(ethernet(packet, 0x0800), 1);
    const layer = result.layers.find((item) => item.proto === "ospf");
    assert.ok(layer);
    assert.strictEqual(layer.href, "ospf.html");
    assert.ok(/192\.0\.2\.1/.test(layer.summary));
  });

  test("GRE reaches the inner IPv4 packet", () => {
    const inner = ipv4TcpBytes();
    const gre = sandbox.GRECodec.buildGre({ protocol: 0x0800, key: 1, payload: inner }).bytes;
    const packet = PH.concatBytes(ipv4(gre, 47, 11), gre);
    const result = Dissector.dissectLink(ethernet(packet, 0x0800), 1);
    const greLayer = result.layers.find((item) => item.proto === "gre");
    assert.ok(greLayer);
    assert.strictEqual(greLayer.href, "gre.html");
    const innerIp = result.layers.find((item) => item.proto === "ipv4" && item.offset > 14);
    assert.ok(innerIp);
  });

  test("LLDP EtherType reaches the LLDP layer", () => {
    const lldp = sandbox.LLDPCodec.buildLldp({
      chassis: { subtype: 4, address: "02:00:00:00:00:01" },
      port: { subtype: 5, address: "eth0" }, ttl: 120,
      systemName: "sw1", capabilities: 0x14
    }).bytes;
    const result = Dissector.dissectLink(ethernet(lldp, 0x88cc), 1);
    const layer = result.layers.find((item) => item.proto === "lldp");
    assert.ok(layer);
    assert.strictEqual(layer.href, "lldp.html");
    assert.strictEqual(layer.fields.find((f) => f.name === "System name").value, "sw1");
  });

  test("NTP over UDP 123 is decoded", () => {
    const ntp = sandbox.NTPCodec.buildNtp({ mode: 4, stratum: 1, referenceIdText: "GPS", transmit: new Date("2026-01-01T00:00:00Z") }).bytes;
    const packet = PH.concatBytes(ipv4(udp(ntp, 123, 123), 17, 12), udp(ntp, 123, 123));
    const result = Dissector.dissectLink(ethernet(packet, 0x0800), 1);
    const layer = result.layers.find((item) => item.proto === "ntp");
    assert.ok(layer);
    assert.strictEqual(layer.href, "ntp.html");
    assert.ok(/NTPv4/.test(layer.summary));
  });

  test("DHCPv6 over UDP 547 is decoded", () => {
    const dhcp6 = sandbox.DHCPv6Codec.buildDhcpv6({
      type: 1, transactionId: 1,
      options: [{ code: 1, duid: { type: 3, hardwareType: 1, linkLayerAddress: "02:00:00:00:00:01" } }]
    }).bytes;
    const packet = PH.concatBytes(ipv4(udp(dhcp6, 546, 547), 17, 13), udp(dhcp6, 546, 547));
    const result = Dissector.dissectLink(ethernet(packet, 0x0800), 1);
    const layer = result.layers.find((item) => item.proto === "dhcpv6");
    assert.ok(layer);
    assert.strictEqual(layer.href, "dhcpv6.html");
    assert.ok(/SOLICIT/.test(layer.summary));
  });

  test("WireGuard transport data over UDP 51820 is decoded", () => {
    const wg = sandbox.WireGuardCodec.buildWireguard({ type: 4, receiverIndex: 7, counter: "1", payload: "00".repeat(20) }).bytes;
    const packet = PH.concatBytes(ipv4(udp(wg, 51820, 51820), 17, 14), udp(wg, 51820, 51820));
    const result = Dissector.dissectLink(ethernet(packet, 0x0800), 1);
    const layer = result.layers.find((item) => item.proto === "wireguard");
    assert.ok(layer);
    assert.strictEqual(layer.href, "wireguard.html");
    assert.ok(/Transport Data/.test(layer.summary));
  });

  test("IPsec ESP is decoded without inventing the inner packet", () => {
    const esp = sandbox.IPsecCodec.buildEsp({ spi: 0x2000, sequence: 1, payload: "de ad be ef", nextHeader: 6, icv: "00".repeat(16), ciphertext: "11".repeat(20) }).bytes;
    const packet = PH.concatBytes(ipv4(esp, 50, 15), esp);
    const result = Dissector.dissectLink(ethernet(packet, 0x0800), 1);
    const layer = result.layers.find((item) => item.proto === "ipsec");
    assert.ok(layer);
    assert.strictEqual(layer.href, "ipsec.html");
    assert.ok(!result.layers.find((item) => item.proto === "tcp"));
  });

  test("ICMPv6 echo is decoded", () => {
    const icmp6 = sandbox.ICMPv6Codec.buildIcmpv6({ type: 128, identifier: 1, sequence: 1, src: "2001:db8::1", dst: "2001:db8::2" }).bytes;
    const packet = ipv6(icmp6, 58);
    const result = Dissector.dissectLink(ethernet(packet, 0x86dd), 1);
    const layer = result.layers.find((item) => item.proto === "icmpv6");
    assert.ok(layer);
    assert.strictEqual(layer.href, "icmpv6.html");
    assert.ok(/Echo Request/.test(layer.summary));
  });

  test("SCTP common header is decoded", () => {
    const sctp = new Uint8Array(16);
    PH.put16be(sctp, 0, 5000);
    PH.put16be(sctp, 2, 5001);
    PH.put32be(sctp, 4, 0x12345678);
    sctp[12] = 0; sctp[13] = 0; PH.put16be(sctp, 14, 4);
    const outer = sandbox.IPv4Codec.buildHeader({
      version: 4, dscp: 0, ecn: 0, id: 3, ttl: 64, protocol: 132,
      fragmentOffset: 0, payloadLength: sctp.length, reserved: false, df: true, mf: false,
      src: "192.0.2.10", dst: "198.51.100.20", options: ""
    }).bytes;
    const result = Dissector.dissectLink(ethernet(PH.concatBytes(outer, sctp), 0x0800), 1);
    const layer = result.layers.find((item) => item.proto === "sctp");
    assert.ok(layer);
    assert.ok(/5000 → 5001/.test(layer.summary));
  });
});
