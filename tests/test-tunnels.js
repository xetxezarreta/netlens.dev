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
