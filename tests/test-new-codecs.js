"use strict";

/* Round-trip and malformed-input tests for the extended protocol codecs. */

const { createRuntime, loadCodecs, run } = require("./harness");

function runtimeWith(names) {
  const runtime = createRuntime();
  loadCodecs(runtime, ["core.js", "ipv6-codec.js"].concat(names));
  return runtime;
}

run("extended codecs", (test, assert) => {
  /* ---------------- ICMPv6 ---------------- */
  const icmp6 = runtimeWith(["icmpv6-codec.js"]).sandbox.ICMPv6Codec;
  const src = "2001:db8::1";
  const dst = "2001:db8::2";

  test("ICMPv6 echo round-trip with checksum", () => {
    const built = icmp6.buildIcmpv6({ type: 128, code: 0, identifier: 0x1234, sequence: 1, data: "de ad be ef", src, dst });
    const decoded = icmp6.decodeIcmpv6(built.bytes, { src, dst });
    assert.strictEqual(decoded.typeName, "Echo Request");
    assert.strictEqual(decoded.details.identifier, 0x1234);
    assert.strictEqual(decoded.details.sequence, 1);
    assert.strictEqual(decoded.checksumState, "valid");
  });

  test("ICMPv6 Neighbor Solicitation carries a target and SLLA option", () => {
    const built = icmp6.buildIcmpv6({
      type: 135, target: dst, options: [{ kind: "slla", mac: "02:00:00:00:00:01" }], src, dst
    });
    const decoded = icmp6.decodeIcmpv6(built.bytes, { src, dst });
    assert.strictEqual(decoded.details.target, "2001:db8::2");
    assert.strictEqual(decoded.details.options.length, 1);
    assert.strictEqual(decoded.details.options[0].address, "02:00:00:00:00:01");
  });

  test("ICMPv6 RA parses Prefix Information", () => {
    const built = icmp6.buildIcmpv6({
      type: 134, curHopLimit: 64, managed: true, routerLifetime: 1800,
      options: [{ kind: "prefix", prefix: "2001:db8::", prefixLength: 64 }], src, dst
    });
    const decoded = icmp6.decodeIcmpv6(built.bytes, { src, dst });
    assert.strictEqual(decoded.details.curHopLimit, 64);
    assert.strictEqual(decoded.details.managed, true);
    assert.strictEqual(decoded.details.options[0].prefix, "2001:db8::");
    assert.strictEqual(decoded.details.options[0].prefixLength, 64);
  });

  test("ICMPv6 Router Solicitation keeps the reserved word before options", () => {
    const built = icmp6.buildIcmpv6({ type: 133, options: [{ kind: "slla", mac: "02:00:00:00:00:01" }], src, dst });
    const decoded = icmp6.decodeIcmpv6(built.bytes, { src, dst });
    assert.strictEqual(decoded.typeName, "Router Solicitation");
    assert.strictEqual(decoded.details.options.length, 1);
    assert.strictEqual(decoded.details.options[0].type, 1);
  });

  test("ICMPv6 rejects a short header", () => {
    assert.throws(() => icmp6.decodeIcmpv6(Uint8Array.from([128, 0, 0])), /at least 4/);
  });

  /* ---------------- OSPF ---------------- */
  const ospf = runtimeWith(["ospf-codec.js"]).sandbox.OSPFCodec;

  test("OSPF Hello round-trip and checksum", () => {
    const built = ospf.buildOspf({
      type: 1, routerId: "192.0.2.1", areaId: "0", networkMask: "255.255.255.0",
      helloInterval: 10, deadInterval: 40, priority: 1,
      designatedRouter: "192.0.2.1", backupRouter: "0.0.0.0",
      neighbors: ["192.0.2.2"], options: 2
    });
    const decoded = ospf.decodeOspf(built.bytes);
    assert.strictEqual(decoded.typeName, "Hello");
    assert.strictEqual(decoded.hello.helloInterval, 10);
    assert.strictEqual(decoded.hello.neighbors.join(","), "192.0.2.2");
    assert.strictEqual(decoded.checksumState, "valid");
  });

  test("OSPF Link State Update decodes one Router LSA", () => {
    const built = ospf.buildOspf({
      type: 4, routerId: "192.0.2.1", areaId: "0",
      lsas: [{ type: 1, linkStateId: "192.0.2.1", advertisingRouter: "192.0.2.1", sequence: 0x80000001, options: 2, body: "00 01 00 00" }]
    });
    const decoded = ospf.decodeOspf(built.bytes);
    assert.strictEqual(decoded.update.count, 1);
    assert.strictEqual(decoded.update.lsas[0].typeName, "Router");
    assert.strictEqual(decoded.checksumState, "valid");
  });

  test("OSPF rejects a short header", () => {
    assert.throws(() => ospf.decodeOspf(Uint8Array.from([2, 1, 0])), /24-byte/);
  });

  /* ---------------- GRE ---------------- */
  const gre = runtimeWith(["gre-codec.js"]).sandbox.GRECodec;

  test("GRE round-trip with checksum, key and sequence", () => {
    const built = gre.buildGre({ protocol: 0x0800, key: 42, sequence: 7, checksum: true, payload: "45 00 00 14 00 01 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02" });
    const decoded = gre.decodeGre(built.bytes);
    assert.strictEqual(decoded.headerLength, 16);
    assert.strictEqual(decoded.key, 42);
    assert.strictEqual(decoded.sequence, 7);
    assert.strictEqual(decoded.checksumState, "valid");
  });

  test("GRE version 1 uses the PPTP layout", () => {
    const built = gre.buildGre({ version: 1, protocol: 0x880b, callId: 5, sequence: 2, payload: "ff 03" });
    const decoded = gre.decodeGre(built.bytes);
    assert.strictEqual(decoded.version, 1);
    assert.strictEqual(decoded.pptp.callId, 5);
    assert.strictEqual(decoded.payload.length, 2);
  });

  /* ---------------- VXLAN / Geneve ---------------- */
  const vx = runtimeWith(["vxlan-codec.js"]).sandbox.VXLANCodec;
  const inner = "ff ff ff ff ff ff 02 00 00 00 00 01 08 00 45 00 00 14 00 00 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02";

  test("VXLAN round-trip and inner Ethernet", () => {
    const built = vx.buildVxlan({ vni: 100, inner });
    const decoded = vx.decodeVxlan(built.bytes);
    assert.strictEqual(decoded.vni, 100);
    assert.strictEqual(decoded.headerLength, 8);
    assert.strictEqual(vx.peer(decoded.inner).type, "IPv4");
  });

  test("Geneve round-trip with an option", () => {
    const built = vx.buildGeneve({ vni: 7, protocol: 0x6558, options: [{ class: 0x0108, type: 0x80, critical: true, value: "00 01 02 03" }], inner });
    const decoded = vx.decodeGeneve(built.bytes);
    assert.strictEqual(decoded.vni, 7);
    assert.strictEqual(decoded.options.length, 1);
    assert.strictEqual(decoded.options[0].length, 4);
    assert.strictEqual(decoded.warnings.length, 0);
  });

  /* ---------------- WireGuard ---------------- */
  const wg = runtimeWith(["wireguard-codec.js"]).sandbox.WireGuardCodec;

  test("WireGuard transport data round-trip", () => {
    const built = wg.buildWireguard({ type: 4, receiverIndex: 9, counter: "0x0102030405060708", payload: "00".repeat(20) });
    const decoded = wg.decodeWireguard(built.bytes);
    assert.strictEqual(decoded.typeName, "Transport Data");
    assert.strictEqual(decoded.receiverIndex, 9);
    assert.strictEqual(decoded.counter.toString(), "72623859790382856");
  });

  test("WireGuard handshake initiation has the fixed 148-byte shape", () => {
    const built = wg.buildWireguard({ type: 1, senderIndex: 3 });
    assert.strictEqual(built.bytes.length, 148);
    assert.strictEqual(wg.decodeWireguard(built.bytes).typeName, "Handshake Initiation");
  });

  /* ---------------- SCTP ---------------- */
  const sctp = runtimeWith(["sctp-codec.js"]).sandbox.SCTPCodec;

  test("SCTP CRC32c matches the published check value", () => {
    assert.strictEqual(sctp.crc32c(new TextEncoder().encode("123456789")), 0xe3069283);
  });

  test("SCTP DATA and INIT round-trip", () => {
    const built = sctp.buildSctp({
      srcPort: 5000, dstPort: 5001, verificationTag: 0x11223344,
      chunks: [
        { type: 1, initiateTag: 0x55667788, aRwnd: 65535, outboundStreams: 10, inboundStreams: 10, initialTsn: 100, params: [{ type: 5, value: "c0 00 02 01" }] },
        { type: 0, flags: 0x03, tsn: 101, streamId: 0, streamSequence: 0, ppid: 0, payload: "de ad be ef" }
      ]
    });
    const decoded = sctp.decodeSctp(built.bytes);
    assert.strictEqual(decoded.checksumState, "valid");
    assert.strictEqual(decoded.chunks.length, 2);
    assert.strictEqual(decoded.chunks[1].payload.length, 4);
  });

  /* ---------------- NTP ---------------- */
  const ntp = runtimeWith(["ntp-codec.js"]).sandbox.NTPCodec;

  test("NTP timestamp epoch and round-trip", () => {
    const stamp = ntp.toNtpTimestamp(new Date("1970-01-01T00:00:00Z"));
    assert.strictEqual(stamp.hi, 2208988800);
    const built = ntp.buildNtp({ mode: 4, stratum: 1, referenceIdText: "GPS", transmit: new Date("2026-01-01T00:00:00Z") });
    const decoded = ntp.decodeNtp(built.bytes);
    assert.strictEqual(decoded.stratum, 1);
    assert.strictEqual(decoded.transmit.date.toISOString(), "2026-01-01T00:00:00.000Z");
  });

  test("NTP extension field is parsed", () => {
    const built = ntp.buildNtp({ mode: 4, stratum: 1, referenceIdText: "GPS", extensions: [{ type: 0x0104, value: "41 42 43 44" }] });
    const decoded = ntp.decodeNtp(built.bytes);
    assert.strictEqual(decoded.extensions.length, 1);
    assert.strictEqual(decoded.extensions[0].length, 16);
  });

  /* ---------------- WebSocket ---------------- */
  const ws = runtimeWith(["websocket-codec.js"]).sandbox.WebSocketCodec;

  test("WebSocket accept matches RFC 6455", () => {
    assert.strictEqual(ws.secWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  });

  test("WebSocket masked text frame round-trip", () => {
    const built = ws.buildFrame({ opcode: 1, text: "Hello", mask: true, maskKey: "37 fa 21 3d" });
    const decoded = ws.decodeFrames(built.bytes);
    assert.strictEqual(decoded.frames[0].text, "Hello");
    assert.strictEqual(decoded.frames[0].mask, true);
    assert.strictEqual(decoded.warnings.length, 0);
  });

  test("WebSocket close code is decoded", () => {
    const built = ws.buildFrame({ opcode: 8, payload: "03 e8", mask: false });
    const decoded = ws.decodeFrames(built.bytes);
    assert.strictEqual(decoded.frames[0].close.code, 1000);
    assert.strictEqual(decoded.frames[0].close.name, "normal closure");
  });

  /* ---------------- DHCPv6 ---------------- */
  const dhcp6 = runtimeWith(["dhcpv6-codec.js"]).sandbox.DHCPv6Codec;

  test("DHCPv6 SOLICIT with IA_NA round-trip", () => {
    const built = dhcp6.buildDhcpv6({
      type: 1, transactionId: 0xabcdef,
      options: [
        { code: 1, duid: { type: 3, hardwareType: 1, linkLayerAddress: "02:00:00:00:00:01" } },
        { code: 6, codes: [23, 24] },
        { code: 3, iaid: 1, t1: 0, t2: 0, options: [{ code: 5, address: "2001:db8::100", preferred: 3600, valid: 7200 }] }
      ]
    });
    const decoded = dhcp6.decodeDhcpv6(built.bytes);
    assert.strictEqual(decoded.typeName, "SOLICIT");
    assert.strictEqual(decoded.transactionId, 0xabcdef);
    assert.strictEqual(decoded.clientId.name, "DUID-LL");
    assert.strictEqual(decoded.options[2].iaType, "IA_NA");
    assert.strictEqual(decoded.options[2].options[0].address, "2001:db8::100");
  });

  /* ---------------- HTTP/3 ---------------- */
  const h3 = runtimeWith(["http3-codec.js"]).sandbox.HTTP3Codec;

  test("HTTP/3 SETTINGS and DATA frames round-trip", () => {
    const settings = h3.buildSettings([{ id: 1, value: 4096 }, { id: 3, value: 16 }]);
    const data = h3.buildFrame({ type: 0, payload: "68 65 6c 6c 6f" });
    const combined = new Uint8Array(settings.length + data.length);
    combined.set(settings, 0); combined.set(data, settings.length);
    const frames = h3.decodeFrames(combined);
    assert.strictEqual(frames.frames[0].typeName, "SETTINGS");
    assert.strictEqual(frames.frames[0].settings.length, 2);
    assert.strictEqual(frames.frames[1].typeName, "DATA");
    assert.strictEqual(frames.frames[1].data.length, 5);
  });

  test("HTTP/3 QPACK static table resolves :method GET", () => {
    const fields = h3.decodeQpackFieldSection(Uint8Array.from([0x91, 0x51, 0x04, 0x50, 0x4f, 0x53, 0x54]));
    assert.strictEqual(fields.fields[0].name, ":method");
    assert.strictEqual(fields.fields[0].value, "GET");
  });

  /* ---------------- IPsec ---------------- */
  const ipsec = runtimeWith(["ipsec-codec.js"]).sandbox.IPsecCodec;

  test("AH round-trip and length", () => {
    const built = ipsec.buildAh({ nextHeader: 6, spi: 0x1000, sequence: 1, icv: "00".repeat(12) });
    const decoded = ipsec.decodeAh(built.bytes);
    assert.strictEqual(decoded.totalLength, 24);
    assert.strictEqual(decoded.icvLength, 12);
    assert.strictEqual(decoded.spi, 0x1000);
  });

  test("ESP keeps the payload opaque", () => {
    const built = ipsec.buildEsp({ spi: 0x2000, sequence: 5, payload: "de ad be ef", nextHeader: 6, icv: "00".repeat(16), ciphertext: "11".repeat(20) });
    const decoded = ipsec.decodeEsp(built.bytes);
    assert.strictEqual(decoded.spi, 0x2000);
    assert.strictEqual(decoded.ciphertextLength, 36); /* ciphertext + trailer + ICV; ESP cannot split them without keys */
    assert.ok(decoded.warnings.length > 0);
  });

  test("IKEv2 payload chain round-trip", () => {
    const built = ipsec.buildIkev2({ initiatorSpi: "01".repeat(8), responderSpi: "02".repeat(8), exchangeType: 34, initiator: true, payloads: [{ type: 33, value: "00 00 00 04" }, { type: 34, value: "00".repeat(8) }] });
    const decoded = ipsec.decodeIkev2(built.bytes);
    assert.strictEqual(decoded.exchangeName, "IKE_SA_INIT");
    assert.strictEqual(decoded.payloads.length, 2);
    assert.strictEqual(decoded.payloads[0].name, "SA");
  });

  /* ---------------- LLDP ---------------- */
  const lldp = runtimeWith(["lldp-codec.js"]).sandbox.LLDPCodec;

  test("LLDP mandatory TLVs and capabilities round-trip", () => {
    const built = lldp.buildLldp({
      chassis: { subtype: 4, address: "02:00:00:00:00:01" },
      port: { subtype: 5, address: "eth0" }, ttl: 120,
      systemName: "sw1", capabilities: 0x0014,
      managementAddress: "192.0.2.1",
      orgSpecific: [{ oui: "00 80 c2", subtype: 1, value: "00 0a" }]
    });
    const decoded = lldp.decodeLldp(built.bytes);
    assert.strictEqual(decoded.ttl, 120);
    assert.strictEqual(decoded.systemName, "sw1");
    assert.strictEqual(decoded.chassis.address, "02:00:00:00:00:01");
    assert.strictEqual(decoded.port.address, "eth0");
    assert.strictEqual(decoded.warnings.length, 0);
  });

  test("LLDP reports missing mandatory TLVs", () => {
    const decoded = lldp.decodeLldp(Uint8Array.from([0x02, 0x07, 0x04, 0x02, 0, 0, 0, 0, 1]));
    assert.ok(decoded.warnings.some((w) => /Port ID/.test(w)));
  });
});

run("subnet and checksum tools", (test, assert) => {
  const runtime = runtimeWith(["subnet-codec.js", "checksum-codec.js"]);
  const subnet = runtime.sandbox.SubnetCodec;
  const checksum = runtime.sandbox.ChecksumCodec;

  test("IPv4 /25 network, range and usable hosts", () => {
    const info = subnet.parseIpv4Cidr("192.168.1.130/25");
    assert.strictEqual(info.networkText, "192.168.1.128");
    assert.strictEqual(info.broadcastText, "192.168.1.255");
    assert.strictEqual(info.firstText, "192.168.1.129");
    assert.strictEqual(info.lastText, "192.168.1.254");
    assert.strictEqual(info.usableHosts, 126);
  });

  test("IPv4 /31 follows RFC 3021", () => {
    const info = subnet.parseIpv4Cidr("10.0.0.0/31");
    assert.strictEqual(info.usableHosts, 2);
    assert.strictEqual(info.firstText, "10.0.0.0");
    assert.strictEqual(info.lastText, "10.0.0.1");
  });

  test("IPv6 /64 network and host count", () => {
    const info = subnet.parseIpv6Cidr("2001:db8::1/64");
    assert.strictEqual(info.networkText, "2001:db8::");
    assert.strictEqual(info.lastText, "2001:db8::ffff:ffff:ffff:ffff");
    assert.strictEqual(info.totalHosts.toString(), "18446744073709551616");
  });

  test("split and VLSM produce aligned prefixes", () => {
    const split = subnet.splitCidr("192.168.1.0/24", 26);
    assert.strictEqual(split.length, 4);
    assert.strictEqual(split[3].cidr, "192.168.1.192/26");
    const plan = subnet.vlsmPlan("192.168.0.0/23", [{ name: "a", hosts: 100 }, { name: "b", hosts: 50 }, { name: "c", hosts: 10 }]);
    assert.strictEqual(plan.plan.length, 3);
    assert.strictEqual(plan.plan[0].cidr, "192.168.0.0/25");
    assert.strictEqual(plan.plan[1].cidr, "192.168.0.128/26");
    assert.strictEqual(plan.plan[2].cidr, "192.168.0.192/28");
  });

  test("checksum vectors for 123456789", () => {
    const bytes = new TextEncoder().encode("123456789");
    assert.strictEqual(checksum.crc32(bytes), 0xcbf43926);
    assert.strictEqual(checksum.crc32c(bytes), 0xe3069283);
    assert.strictEqual(checksum.adler32(bytes), 0x091e01de);
    assert.strictEqual(checksum.fnv1a32(bytes), 0xbb86b11c);
  });

  test("Internet checksum validates its own output", () => {
    const payload = Uint8Array.from([0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]);
    const sum = checksum.internetChecksum(payload);
    const full = new Uint8Array(payload.length + 2);
    full.set(payload, 0); full[payload.length] = sum >> 8; full[payload.length + 1] = sum & 255;
    assert.strictEqual(checksum.checksumValid(full), true);
  });
});
