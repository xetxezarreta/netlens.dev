"use strict";

const { createRuntime, loadCodecs, run, DISSECT_SCRIPTS } = require("./harness");

const runtime = createRuntime();
loadCodecs(runtime, DISSECT_SCRIPTS);
const sandbox = runtime.sandbox;
const PH = sandbox.PH;
const Dissector = sandbox.Dissector;

function ipv4TcpFrame() {
  const tcp = sandbox.TCPCodec.buildExamplePacket();
  const ip = sandbox.IPv4Codec.buildHeader({
    version: 4, dscp: 0, ecn: 0, id: 1, ttl: 64, protocol: 6,
    fragmentOffset: 0, payloadLength: tcp.length, reserved: false, df: true, mf: false,
    src: "192.0.2.10", dst: "198.51.100.20", options: ""
  }).bytes;
  const ethernet = sandbox.EthernetCodec.buildFrame({
    dst: "02:00:00:00:00:01", src: "02:00:00:00:00:02",
    etherType: 0x0800, payload: PH.concatBytes(ip, tcp), pad: false, fcs: false
  }).bytes;
  return { ethernet, ip: PH.concatBytes(ip, tcp) };
}

function wifiFrame(ipBytes) {
  const header = new Uint8Array(24);
  header[0] = 0x08; // data frame, subtype 0
  header[4] = 0x02; header[5] = 0x00; header[6] = 0x00;
  header[7] = 0x00; header[8] = 0x00; header[9] = 0x01;
  header[10] = 0x02; header[11] = 0x00; header[12] = 0x00;
  header[13] = 0x00; header[14] = 0x00; header[15] = 0x02;
  header[16] = 0x02; header[17] = 0x00; header[18] = 0x00;
  header[19] = 0x00; header[20] = 0x00; header[21] = 0x03;
  const llc = Uint8Array.from([0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
  return PH.concatBytes(header, llc, ipBytes);
}

function sllFrame(ipBytes, protocol) {
  const bytes = new Uint8Array(16 + ipBytes.length);
  bytes[1] = 0; // packet type 0
  bytes[3] = 1; // ARPHRD Ethernet
  bytes[4] = 0; bytes[5] = 6; // address length
  bytes[6] = 0x02; bytes[7] = 0x00; bytes[8] = 0x00;
  bytes[9] = 0x00; bytes[10] = 0x00; bytes[11] = 0x02;
  bytes[14] = (protocol >> 8) & 255; bytes[15] = protocol & 255;
  bytes.set(ipBytes, 16);
  return bytes;
}

function sll2Frame(ipBytes, protocol) {
  const bytes = new Uint8Array(20 + ipBytes.length);
  bytes[0] = (protocol >> 8) & 255; bytes[1] = protocol & 255;
  bytes[4] = 0; bytes[5] = 0; bytes[6] = 0; bytes[7] = 2;
  bytes[8] = 0; bytes[9] = 1;
  bytes[10] = 0; bytes[11] = 6;
  bytes[12] = 0x02; bytes[13] = 0x00; bytes[14] = 0x00;
  bytes[15] = 0x00; bytes[16] = 0x00; bytes[17] = 0x02;
  bytes.set(ipBytes, 20);
  return bytes;
}

run("dissectLink", (test, assert) => {
  const { ethernet, ip } = ipv4TcpFrame();

  test("Ethernet frames keep absolute offsets", () => {
    const result = Dissector.dissectLink(ethernet, 1);
    assert.strictEqual(result.layers[0].proto, "ethernet");
    assert.strictEqual(result.layers[0].offset, 0);
    const ipv4 = result.layers.find((layer) => layer.proto === "ipv4");
    assert.strictEqual(ipv4.offset, 14);
    const tcp = result.layers.find((layer) => layer.proto === "tcp");
    assert.strictEqual(tcp.offset, 34);
  });

  test("raw IP link types decode directly", () => {
    const result = Dissector.dissectLink(ip, 101);
    assert.strictEqual(result.layers[0].proto, "ipv4");
    assert.strictEqual(result.layers.find((layer) => layer.proto === "tcp").offset, 20);
    assert.strictEqual(Dissector.dissectLink(ip, 228).layers[0].proto, "ipv4");
  });

  test("Linux SLL shifts inner offsets", () => {
    const frame = sllFrame(ip, 0x0800);
    const result = Dissector.dissectLink(frame, 113);
    assert.strictEqual(result.layers[0].name, "Linux SLL");
    assert.strictEqual(result.layers[0].length, 16);
    assert.strictEqual(result.layers.find((layer) => layer.proto === "ipv4").offset, 16);
    assert.strictEqual(result.layers.find((layer) => layer.proto === "tcp").offset, 36);
    assert.strictEqual(result.bytes.length, frame.length);
  });

  test("Linux SLL2 shifts inner offsets", () => {
    const frame = sll2Frame(ip, 0x0800);
    const result = Dissector.dissectLink(frame, 276);
    assert.strictEqual(result.layers[0].name, "Linux SLL2");
    assert.strictEqual(result.layers[0].length, 20);
    assert.strictEqual(result.layers.find((layer) => layer.proto === "ipv4").offset, 20);
    assert.strictEqual(result.layers.find((layer) => layer.proto === "tcp").offset, 40);
  });

  test("null/loopback shifts inner offsets", () => {
    const frame = new Uint8Array(4 + ip.length);
    frame[0] = 2; // AF_INET, little-endian on this test host
    frame.set(ip, 4);
    const result = Dissector.dissectLink(frame, 0);
    assert.strictEqual(result.layers[0].name, "Null / loopback");
    assert.strictEqual(result.layers.find((layer) => layer.proto === "ipv4").offset, 4);
    assert.strictEqual(result.layers.find((layer) => layer.proto === "tcp").offset, 24);
  });

  test("ARP over SLL is decoded", () => {
    const arp = sandbox.ARPCodec.buildArp({
      htype: 1, ptype: 0x0800, opcode: 1,
      senderMac: "02:00:00:00:00:02", senderIp: "192.0.2.10",
      targetMac: "00:00:00:00:00:00", targetIp: "192.0.2.1"
    }).bytes;
    const frame = sllFrame(arp, 0x0806);
    const result = Dissector.dissectLink(frame, 113);
    assert.strictEqual(result.layers[0].name, "Linux SLL");
    const arpLayer = result.layers.find((layer) => layer.proto === "arp");
    assert.strictEqual(arpLayer.offset, 16);
    assert.strictEqual(arpLayer.name, "ARP");
  });

  test("IEEE 802.11 and radiotap data frames reach IPv4", () => {
    const wifi = wifiFrame(ip);
    const direct = Dissector.dissectLink(wifi, 105);
    assert.strictEqual(direct.layers[0].proto, "wifi");
    const directIp = direct.layers.find((layer) => layer.proto === "ipv4");
    assert.strictEqual(directIp.offset, 32);
    const radiotap = PH.concatBytes(Uint8Array.from([0, 0, 8, 0, 0, 0, 0, 0]), wifi);
    const wrapped = Dissector.dissectLink(radiotap, 127);
    assert.strictEqual(wrapped.layers[0].proto, "radiotap");
    const wrappedIp = wrapped.layers.find((layer) => layer.proto === "ipv4");
    assert.strictEqual(wrappedIp.offset, 40);
  });

  test("unknown link types fall back to raw bytes with a warning", () => {
    const result = Dissector.dissectLink(ethernet, 999);
    assert.strictEqual(result.layers[0].proto, "raw");
    assert.ok(result.warnings.some((warning) => /not decoded/.test(warning)));
  });
});
