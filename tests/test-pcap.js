"use strict";

const { createRuntime, run } = require("./harness");

const runtime = createRuntime();
runtime.load("pcap-codec.js");
const PCap = runtime.sandbox.PCapCodec;

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function bufferOf(bytes) {
  return Buffer.from(bytes);
}

function classicBigEndian(timestampFraction) {
  const parts = [];
  const u32 = (value) => {
    parts.push((value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
  };
  // magic, version 2.4, thiszone, sigfigs, snaplen, link type
  parts.push(0xa1, 0xb2, 0x3c, 0x4d); // nanosecond magic, big-endian file
  parts.push(0x00, 0x02, 0x00, 0x04);
  u32(0); u32(0); u32(65535); u32(1);
  u32(1); u32(timestampFraction); u32(4); u32(4);
  parts.push(0xde, 0xad, 0xbe, 0xef);
  return Uint8Array.from(parts);
}

run("pcap-codec", (test, assert) => {
  test("fromFrames stores offsets and timestamps", () => {
    const capture = PCap.fromFrames([
      { bytes: Uint8Array.from([1, 2, 3]), linkType: 1, ts: 1.5 },
      { bytes: Uint8Array.from([4, 5]), linkType: 1, ts: 2.25 }
    ]);
    assert.strictEqual(capture.records.length, 2);
    assert.strictEqual(capture.records[0].offset, 0);
    assert.strictEqual(capture.records[1].offset, 3);
    assert.strictEqual(capture.records[1].ts, 2.25);
  });

  test("classic pcap round-trips", () => {
    const capture = PCap.fromFrames([
      { bytes: Uint8Array.from([1, 2, 3, 4]), linkType: 1, ts: 1.5 },
      { bytes: Uint8Array.from([9, 8, 7]), linkType: 1, ts: 2.25 }
    ]);
    const encoded = PCap.encodeClassic(capture, capture.records);
    const parsed = PCap.parse(encoded);
    assert.strictEqual(parsed.format, "pcap");
    assert.strictEqual(parsed.records.length, 2);
    assert.strictEqual(parsed.linkType, 1);
    assert.strictEqual(hex(PCap.recordBytes(parsed, parsed.records[0])), "01020304");
    assert.strictEqual(hex(PCap.recordBytes(parsed, parsed.records[1])), "090807");
    assert.ok(Math.abs(parsed.records[1].ts - 2.25) < 1e-6);
  });

  test("big-endian nanosecond pcap is understood", () => {
    const parsed = PCap.parse(classicBigEndian(500000000));
    assert.strictEqual(parsed.littleEndian, false);
    assert.strictEqual(parsed.resolution, 1e-9);
    assert.strictEqual(parsed.records.length, 1);
    assert.ok(Math.abs(parsed.records[0].ts - 1.5) < 1e-9);
    assert.strictEqual(hex(PCap.recordBytes(parsed, parsed.records[0])), "deadbeef");
  });

  test("pcapng round-trips", () => {
    const capture = PCap.fromFrames([
      { bytes: Uint8Array.from([1, 2, 3]), linkType: 1, ts: 1.25 },
      { bytes: Uint8Array.from([4, 5, 6, 7]), linkType: 1, ts: 2.5 }
    ]);
    const encoded = PCap.encodeNg(capture, capture.records);
    const parsed = PCap.parse(encoded);
    assert.strictEqual(parsed.format, "pcapng");
    assert.strictEqual(parsed.records.length, 2);
    assert.strictEqual(parsed.interfaces.length, 1);
    assert.strictEqual(hex(PCap.recordBytes(parsed, parsed.records[0])), "010203");
    assert.ok(Math.abs(parsed.records[0].ts - 1.25) < 1e-6);
  });

  test("pcapng keeps multiple link types", () => {
    const capture = PCap.fromFrames([
      { bytes: Uint8Array.from([1, 2, 3]), linkType: 1, ts: 1 },
      { bytes: Uint8Array.from([4, 5, 6]), linkType: 101, ts: 2 }
    ]);
    const parsed = PCap.parse(PCap.encodeNg(capture, capture.records));
    assert.strictEqual(parsed.interfaces.length, 2);
    assert.strictEqual(parsed.records[0].linkType, 1);
    assert.strictEqual(parsed.records[1].linkType, 101);
  });

  test("pcapng reads multiple sections and decryption secrets", () => {
    const capture = PCap.fromFrames([{ bytes: Uint8Array.from([1, 2, 3]), linkType: 1, ts: 1 }]);
    capture.decryptionSecrets = [{ type: 0x544c534b, data: Uint8Array.from(Buffer.from("secret")) }];
    const encoded = PCap.encodeNg(capture, capture.records);
    const parsed = PCap.parse(encoded);
    assert.strictEqual(parsed.decryptionSecrets.length, 1);
    assert.strictEqual(Buffer.from(parsed.decryptionSecrets[0].data).toString(), "secret");
    const combined = Buffer.concat([Buffer.from(encoded), Buffer.from(encoded)]);
    const multi = PCap.parse(combined);
    assert.strictEqual(multi.sections.length, 2);
    assert.strictEqual(multi.records.length, 2);
    assert.strictEqual(multi.interfaces.length, 2);
  });

  test("truncated classic record becomes a warning, not a throw", () => {
    const capture = PCap.fromFrames([
      { bytes: Uint8Array.from([1, 2, 3, 4]), linkType: 1, ts: 1 },
      { bytes: Uint8Array.from([5, 6, 7, 8]), linkType: 1, ts: 2 }
    ]);
    const encoded = PCap.encodeClassic(capture, capture.records);
    const parsed = PCap.parse(encoded.subarray(0, encoded.length - 2));
    assert.strictEqual(parsed.records.length, 1);
    assert.ok(parsed.warnings.some((warning) => /truncated/.test(warning)));
  });

  test("bad magic throws", () => {
    assert.throws(() => PCap.parse(bufferOf("not a capture")), /Not a pcap or pcapng|Empty/);
  });

  test("summary is derived from records", () => {
    const capture = PCap.fromFrames([
      { bytes: Uint8Array.from([1]), linkType: 1, ts: 1 },
      { bytes: Uint8Array.from([2]), linkType: 1, ts: 3 }
    ]);
    const summary = PCap.summary(capture);
    assert.strictEqual(summary.packets, 2);
    assert.strictEqual(summary.duration, 2);
  });
});
