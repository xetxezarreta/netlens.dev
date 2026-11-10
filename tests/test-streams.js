"use strict";

const { createRuntime, run } = require("./harness");

const runtime = createRuntime();
runtime.load("streams.js");
const Streams = runtime.sandbox.PHStreams;

function record(number) {
  return { number, index: number - 1 };
}

function tcp(src, sport, dst, dport, seq, payloadLength, flags) {
  return {
    ipv4: { src, dst },
    tcp: {
      sport, dport, seq, flags: flags == null ? 0x18 : flags,
      syn: Boolean((flags || 0) & 0x02),
      ackFlag: Boolean((flags || 0) & 0x10),
      payloadLen: payloadLength || 0,
      payloadOffset: 0
    }
  };
}

function frames(payloads) {
  return (item) => Uint8Array.from(payloads[item.index] || []);
}

run("streams", (test, assert) => {
  test("orders payload and labels endpoints", () => {
    const records = [record(1), record(2), record(3), record(4)];
    const indexes = [
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 100, 0, 0x02),
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 103, 2, 0x18),
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 101, 2, 0x18),
      tcp("10.0.0.2", 80, "10.0.0.1", 1111, 500, 2, 0x18)
    ];
    const payloads = [null, [67, 68], [65, 66], [79, 75]];
    const stream = Streams.build(records, records[1], frames(payloads), (item) => indexes[item.index]);
    assert.strictEqual(stream.a.addr, "10.0.0.1");
    assert.strictEqual(stream.a.port, 1111);
    assert.strictEqual(stream.b.addr, "10.0.0.2");
    assert.strictEqual(stream.b.port, 80);
    assert.strictEqual(stream.app, "http");
    assert.strictEqual(stream.directions.aToB.bytes, 4);
    assert.strictEqual(stream.directions.bToA.bytes, 2);
    assert.strictEqual(Streams.textAndHex(stream, "aToB").text, "ABCD");
    assert.strictEqual(Streams.textAndHex(stream, "bToA").text, "OK");
  });

  test("drops exact retransmissions", () => {
    const records = [record(1), record(2), record(3)];
    const indexes = [
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 100, 2, 0x18),
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 100, 2, 0x18),
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 102, 1, 0x18)
    ];
    const payloads = [[65, 66], [65, 66], [67]];
    const stream = Streams.build(records, records[0], frames(payloads), (item) => indexes[item.index]);
    assert.strictEqual(stream.directions.aToB.retransmits, 1);
    assert.strictEqual(stream.directions.aToB.bytes, 3);
    assert.strictEqual(Streams.textAndHex(stream, "aToB").text, "ABC");
  });

  test("marks gaps instead of inventing bytes", () => {
    const records = [record(1), record(2)];
    const indexes = [
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 100, 3, 0x18),
      tcp("10.0.0.1", 1111, "10.0.0.2", 80, 110, 2, 0x18)
    ];
    const payloads = [[65, 66, 67], [88, 89]];
    const stream = Streams.build(records, records[0], frames(payloads), (item) => indexes[item.index]);
    assert.strictEqual(stream.directions.aToB.gaps, 1);
    assert.strictEqual(stream.directions.aToB.gapBytes, 7);
    assert.ok(/gap 7 bytes/.test(Streams.textAndHex(stream, "aToB").text));
  });

  test("non-TCP input returns an error", () => {
    const records = [record(1)];
    const indexes = [{ ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }, udp: { sport: 1, dport: 2 } }];
    const stream = Streams.build(records, records[0], frames([]), (item) => indexes[item.index]);
    assert.ok(/TCP/.test(stream.error));
  });
});
