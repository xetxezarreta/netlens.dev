"use strict";

const { createRuntime, loadCodecs, run, DISSECT_SCRIPTS } = require("./harness");

const runtime = createRuntime();
loadCodecs(runtime, DISSECT_SCRIPTS.concat(["flows.js", "bgp.js"]));
const sandbox = runtime.sandbox;
const PH = sandbox.PH;
const Flows = sandbox.PHFlows;
const Dissector = sandbox.Dissector;
const PCap = sandbox.PCapCodec;

const CLIENT = "192.0.2.10";
const SERVER = "198.51.100.20";
const CLIENT_MAC = "02:00:00:00:00:0a";
const SERVER_MAC = "02:00:00:00:00:01";

function tcpFrame(options) {
  const tcp = sandbox.TCPCodec.buildSegment({
    sport: options.sport, dport: options.dport,
    seq: options.seq, ack: options.ack || 0,
    flags: options.flags == null ? 0x18 : options.flags,
    window: options.window == null ? 64240 : options.window,
    urgent: 0, reserved: 0,
    src: options.src, dst: options.dst, options: "",
    payload: options.payload || new Uint8Array(0)
  }).bytes;
  const ip = sandbox.IPv4Codec.buildHeader({
    version: 4, dscp: 0, ecn: 0, id: options.id || 1, ttl: 64, protocol: 6,
    fragmentOffset: 0, payloadLength: tcp.length,
    reserved: false, df: true, mf: false,
    src: options.src, dst: options.dst, options: ""
  }).bytes;
  return sandbox.EthernetCodec.buildFrame({
    dst: options.dstMac, src: options.srcMac, etherType: 0x0800,
    payload: PH.concatBytes(ip, tcp), pad: false, fcs: true
  }).bytes;
}

function buildCapture(frames) {
  const capture = PCap.fromFrames(frames);
  const records = capture.records.map((record) => Object.assign({}, record));
  records.forEach((record, index) => {
    record.number = index + 1;
    record.index = index;
    record.offset = capture.records[index].offset;
    record.caplen = capture.records[index].caplen;
    record.origlen = capture.records[index].origlen;
    record.linkType = capture.records[index].linkType;
    record.ts = capture.records[index].ts;
  });
  return { capture, records };
}

function analyze(capture, records) {
  return Flows.build(records, (record) =>
    Dissector.dissectLink(PCap.recordBytes(capture, record), record.linkType, { headersOnly: true })
  );
}

function tcpBase(port, startSeq, startAck) {
  const frames = [];
  frames.push({
    bytes: tcpFrame({
      src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
      sport: port, dport: 80, seq: startSeq, flags: 0x02, id: 1
    }), ts: 1
  });
  frames.push({
    bytes: tcpFrame({
      src: SERVER, dst: CLIENT, srcMac: SERVER_MAC, dstMac: CLIENT_MAC,
      sport: 80, dport: port, seq: startAck, ack: startSeq + 1, flags: 0x12, id: 2
    }), ts: 1.1
  });
  frames.push({
    bytes: tcpFrame({
      src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
      sport: port, dport: 80, seq: startSeq + 1, ack: startAck + 1, flags: 0x10, id: 3
    }), ts: 1.2
  });
  return frames;
}

function hpackLiteral(text) {
  const name = "x-test";
  const value = text;
  const out = new Uint8Array(1 + 1 + name.length + 1 + value.length);
  out[0] = 0x40; // literal header field with incremental indexing, new name
  out[1] = name.length;
  for (let i = 0; i < name.length; i += 1) out[2 + i] = name.charCodeAt(i);
  out[2 + name.length] = value.length;
  for (let i = 0; i < value.length; i += 1) out[3 + name.length + i] = value.charCodeAt(i);
  return out;
}

run("flows", (test, assert) => {
  test("split HTTP/1.1 response is reassembled", () => {
    const request = sandbox.HTTPCodec.buildHttp1({
      kind: "request", method: "GET", target: "/index.html", host: "example.com",
      headers: [{ name: "Accept", value: "text/html" }]
    }).bytes;
    const response = sandbox.HTTPCodec.buildHttp1({
      kind: "response", status: 200,
      headers: [{ name: "Content-Type", value: "text/plain" }, { name: "Content-Length", value: "20" }],
      body: "hello world 12345678"
    }).bytes;
    const frames = tcpBase(50000, 1000, 5000);
    frames.push({
      bytes: tcpFrame({
        src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
        sport: 50000, dport: 80, seq: 1001, ack: 5001, payload: request, id: 4
      }), ts: 1.3
    });
    frames.push({
      bytes: tcpFrame({
        src: SERVER, dst: CLIENT, srcMac: SERVER_MAC, dstMac: CLIENT_MAC,
        sport: 80, dport: 50000, seq: 5001, ack: 1001 + request.length, payload: response.subarray(0, 18), id: 5
      }), ts: 1.4
    });
    frames.push({
      bytes: tcpFrame({
        src: SERVER, dst: CLIENT, srcMac: SERVER_MAC, dstMac: CLIENT_MAC,
        sport: 80, dport: 50000, seq: 5019, ack: 1001 + request.length, payload: response.subarray(18), id: 6
      }), ts: 1.5
    });
    const { capture, records } = buildCapture(frames);
    const result = analyze(capture, records);
    assert.strictEqual(result.flows.length, 1);
    const app = result.flows[0].app;
    assert.strictEqual(app.kind, "http");
    const responseMessage = app.messages.find((entry) => entry.message.messageKind === "response");
    assert.ok(responseMessage);
    assert.strictEqual(responseMessage.message.status, 200);
    assert.strictEqual(responseMessage.message.body.length, 20);
    assert.deepStrictEqual(Array.from(responseMessage.packets), [5, 6]);
    assert.strictEqual(result.byNumber.get(6).flowFields["http.response.status"], 200);
  });

  test("split TLS ClientHello is reassembled and parsed", () => {
    const hello = sandbox.TLSCodec.buildClientHello({ sni: "example.com", alpn: ["h2", "http/1.1"] }).bytes;
    const frames = tcpBase(50001, 7000, 9000).map((frame) => {
      frame.bytes = tcpFrame({
        src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
        sport: 50001, dport: 443,
        seq: frame.ts === 1 ? 7000 : frame.ts === 1.1 ? 9000 : 7001,
        ack: frame.ts === 1 ? 0 : frame.ts === 1.1 ? 7001 : 9001,
        flags: frame.ts === 1 ? 0x02 : frame.ts === 1.1 ? 0x12 : 0x10,
        id: frame.ts * 10
      });
      return frame;
    });
    frames.push({
      bytes: tcpFrame({
        src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
        sport: 50001, dport: 443, seq: 7001, ack: 9001, payload: hello.subarray(0, 30), id: 4
      }), ts: 1.3
    });
    frames.push({
      bytes: tcpFrame({
        src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
        sport: 50001, dport: 443, seq: 7031, ack: 9001, payload: hello.subarray(30), id: 5
      }), ts: 1.4
    });
    const { capture, records } = buildCapture(frames);
    const result = analyze(capture, records);
    const app = result.flows[0].app;
    assert.strictEqual(app.kind, "tls");
    assert.strictEqual(app.context.sni, "example.com");
    assert.deepStrictEqual(Array.from(app.messages[0].packets), [4, 5]);
    assert.strictEqual(result.byNumber.get(5).flowFields["tls.handshake.extensions_server_name"], "example.com");
  });

  test("fragmented UDP DNS is reassembled", () => {
    const message = sandbox.DNSCodec.buildMessage({
      id: 0x1234, rd: true,
      questions: [{ name: "example.com.", type: "A", class: "IN" }]
    }).bytes;
    const udp = sandbox.UDPCodec.buildUdp({
      srcPort: 53000, dstPort: 53, payload: message,
      ipVersion: 4, srcIp: CLIENT, dstIp: SERVER, zeroChecksum: true
    }).bytes;
    const cut = 24;
    function fragment(offset, more, payload, id) {
      const ip = sandbox.IPv4Codec.buildHeader({
        version: 4, dscp: 0, ecn: 0, id, ttl: 64, protocol: 17,
        fragmentOffset: offset, payloadLength: payload.length,
        reserved: false, df: false, mf: more,
        src: CLIENT, dst: SERVER, options: ""
      }).bytes;
      return sandbox.EthernetCodec.buildFrame({
        dst: SERVER_MAC, src: CLIENT_MAC, etherType: 0x0800,
        payload: PH.concatBytes(ip, payload), pad: false, fcs: true
      }).bytes;
    }
    const frames = [
      { bytes: fragment(0, true, udp.subarray(0, cut), 7), ts: 1 },
      { bytes: fragment(cut / 8, false, udp.subarray(cut), 7), ts: 1.1 }
    ];
    const { capture, records } = buildCapture(frames);
    const result = analyze(capture, records);
    assert.strictEqual(result.flows.length, 1);
    assert.strictEqual(result.flows[0].app.kind, "dns");
    assert.strictEqual(result.flows[0].app.messages[0].message.questions[0].name, "example.com.");
    assert.strictEqual(result.byNumber.get(2).flowFields["dns.qry.name"], "example.com.");
  });

  test("HTTP/2 dynamic HPACK entries survive across frames", () => {
    const preface = sandbox.HTTPCodec.H2_PREFACE;
    const parts = [];
    for (let i = 0; i < preface.length; i += 1) parts.push(preface.charCodeAt(i));
    const prefaceBytes = Uint8Array.from(parts);
    const settings = sandbox.HTTPCodec.buildFrame(4, 0, 0, new Uint8Array(0));
    const first = sandbox.HTTPCodec.buildFrame(1, 0x5, 1, hpackLiteral("first-value"));
    const second = sandbox.HTTPCodec.buildFrame(1, 0x5, 3, Uint8Array.from([0xbe]));
    const stream = PH.concatBytes(prefaceBytes, settings, first, second);
    const frames = tcpBase(50002, 1000, 2000);
    const cuts = [0, 24, 50, 70, stream.length];
    for (let i = 0; i < cuts.length - 1; i += 1) {
      frames.push({
        bytes: tcpFrame({
          src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
          sport: 50002, dport: 80, seq: 1001 + cuts[i], ack: 2001,
          payload: stream.subarray(cuts[i], cuts[i + 1]), id: 4 + i
        }), ts: 1.3 + i * 0.01
      });
    }
    const { capture, records } = buildCapture(frames);
    const result = analyze(capture, records);
    const app = result.flows[0].app;
    assert.strictEqual(app.kind, "h2");
    const stream3 = app.messages.find((entry) => entry.id === 3);
    assert.ok(stream3, "stream 3 should exist");
    const header = stream3.headers.find((entry) => entry.name === "x-test");
    assert.ok(header, "dynamic HPACK entry should decode on the second header block");
    assert.strictEqual(header.value, "first-value");
  });

  test("TCP analysis records retransmission and RTT", () => {
    const frames = tcpBase(50003, 3000, 4000);
    frames.push({
      bytes: tcpFrame({
        src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
        sport: 50003, dport: 80, seq: 3001, ack: 4001, payload: new Uint8Array(10), id: 4
      }), ts: 1.25
    });
    // Retransmit the same 10 bytes.
    frames.push({
      bytes: tcpFrame({
        src: CLIENT, dst: SERVER, srcMac: CLIENT_MAC, dstMac: SERVER_MAC,
        sport: 50003, dport: 80, seq: 3001, ack: 4001, payload: new Uint8Array(10), id: 5
      }), ts: 1.3
    });
    frames.push({
      bytes: tcpFrame({
        src: SERVER, dst: CLIENT, srcMac: SERVER_MAC, dstMac: CLIENT_MAC,
        sport: 80, dport: 50003, seq: 4001, ack: 3011, flags: 0x10, id: 6
      }), ts: 1.5
    });
    const { capture, records } = buildCapture(frames);
    const result = analyze(capture, records);
    const flow = result.flows[0];
    assert.ok(flow.dirs.aToB.retransmissions >= 1);
    assert.strictEqual(result.byNumber.get(5).flowFields["tcp.analysis.retransmission"], true);
    assert.ok(result.byNumber.get(6).flowFields["tcp.analysis.rtt"] > 0);
  });
});
